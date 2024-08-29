package enforcer

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"code.cloudfoundry.org/executor"
	"code.cloudfoundry.org/lib/rules"

	"code.cloudfoundry.org/lager/v3"
)

const (
	TimestampedRegex       = `([0-9]{10,16})`
	ASGChainRegex          = `^c?asg-[A-Za-z0-9]+`
	ContainerPrefixToStrip = `check-`
	JumpRuleRegex          = `-A\s+%s\s+.*-g\s+([^\s]+)`
)

type Timestamper struct{}

func (Timestamper) CurrentTime() int64 {
	return time.Now().UnixNano() / int64(time.Microsecond)
}

//go:generate counterfeiter -o fakes/timestamper.go --fake-name TimeStamper . TimeStamper
type TimeStamper interface {
	CurrentTime() int64
}

type Enforcer struct {
	Logger      lager.Logger
	timestamper TimeStamper
	iptables    rules.IPTablesAdapter
	conf        EnforcerConfig
}

func NewEnforcer(logger lager.Logger, timestamper TimeStamper, ipt rules.IPTablesAdapter, conf EnforcerConfig) *Enforcer {
	return &Enforcer{
		Logger:      logger,
		timestamper: timestamper,
		iptables:    ipt,
		conf:        conf,
	}
}

type EnforcerConfig struct {
	DisableContainerNetworkPolicy bool
	OverlayNetwork                string
}

const FilterTable = "filter"

type Chain struct {
	Table       string
	ParentChain string
	Name        string
	Timestamped bool
}

func NewPolicyChain() Chain {
	return Chain{
		Table:       FilterTable,
		ParentChain: "FORWARD",
		Name:        "vpa--",
		Timestamped: true,
	}
}

func NewASGChain(parentChain string, containerHandle string) Chain {
	return Chain{
		Table:       FilterTable,
		ParentChain: parentChain,
		Name:        ASGChainName(containerHandle),
		Timestamped: false,
	}
}

func ASGChainName(handle string) string {
	prefixStripped := strings.TrimPrefix(handle, ContainerPrefixToStrip)
	dashesStripped := strings.Replace(prefixStripped, "-", "", -1)
	name := dashesStripped
	if len(dashesStripped) > 20 {
		name = dashesStripped[:20]
	}

	return fmt.Sprintf("asg-%s", name)
}

type LiveChain struct {
	Table string
	Name  string
}

type RulesWithChain struct {
	Chain     Chain
	Rules     []rules.IPTablesRule
	LogConfig executor.LogConfig
}

type CleanupErr struct {
	Err error
}

func (e *CleanupErr) Error() string {
	return fmt.Sprintf("cleaning up: %s", e.Err)
}

func (r *RulesWithChain) Equals(other RulesWithChain) bool {
	if r.Chain != other.Chain {
		return false
	}

	if len(r.Rules) != len(other.Rules) {
		return false
	}

	for i, rule := range r.Rules {
		otherRule := other.Rules[i]
		if len(rule) != len(otherRule) {
			return false
		}
		for j := range rule {
			if rule[j] != otherRule[j] {
				return false
			}
		}
	}
	return true
}

func (e *Enforcer) CleanChainsMatching(regex *regexp.Regexp, desiredChains []LiveChain) ([]LiveChain, error) {
	desiredMap := make(map[string]struct{})
	for _, chain := range desiredChains {
		if _, ok := desiredMap[chain.Name]; !ok {
			desiredMap[chain.Name] = struct{}{}
			desiredMap[e.candidateChainName(chain.Name)] = struct{}{}
		}
	}

	var chainsToDelete []LiveChain

	allChains, err := e.iptables.ListChains(FilterTable)
	if err != nil {
		e.Logger.Error(fmt.Sprintf("list-chains-%s", FilterTable), err)
		return []LiveChain{}, fmt.Errorf("listing chains in %s: %s", FilterTable, err)
	}
	e.Logger.Debug("allchains", lager.Data{"chains": allChains})

	for _, chainName := range allChains {
		if regex.MatchString(chainName) {
			if _, ok := desiredMap[chainName]; !ok {
				chainsToDelete = append(chainsToDelete, LiveChain{Table: FilterTable, Name: chainName})
			}
		}
	}

	for _, chain := range chainsToDelete {
		e.Logger.Debug("deleting-chain-in-enforce-chains-matching", lager.Data{"chain": chain})
		err := e.deleteChain(e.Logger, chain, "")
		if err != nil {
			e.Logger.Error(fmt.Sprintf("delete-chain-%s-from-%s", chain.Name, chain.Table), err)
			return []LiveChain{}, fmt.Errorf("deleting chain %s from table %s: %s", chain.Name, chain.Table, err)
		}
	}
	return chainsToDelete, nil
}

func (e *Enforcer) CleanupChain(chain LiveChain) error {
	e.Logger.Debug("cleanup-chain", lager.Data{"name": chain.Name, "table": chain.Table})
	chainExists, _ := e.iptables.ChainExists(chain.Table, chain.Name)
	if chainExists {
		e.Logger.Debug("deleting-chain", lager.Data{"name": chain.Name, "table": chain.Table})
		err := e.deleteChain(e.Logger, LiveChain{Table: chain.Table, Name: chain.Name}, "")
		if err != nil {
			e.Logger.Error(fmt.Sprintf("delete-chain-%s-from-%s", chain.Name, chain.Table), err)
			return fmt.Errorf("deleting chain %s from table %s: %s", chain.Name, chain.Table, err)
		}
	}
	candidateChainName := e.candidateChainName(chain.Name)
	candidateChainExists, _ := e.iptables.ChainExists(chain.Table, candidateChainName)
	if candidateChainExists {
		e.Logger.Debug("deleting-chain", lager.Data{"name": candidateChainName, "table": chain.Table})
		err := e.deleteChain(e.Logger, LiveChain{Table: chain.Table, Name: candidateChainName}, "")
		if err != nil {
			e.Logger.Error(fmt.Sprintf("delete-chain-%s-from-%s", candidateChainName, chain.Table), err)
			return fmt.Errorf("deleting chain %s from table %s: %s", candidateChainName, chain.Table, err)
		}
	}

	return nil
}

func (e *Enforcer) EnforceRulesAndChain(rulesAndChain RulesWithChain) (string, error) {
	return e.EnforceOnChain(rulesAndChain.Chain, rulesAndChain.Rules)
}

func (e *Enforcer) EnforceOnChain(c Chain, rulesSpec []rules.IPTablesRule) (string, error) {
	if c.Timestamped {
		// used for C2C
		newTime := e.timestamper.CurrentTime()
		chainName := fmt.Sprintf("%s%d", c.Name, newTime)

		logger := e.Logger.Session(chainName)
		err := e.enforce(logger, c.Table, c.ParentChain, chainName, rulesSpec...)
		if err != nil {
			return "", err
		}

		logger.Debug("cleaning-up-old-rules", lager.Data{"chain": chainName, "table": c.Table, "rules": rulesSpec, "prefix": c.Name})
		managedChainsRegex := c.Name + TimestampedRegex
		err = e.cleanupOldRules(logger, c.Table, c.ParentChain, managedChainsRegex, newTime)
		if err != nil {
			logger.Error("cleanup-rules", err)
			return chainName, &CleanupErr{err}
		}

		return chainName, nil
	}

	// used for ASGS
	logger := e.Logger.Session(c.Name)

	err := e.replaceChainRules(logger, c, rulesSpec)
	if err != nil {
		logger.Error("replace-chain", err)
		return "", err
	}

	// Delete everything after the first rule in the parent chain. Rule 1 should be the jump to the new/desired asg-* chain.
	// Everything else is either an original rule from before asg-syncing kicked in, or the previous asg-* chain jump rule
	// Nothing should be modifying the netout-* chains, as the first rule will always end up being a jump to the asg-*
	// chain after ~60s, and it ends in a blanket REJECT, so no other rules would be effective anyway.
	err = e.iptables.DeleteAfterRuleNumKeepReject(c.Table, c.ParentChain, 2)
	if err != nil {
		return c.Name, &CleanupErr{fmt.Errorf("clean up parent chain: %s", err)}
	}

	return c.Name, nil
}

func (e *Enforcer) enforce(logger lager.Logger, table string, parentChain string, chainName string, rulespec ...rules.IPTablesRule) error {
	logger.Debug("create-chain", lager.Data{"chain": chainName, "table": table})
	err := e.iptables.NewChain(table, chainName)
	if err != nil {
		logger.Error("create-chain", err)
		return fmt.Errorf("creating chain: %s", err)
	}

	if e.conf.DisableContainerNetworkPolicy {
		rulespec = append([]rules.IPTablesRule{rules.NewAcceptEverythingRule(e.conf.OverlayNetwork)}, rulespec...)
	}

	logger.Debug("insert-chain", lager.Data{"parent-chain": parentChain, "table": table, "index": 1, "rule": rules.IPTablesRule{"-j", chainName}})
	err = e.iptables.BulkInsert(table, parentChain, 1, rules.IPTablesRule{"-j", chainName})
	if err != nil {
		logger.Error("insert-chain", err)
		delErr := e.deleteChain(logger, LiveChain{Table: table, Name: chainName}, "")
		if delErr != nil {
			logger.Error("cleanup-failed-insert", delErr)
		}
		return fmt.Errorf("inserting chain: %s", err)
	}

	logger.Debug("bulk-append", lager.Data{"chain": chainName, "table": table, "rules": rulespec})
	err = e.iptables.BulkAppend(table, chainName, rulespec...)
	if err != nil {
		logger.Error("bulk-append", err)
		cleanErr := e.cleanupOldChain(logger, LiveChain{Table: table, Name: chainName}, parentChain, "")
		if cleanErr != nil {
			logger.Error("cleanup-failed-append", cleanErr)
		}
		return fmt.Errorf("bulk appending: %s", err)
	}

	return nil
}

// Replaces chain if exists with provided rule spec:
// 1. First it checks if candidate chain exists in case if previos run failed for any reason and cleans it up
// 2. Creates a temporary candidate chain that is appended to the parent chain
// 3. Deletes original chain
// 4. Renames candidate chain to original chain
func (e *Enforcer) replaceChainRules(logger lager.Logger, c Chain, rulesSpec []rules.IPTablesRule) error {
	logger.Debug("replace-chain", lager.Data{"chain": c.Name, "table": c.Table, "rulesSpec": rulesSpec})

	candidateName := e.candidateChainName(c.Name)
	originalChainJumpExists, _ := e.iptables.Exists(c.Table, c.ParentChain, rules.IPTablesRule{"-j", c.Name})
	candidateChainJumpExists, _ := e.iptables.Exists(c.Table, c.ParentChain, rules.IPTablesRule{"-j", candidateName})

	logger.Debug("replace-chain-exists", lager.Data{"original": originalChainJumpExists, "candidate": candidateChainJumpExists})
	if !originalChainJumpExists && !candidateChainJumpExists {
		return e.enforce(logger, c.Table, c.ParentChain, c.Name, rulesSpec...)
	}

	if candidateChainJumpExists {
		if originalChainJumpExists {
			err := e.cleanupOldChain(e.Logger, LiveChain{Table: c.Table, Name: candidateName}, c.ParentChain, "")
			if err != nil {
				return err
			}
		} else {
			logger.Debug("replace-chain-rename-original", lager.Data{"chain": c.Name, "table": c.Table})
			err := e.iptables.RenameChain(c.Table, candidateName, c.Name)
			if err != nil {
				return err
			}
		}
	}

	err := e.enforce(logger, c.Table, c.ParentChain, candidateName, rulesSpec...)
	if err != nil {
		return err
	}

	// deleting without jump targets if they are unused
	err = e.cleanupOldChain(e.Logger, LiveChain{Table: c.Table, Name: c.Name}, c.ParentChain, candidateName)
	if err != nil {
		return err
	}

	logger.Debug("replace-chain-rename-candidate", lager.Data{"chain": c.Name, "candidate-chain": candidateName, "table": c.Table})
	err = e.iptables.RenameChain(c.Table, candidateName, c.Name)
	if err != nil {
		return err
	}

	return nil
}

func (e *Enforcer) cleanupOldRules(logger lager.Logger, table, parentChain, managedChainsRegex string, newTime int64) error {
	rulesList, err := e.iptables.List(table, parentChain)
	if err != nil {
		return fmt.Errorf("listing forward rules: %s", err)
	}

	reManagedChain := regexp.MustCompile(managedChainsRegex)

	for _, r := range rulesList {
		matches := reManagedChain.FindStringSubmatch(r)

		if len(matches) > 1 {
			oldTime, err := strconv.ParseInt(matches[1], 10, 64)
			if err != nil {
				return err // not tested
			}

			if oldTime < newTime {
				logger.Debug("clean-up-old-chain", lager.Data{"name": matches[0]})
				err = e.cleanupOldChain(logger, LiveChain{Table: table, Name: matches[0]}, parentChain, "")
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// Deletes chain and its jump targets
func (e *Enforcer) cleanupOldChain(logger lager.Logger, chain LiveChain, parentChain string, newChainName string) error {
	logger.Debug("delete-parent-chain-jump-rule", lager.Data{"table": chain.Table, "chain": parentChain, "rule": rules.IPTablesRule{"-j", chain.Name}})
	err := e.iptables.Delete(chain.Table, parentChain, rules.IPTablesRule{"-j", chain.Name})
	if err != nil {
		return fmt.Errorf("remove reference to old chain: %s", err)
	}

	err = e.deleteChain(logger, chain, newChainName)

	return err
}

func (e *Enforcer) deleteChain(logger lager.Logger, chain LiveChain, newChainName string) error {
	// find gotos and delete those chains as well (since we may have log tables that we reference that need deleting)
	logger.Debug("list-chain", lager.Data{"table": chain.Table, "chain": chain.Name})
	rules, err := e.iptables.List(chain.Table, chain.Name)
	if err != nil {
		return fmt.Errorf("list rules for chain: %s", err)
	}

	reJumpRule := regexp.MustCompile(fmt.Sprintf(JumpRuleRegex, chain.Name))
	jumpTargets := map[string]struct{}{}
	for _, rule := range rules {
		matches := reJumpRule.FindStringSubmatch(rule)
		if len(matches) > 1 {
			logger.Debug("found-target-chain-to-recurse", lager.Data{"table": chain.Table, "chain": chain.Name, "target-chain": matches[1]})
			jumpTargets[matches[1]] = struct{}{}
		}
	}

	if newChainName != "" {
		newRules, err := e.iptables.List(chain.Table, newChainName)
		if err != nil {
			return fmt.Errorf("list rules for new chain: %s", err)
		}
		reJumpRule := regexp.MustCompile(fmt.Sprintf(JumpRuleRegex, newChainName))
		for _, rule := range newRules {
			matches := reJumpRule.FindStringSubmatch(rule)
			if len(matches) > 1 {
				logger.Debug("found-target-chain-in-use", lager.Data{"table": chain.Table, "chain": newChainName, "target-chain": matches[1]})
				delete(jumpTargets, matches[1])
			}
		}
	}

	logger.Debug("flush-chain", lager.Data{"table": chain.Table, "chain": chain.Name})
	err = e.iptables.ClearChain(chain.Table, chain.Name)
	if err != nil {
		return fmt.Errorf("cleanup old chain: %s", err)
	}

	logger.Debug("delete-chain", lager.Data{"table": chain.Table, "chain": chain.Name})
	err = e.iptables.DeleteChain(chain.Table, chain.Name)
	if err != nil {
		return fmt.Errorf("delete old chain: %s", err)
	}

	for target := range jumpTargets {
		logger.Debug("deleting-target-chain", lager.Data{"table": chain.Table, "target-chain": target})
		if err := e.iptables.DeleteChain(chain.Table, target); err != nil {
			return fmt.Errorf("cleanup jump target %s: %s", target, err)
		}
	}

	return nil
}

func (e *Enforcer) candidateChainName(name string) string {
	return fmt.Sprintf("c%s", name)
}
