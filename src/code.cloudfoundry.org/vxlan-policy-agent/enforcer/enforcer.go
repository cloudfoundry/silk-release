package enforcer

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"code.cloudfoundry.org/lib/rules"

	"code.cloudfoundry.org/lager"
)

type Timestamper struct{}

func (_ Timestamper) CurrentTime() int64 {
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
	Table              string
	ParentChain        string
	Prefix             string
	ManagedChainsRegex string
	CleanUpParentChain bool
}

type LiveChain struct {
	Table string
	Name  string
}

type RulesWithChain struct {
	Chain Chain
	Rules []rules.IPTablesRule
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
		for j, _ := range rule {
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
		err := e.deleteChain(e.Logger, chain)
		if err != nil {
			e.Logger.Error(fmt.Sprintf("delete-chain-%s-from-%s", chain.Name, chain.Table), err)
			return []LiveChain{}, fmt.Errorf("deleting chain %s from table %s: %s", chain.Name, chain.Table, err)
		}
	}
	return chainsToDelete, nil
}

func (e *Enforcer) EnforceRulesAndChain(rulesAndChain RulesWithChain) (string, error) {
	return e.EnforceOnChain(rulesAndChain.Chain, rulesAndChain.Rules)
}

func (e *Enforcer) EnforceOnChain(c Chain, rules []rules.IPTablesRule) (string, error) {
	var managedChainsRegex string
	if c.ManagedChainsRegex != "" {
		managedChainsRegex = c.ManagedChainsRegex
	} else {
		managedChainsRegex = c.Prefix
	}
	return e.Enforce(c.Table, c.ParentChain, c.Prefix, managedChainsRegex, c.CleanUpParentChain, rules...)
}

func (e *Enforcer) Enforce(table, parentChain, chainPrefix, managedChainsRegex string, cleanupParentChain bool, rulespec ...rules.IPTablesRule) (string, error) {
	newTime := e.timestamper.CurrentTime()
	chain := fmt.Sprintf("%s%d", chainPrefix, newTime)
	logger := e.Logger.Session(chain)

	logger.Debug("create-chain", lager.Data{"chain": chain, "table": table})
	err := e.iptables.NewChain(table, chain)
	if err != nil {
		logger.Error("create-chain", err)
		return "", fmt.Errorf("creating chain: %s", err)
	}

	if e.conf.DisableContainerNetworkPolicy {
		rulespec = append([]rules.IPTablesRule{rules.NewAcceptEverythingRule(e.conf.OverlayNetwork)}, rulespec...)
	}

	logger.Debug("insert-chain", lager.Data{"chain": parentChain, "table": table, "index": 1, "rule": rules.IPTablesRule{"-j", chain}})
	err = e.iptables.BulkInsert(table, parentChain, 1, rules.IPTablesRule{"-j", chain})
	if err != nil {
		logger.Error("insert-chain", err)
		delErr := e.deleteChain(logger, LiveChain{Table: table, Name: chain})
		if delErr != nil {
			logger.Error("cleanup-failed-insert", delErr)
		}
		return "", fmt.Errorf("inserting chain: %s", err)
	}

	logger.Debug("bulk-append", lager.Data{"chain": chain, "table": table, "rules": rulespec})
	err = e.iptables.BulkAppend(table, chain, rulespec...)
	if err != nil {
		logger.Error("bulk-append", err)
		cleanErr := e.cleanupOldChain(logger, LiveChain{Table: table, Name: chain}, parentChain)
		if cleanErr != nil {
			logger.Error("cleanup-failed-append", cleanErr)
		}
		return "", fmt.Errorf("bulk appending: %s", err)
	}

	logger.Debug("cleaning-up-old-rules", lager.Data{"chain": chain, "table": table, "rules": rulespec})
	err = e.cleanupOldRules(logger, table, parentChain, managedChainsRegex, cleanupParentChain, newTime)
	if err != nil {
		logger.Error("cleanup-rules", err)
		return "", fmt.Errorf("cleaning up: %s", err)
	}

	return chain, nil
}

func (e *Enforcer) cleanupOldRules(logger lager.Logger, table, parentChain, managedChainsRegex string, cleanupParentChain bool, newTime int64) error {
	rulesList, err := e.iptables.List(table, parentChain)
	if err != nil {
		return fmt.Errorf("listing forward rules: %s", err)
	}

	reManagedChain := regexp.MustCompile(managedChainsRegex + "([0-9]{10,16})")
	reOtherRules := regexp.MustCompile(fmt.Sprintf(`-A\s+%s\s+(.*)`, parentChain))

	for _, r := range rulesList {
		matches := reManagedChain.FindStringSubmatch(r)

		if len(matches) > 1 {
			oldTime, err := strconv.ParseInt(matches[1], 10, 64)
			if err != nil {
				return err // not tested
			}

			if oldTime < newTime {
				logger.Debug("clean-up-old-chain", lager.Data{"name": matches[0]})
				err = e.cleanupOldChain(logger, LiveChain{Table: table, Name: matches[0]}, parentChain)
				if err != nil {
					return err
				}
			}
		} else {
			if cleanupParentChain {
				matches := reOtherRules.FindStringSubmatch(r)

				if len(matches) > 1 {
					logger.Debug("cleaning-up-parent-ruleset", lager.Data{"name": matches[0]})
					rule, err := rules.NewIPTablesRuleFromIPTablesLine(matches[1])
					if err != nil {
						return fmt.Errorf("parsing parent chain rule: %s", err)
					}
					logger.Debug("removing-rule", lager.Data{"rule": rule})
					err = e.iptables.Delete(table, parentChain, rule)
					if err != nil {
						return fmt.Errorf("clean up parent chain: %s", err)
					}
				}
			}
		}
	}

	return nil
}

func (e *Enforcer) cleanupOldChain(logger lager.Logger, chain LiveChain, parentChain string) error {
	logger.Debug("delete-parent-chain-jump-rule", lager.Data{"table": chain.Table, "chain": parentChain, "rule": rules.IPTablesRule{"-j", chain.Name}})
	err := e.iptables.Delete(chain.Table, parentChain, rules.IPTablesRule{"-j", chain.Name})
	if err != nil {
		return fmt.Errorf("remove reference to old chain: %s", err)
	}

	err = e.deleteChain(logger, chain)

	return err
}

func (e *Enforcer) deleteChain(logger lager.Logger, chain LiveChain) error {
	// find gotos and delete those chains as well (since we may have log tables that we reference that need deleting)
	logger.Debug("list-chain", lager.Data{"table": chain.Table, "chain": chain.Name})
	rules, err := e.iptables.List(chain.Table, chain.Name)
	if err != nil {
		return fmt.Errorf("list rules for chain: %s", err)
	}

	reJumpRule := regexp.MustCompile(fmt.Sprintf(`-A\s+%s\s+.*-g\s+([^\s]+)`, chain.Name))
	jumpTargets := map[string]struct{}{}
	for _, rule := range rules {
		matches := reJumpRule.FindStringSubmatch(rule)
		if len(matches) > 1 {
			logger.Debug("found-target-chain-to-recurse", lager.Data{"table": chain.Table, "chain": chain.Name, "target-chain": matches[1]})
			jumpTargets[matches[1]] = struct{}{}
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

	for target, _ := range jumpTargets {
		logger.Debug("deleting-target-chain", lager.Data{"table": chain.Table, "target-chain": target})
		if err := e.iptables.DeleteChain(chain.Table, target); err != nil {
			return fmt.Errorf("cleanup jump target %s: %s", target, err)
		}
	}

	return nil
}
