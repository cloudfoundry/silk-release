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

type Chain struct {
	Table              string
	ParentChain        string
	Prefix             string
	ManagedChainsRegex string
	CleanUpParentChain bool
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

func (e *Enforcer) EnforceRulesAndChain(rulesAndChain RulesWithChain) error {
	return e.EnforceOnChain(rulesAndChain.Chain, rulesAndChain.Rules)
}

func (e *Enforcer) EnforceOnChain(c Chain, rules []rules.IPTablesRule) error {
	var managedChainsRegex string
	if c.ManagedChainsRegex != "" {
		managedChainsRegex = c.ManagedChainsRegex
	} else {
		managedChainsRegex = c.Prefix
	}
	return e.Enforce(c.Table, c.ParentChain, c.Prefix, managedChainsRegex, c.CleanUpParentChain, rules...)
}

func (e *Enforcer) Enforce(table, parentChain, chainPrefix, managedChainsRegex string, cleanupParentChain bool, rulespec ...rules.IPTablesRule) error {
	newTime := e.timestamper.CurrentTime()
	chain := fmt.Sprintf("%s%d", chainPrefix, newTime)

	err := e.iptables.NewChain(table, chain)
	if err != nil {
		e.Logger.Error("create-chain", err)
		return fmt.Errorf("creating chain: %s", err)
	}

	if e.conf.DisableContainerNetworkPolicy {
		rulespec = append([]rules.IPTablesRule{rules.NewAcceptEverythingRule(e.conf.OverlayNetwork)}, rulespec...)
	}

	err = e.iptables.BulkInsert(table, parentChain, 1, rules.IPTablesRule{"-j", chain})
	if err != nil {
		e.Logger.Error("insert-chain", err)
		return fmt.Errorf("inserting chain: %s", err)
	}

	err = e.iptables.BulkAppend(table, chain, rulespec...)
	if err != nil {
		return fmt.Errorf("bulk appending: %s", err)
	}

	err = e.cleanupOldRules(table, parentChain, managedChainsRegex, cleanupParentChain, newTime)
	if err != nil {
		e.Logger.Error("cleanup-rules", err)
		return err
	}

	return nil
}

func (e *Enforcer) cleanupOldRules(table, parentChain, managedChainsRegex string, cleanupParentChain bool, newTime int64) error {
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
				err = e.cleanupOldChain(table, parentChain, matches[0])
				if err != nil {
					return err
				}
			}
		} else {
			if cleanupParentChain {
				matches := reOtherRules.FindStringSubmatch(r)

				if len(matches) > 1 {
					err := e.iptables.Delete(table, parentChain, rules.NewIPTablesRuleFromIPTablesLine(matches[1]))
					if err != nil {
						return fmt.Errorf("clean up parent chain: %s", err)
					}
				}
			}
		}
	}

	return nil
}

func (e *Enforcer) cleanupOldChain(table, parentChain, timeStampedChain string) error {
	err := e.iptables.Delete(table, parentChain, rules.IPTablesRule{"-j", timeStampedChain})
	if err != nil {
		return fmt.Errorf("cleanup old chain: %s", err)
	}

	err = e.iptables.ClearChain(table, timeStampedChain)
	if err != nil {
		return fmt.Errorf("cleanup old chain: %s", err)
	}

	err = e.iptables.DeleteChain(table, timeStampedChain)
	if err != nil {
		return fmt.Errorf("cleanup old chain: %s", err)
	}

	return nil
}
