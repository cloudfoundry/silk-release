package netrules

import (
	"errors"
	"fmt"
	"strings"

	"code.cloudfoundry.org/lib/rules"
)

const antiSpoofGuardPrefix = "ip6g--"

type AntiSpoof struct {
	ChainNamer chainNamer
	IPTables   rules.IPTablesAdapter
}

func (a *AntiSpoof) Install(containerHandle, hostVeth, containerIPv6 string) error {
	chain := a.ChainNamer.Prefix("ip6g", containerHandle)
	if err := a.reconcile(hostVeth, chain); err != nil {
		return fmt.Errorf("reconcile guard: %w", err)
	}
	if err := a.IPTables.NewChain("raw", chain); err != nil {
		return fmt.Errorf("create chain: %w", err)
	}

	dropRule := rules.AppendComment(rules.IPTablesRule{"!", "-s", containerIPv6 + "/128"}, "ip6 anti-spoof")
	dropRule = append(dropRule, "-j", "DROP")
	if err := a.IPTables.BulkAppend("raw", chain, dropRule); err != nil {
		return errors.Join(fmt.Errorf("append drop rule: %w", err), wrapRollback("delete chain", a.IPTables.DeleteChain("raw", chain)))
	}

	jumpRule := rules.AppendComment(rules.IPTablesRule{"-i", hostVeth}, "ip6 anti-spoof")
	jumpRule = append(jumpRule, "-j", chain)
	if err := a.IPTables.BulkInsert("raw", "PREROUTING", 1, jumpRule); err != nil {
		return errors.Join(fmt.Errorf("insert jump: %w", err), wrapRollback("remove guard", a.removeGuard(chain)))
	}
	return nil
}

func wrapRollback(action string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("rollback %s: %w", action, err)
}

func (a *AntiSpoof) Cleanup(containerHandle string) error {
	return a.removeGuard(a.ChainNamer.Prefix("ip6g", containerHandle))
}

func (a *AntiSpoof) removeGuard(chain string) error {
	lines, err := a.IPTables.List("raw", "PREROUTING")
	if err != nil {
		return fmt.Errorf("list raw PREROUTING: %w", err)
	}

	var deleteErrors []error
	for _, line := range lines {
		rule, parseErr := rules.NewIPTablesRuleFromIPTablesLine(line)
		if parseErr != nil {
			return fmt.Errorf("parse raw PREROUTING rule: %w", parseErr)
		}
		if !isAppendTo(rule, "PREROUTING") || jumpTarget(rule) != chain {
			continue
		}
		if err := a.IPTables.Delete("raw", "PREROUTING", rule[2:]); err != nil {
			deleteErrors = append(deleteErrors, fmt.Errorf("delete jump: %w", err))
		}
	}

	if len(deleteErrors) > 0 {
		lines, err = a.IPTables.List("raw", "PREROUTING")
		if err != nil {
			return errors.Join(append(deleteErrors, fmt.Errorf("re-list raw PREROUTING: %w", err))...)
		}
		for _, line := range lines {
			rule, parseErr := rules.NewIPTablesRuleFromIPTablesLine(line)
			if parseErr != nil {
				return errors.Join(append(deleteErrors, fmt.Errorf("parse raw PREROUTING rule: %w", parseErr))...)
			}
			if isAppendTo(rule, "PREROUTING") && jumpTarget(rule) == chain {
				return errors.Join(deleteErrors...)
			}
		}
	}

	exists, err := a.IPTables.ChainExists("raw", chain)
	if err != nil {
		return fmt.Errorf("check chain: %w", err)
	}
	if !exists {
		return nil
	}
	if err := a.IPTables.ClearChain("raw", chain); err != nil {
		exists, recheckErr := a.IPTables.ChainExists("raw", chain)
		if recheckErr != nil {
			return errors.Join(fmt.Errorf("clear chain: %w", err), fmt.Errorf("re-check chain: %w", recheckErr))
		}
		if !exists {
			return nil
		}
		return fmt.Errorf("clear chain: %w", err)
	}
	if err := a.IPTables.DeleteChain("raw", chain); err != nil {
		exists, recheckErr := a.IPTables.ChainExists("raw", chain)
		if recheckErr != nil {
			return errors.Join(fmt.Errorf("delete chain: %w", err), fmt.Errorf("re-check chain: %w", recheckErr))
		}
		if !exists {
			return nil
		}
		return fmt.Errorf("delete chain: %w", err)
	}
	return nil
}

func (a *AntiSpoof) reconcile(hostVeth, chain string) error {
	lines, err := a.IPTables.List("raw", "PREROUTING")
	if err != nil {
		return fmt.Errorf("list raw PREROUTING: %w", err)
	}
	seen := map[string]struct{}{}
	for _, line := range lines {
		rule, parseErr := rules.NewIPTablesRuleFromIPTablesLine(line)
		if parseErr != nil {
			return fmt.Errorf("parse raw PREROUTING rule: %w", parseErr)
		}
		if !isAppendTo(rule, "PREROUTING") {
			continue
		}
		target := jumpTarget(rule)
		if target == "" || (target != chain && (!hasInputInterface(rule, hostVeth) || !strings.HasPrefix(target, antiSpoofGuardPrefix))) {
			continue
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		if err := a.removeGuard(target); err != nil {
			return fmt.Errorf("remove stale guard %s: %w", target, err)
		}
	}
	exists, err := a.IPTables.ChainExists("raw", chain)
	if err != nil {
		return fmt.Errorf("check chain: %w", err)
	}
	if exists {
		if err := a.removeGuard(chain); err != nil {
			return fmt.Errorf("remove leftover guard %s: %w", chain, err)
		}
	}
	return nil
}

func isAppendTo(rule rules.IPTablesRule, chain string) bool {
	return len(rule) >= 2 && rule[0] == "-A" && rule[1] == chain
}

func jumpTarget(rule rules.IPTablesRule) string {
	for i := 0; i+1 < len(rule); i++ {
		if rule[i] == "-j" || rule[i] == "--jump" {
			return rule[i+1]
		}
	}
	return ""
}

func hasInputInterface(rule rules.IPTablesRule, hostVeth string) bool {
	for i := 0; i+1 < len(rule); i++ {
		if rule[i] == "-i" && rule[i+1] == hostVeth {
			return true
		}
	}
	return false
}
