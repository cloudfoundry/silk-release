package legacynet

import (
	"fmt"
	"lib/rules"

	multierror "github.com/hashicorp/go-multierror"
)

func initChains(iptables rules.IPTablesAdapter, fullRules []IpTablesFullChain) error {
	for _, rule := range fullRules {
		err := iptables.NewChain(rule.Table, rule.ChainName)
		if err != nil {
			return fmt.Errorf("creating chain: %s", err)
		}

		if rule.ParentChain != "" {
			err = iptables.BulkAppend(rule.Table, rule.ParentChain, rule.JumpConditions...)
			if err != nil {
				return fmt.Errorf("appending rule to chain: %s", err)
			}
		}
	}

	return nil
}

func applyRules(iptables rules.IPTablesAdapter, fullRules []IpTablesFullChain) error {
	for _, rule := range fullRules {
		err := iptables.BulkAppend(rule.Table, rule.ChainName, rule.Rules...)
		if err != nil {
			return fmt.Errorf("appending rule: %s", err)
		}
	}

	return nil
}

func cleanupChain(table, parentChain, chain string, jumpConditions []rules.IPTablesRule, iptables rules.IPTablesAdapter) error {
	var result error
	if parentChain != "" {
		for _, condition := range jumpConditions {
			if err := iptables.Delete(table, parentChain, condition); err != nil {
				result = multierror.Append(result, fmt.Errorf("delete rule: %s", err))
			}
		}
	}

	if err := iptables.ClearChain(table, chain); err != nil {
		result = multierror.Append(result, fmt.Errorf("clear chain: %s", err))
	}

	if err := iptables.DeleteChain(table, chain); err != nil {
		result = multierror.Append(result, fmt.Errorf("delete chain: %s", err))
	}
	return result
}

func cleanupChains(args []IpTablesFullChain, iptables rules.IPTablesAdapter) error {
	var result error
	for _, arg := range args {
		if err := cleanupChain(arg.Table, arg.ParentChain, arg.ChainName, arg.JumpConditions, iptables); err != nil {
			result = multierror.Append(result, err)
		}
	}
	return result
}
