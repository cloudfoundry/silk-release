package netrules

import (
	"fmt"
	"math"
	"net"
	"strconv"

	"code.cloudfoundry.org/lib/rules"
)

type NetOutChain struct {
	ChainNamer       chainNamer
	Converter        ruleConverter
	DenyNetworks     DenyNetworks
	ASGLogging       bool
	DeniedLogsPerSec int
	Conn             OutConn
}

func (c *NetOutChain) Validate() error {
	allDenyNetworkRules := [][]string{
		c.DenyNetworks.Always,
		c.DenyNetworks.Running,
		c.DenyNetworks.Staging,
	}

	for _, denyNetworks := range allDenyNetworkRules {
		for destinationIndex, destination := range denyNetworks {
			_, validatedDestination, err := net.ParseCIDR(destination)

			if err != nil {
				return fmt.Errorf("deny networks: %s", err)
			}

			denyNetworks[destinationIndex] = fmt.Sprintf("%s", validatedDestination)
		}
	}

	return nil
}

func (c *NetOutChain) DefaultRules(containerHandle string) []rules.IPTablesRule {
	ruleSpec := []rules.IPTablesRule{}
	if c.ASGLogging {
		ruleSpec = append(ruleSpec, rules.NewNetOutDefaultRejectLogRule(containerHandle, c.DeniedLogsPerSec))
	}

	ruleSpec = append(ruleSpec, rules.NewNetOutDefaultRejectRule())
	return ruleSpec
}

func (c *NetOutChain) Name(containerHandle string) string {
	return c.ChainNamer.Prefix(prefixNetOut, containerHandle)
}

func (c *NetOutChain) IPTablesRules(containerHandle string, containerWorkload string, ruleSpec []Rule) ([]rules.IPTablesRule, error) {
	forwardChainName := c.Name(containerHandle)
	logChain, err := c.ChainNamer.Postfix(forwardChainName, suffixNetOutLog)
	if err != nil {
		return nil, fmt.Errorf("getting chain name: %s", err)
	}

	iptablesRules := c.Converter.BulkConvert(ruleSpec, logChain, c.ASGLogging)
	iptablesRules = append(iptablesRules, c.denyNetworksRules(containerWorkload)...)

	if c.Conn.Limit || c.Conn.DryRun {
		rateLimitRule, err := c.rateLimitRule(forwardChainName, containerHandle)
		if err != nil {
			return nil, fmt.Errorf("getting chain name: %s", err)
		}

		iptablesRules = append(iptablesRules, rateLimitRule)
	}

	iptablesRules = append(iptablesRules, []rules.IPTablesRule{
		{"-p", "tcp", "-m", "state", "--state", "INVALID", "-j", "DROP"},
		{"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}...)

	return iptablesRules, nil
}

func (c *NetOutChain) denyNetworksRules(containerWorkload string) []rules.IPTablesRule {
	denyRules := []rules.IPTablesRule{}

	for _, denyNetwork := range c.DenyNetworks.Always {
		denyRules = append(denyRules, rules.NewInputRejectRule(denyNetwork))
	}

	if containerWorkload == "app" || containerWorkload == "task" {
		for _, denyNetwork := range c.DenyNetworks.Running {
			denyRules = append(denyRules, rules.NewInputRejectRule(denyNetwork))
		}
	}

	if containerWorkload == "staging" {
		for _, denyNetwork := range c.DenyNetworks.Staging {
			denyRules = append(denyRules, rules.NewInputRejectRule(denyNetwork))
		}
	}

	return denyRules
}

func (c *NetOutChain) rateLimitRule(forwardChainName string, containerHandle string) (rule rules.IPTablesRule, err error) {
	jumpTarget := "REJECT"

	if c.Conn.Logging || c.Conn.DryRun {
		jumpTarget, err = c.ChainNamer.Postfix(forwardChainName, suffixNetOutRateLimitLog)
		if err != nil {
			return rules.IPTablesRule{}, err
		}
	}

	burst := strconv.Itoa(c.Conn.Burst)
	rate := fmt.Sprintf("%d/sec", c.Conn.RatePerSec)
	expiryPeriod := c.rateLimitExpiryPeriod()

	return rules.NewNetOutConnRateLimitRule(rate, burst, containerHandle, expiryPeriod, jumpTarget), nil
}

func (c *NetOutChain) rateLimitExpiryPeriod() string {
	burst := float64(c.Conn.Burst)
	ratePerSec := float64(c.Conn.RatePerSec)
	expiryPeriodInSeconds := int64(math.Ceil(burst / ratePerSec))
	expiryPeriodInMillis := expiryPeriodInSeconds * int64(secondInMillis)

	return fmt.Sprintf("%d", expiryPeriodInMillis)
}
