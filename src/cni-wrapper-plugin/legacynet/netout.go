package legacynet

import (
	"fmt"
	"lib/rules"

	"github.com/hashicorp/go-multierror"

	"code.cloudfoundry.org/garden"
)

const prefixInput = "input"
const prefixNetOut = "netout"
const prefixOverlay = "overlay"
const suffixNetOutLog = "log"

//go:generate counterfeiter -o ../fakes/net_out_rule_converter.go --fake-name NetOutRuleConverter . netOutRuleConverter
type netOutRuleConverter interface {
	Convert(rule garden.NetOutRule, logChainName string, logging bool) []rules.IPTablesRule
	BulkConvert(rules []garden.NetOutRule, logChainName string, logging bool) []rules.IPTablesRule
}

type NetOut struct {
	ChainNamer            chainNamer
	IPTables              rules.IPTablesAdapter
	Converter             netOutRuleConverter
	ASGLogging            bool
	C2CLogging            bool
	IngressTag            string
	VTEPName              string
	HostInterfaceName     string
	DeniedLogsPerSec      int
	AcceptedUDPLogsPerSec int
	ContainerHandle       string
	ContainerIP           string
}

func (m *NetOut) Initialize(dnsServers []string) error {
	args, err := m.defaultNetOutRules()
	if err != nil {
		return err
	}

	args = m.appendDnsRules(args, dnsServers)

	err = initChains(m.IPTables, args)
	if err != nil {
		return err
	}

	return applyRules(m.IPTables, args)
}

func (m *NetOut) Cleanup() error {
	args, err := m.defaultNetOutRules()

	if err != nil {
		return err
	}

	return cleanupChains(args, m.IPTables)
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

func (m *NetOut) BulkInsertRules(netOutRules []garden.NetOutRule) error {
	chain := m.ChainNamer.Prefix(prefixNetOut, m.ContainerHandle)
	logChain, err := m.ChainNamer.Postfix(chain, suffixNetOutLog)
	if err != nil {
		return fmt.Errorf("getting chain name: %s", err)
	}

	ruleSpec := m.Converter.BulkConvert(netOutRules, logChain, m.ASGLogging)
	err = m.IPTables.BulkInsert("filter", chain, 1, ruleSpec...)
	if err != nil {
		return fmt.Errorf("bulk inserting net-out rules: %s", err)
	}

	return nil
}

func (m *NetOut) defaultNetOutRules() ([]IpTablesFullChain, error) {
	inputChainName := m.ChainNamer.Prefix(prefixInput, m.ContainerHandle)
	forwardChainName := m.ChainNamer.Prefix(prefixNetOut, m.ContainerHandle)
	overlayChain := m.ChainNamer.Prefix(prefixOverlay, m.ContainerHandle)
	logChain, err := m.ChainNamer.Postfix(forwardChainName, suffixNetOutLog)
	if err != nil {
		return []IpTablesFullChain{}, fmt.Errorf("getting chain name: %s", err)
	}

	args := []IpTablesFullChain{
		{
			"filter",
			"INPUT",
			inputChainName,
			[]rules.IPTablesRule{{
				"-s", m.ContainerIP,
				"--jump", inputChainName,
			}},
			[]rules.IPTablesRule{
				rules.NewInputRelatedEstablishedRule(),
				rules.NewInputDefaultRejectRule(),
			}},
		m.addASGLogging(IpTablesFullChain{
			"filter",
			"FORWARD",
			forwardChainName,
			[]rules.IPTablesRule{{
				"-s", m.ContainerIP,
				"-o", m.HostInterfaceName,
				"--jump", forwardChainName,
			}},
			[]rules.IPTablesRule{
				rules.NewNetOutRelatedEstablishedRule(),
				rules.NewNetOutDefaultRejectRule(),
			}}),
		m.addC2CLogging(IpTablesFullChain{
			"filter",
			"FORWARD",
			overlayChain,
			[]rules.IPTablesRule{{
				"--jump", overlayChain,
			}},
			[]rules.IPTablesRule{
				rules.NewOverlayAllowEgress(m.VTEPName, m.ContainerIP),
				rules.NewOverlayRelatedEstablishedRule(m.ContainerIP),
				rules.NewOverlayTagAcceptRule(m.ContainerIP, m.IngressTag),
				rules.NewOverlayDefaultRejectRule(m.ContainerIP),
			}}),
		{
			"filter",
			"",
			logChain,
			[]rules.IPTablesRule{{
				"--jump", logChain,
			}},
			[]rules.IPTablesRule{
				rules.NewNetOutDefaultNonUDPLogRule(m.ContainerHandle),
				rules.NewNetOutDefaultUDPLogRule(m.ContainerHandle, m.AcceptedUDPLogsPerSec),
				rules.NewAcceptRule(),
			}},
	}

	return args, nil
}

func (m *NetOut) addASGLogging(c IpTablesFullChain) IpTablesFullChain {
	if m.ASGLogging {
		c.Rules = []rules.IPTablesRule{
			rules.NewNetOutRelatedEstablishedRule(),
			rules.NewNetOutDefaultRejectLogRule(m.ContainerHandle, m.DeniedLogsPerSec),
			rules.NewNetOutDefaultRejectRule(),
		}
	}

	return c
}

func (m *NetOut) addC2CLogging(c IpTablesFullChain) IpTablesFullChain {
	if m.C2CLogging {
		c.Rules = []rules.IPTablesRule{
			rules.NewOverlayAllowEgress(m.VTEPName, m.ContainerIP),
			rules.NewOverlayRelatedEstablishedRule(m.ContainerIP),
			rules.NewOverlayTagAcceptRule(m.ContainerIP, m.IngressTag),
			rules.NewOverlayDefaultRejectLogRule(m.ContainerHandle, m.ContainerIP, m.DeniedLogsPerSec),
			rules.NewOverlayDefaultRejectRule(m.ContainerIP),
		}
	}

	return c
}

func (m *NetOut) appendDnsRules(args []IpTablesFullChain, dnsServers []string) []IpTablesFullChain {
	if len(dnsServers) > 0 {
		args[0].Rules = []rules.IPTablesRule{
			rules.NewInputRelatedEstablishedRule(),
		}
		for _, dnsServer := range dnsServers {
			args[0].Rules = append(args[0].Rules, rules.NewInputAllowRule("tcp", dnsServer, 53))
			args[0].Rules = append(args[0].Rules, rules.NewInputAllowRule("udp", dnsServer, 53))
		}
		args[0].Rules = append(args[0].Rules, rules.NewInputDefaultRejectRule())
	}

	return args
}
