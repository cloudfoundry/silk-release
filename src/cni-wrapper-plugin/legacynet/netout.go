package legacynet

import (
	"errors"
	"fmt"
	"lib/rules"
	"net"

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
}

type fullRule struct {
	Table          string
	ParentChain    string
	Chain          string
	JumpConditions []rules.IPTablesRule
	Rules          []rules.IPTablesRule
}

func (m *NetOut) Initialize(containerHandle string, containerIP net.IP, dnsServers []string) error {
	if containerHandle == "" {
		return errors.New("invalid handle")
	}

	args, err := m.defaultNetOutRules(containerHandle, containerIP.String())
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

func (m *NetOut) Cleanup(containerHandle, containerIP string) error {
	args, err := m.defaultNetOutRules(containerHandle, containerIP)

	if err != nil {
		return err
	}

	return cleanupChains(args, m.IPTables)
}

func cleanupChains(args []fullRule, iptables rules.IPTablesAdapter) error {
	var result error
	for _, arg := range args {
		if err := cleanupChain(arg.Table, arg.ParentChain, arg.Chain, arg.JumpConditions, iptables); err != nil {
			result = multierror.Append(result, err)
		}
	}
	return result
}

func (m *NetOut) BulkInsertRules(containerHandle string, netOutRules []garden.NetOutRule) error {
	chain := m.ChainNamer.Prefix(prefixNetOut, containerHandle)
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

func (m *NetOut) defaultNetOutRules(containerHandle string, containerIP string) ([]fullRule, error) {
	inputChain := m.ChainNamer.Prefix(prefixInput, containerHandle)
	forwardChain := m.ChainNamer.Prefix(prefixNetOut, containerHandle)
	overlayChain := m.ChainNamer.Prefix(prefixOverlay, containerHandle)
	logChain, err := m.ChainNamer.Postfix(forwardChain, suffixNetOutLog)
	if err != nil {
		return []fullRule{}, fmt.Errorf("getting chain name: %s", err)
	}

	args := []fullRule{
		{
			Table:       "filter",
			ParentChain: "INPUT",
			Chain:       inputChain,
			JumpConditions: []rules.IPTablesRule{{
				"-s", containerIP,
				"--jump", inputChain,
			}},
			Rules: []rules.IPTablesRule{
				rules.NewInputRelatedEstablishedRule(),
				rules.NewInputDefaultRejectRule(),
			},
		},
		{
			Table:       "filter",
			ParentChain: "FORWARD",
			Chain:       forwardChain,
			JumpConditions: []rules.IPTablesRule{{
				"-s", containerIP,
				"-o", m.HostInterfaceName,
				"--jump", forwardChain,
			}},
			Rules: []rules.IPTablesRule{
				rules.NewNetOutRelatedEstablishedRule(),
				rules.NewNetOutDefaultRejectRule(),
			},
		},
		{
			Table:       "filter",
			ParentChain: "FORWARD",
			Chain:       overlayChain,
			JumpConditions: []rules.IPTablesRule{{
				"--jump", overlayChain,
			}},
			Rules: []rules.IPTablesRule{
				rules.NewOverlayAllowEgress(m.VTEPName, containerIP),
				rules.NewOverlayRelatedEstablishedRule(containerIP),
				rules.NewOverlayTagAcceptRule(containerIP, m.IngressTag),
				rules.NewOverlayDefaultRejectRule(containerIP),
			},
		},
		{
			Table: "filter",
			Chain: logChain,
			JumpConditions: []rules.IPTablesRule{{
				"--jump", logChain,
			}},
			Rules: []rules.IPTablesRule{
				rules.NewNetOutDefaultNonUDPLogRule(containerHandle),
				rules.NewNetOutDefaultUDPLogRule(containerHandle, m.AcceptedUDPLogsPerSec),
				rules.NewAcceptRule(),
			},
		},
	}

	if m.ASGLogging {
		args[1].Rules = []rules.IPTablesRule{
			rules.NewNetOutRelatedEstablishedRule(),
			rules.NewNetOutDefaultRejectLogRule(containerHandle, m.DeniedLogsPerSec),
			rules.NewNetOutDefaultRejectRule(),
		}
	}

	if m.C2CLogging {
		args[2].Rules = []rules.IPTablesRule{
			rules.NewOverlayAllowEgress(m.VTEPName, containerIP),
			rules.NewOverlayRelatedEstablishedRule(containerIP),
			rules.NewOverlayTagAcceptRule(containerIP, m.IngressTag),
			rules.NewOverlayDefaultRejectLogRule(containerHandle, containerIP, m.DeniedLogsPerSec),
			rules.NewOverlayDefaultRejectRule(containerIP),
		}
	}

	return args, nil
}

func (m *NetOut) appendDnsRules(args []fullRule, dnsServers []string) []fullRule {
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