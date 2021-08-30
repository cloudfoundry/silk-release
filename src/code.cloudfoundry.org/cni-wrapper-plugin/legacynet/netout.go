package legacynet

import (
	"fmt"
	"code.cloudfoundry.org/lib/rules"
	"net"

	"strconv"

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
	HostInterfaceNames    []string
	DeniedLogsPerSec      int
	AcceptedUDPLogsPerSec int
	ContainerHandle       string
	ContainerIP           string
	HostTCPServices       []string
	HostUDPServices       []string
	DenyNetworks          DenyNetworks
	DNSServers            []string
	ContainerWorkload     string
}

func (m *NetOut) Initialize() error {
	args, err := m.defaultNetOutRules()
	if err != nil {
		return err
	}

	err = m.validateDenyNetworks()
	if err != nil {
		return err
	}

	args, err = m.appendInputRules(
		args,
		m.DNSServers,
		m.HostTCPServices,
		m.HostUDPServices,
	)
	if err != nil {
		return fmt.Errorf("input rules: %s", err)
	}

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

func (m *NetOut) BulkInsertRules(netOutRules []garden.NetOutRule) error {
	chain := m.ChainNamer.Prefix(prefixNetOut, m.ContainerHandle)
	logChain, err := m.ChainNamer.Postfix(chain, suffixNetOutLog)
	if err != nil {
		return fmt.Errorf("getting chain name: %s", err)
	}

	ruleSpec := m.Converter.BulkConvert(netOutRules, logChain, m.ASGLogging)
	ruleSpec = append(ruleSpec, m.denyNetworksRules()...)
	ruleSpec = append(ruleSpec, []rules.IPTablesRule{
		{"-p", "tcp", "-m", "state", "--state", "INVALID", "-j", "DROP"},
		{"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}...)

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
			},
		},
		m.addASGLogging(IpTablesFullChain{
			"filter",
			"FORWARD",
			forwardChainName,
			rules.NewNetOutJumpConditions(m.HostInterfaceNames, m.ContainerIP, forwardChainName),
			[]rules.IPTablesRule{
				rules.NewNetOutDefaultRejectRule(),
			},
		}),
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
			},
		}),
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
			},
		},
	}

	return args, nil
}

func (m *NetOut) addASGLogging(c IpTablesFullChain) IpTablesFullChain {
	if m.ASGLogging {
		lastIndex := len(c.Rules) - 1
		c.Rules = append(
			c.Rules[:lastIndex],
			rules.NewNetOutDefaultRejectLogRule(m.ContainerHandle, m.DeniedLogsPerSec),
			c.Rules[lastIndex],
		)
	}

	return c
}

func (m *NetOut) addC2CLogging(c IpTablesFullChain) IpTablesFullChain {
	if m.C2CLogging {
		lastIndex := len(c.Rules) - 1
		c.Rules = append(
			c.Rules[:lastIndex],
			rules.NewOverlayDefaultRejectLogRule(m.ContainerHandle, m.ContainerIP, m.DeniedLogsPerSec),
			c.Rules[lastIndex],
		)
	}

	return c
}

func (m *NetOut) appendInputRules(
	args []IpTablesFullChain,
	dnsServers []string,
	hostTCPServices []string,
	hostUDPServices []string,
) ([]IpTablesFullChain, error) {
	args[0].Rules = []rules.IPTablesRule{
		rules.NewInputRelatedEstablishedRule(),
	}

	for _, dnsServer := range dnsServers {
		args[0].Rules = append(args[0].Rules, rules.NewInputAllowRule("tcp", dnsServer, 53))
		args[0].Rules = append(args[0].Rules, rules.NewInputAllowRule("udp", dnsServer, 53))
	}

	for _, hostService := range hostTCPServices {
		host, port, err := net.SplitHostPort(hostService)
		if err != nil {
			return nil, fmt.Errorf("host tcp services: %s", err)
		}

		portInt, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("host tcp services: %s", err)
		}

		args[0].Rules = append(args[0].Rules, rules.NewInputAllowRule("tcp", host, portInt))
	}

	for _, hostService := range hostUDPServices {
		host, port, err := net.SplitHostPort(hostService)
		if err != nil {
			return nil, fmt.Errorf("host udp services: %s", err)
		}

		portInt, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("host udp services: %s", err)
		}

		args[0].Rules = append(args[0].Rules, rules.NewInputAllowRule("udp", host, portInt))
	}

	args[0].Rules = append(args[0].Rules, rules.NewInputDefaultRejectRule())

	return args, nil
}

func (m *NetOut) validateDenyNetworks() error {
	allDenyNetworkRules := [][]string{
		m.DenyNetworks.Always,
		m.DenyNetworks.Running,
		m.DenyNetworks.Staging,
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

func (m *NetOut) denyNetworksRules() []rules.IPTablesRule {
	denyRules := []rules.IPTablesRule{}

	for _, denyNetwork := range m.DenyNetworks.Always {
		denyRules = append(denyRules, rules.NewInputRejectRule(denyNetwork))
	}

	if m.ContainerWorkload == "app" || m.ContainerWorkload == "task" {
		for _, denyNetwork := range m.DenyNetworks.Running {
			denyRules = append(denyRules, rules.NewInputRejectRule(denyNetwork))
		}
	}

	if m.ContainerWorkload == "staging" {
		for _, denyNetwork := range m.DenyNetworks.Staging {
			denyRules = append(denyRules, rules.NewInputRejectRule(denyNetwork))
		}
	}

	return denyRules
}
