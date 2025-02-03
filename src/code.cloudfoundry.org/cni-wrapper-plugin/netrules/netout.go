package netrules

import (
	"fmt"
	"net"
	"strconv"

	"code.cloudfoundry.org/lib/rules"
)

const prefixInput = "input"
const prefixNetOut = "netout"
const prefixOverlay = "overlay"
const suffixNetOutLog = "log"
const suffixNetOutRateLimitLog = "rl-log"
const secondInMillis = 1000

//go:generate counterfeiter -o ../fakes/rule_converter.go --fake-name RuleConverter . ruleConverter
type ruleConverter interface {
	Convert(Rule, string, bool) []rules.IPTablesRule
	BulkConvert([]Rule, string, bool) []rules.IPTablesRule
	DeduplicateRules([]rules.IPTablesRule) []rules.IPTablesRule
}

type OutConn struct {
	Limit      bool
	Logging    bool
	Burst      int
	RatePerSec int
	DryRun     bool
}

type NetOut struct {
	ChainNamer            chainNamer
	IPTables              rules.IPTablesAdapter
	C2CLogging            bool
	IngressTag            string
	VTEPName              string
	HostInterfaceNames    []string
	DeniedLogsPerSec      int
	AcceptedUDPLogsPerSec int
	ContainerHandle       string
	ContainerWorkload     string
	ContainerIP           string
	HostTCPServices       []string
	HostUDPServices       []string
	DNSServers            []string
	Conn                  OutConn
	NetOutChain           *NetOutChain
	IPv6                  bool
}

func (m *NetOut) Initialize() error {
	args, err := m.defaultNetOutRules()
	if err != nil {
		return err
	}

	err = m.NetOutChain.Validate()
	if err != nil {
		return err
	}

	err = m.validateDnsServers()
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

func (m *NetOut) BulkInsertRules(ruleSpec []Rule) error {
	iptablesRules, err := m.NetOutChain.IPTablesRules(m.ContainerHandle, m.ContainerWorkload, ruleSpec)
	if err != nil {
		return fmt.Errorf("bulk converting net-out rules: %s", err)
	}
	chain := m.NetOutChain.Name(m.ContainerHandle)
	err = m.IPTables.BulkInsert("filter", chain, 1, iptablesRules...)
	if err != nil {
		return fmt.Errorf("bulk inserting net-out rules: %s", err)
	}
	return nil
}

func (m *NetOut) Cleanup() error {
	args, err := m.defaultNetOutRules()

	if err != nil {
		return err
	}

	return cleanupChains(args, m.IPTables)
}

func (m *NetOut) defaultNetOutRules() ([]IpTablesFullChain, error) {
	inputChainName := m.ChainNamer.Prefix(prefixInput, m.ContainerHandle)
	forwardChainName := m.ChainNamer.Prefix(prefixNetOut, m.ContainerHandle)
	overlayChain := m.ChainNamer.Prefix(prefixOverlay, m.ContainerHandle)

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
				rules.NewInputDefaultRejectRule(m.IPv6),
			},
		},
		{
			"filter",
			"FORWARD",
			forwardChainName,
			rules.NewNetOutJumpConditions(m.HostInterfaceNames, m.ContainerIP, forwardChainName),
			m.NetOutChain.DefaultRules(m.ContainerHandle),
		},
		m.addC2CLogging(IpTablesFullChain{
			"filter",
			"FORWARD",
			overlayChain,
			[]rules.IPTablesRule{{
				"--jump", overlayChain,
			}},
			m.getOverlayRules(),
		}),
	}

	// This log chain is not connected to parent chains, it only gets used when asg logging is set
	logChainRules := []rules.IPTablesRule{
		rules.NewNetOutDefaultNonUDPLogRule(m.ContainerHandle),
		rules.NewNetOutDefaultUDPLogRule(m.ContainerHandle, m.AcceptedUDPLogsPerSec),
		rules.NewAcceptRule(),
	}
	logChain, err := m.netOutLogChain(forwardChainName, suffixNetOutLog, logChainRules)
	if err != nil {
		return []IpTablesFullChain{}, fmt.Errorf("getting chain name: %s", err)
	}

	args = append(args, logChain)

	if (m.Conn.Limit && m.Conn.Logging) || m.Conn.DryRun {
		rateLimitLogChain, err := m.connRateLimitLogChain(forwardChainName)
		if err != nil {
			return []IpTablesFullChain{}, fmt.Errorf("getting chain name: %s", err)
		}

		args = append(args, rateLimitLogChain)
	}

	return args, nil
}

func (m *NetOut) getOverlayRules() []rules.IPTablesRule {
	if !m.IPv6 {
		return []rules.IPTablesRule{
			rules.NewOverlayAllowEgress(m.VTEPName, m.ContainerIP),
			rules.NewOverlayRelatedEstablishedRule(m.ContainerIP),
			rules.NewOverlayTagAcceptRule(m.ContainerIP, m.IngressTag),
			rules.NewOverlayDefaultRejectRule(m.ContainerIP, m.IPv6),
		}
	} else {
		return []rules.IPTablesRule{
			rules.NewOverlayRelatedEstablishedRule(m.ContainerIP),
			rules.NewOverlayDefaultRejectRule(m.ContainerIP, m.IPv6),
		}
	}
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
		host, port, err := m.splitHostPort(hostService)
		if err != nil {
			return nil, fmt.Errorf("host tcp services: %s", err)
		}

		args[0].Rules = append(args[0].Rules, rules.NewInputAllowRule("tcp", host, port))
	}

	for _, hostService := range hostUDPServices {
		host, port, err := m.splitHostPort(hostService)
		if err != nil {
			return nil, fmt.Errorf("host udp services: %s", err)
		}

		args[0].Rules = append(args[0].Rules, rules.NewInputAllowRule("udp", host, port))
	}

	args[0].Rules = append(args[0].Rules, rules.NewInputDefaultRejectRule(m.IPv6))

	return args, nil
}

func (m *NetOut) connRateLimitLogChain(forwardChainName string) (IpTablesFullChain, error) {
	logRules := []rules.IPTablesRule{}

	if m.Conn.Logging || m.Conn.DryRun {
		logRules = append(logRules, rules.NewNetOutConnRateLimitRejectLogRule(m.ContainerHandle, m.DeniedLogsPerSec))
	}

	if !m.Conn.DryRun {
		logRules = append(logRules, rules.NewNetOutDefaultRejectRule(m.IPv6))
	}

	return m.netOutLogChain(forwardChainName, suffixNetOutRateLimitLog, logRules)
}

func (m *NetOut) netOutLogChain(forwardChainName, suffix string, logRules []rules.IPTablesRule) (IpTablesFullChain, error) {
	logChainName, err := m.ChainNamer.Postfix(forwardChainName, suffix)
	if err != nil {
		return IpTablesFullChain{}, err
	}

	jumpConditions := []rules.IPTablesRule{{"--jump", logChainName}}
	return IpTablesFullChain{"filter", "", logChainName, jumpConditions, logRules}, nil
}

func (m *NetOut) validateDnsServers() error {
	for _, dns := range m.DNSServers {
		err := m.validateAddressAndVersion(dns)
		if err != nil {
			return fmt.Errorf("invalid dns server: %s", dns)
		}
	}

	return nil
}

func (m *NetOut) splitHostPort(hostport string) (string, int, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err
	}

	err = m.validateAddressAndVersion(host)
	if err != nil {
		return "", 0, err
	}

	portInt, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, err
	}

	return host, portInt, nil
}

func (m *NetOut) validateAddressAndVersion(address string) error {
	ip := net.ParseIP(address)
	if ip == nil {
		return fmt.Errorf("invalid ip address")
	}

	isIpv4Address := ip.To4() != nil

	if m.IPv6 && isIpv4Address {
		return fmt.Errorf("network is ipv4 in ipv6 mode: %s", ip)
	} else if !m.IPv6 && !isIpv4Address {
		return fmt.Errorf("network is ipv6 in ipv4 mode: %s", ip)
	}

	return nil
}
