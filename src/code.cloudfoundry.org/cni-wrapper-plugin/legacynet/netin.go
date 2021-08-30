package legacynet

import (
	"fmt"
	"code.cloudfoundry.org/lib/rules"
	"net"

	"github.com/hashicorp/go-multierror"
)

const prefixNetIn = "netin"

type NetIn struct {
	ChainNamer         chainNamer
	IPTables           rules.IPTablesAdapter
	IngressTag         string
	HostInterfaceNames []string
}

func (m *NetIn) Initialize(containerHandle string) error {
	return initChains(m.IPTables, m.defaultNetInRules(containerHandle))
}

func (m *NetIn) defaultNetInRules(containerHandle string) []IpTablesFullChain {
	chain := m.ChainNamer.Prefix(prefixNetIn, containerHandle)

	return []IpTablesFullChain{
		{
			Table:       "nat",
			ParentChain: "PREROUTING",
			ChainName:   chain,
			JumpConditions: []rules.IPTablesRule{
				{"--jump", chain},
			},
		},
		{
			Table:       "mangle",
			ParentChain: "PREROUTING",
			ChainName:   chain,
			JumpConditions: []rules.IPTablesRule{
				{"--jump", chain},
			},
		},
	}
}

func (m *NetIn) Cleanup(containerHandle string) error {
	var result error

	for _, rule := range m.defaultNetInRules(containerHandle) {
		err := cleanupChain(rule.Table, rule.ParentChain, rule.ChainName, rule.JumpConditions, m.IPTables)
		if err != nil {
			result = multierror.Append(result, err)
		}
	}

	return result
}

func (m *NetIn) AddRule(containerHandle string, hostPort, containerPort int, hostIP, containerIP string) error {
	chain := m.ChainNamer.Prefix(prefixNetIn, containerHandle)

	parsedIP := net.ParseIP(hostIP)
	if parsedIP == nil {
		return fmt.Errorf("invalid ip: %s", hostIP)
	}

	parsedIP = net.ParseIP(containerIP)
	if parsedIP == nil {
		return fmt.Errorf("invalid ip: %s", containerIP)
	}

	containerIngressRules := []IpTablesFullChain{
		{
			Table:       "nat",
			ParentChain: "PREROUTING",
			ChainName:   chain,
			Rules: []rules.IPTablesRule{
				rules.NewPortForwardingRule(hostPort, containerPort, hostIP, containerIP),
			},
		},
		{
			Table:       "mangle",
			ParentChain: "PREROUTING",
			ChainName:   chain,
			Rules:       rules.NewIngressMarkRules(m.HostInterfaceNames, hostPort, hostIP, m.IngressTag),
		},
	}

	return applyRules(m.IPTables, containerIngressRules)
}
