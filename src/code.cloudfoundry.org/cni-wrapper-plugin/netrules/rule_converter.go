package netrules

import (
	"fmt"
	"io"
	"net"

	"code.cloudfoundry.org/lib/rules"

	"code.cloudfoundry.org/garden"
)

type Protocol string

const (
	ProtocolTCP  = Protocol("tcp")
	ProtocolUDP  = Protocol("udp")
	ProtocolICMP = Protocol("icmp")
	ProtocolAll  = Protocol("all")
)

type PortRange struct {
	Start uint16
	End   uint16
}

type IPRange struct {
	Start net.IP
	End   net.IP
}

type ICMPInfo struct {
	Type int
	Code int
}

type Rule interface {
	Log() bool
	Protocol() Protocol
	Networks() []IPRange
	Ports() []PortRange
	ICMPInfo() *ICMPInfo
}

type RuleConverter struct {
	Logger io.Writer
}

func (c *RuleConverter) BulkConvert(ruleSpec []Rule, logChainName string, globalLogging bool) []rules.IPTablesRule {
	iptablesRules := []rules.IPTablesRule{}
	for _, rule := range ruleSpec {
		for _, t := range c.Convert(rule, logChainName, globalLogging) {
			iptablesRules = append(iptablesRules, t)
		}
	}
	return iptablesRules
}

func (c *RuleConverter) Convert(rule Rule, logChainName string, globalLogging bool) []rules.IPTablesRule {
	ruleSpec := []rules.IPTablesRule{}
	for _, network := range rule.Networks() {
		startIP, endIP := network.Start.String(), network.End.String()
		protocol := rule.Protocol()
		log := rule.Log() || globalLogging
		ports := rule.Ports()
		switch protocol {
		case ProtocolTCP:
			fallthrough
		case ProtocolUDP:
			if len(ports) == 0 {
				fmt.Fprintf(c.Logger, "UDP/TCP rule must specify ports: %+v\n", rule)
				continue
			}
			for _, portRange := range ports {
				startPort := int(portRange.Start)
				endPort := int(portRange.End)
				if log {
					ruleSpec = append(ruleSpec, rules.NewNetOutWithPortsLogRule(startIP, endIP, startPort, endPort, string(protocol), logChainName))
				} else {
					ruleSpec = append(ruleSpec, rules.NewNetOutWithPortsRule(startIP, endIP, startPort, endPort, string(protocol)))
				}
			}
		case ProtocolICMP:
			icmpInfo := rule.ICMPInfo()
			if icmpInfo == nil {
				fmt.Fprintf(c.Logger, "ICMP rule must specify ICMP type/code: %+v\n", rule)
				continue
			}
			if len(ports) > 0 {
				fmt.Fprintf(c.Logger, "ICMP rule must not specify ports: %+v\n", rule)
				continue
			}
			if log {
				ruleSpec = append(ruleSpec, rules.NewNetOutICMPLogRule(startIP, endIP, icmpInfo.Type, icmpInfo.Code, logChainName))
			} else {
				ruleSpec = append(ruleSpec, rules.NewNetOutICMPRule(startIP, endIP, icmpInfo.Type, icmpInfo.Code))
			}
		case ProtocolAll:
			if len(ports) > 0 {
				fmt.Fprintf(c.Logger, "Rule for all protocols (TCP/UDP/ICMP) must not specify ports: %+v\n", rule)
				continue
			}
			if log {
				ruleSpec = append(ruleSpec, rules.NewNetOutLogRule(startIP, endIP, logChainName))
			} else {
				ruleSpec = append(ruleSpec, rules.NewNetOutRule(startIP, endIP))
			}
		}
	}
	return ruleSpec
}

func udpOrTcp(protocol garden.Protocol) bool {
	return protocol == garden.ProtocolTCP || protocol == garden.ProtocolUDP
}
