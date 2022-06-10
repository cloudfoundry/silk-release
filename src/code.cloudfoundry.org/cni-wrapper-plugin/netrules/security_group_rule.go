package netrules

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/policy_client"
)

var ErrIPRangeConversionFailed = errors.New("failed to convert destination to ip range")

type securityGroupRule struct {
	rule     policy_client.SecurityGroupRule
	networks []IPRange
}

func NewRuleFromSecurityGroupRule(sgRule policy_client.SecurityGroupRule) (Rule, error) {
	ipRange, err := toIPRange(sgRule.Destination)
	if err != nil {
		return nil, err
	}
	return &securityGroupRule{rule: sgRule, networks: []IPRange{ipRange}}, nil
}

func NewRulesFromSecurityGroupRules(securityGroupRules []policy_client.SecurityGroupRule) ([]Rule, error) {
	ruleSpec := []Rule{}
	for _, sgRule := range securityGroupRules {
		rule, err := NewRuleFromSecurityGroupRule(sgRule)
		if err != nil {
			return nil, err
		}
		ruleSpec = append(ruleSpec, rule)
	}
	return ruleSpec, nil
}

func (r *securityGroupRule) Log() bool {
	return r.rule.Log
}

func (r *securityGroupRule) Protocol() Protocol {
	return Protocol(r.rule.Protocol)
}

func (r *securityGroupRule) Networks() []IPRange {
	return r.networks
}

func (r *securityGroupRule) Ports() []PortRange {
	portRangeStrs := strings.Split(r.rule.Ports, ",")
	var portRanges []PortRange
	for _, portRangeStr := range portRangeStrs {
		ports := strings.Split(portRangeStr, "-")
		if len(ports) == 1 {
			port, err := strconv.Atoi(strings.TrimSpace(ports[0]))
			if err != nil {
				continue
			}
			portRanges = append(portRanges, PortRange{Start: uint16(port), End: uint16(port)})
		} else if len(ports) == 2 {
			startPort, err := strconv.Atoi(strings.TrimSpace(ports[0]))
			if err != nil {
				continue
			}
			endPort, err := strconv.Atoi(strings.TrimSpace(ports[1]))
			if err != nil {
				continue
			}
			portRanges = append(portRanges, PortRange{Start: uint16(startPort), End: uint16(endPort)})
		}
	}
	return portRanges
}

func (r *securityGroupRule) ICMPInfo() *ICMPInfo {
	return &ICMPInfo{
		Type: garden.ICMPType(r.rule.Type),
		Code: garden.ICMPCode(r.rule.Code),
	}
}

func toIPRange(dest string) (IPRange, error) {
	idx := strings.IndexAny(dest, "-/")

	// Not a range or a CIDR
	if idx == -1 {
		ip := net.ParseIP(dest)
		if ip == nil {
			return IPRange{}, ErrIPRangeConversionFailed
		}

		return IPRange(garden.IPRangeFromIP(ip)), nil
	}

	// We have a CIDR
	if dest[idx] == '/' {
		_, ipNet, err := net.ParseCIDR(dest)
		if err != nil {
			return IPRange{}, ErrIPRangeConversionFailed
		}

		return IPRange(garden.IPRangeFromIPNet(ipNet)), nil
	}

	// We have an IP range
	firstIP := net.ParseIP(dest[:idx])
	secondIP := net.ParseIP(dest[idx+1:])
	if firstIP == nil || secondIP == nil {
		return IPRange{}, ErrIPRangeConversionFailed
	}

	return IPRange{Start: firstIP, End: secondIP}, nil
}
