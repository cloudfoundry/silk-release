package netrules

import (
	"code.cloudfoundry.org/garden"
)

type gardenNetOutRule struct {
	rule garden.NetOutRule
}

func NewRuleFromGardenNetOutRule(gardenRule garden.NetOutRule) Rule {
	return &gardenNetOutRule{rule: gardenRule}
}

func NewRulesFromGardenNetOutRules(gardenRules []garden.NetOutRule) []Rule {
	ruleSpec := []Rule{}
	for _, gardenRule := range gardenRules {
		ruleSpec = append(ruleSpec, NewRuleFromGardenNetOutRule(gardenRule))
	}
	return ruleSpec
}

func (r *gardenNetOutRule) Log() bool {
	return r.rule.Log
}

func (r *gardenNetOutRule) Protocol() Protocol {
	switch r.rule.Protocol {
	case garden.ProtocolTCP:
		return ProtocolTCP
	case garden.ProtocolUDP:
		return ProtocolUDP
	case garden.ProtocolICMP:
		return ProtocolICMP
	default:
		return ProtocolAll
	}
}

func (r *gardenNetOutRule) Networks() []IPRange {
	var networks []IPRange
	for _, network := range r.rule.Networks {
		networks = append(networks, IPRange{
			Start: network.Start,
			End:   network.End,
		})
	}
	return networks
}

func (r *gardenNetOutRule) Ports() []PortRange {
	var ports []PortRange
	for _, port := range r.rule.Ports {
		ports = append(ports, PortRange{
			Start: port.Start,
			End:   port.End,
		})
	}
	return ports
}

func (r *gardenNetOutRule) ICMPInfo() *ICMPInfo {
	if r.rule.ICMPs == nil || r.rule.ICMPs.Code == nil {
		return nil
	}
	return &ICMPInfo{
		Type: int(r.rule.ICMPs.Type),
		Code: int(*r.rule.ICMPs.Code),
	}
}
