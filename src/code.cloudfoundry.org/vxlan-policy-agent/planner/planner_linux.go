//go:build !windows
// +build !windows

package planner

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"code.cloudfoundry.org/cni-wrapper-plugin/netrules"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lib/rules"
	"code.cloudfoundry.org/policy_client"
	"code.cloudfoundry.org/vxlan-policy-agent/enforcer"
)

type containerPolicySet struct {
	Source      sourceSlice
	Destination destinationSlice
	Ingress     ingressSlice
}

type source struct {
	IP   string
	Tag  string
	GUID string
}

type sourceSlice []source

func (s sourceSlice) Len() int {
	return len(s)
}

func (s sourceSlice) Less(i, j int) bool {
	a, err := json.Marshal(s[i])
	if err != nil {
		panic(err)
	}

	b, err := json.Marshal(s[j])
	if err != nil {
		panic(err)
	}

	return strings.Compare(string(a), string(b)) < 0
}

func (s sourceSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type destination struct {
	IP                 string
	StartPort, EndPort int
	GUID               string
	SourceGUID         string
	Protocol           string
	SourceTag          string
}

type destinationSlice []destination

func (s destinationSlice) Len() int {
	return len(s)
}

func (s destinationSlice) Less(i, j int) bool {
	a, err := json.Marshal(s[i])
	if err != nil {
		panic(err)
	}

	b, err := json.Marshal(s[j])
	if err != nil {
		panic(err)
	}

	return strings.Compare(string(a), string(b)) < 0
}

func (s destinationSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type ingress struct {
	IngressTag string
	IP         string
	Protocol   string
	Port       int
}

type ingressSlice []ingress

func (s ingressSlice) Len() int {
	return len(s)
}

func (s ingressSlice) Less(i, j int) bool {
	a, err := json.Marshal(s[i])
	if err != nil {
		panic(err)
	}

	b, err := json.Marshal(s[j])
	if err != nil {
		panic(err)
	}

	return strings.Compare(string(a), string(b)) < 0
}

func (s ingressSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

const ASGManagedChainsRegex = `asg-[a-z0-9]{6}`

func (p *VxlanPolicyPlanner) GetPolicyRulesAndChain() (enforcer.RulesWithChain, error) {
	allContainers, err := p.readFile()
	if err != nil {
		p.Logger.Error("datastore", err)
		return enforcer.RulesWithChain{}, err
	}

	containerPolicySet, err := p.getContainerPolicies(allContainers)
	if err != nil {
		p.Logger.Error("policy-client-get-container-policies", err)
		return enforcer.RulesWithChain{}, err
	}
	ruleset := p.planIPTableRules(containerPolicySet)

	p.Logger.Debug("generated-rules", lager.Data{"rules": ruleset})
	return enforcer.RulesWithChain{
		Chain: p.Chain,
		Rules: ruleset,
	}, nil
}

func (p *VxlanPolicyPlanner) GetASGRulesAndChains(specifiedContainers ...string) ([]enforcer.RulesWithChain, error) {
	allContainers, err := p.readFile(specifiedContainers...)
	if err != nil {
		p.Logger.Error("datastore", err)
		return nil, err
	}

	securityGroups, err := p.getContainerSecurityGroups(allContainers)
	if err != nil {
		p.Logger.Error("policy-client-get-security-group-rules", err)
		return nil, err
	}

	rulesWithChains := []enforcer.RulesWithChain{}
	stagingRulesForSpace := map[string][]policy_client.SecurityGroupRule{}
	runningRulesForSpace := map[string][]policy_client.SecurityGroupRule{}
	defaultStagingRules := []policy_client.SecurityGroupRule{}
	defaultRunningRules := []policy_client.SecurityGroupRule{}
	for _, securityGroup := range securityGroups {
		if securityGroup.StagingDefault {
			defaultStagingRules = append(defaultStagingRules, securityGroup.Rules...)
		}
		if securityGroup.RunningDefault {
			defaultRunningRules = append(defaultRunningRules, securityGroup.Rules...)
		}

		for _, spaceGuid := range securityGroup.StagingSpaceGuids {
			if !securityGroup.StagingDefault {
				stagingRulesForSpace[spaceGuid] = append(stagingRulesForSpace[spaceGuid], securityGroup.Rules...)
			}
		}
		for _, spaceGuid := range securityGroup.RunningSpaceGuids {
			if !securityGroup.RunningDefault {
				runningRulesForSpace[spaceGuid] = append(runningRulesForSpace[spaceGuid], securityGroup.Rules...)
			}
		}
	}

	for _, container := range allContainers {
		if container.SpaceID == "" {
			continue
		}

		parentChainName := p.NetOutChain.Name(container.Handle)
		var sgRules []policy_client.SecurityGroupRule
		if container.Purpose == "staging" {
			sgRules = append(defaultStagingRules, stagingRulesForSpace[container.SpaceID]...)
		} else if container.Purpose == "app" || container.Purpose == "task" {
			sgRules = append(defaultRunningRules, runningRulesForSpace[container.SpaceID]...)
		}
		ruleSpec, err := netrules.NewRulesFromSecurityGroupRules(sgRules)
		if err != nil {
			p.Logger.Error("rules-from-security-group-rules", err)
			continue
		}

		defaultRules := p.NetOutChain.DefaultRules(container.Handle)

		iptablesRules, err := p.NetOutChain.IPTablesRules(container.Handle, container.Purpose, ruleSpec)
		if err != nil {
			p.Logger.Error("converting-to-iptables-rules", err)
			continue
		}

		rulesWithChains = append(rulesWithChains, enforcer.RulesWithChain{
			Chain: enforcer.Chain{
				Table:              enforcer.FilterTable,
				ParentChain:        parentChainName,
				Prefix:             ASGChainPrefix(container.Handle),
				ManagedChainsRegex: ASGManagedChainsRegex,
				CleanUpParentChain: true,
			},
			Rules:     reverseOrderIptablesRules(iptablesRules, defaultRules),
			LogConfig: container.LogConfig,
		})
	}

	return rulesWithChains, nil
}

func reverseOrderIptablesRules(iptablesRules, defaultRules []rules.IPTablesRule) []rules.IPTablesRule {
	allRules := []rules.IPTablesRule{}
	for i := len(iptablesRules) - 1; i >= 0; i-- {
		allRules = append(allRules, iptablesRules[i])
	}

	// default rules come in the correct order. we need to reverse-append the others above, so that the 'insert at 1'
	// logic puts them above the default rules in the right order. then we can add default rules in the normal order
	allRules = append(allRules, defaultRules...)
	return allRules
}

func (p *VxlanPolicyPlanner) getContainerSecurityGroups(allContainers []container) ([]policy_client.SecurityGroup, error) {
	policyServerStartRequestTime := time.Now()
	spaceGuids := extractSpaceGUIDs(allContainers)
	securityGroups, err := p.PolicyClient.GetSecurityGroupsForSpace(spaceGuids...)
	if err != nil {
		err = fmt.Errorf("failed to get ingress tags: %s", err)
		return []policy_client.SecurityGroup{}, err
	}

	policyServerPollDuration := time.Now().Sub(policyServerStartRequestTime)
	p.MetricsSender.SendDuration(metricPolicyServerASGPoll, policyServerPollDuration)
	return securityGroups, nil
}

func (p *VxlanPolicyPlanner) getContainerPolicies(allContainers []container) (containerPolicySet, error) {
	policyServerStartRequestTime := time.Now()
	guids := extractGUIDs(allContainers)

	var policies []policy_client.Policy
	if len(guids) > 0 {
		var err error
		policies, err = p.PolicyClient.GetPoliciesByID(guids...)
		if err != nil {
			err = fmt.Errorf("failed to get policies: %s", err)
			return containerPolicySet{}, err
		}
	}

	var ingressTag string
	if p.EnableOverlayIngressRules {
		var err error
		ingressTag, err = p.PolicyClient.CreateOrGetTag("INGRESS_ROUTER", "router")
		if err != nil {
			err = fmt.Errorf("failed to get ingress tags: %s", err)
			return containerPolicySet{}, err
		}
	}

	policyServerPollDuration := time.Now().Sub(policyServerStartRequestTime)
	p.MetricsSender.SendDuration(metricPolicyServerPoll, policyServerPollDuration)

	visited := make(map[string]bool)
	var containerPolicySet containerPolicySet
	for _, container := range allContainers {
		for _, policy := range policies {
			if container.AppID == policy.Source.ID {
				if _, ok := visited[container.IP]; !ok {
					containerPolicy := source{
						Tag:  policy.Source.Tag,
						GUID: policy.Source.ID,
						IP:   container.IP,
					}
					containerPolicySet.Source = append(containerPolicySet.Source, containerPolicy)
					visited[container.IP] = true
				}
			}

			if container.AppID == policy.Destination.ID {
				containerPolicy := destination{
					IP:         container.IP,
					StartPort:  policy.Destination.Ports.Start,
					EndPort:    policy.Destination.Ports.End,
					Protocol:   policy.Destination.Protocol,
					SourceTag:  policy.Source.Tag,
					GUID:       policy.Destination.ID,
					SourceGUID: policy.Source.ID,
				}
				containerPolicySet.Destination = append(containerPolicySet.Destination, containerPolicy)
			}
		}

		if p.EnableOverlayIngressRules {
			if container.Ports != "" {
				for _, port := range strings.Split(container.Ports, ",") {
					convPort, err := strconv.Atoi(strings.TrimSpace(port))
					if err != nil {
						return containerPolicySet, fmt.Errorf("converting container metadata port to int: %s", err)
					}
					containerPolicySet.Ingress = append(containerPolicySet.Ingress, ingress{
						IngressTag: ingressTag,
						IP:         container.IP,
						Protocol:   "tcp",
						Port:       convPort,
					})
				}
			}
		}
	}

	sort.Sort(containerPolicySet.Source)
	sort.Sort(containerPolicySet.Destination)
	sort.Sort(containerPolicySet.Ingress)

	return containerPolicySet, nil
}

func (p *VxlanPolicyPlanner) planIPTableRules(containerPolicySet containerPolicySet) []rules.IPTablesRule {
	var ruleset []rules.IPTablesRule
	for _, c2cSource := range containerPolicySet.Source {
		ruleset = append(ruleset, rules.NewMarkSetRule(
			c2cSource.IP,
			c2cSource.Tag,
			c2cSource.GUID))
	}

	for _, c2cDestination := range containerPolicySet.Destination {
		if p.LoggingState.IsEnabled() {
			ruleset = append(ruleset, rules.NewMarkAllowLogRule(
				c2cDestination.IP,
				c2cDestination.Protocol,
				c2cDestination.StartPort,
				c2cDestination.EndPort,
				c2cDestination.SourceTag,
				c2cDestination.GUID,
				p.IPTablesAcceptedUDPLogsPerSec,
			))
		}
		ruleset = append(ruleset, rules.NewMarkAllowRule(
			c2cDestination.IP,
			c2cDestination.Protocol,
			c2cDestination.StartPort,
			c2cDestination.EndPort,
			c2cDestination.SourceTag,
			c2cDestination.SourceGUID,
			c2cDestination.GUID,
		))
	}

	for _, ingressSource := range containerPolicySet.Ingress {
		ruleset = append(ruleset, rules.NewMarkAllowRuleNoComment(
			ingressSource.IP,
			ingressSource.Protocol,
			ingressSource.Port,
			ingressSource.IngressTag,
		))
	}

	return ruleset
}

func containerPurposeMatchesAppLifecycle(containerPurpose, appLifecycle string) bool {
	return appLifecycle == "all" ||
		containerPurpose == "" ||
		(appLifecycle == "running" && (containerPurpose == "task" || containerPurpose == "app")) ||
		appLifecycle == "staging" && containerPurpose == "staging"

}
