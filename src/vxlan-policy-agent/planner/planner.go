package planner

import (
	"lib/datastore"
	"lib/policy_client"
	"lib/rules"
	"sort"
	"strings"
	"time"
	"vxlan-policy-agent/enforcer"

	"fmt"
	"strconv"

	"code.cloudfoundry.org/lager"
)

//go:generate counterfeiter -o fakes/policy_client.go --fake-name PolicyClient . policyClient
type policyClient interface {
	GetPoliciesByID(ids ...string) ([]policy_client.Policy, []policy_client.EgressPolicy, error)
	CreateOrGetTag(id, groupType string) (string, error)
}

//go:generate counterfeiter -o fakes/dstore.go --fake-name Dstore . dstore
type dstore interface {
	ReadAll() (map[string]datastore.Container, error)
}

//go:generate counterfeiter -o fakes/metrics_sender.go --fake-name MetricsSender . metricsSender
type metricsSender interface {
	SendDuration(string, time.Duration)
}

//go:generate counterfeiter -o fakes/loggingStateGetter.go --fake-name LoggingStateGetter . loggingStateGetter
type loggingStateGetter interface {
	IsEnabled() bool
}

type VxlanPolicyPlanner struct {
	Logger                        lager.Logger
	Datastore                     dstore
	PolicyClient                  policyClient
	VNI                           int
	MetricsSender                 metricsSender
	Chain                         enforcer.Chain
	LoggingState                  loggingStateGetter
	IPTablesAcceptedUDPLogsPerSec int
	EnableOverlayIngressRules     bool
}

type Container struct {
	IP    string
	Ports []string
}

const metricContainerMetadata = "containerMetadataTime"
const metricPolicyServerPoll = "policyServerPollTime"

func (p *VxlanPolicyPlanner) getContainersMap(allContainers map[string]datastore.Container) (map[string][]Container, error) {
	containersMap := map[string][]Container{}
	for _, container := range allContainers {
		if container.Metadata == nil {
			continue
		}
		groupID, ok := container.Metadata["policy_group_id"].(string)
		if !ok {
			message := "Container metadata is missing key policy_group_id. CloudController version may be out of date or apps may need to be restaged."
			p.Logger.Debug("container-metadata-policy-group-id", lager.Data{"container_handle": container.Handle, "message": message})
			continue
		}

		var ports []string
		stringPorts, ok := container.Metadata["ports"].(string)
		if ok {
			ports = strings.Split(stringPorts, ",")
		} else {
			message := "Container metadata is missing key ports. CloudController version may be out of date or apps may need to be restaged."
			p.Logger.Debug("container-metadata-policy-group-id", lager.Data{"container_handle": container.Handle, "message": message})
		}

		containersMap[groupID] = append(containersMap[groupID], Container{
			IP:    container.IP,
			Ports: ports,
		})
	}
	return containersMap, nil
}

func (p *VxlanPolicyPlanner) GetRulesAndChain() (enforcer.RulesWithChain, error) {
	containerMetadataStartTime := time.Now()
	containerMetadata, err := p.Datastore.ReadAll()
	if err != nil {
		p.Logger.Error("datastore", err)
		return enforcer.RulesWithChain{}, err
	}

	containersMap, err := p.getContainersMap(containerMetadata)
	groupIDs := make([]string, len(containersMap))
	i := 0
	for groupID := range containersMap {
		groupIDs[i] = groupID
		i++
	}
	if err != nil {
		p.Logger.Error("container-info", err)
		return enforcer.RulesWithChain{}, err
	}
	containerMetadataDuration := time.Now().Sub(containerMetadataStartTime)
	p.Logger.Debug("got-containers", lager.Data{"containers": containersMap})

	policyServerStartRequestTime := time.Now()
	var policies []policy_client.Policy
	var egressPolicies []policy_client.EgressPolicy
	if len(groupIDs) > 0 {
		policies, egressPolicies, err = p.PolicyClient.GetPoliciesByID(groupIDs...)
		if err != nil {
			p.Logger.Error("policy-client-get-policies", err)
			return enforcer.RulesWithChain{}, err
		}
	}

	policyServerPollDuration := time.Now().Sub(policyServerStartRequestTime)
	p.MetricsSender.SendDuration(metricContainerMetadata, containerMetadataDuration)
	p.MetricsSender.SendDuration(metricPolicyServerPoll, policyServerPollDuration)

	marksRuleset := []rules.IPTablesRule{}
	markedSourceIPs := make(map[string]struct{})
	filterRuleset := []rules.IPTablesRule{}

	iptablesLoggingEnabled := p.LoggingState.IsEnabled()
	policySlice := policy_client.PolicySlice(policies)
	sort.Sort(policySlice)
	for _, policy := range policySlice {
		srcContainers, srcOk := containersMap[policy.Source.ID]
		dstContainers, dstOk := containersMap[policy.Destination.ID]

		if dstOk {
			var dstContainerIPs []string
			for _, container := range dstContainers {
				dstContainerIPs = append(dstContainerIPs, container.IP)
			}

			// there are some containers on this host that are dests for the policy
			ips := sort.StringSlice(dstContainerIPs)
			sort.Sort(ips)
			for _, dstContainerIP := range ips {
				if iptablesLoggingEnabled {
					filterRuleset = append(
						filterRuleset,
						rules.NewMarkAllowLogRule(
							dstContainerIP,
							policy.Destination.Protocol,
							policy.Destination.Ports.Start,
							policy.Destination.Ports.End,
							policy.Source.Tag,
							policy.Destination.ID,
							p.IPTablesAcceptedUDPLogsPerSec,
						),
					)
				}
				filterRuleset = append(
					filterRuleset,
					rules.NewMarkAllowRule(
						dstContainerIP,
						policy.Destination.Protocol,
						policy.Destination.Ports.Start,
						policy.Destination.Ports.End,
						policy.Source.Tag,
						policy.Source.ID,
						policy.Destination.ID,
					),
				)
			}
		}

		if srcOk {
			// there are some containers on this host that are sources for the policy
			sort.Slice(srcContainers, func(i, j int) bool {
				return srcContainers[i].IP < srcContainers[j].IP
			})

			for _, srcContainer := range srcContainers {
				_, added := markedSourceIPs[srcContainer.IP]
				if !added {
					rule := rules.NewMarkSetRule(srcContainer.IP, policy.Source.Tag, policy.Source.ID)
					marksRuleset = append(marksRuleset, rule)
					markedSourceIPs[srcContainer.IP] = struct{}{}
				}
			}
		}
	}

	if p.EnableOverlayIngressRules {
		var allContainers []Container
		for _, containers := range containersMap {
			allContainers = append(allContainers, containers...)
		}

		sort.Slice(allContainers, func(i, j int) bool {
			return allContainers[i].IP < allContainers[j].IP
		})

		ingressTag, err := p.PolicyClient.CreateOrGetTag("INGRESS_ROUTER", "router")
		if err != nil {
			p.Logger.Error("policy-client-get-ingress-tags", err)
			return enforcer.RulesWithChain{}, err
		}

		for _, container := range allContainers {
			ports := sort.StringSlice(container.Ports)
			sort.Sort(ports)
			for _, port := range ports {
				portNumber, err := strconv.Atoi(strings.TrimSpace(port))
				if err != nil {
					err = fmt.Errorf("converting container metadata port to int: %s", err)
					p.Logger.Error("policy-client-get-ingress-tags", err)
					return enforcer.RulesWithChain{}, err
				}

				filterRuleset = append(
					filterRuleset,
					rules.NewMarkAllowRuleNoComment(
						container.IP,
						"tcp",
						portNumber,
						ingressTag,
					),
				)
			}
		}
	}

	egressPolicySlice := policy_client.EgressPolicySlice(egressPolicies)
	sort.Sort(egressPolicySlice)
	for _, policy := range egressPolicySlice {
		sourceContainers := containersMap[policy.Source.ID]

		for _, container := range sourceContainers {
			egressRule := rules.IPTablesRule{
				"-s", container.IP,
				"-p", policy.Destination.Protocol,
				"-m", "iprange",
				"--dst-range", fmt.Sprintf("%s-%s", policy.Destination.IPRanges[0].Start, policy.Destination.IPRanges[0].End),
			}

			if policy.Destination.Protocol == "icmp" {
				if policy.Destination.ICMPType != -1 {
					icmpType := strconv.Itoa(policy.Destination.ICMPType)
					if policy.Destination.ICMPCode != -1 {
						icmpType += "/" + strconv.Itoa(policy.Destination.ICMPCode)
					}
					egressRule = append(egressRule, "-m", "icmp", "--icmp-type", icmpType)
				}
			}

			if len(policy.Destination.Ports) > 0 && (policy.Destination.Protocol == "tcp" || policy.Destination.Protocol == "udp") {
				egressRule = append(egressRule,
					"-m", policy.Destination.Protocol,
					"--dport", fmt.Sprintf("%d:%d", policy.Destination.Ports[0].Start, policy.Destination.Ports[0].End))
			}

			egressRule = append(egressRule, "-j", "ACCEPT")

			filterRuleset = append(filterRuleset, egressRule)
		}
	}

	ruleset := append(marksRuleset, filterRuleset...)
	p.Logger.Debug("generated-rules", lager.Data{"rules": ruleset})
	return enforcer.RulesWithChain{
		Chain: p.Chain,
		Rules: ruleset,
	}, nil
}
