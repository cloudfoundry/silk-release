package planner

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"code.cloudfoundry.org/cni-wrapper-plugin/netrules"
	"code.cloudfoundry.org/executor"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lib/datastore"
	"code.cloudfoundry.org/lib/rules"
	"code.cloudfoundry.org/policy_client"
	"code.cloudfoundry.org/vxlan-policy-agent/enforcer"
)

type container struct {
	Handle    string
	AppID     string
	SpaceID   string
	Ports     string
	IP        string
	Purpose   string
	LogConfig executor.LogConfig
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
	HostInterfaceNames            []string
	NetOutChain                   netOutChain
}

//go:generate counterfeiter -o fakes/dstore.go --fake-name Dstore . dstore
type dstore interface {
	ReadAll() (map[string]datastore.Container, error)
}

//go:generate counterfeiter -o fakes/policy_client.go --fake-name PolicyClient . policyClient
type policyClient interface {
	GetPoliciesByID(ids ...string) ([]policy_client.Policy, []policy_client.EgressPolicy, error)
	GetSecurityGroupsForSpace(spaceGuids ...string) ([]policy_client.SecurityGroup, error)
	CreateOrGetTag(id, groupType string) (string, error)
}

//go:generate counterfeiter -o fakes/metrics_sender.go --fake-name MetricsSender . metricsSender
type metricsSender interface {
	SendDuration(string, time.Duration)
}

//go:generate counterfeiter -o fakes/loggingStateGetter.go --fake-name LoggingStateGetter . loggingStateGetter
type loggingStateGetter interface {
	IsEnabled() bool
}

//go:generate counterfeiter -o fakes/netout_chain.go --fake-name NetOutChain . netOutChain
type netOutChain interface {
	Name(containerHandle string) string
	DefaultRules(containerHandle string) []rules.IPTablesRule
	IPTablesRules(containerHandle string, containerWorkload string, ruleSpec []netrules.Rule) ([]rules.IPTablesRule, error)
}

const metricContainerMetadata = "containerMetadataTime"
const metricPolicyServerPoll = "policyServerPollTime"
const metricPolicyServerASGPoll = "policyServerASGPollTime"

func ASGChainPrefix(handle string) string {
	h := sha1.New()
	h.Write([]byte(handle))
	smallHash := h.Sum(nil)

	return fmt.Sprintf("asg-%x", smallHash[0:3]) //only need 6 digits so we use 3.
}

func (p *VxlanPolicyPlanner) readFile(specifiedContainers ...string) ([]container, error) {
	containerMetadataStartTime := time.Now()
	containerMetadata, err := p.Datastore.ReadAll()

	specifiedContainerMetadata := map[string]datastore.Container{}
	if len(specifiedContainers) == 0 {
		specifiedContainerMetadata = containerMetadata
	} else {
		for _, specifiedContainer := range specifiedContainers {
			specifiedContainerMetadata[specifiedContainer] = containerMetadata[specifiedContainer]
		}
	}
	if err != nil {
		return nil, err
	}

	var allContainers []container
	for handle, containerMeta := range specifiedContainerMetadata {
		ports, ok := containerMeta.Metadata["ports"].(string)
		if !ok || ports == "" {
			message := "Container metadata is missing key ports. CloudController version may be out of date or apps may need to be restaged."
			p.Logger.Debug("container-metadata-policy-group-id", lager.Data{"container_handle": handle, "message": message})
		}

		policyGroupID, ok := containerMeta.Metadata["policy_group_id"].(string)
		if !ok || policyGroupID == "" {
			message := "Container metadata is missing key policy_group_id. CloudController version may be out of date or apps may need to be restaged."
			p.Logger.Debug("container-metadata-policy-group-id", lager.Data{"container_handle": handle, "message": message})
			continue
		}

		spaceID, ok := containerMeta.Metadata["space_id"].(string)
		if !ok {
			spaceID = ""
		}

		purpose, ok := containerMeta.Metadata["container_workload"].(string)
		if !ok {
			purpose = ""
		}

		var logConfig executor.LogConfig
		logConfigStr, ok := containerMeta.Metadata["log_config"].(string)
		if ok {
			err := json.Unmarshal([]byte(logConfigStr), &logConfig)
			if err != nil {
				return nil, err
			}
		}

		allContainers = append(allContainers, container{
			Handle:    containerMeta.Handle,
			AppID:     policyGroupID,
			SpaceID:   spaceID,
			Ports:     ports,
			IP:        containerMeta.IP,
			Purpose:   purpose,
			LogConfig: logConfig,
		})
	}
	containerMetadataDuration := time.Now().Sub(containerMetadataStartTime)
	p.Logger.Debug("got-containers", lager.Data{"containers": allContainers})
	p.MetricsSender.SendDuration(metricContainerMetadata, containerMetadataDuration)

	sort.Slice(allContainers, func(i, j int) bool {
		return allContainers[i].Handle > allContainers[j].Handle
	})

	return allContainers, nil
}

func extractGUIDs(allContainers []container) []string {
	allGUIDs := make(map[string]interface{})
	for _, container := range allContainers {
		if container.AppID != "" {
			allGUIDs[container.AppID] = nil
		}
		if container.SpaceID != "" {
			allGUIDs[container.SpaceID] = nil
		}
	}

	i := 0
	guids := make([]string, len(allGUIDs))
	for key := range allGUIDs {
		guids[i] = key
		i++
	}
	return guids
}

func extractSpaceGUIDs(allContainers []container) []string {
	allGUIDs := make(map[string]interface{})
	for _, container := range allContainers {
		if container.SpaceID != "" {
			allGUIDs[container.SpaceID] = nil
		}
	}

	i := 0
	guids := make([]string, len(allGUIDs))
	for key := range allGUIDs {
		guids[i] = key
		i++
	}
	return guids
}
