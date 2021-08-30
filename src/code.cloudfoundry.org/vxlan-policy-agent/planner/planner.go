package planner

import (
	"time"

	"code.cloudfoundry.org/lib/datastore"
	"code.cloudfoundry.org/policy_client"
	"code.cloudfoundry.org/vxlan-policy-agent/enforcer"

	"code.cloudfoundry.org/lager"
)

type container struct {
	AppID   string
	SpaceID string
	Ports   string
	IP      string
	Purpose string
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
}

//go:generate counterfeiter -o fakes/dstore.go --fake-name Dstore . dstore
type dstore interface {
	ReadAll() (map[string]datastore.Container, error)
}

//go:generate counterfeiter -o fakes/policy_client.go --fake-name PolicyClient . policyClient
type policyClient interface {
	GetPoliciesByID(ids ...string) ([]policy_client.Policy, []policy_client.EgressPolicy, error)
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

const metricContainerMetadata = "containerMetadataTime"
const metricPolicyServerPoll = "policyServerPollTime"

func (p *VxlanPolicyPlanner) readFile() ([]container, error) {
	containerMetadataStartTime := time.Now()
	containerMetadata, err := p.Datastore.ReadAll()
	if err != nil {
		return nil, err
	}

	var allContainers []container
	for handle, containerMeta := range containerMetadata {
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

		allContainers = append(allContainers, container{
			AppID:   policyGroupID,
			SpaceID: spaceID,
			Ports:   ports,
			IP:      containerMeta.IP,
			Purpose: purpose,
		})
	}
	containerMetadataDuration := time.Now().Sub(containerMetadataStartTime)
	p.Logger.Debug("got-containers", lager.Data{"containers": allContainers})
	p.MetricsSender.SendDuration(metricContainerMetadata, containerMetadataDuration)

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
