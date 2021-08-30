// +build windows

package planner

import (
	"fmt"
	"code.cloudfoundry.org/policy_client"
	"time"
)

func (p *VxlanPolicyPlanner) GetRules() ([]policy_client.EgressPolicy, error) {
	allContainers, err := p.readFile()
	if err != nil {
		p.Logger.Error("datastore", err)
		return []policy_client.EgressPolicy{}, err
	}

	egressPolicies, err := p.queryPolicyServer(allContainers)
	if err != nil {
		p.Logger.Error("policy-client-query", err)
		return []policy_client.EgressPolicy{}, err
	}

	return egressPolicies, nil
}

func (p *VxlanPolicyPlanner) queryPolicyServer(allContainers []container) ([]policy_client.EgressPolicy, error) {
	policyServerStartRequestTime := time.Now()
	guids := extractGUIDs(allContainers)

	var egressPolicies []policy_client.EgressPolicy
	if len(guids) > 0 {
		var err error
		_, egressPolicies, err = p.PolicyClient.GetPoliciesByID(guids...)
		if err != nil {
			err = fmt.Errorf("failed to get policies: %s", err)
			return egressPolicies, err
		}
	}

	policyServerPollDuration := time.Now().Sub(policyServerStartRequestTime)
	p.MetricsSender.SendDuration(metricPolicyServerPoll, policyServerPollDuration)
	return egressPolicies, nil
}
