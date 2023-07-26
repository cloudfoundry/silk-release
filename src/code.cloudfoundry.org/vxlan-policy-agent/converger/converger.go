package converger

import (
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"

	loggingclient "code.cloudfoundry.org/diego-logging-client"
	"code.cloudfoundry.org/executor"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/vxlan-policy-agent/enforcer"
	"code.cloudfoundry.org/vxlan-policy-agent/planner"
	"github.com/hashicorp/go-multierror"
)

//go:generate counterfeiter -o fakes/policy_client.go --fake-name PolicyClient . policyClient
type policyClient interface {
	GetPoliciesLastUpdated() (int, error)
}

//go:generate counterfeiter -o fakes/planner.go --fake-name Planner . Planner
type Planner interface {
	GetPolicyRulesAndChain() (enforcer.RulesWithChain, error)
	GetASGRulesAndChains(containers ...string) ([]enforcer.RulesWithChain, error)
}

//go:generate counterfeiter -o fakes/rule_enforcer.go --fake-name RuleEnforcer . ruleEnforcer
type ruleEnforcer interface {
	EnforceRulesAndChain(enforcer.RulesWithChain) (string, error)
	CleanChainsMatching(regex *regexp.Regexp, desiredChains []enforcer.LiveChain) ([]enforcer.LiveChain, error)
}

//go:generate counterfeiter -o fakes/metrics_sender.go --fake-name MetricsSender . metricsSender
type metricsSender interface {
	SendDuration(string, time.Duration)
}

type SinglePollCycle struct {
	planners            []Planner
	enforcer            ruleEnforcer
	metricsSender       metricsSender
	policyClient        policyClient
	lastUpdated         int
	logger              lager.Logger
	policyRuleSets      map[enforcer.Chain]enforcer.RulesWithChain
	asgRuleSets         map[enforcer.LiveChain]enforcer.RulesWithChain
	containerToASGChain map[enforcer.LiveChain]string
	metronClient        loggingclient.IngressClient
	policyMutex         sync.Locker
	asgMutex            sync.Locker
}

func NewSinglePollCycle(planners []Planner, re ruleEnforcer, p policyClient, ms metricsSender, metronClient loggingclient.IngressClient, logger lager.Logger) *SinglePollCycle {
	return &SinglePollCycle{
		planners:      planners,
		enforcer:      re,
		policyClient:  p,
		metricsSender: ms,
		lastUpdated:   0,
		logger:        logger,
		metronClient:  metronClient,
		policyMutex:   new(sync.Mutex),
		asgMutex:      new(sync.Mutex),
	}
}

const metricEnforceDuration = "iptablesEnforceTime"
const metricPollDuration = "totalPollTime"

const metricASGEnforceDuration = "asgIptablesEnforceTime"
const metricASGCleanupDuration = "asgIptablesCleanupTime"
const metricASGPollDuration = "asgTotalPollTime"

func (m *SinglePollCycle) DoPolicyCycleWithLastUpdatedCheck() error {
	lastUpdated, err := m.policyClient.GetPoliciesLastUpdated()
	if err != nil {
		m.logger.Error("error-getting-policies-last-updated", err)
		return m.DoPolicyCycle()
	}
	if m.lastUpdated == 0 || lastUpdated > m.lastUpdated {
		m.logger.Debug("running-poll-cycle-for-updated-policies", lager.Data{"last-updated-remotely": lastUpdated, "last-updated-locally": m.lastUpdated})
		m.lastUpdated = lastUpdated
		return m.DoPolicyCycle()
	}

	m.logger.Debug("skipping-poll-cycle", lager.Data{"last-updated-remotely": lastUpdated, "last-updated-locally": m.lastUpdated})

	return nil
}

func (m *SinglePollCycle) DoPolicyCycle() error {
	m.policyMutex.Lock()

	if m.policyRuleSets == nil {
		m.policyRuleSets = make(map[enforcer.Chain]enforcer.RulesWithChain)
	}

	pollStartTime := time.Now()
	var enforceDuration time.Duration
	for _, p := range m.planners {
		ruleSet, err := p.GetPolicyRulesAndChain()
		if err != nil {
			m.policyMutex.Unlock()
			return fmt.Errorf("get-rules: %s", err)
		}
		enforceStartTime := time.Now()

		oldRuleSet := m.policyRuleSets[ruleSet.Chain]
		if !ruleSet.Equals(oldRuleSet) {
			m.logger.Debug("poll-cycle", lager.Data{
				"message":       "updating iptables rules",
				"num old rules": len(oldRuleSet.Rules),
				"num new rules": len(ruleSet.Rules),
				"old rules":     oldRuleSet,
				"new rules":     ruleSet,
			})
			_, err = m.enforcer.EnforceRulesAndChain(ruleSet)
			if err != nil {
				m.policyMutex.Unlock()
				return fmt.Errorf("enforce: %s", err)
			}
			m.policyRuleSets[ruleSet.Chain] = ruleSet
		}

		enforceDuration += time.Now().Sub(enforceStartTime)
	}

	m.policyMutex.Unlock()

	pollDuration := time.Now().Sub(pollStartTime)
	m.metricsSender.SendDuration(metricEnforceDuration, enforceDuration)
	m.metricsSender.SendDuration(metricPollDuration, pollDuration)

	return nil
}

func (m *SinglePollCycle) DoASGCycle() error {
	return m.SyncASGsForContainers() // syncs for all containers when arguments are empty
}

func (m *SinglePollCycle) SyncASGsForContainers(containers ...string) error {
	m.asgMutex.Lock()

	if m.asgRuleSets == nil {
		m.asgRuleSets = make(map[enforcer.LiveChain]enforcer.RulesWithChain)
	}
	if m.containerToASGChain == nil {
		m.containerToASGChain = make(map[enforcer.LiveChain]string)
	}

	pollStartTime := time.Now()
	var enforceDuration time.Duration

	var allRuleSets []enforcer.RulesWithChain
	var desiredChains []enforcer.LiveChain

	var errors error

	for _, p := range m.planners {
		asgrulesets, err := p.GetASGRulesAndChains(containers...)
		if err != nil {
			m.asgMutex.Unlock()
			return fmt.Errorf("get-asg-rules: %s", err)
		}

		enforceStartTime := time.Now()

		allRuleSets = append(allRuleSets, asgrulesets...)
		for _, ruleset := range asgrulesets {
			chainKey := enforcer.LiveChain{Table: ruleset.Chain.Table, Name: ruleset.Chain.ParentChain}
			oldRuleSet := m.asgRuleSets[chainKey]
			if !ruleset.Equals(oldRuleSet) {
				m.logger.Debug("poll-cycle-asg", lager.Data{
					"message":       "updating iptables rules",
					"num old rules": len(oldRuleSet.Rules),
					"num new rules": len(ruleset.Rules),
					"old rules":     oldRuleSet,
					"new rules":     ruleset,
				})
				chain, err := m.enforcer.EnforceRulesAndChain(ruleset)
				if err != nil {
					if _, ok := err.(*enforcer.CleanupErr); ok {
						m.updateRuleSet(chainKey, chain, ruleset)
					}

					errors = multierror.Append(errors, fmt.Errorf("enforce-asg: %s", err))
				} else {
					m.updateRuleSet(chainKey, chain, ruleset)
				}
			}
			desiredChains = append(desiredChains, enforcer.LiveChain{Table: ruleset.Chain.Table, Name: m.containerToASGChain[chainKey]})
		}
		enforceDuration += time.Now().Sub(enforceStartTime)
	}

	pollingLoop := len(containers) == 0

	var cleanupDuration time.Duration
	if pollingLoop {
		cleanupStart := time.Now()
		err := m.cleanupASGsChains(planner.ASGManagedChainsRegex, desiredChains)
		if err != nil {
			errors = multierror.Append(errors, err)
		}
		cleanupDuration = time.Now().Sub(cleanupStart)
	}
	m.asgMutex.Unlock()

	if pollingLoop {
		m.metricsSender.SendDuration(metricASGEnforceDuration, enforceDuration)
		m.metricsSender.SendDuration(metricASGCleanupDuration, cleanupDuration)
		pollDuration := time.Now().Sub(pollStartTime)
		m.metricsSender.SendDuration(metricASGPollDuration, pollDuration)
	}

	return errors
}

func (m *SinglePollCycle) CleanupOrphanedASGsChains(containerHandle string) error {
	m.asgMutex.Lock()
	defer m.asgMutex.Unlock()

	return m.cleanupASGsChains(planner.ASGChainPrefix(containerHandle), []enforcer.LiveChain{})
}

func (m *SinglePollCycle) updateRuleSet(chainKey enforcer.LiveChain, chain string, ruleset enforcer.RulesWithChain) {
	m.containerToASGChain[chainKey] = chain
	m.asgRuleSets[chainKey] = ruleset
	m.sendAppLog(ruleset.LogConfig)
}

func (m *SinglePollCycle) cleanupASGsChains(prefix string, desiredChains []enforcer.LiveChain) error {
	deletedChains, err := m.enforcer.CleanChainsMatching(regexp.MustCompile(prefix), desiredChains)
	if err != nil {
		return fmt.Errorf("clean-up-orphaned-asg-chains: %s", err)
	} else {
		m.logger.Debug("policy-cycle-asg", lager.Data{
			"message": "deleted-orphaned-chains",
			"chains":  deletedChains,
		})

		for chainKey, chainName := range m.containerToASGChain {
			for _, deletedChain := range deletedChains {
				if deletedChain.Table == chainKey.Table && deletedChain.Name == chainName {
					delete(m.containerToASGChain, chainKey)
					delete(m.asgRuleSets, chainKey)
				}
			}
		}
	}

	return nil
}

// used to test that we're deleting the right chains and nothing else
func (m *SinglePollCycle) CurrentlyAppliedChainNames() []string {
	chains := []string{}
	for _, chain := range m.containerToASGChain {
		chains = append(chains, chain)
	}
	return chains
}

func (m *SinglePollCycle) sendAppLog(logConfig executor.LogConfig) {
	if logConfig.Guid == "" {
		return
	}
	tags := map[string]string{}
	if logConfig.Tags != nil {
		tags = logConfig.Tags
	}
	if _, ok := tags["source_id"]; !ok {
		tags["source_id"] = logConfig.Guid
	}
	sourceIndex := strconv.Itoa(logConfig.Index)
	if _, ok := tags["instance_id"]; !ok {
		tags["instance_id"] = sourceIndex
	}
	err := m.metronClient.SendAppLog("Security group rules were updated", logConfig.SourceName, tags)
	if err != nil {
		m.logger.Error("failed-sending-app-log", err, lager.Data{"log-config": logConfig})
	}
}
