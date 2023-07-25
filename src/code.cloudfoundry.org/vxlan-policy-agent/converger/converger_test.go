package converger_test

import (
	"errors"
	"fmt"
	"regexp"

	diegologgingclientfakes "code.cloudfoundry.org/diego-logging-client/testhelpers"
	"code.cloudfoundry.org/executor"
	"code.cloudfoundry.org/lib/rules"
	"code.cloudfoundry.org/vxlan-policy-agent/converger"
	"code.cloudfoundry.org/vxlan-policy-agent/converger/fakes"
	"code.cloudfoundry.org/vxlan-policy-agent/enforcer"
	"code.cloudfoundry.org/vxlan-policy-agent/planner"

	"code.cloudfoundry.org/lager/v3/lagertest"

	"github.com/hashicorp/go-multierror"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = Describe("Single Poll Cycle", func() {
	Describe("Policies", func() {
		var (
			p                    *converger.SinglePollCycle
			fakePolicyPlanner    *fakes.Planner
			fakeLocalPlanner     *fakes.Planner
			fakeRemotePlanner    *fakes.Planner
			fakeEnforcer         *fakes.RuleEnforcer
			fakePolicyClient     *fakes.PolicyClient
			metricsSender        *fakes.MetricsSender
			fakeMetronClient     *diegologgingclientfakes.FakeIngressClient
			localRulesWithChain  enforcer.RulesWithChain
			remoteRulesWithChain enforcer.RulesWithChain
			policyRulesWithChain enforcer.RulesWithChain
			logger               *lagertest.TestLogger
		)

		BeforeEach(func() {
			fakePolicyPlanner = &fakes.Planner{}
			fakeLocalPlanner = &fakes.Planner{}
			fakeRemotePlanner = &fakes.Planner{}
			fakeEnforcer = &fakes.RuleEnforcer{}
			fakePolicyClient = &fakes.PolicyClient{}
			fakeMetronClient = &diegologgingclientfakes.FakeIngressClient{}
			metricsSender = &fakes.MetricsSender{}
			logger = lagertest.NewTestLogger("test")

			p = converger.NewSinglePollCycle(
				[]converger.Planner{fakeLocalPlanner, fakeRemotePlanner, fakePolicyPlanner},
				fakeEnforcer,
				fakePolicyClient,
				metricsSender,
				fakeMetronClient,
				logger,
			)

			localRulesWithChain = enforcer.RulesWithChain{
				Rules: []rules.IPTablesRule{[]string{"local-rule"}},
				Chain: enforcer.Chain{
					Table:       "local-table",
					ParentChain: "INPUT",
					Prefix:      "some-prefix",
				},
			}
			remoteRulesWithChain = enforcer.RulesWithChain{
				Rules: []rules.IPTablesRule{[]string{"remote-rule"}},
				Chain: enforcer.Chain{
					Table:       "remote-table",
					ParentChain: "INPUT",
					Prefix:      "some-prefix",
				},
			}
			policyRulesWithChain = enforcer.RulesWithChain{
				Rules: []rules.IPTablesRule{[]string{"policy-rule"}},
				Chain: enforcer.Chain{
					Table:       "policy-table",
					ParentChain: "INPUT",
					Prefix:      "some-prefix",
				},
			}

			fakeLocalPlanner.GetPolicyRulesAndChainReturns(localRulesWithChain, nil)
			fakeRemotePlanner.GetPolicyRulesAndChainReturns(remoteRulesWithChain, nil)
			fakePolicyPlanner.GetPolicyRulesAndChainReturns(policyRulesWithChain, nil)
		})

		Describe("DoPolicyCycleWithLastUpdatedCheck", func() {
			Context("when policy server returns an error getting last updated date", func() {
				BeforeEach(func() {
					fakePolicyClient.GetPoliciesLastUpdatedReturns(0, errors.New("endpoint-does-not-exist"))
				})

				It("runs policy cycle", func() {
					Expect(fakeLocalPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(0))
					err := p.DoPolicyCycleWithLastUpdatedCheck()
					Expect(err).NotTo(HaveOccurred())
					Expect(fakeLocalPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(1))
				})
			})

			Context("when never called before", func() {
				It("runs policy cycle", func() {
					Expect(fakeLocalPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(0))
					err := p.DoPolicyCycleWithLastUpdatedCheck()
					Expect(err).NotTo(HaveOccurred())
					Expect(fakeLocalPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(1))
				})
			})

			Context("when called before", func() {
				BeforeEach(func() {
					fakePolicyClient.GetPoliciesLastUpdatedReturns(10, nil)
					err := p.DoPolicyCycleWithLastUpdatedCheck()
					Expect(err).NotTo(HaveOccurred())
				})

				Context("when policy server last updated is newer", func() {
					BeforeEach(func() {
						fakePolicyClient.GetPoliciesLastUpdatedReturns(20, nil)
					})

					It("runs policy cycle", func() {
						Expect(fakeLocalPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(1))
						err := p.DoPolicyCycleWithLastUpdatedCheck()
						Expect(err).NotTo(HaveOccurred())
						Expect(fakeLocalPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(2))
					})
				})

				Context("when policy server last updated is the same", func() {
					BeforeEach(func() {
						fakePolicyClient.GetPoliciesLastUpdatedReturns(10, nil)
					})

					It("doesn't run policy cycle", func() {
						Expect(fakeLocalPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(1))
						err := p.DoPolicyCycleWithLastUpdatedCheck()
						Expect(err).NotTo(HaveOccurred())
						Expect(fakeLocalPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(1))
					})
				})
			})
		})

		Describe("DoPolicyCycle", func() {
			It("enforces local, remote and policy rules on configured interval", func() {
				err := p.DoPolicyCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeLocalPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(1))
				Expect(fakeRemotePlanner.GetPolicyRulesAndChainCallCount()).To(Equal(1))
				Expect(fakePolicyPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(1))
				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))

				rws := fakeEnforcer.EnforceRulesAndChainArgsForCall(0)
				Expect(rws).To(Equal(localRulesWithChain))
				rws = fakeEnforcer.EnforceRulesAndChainArgsForCall(1)
				Expect(rws).To(Equal(remoteRulesWithChain))
				rws = fakeEnforcer.EnforceRulesAndChainArgsForCall(2)
				Expect(rws).To(Equal(policyRulesWithChain))
			})

			It("emits time metrics", func() {
				err := p.DoPolicyCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(metricsSender.SendDurationCallCount()).To(Equal(2))
				name, _ := metricsSender.SendDurationArgsForCall(0)
				Expect(name).To(Equal("iptablesEnforceTime"))
				name, _ = metricsSender.SendDurationArgsForCall(1)
				Expect(name).To(Equal("totalPollTime"))
			})

			Context("when a ruleset has not changed since the last poll cycle", func() {
				BeforeEach(func() {
					err := p.DoPolicyCycle()
					Expect(err).NotTo(HaveOccurred())
					Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))
				})

				It("does not re-write the ip tables rules", func() {
					err := p.DoPolicyCycle()
					Expect(err).NotTo(HaveOccurred())
					Expect(fakeLocalPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(2))
					Expect(fakeRemotePlanner.GetPolicyRulesAndChainCallCount()).To(Equal(2))
					Expect(fakePolicyPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(2))

					Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))
				})
			})

			Context("when a ruleset has changed since the last poll cycle", func() {
				BeforeEach(func() {
					err := p.DoPolicyCycle()
					Expect(err).NotTo(HaveOccurred())
					Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))
					localRulesWithChain.Rules = []rules.IPTablesRule{[]string{"new-rule"}}
					fakeLocalPlanner.GetPolicyRulesAndChainReturns(localRulesWithChain, nil)
				})

				It("re-writes the ip tables rules for that chain", func() {
					err := p.DoPolicyCycle()
					Expect(err).NotTo(HaveOccurred())
					Expect(fakeLocalPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(2))
					Expect(fakeRemotePlanner.GetPolicyRulesAndChainCallCount()).To(Equal(2))
					Expect(fakePolicyPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(2))

					Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(4))
				})

				It("logs a message about writing ip tables rules", func() {
					err := p.DoPolicyCycle()
					Expect(err).NotTo(HaveOccurred())
					Expect(logger).To(gbytes.Say("poll-cycle.*updating iptables rules.*new rules.*new-rule.*num new rules.*1.*num old rules.*1.*old rules.*local-rule"))
				})
			})

			Context("when a ruleset has all rules removed since the last poll cycle", func() {
				BeforeEach(func() {
					err := p.DoPolicyCycle()
					Expect(err).NotTo(HaveOccurred())
					Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))
					localRulesWithChain.Rules = []rules.IPTablesRule{}
					fakeLocalPlanner.GetPolicyRulesAndChainReturns(localRulesWithChain, nil)
				})

				It("re-writes the ip tables rules for that chain", func() {
					err := p.DoPolicyCycle()
					Expect(err).NotTo(HaveOccurred())
					Expect(fakeLocalPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(2))
					Expect(fakeRemotePlanner.GetPolicyRulesAndChainCallCount()).To(Equal(2))
					Expect(fakePolicyPlanner.GetPolicyRulesAndChainCallCount()).To(Equal(2))

					Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(4))
				})
			})

			Context("when a new empty chain is created", func() {
				BeforeEach(func() {
					localRulesWithChain.Rules = []rules.IPTablesRule{}
					fakeLocalPlanner.GetPolicyRulesAndChainReturns(localRulesWithChain, nil)
				})

				It("enforces the rules for that chain", func() {
					err := p.DoPolicyCycle()
					Expect(err).NotTo(HaveOccurred())

					Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))
					Expect(metricsSender.SendDurationCallCount()).To(Equal(2))
				})
			})

			Context("when the local planner errors", func() {
				BeforeEach(func() {
					fakeLocalPlanner.GetPolicyRulesAndChainReturns(policyRulesWithChain, errors.New("eggplant"))
				})

				It("logs the error and returns", func() {
					err := p.DoPolicyCycle()
					Expect(err).To(MatchError("get-rules: eggplant"))

					Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(0))
					Expect(metricsSender.SendDurationCallCount()).To(Equal(0))
				})
			})

			Context("when the remote planner errors", func() {
				BeforeEach(func() {
					fakeRemotePlanner.GetPolicyRulesAndChainReturns(policyRulesWithChain, errors.New("eggplant"))
				})

				It("logs the error and returns", func() {
					err := p.DoPolicyCycle()
					Expect(err).To(MatchError("get-rules: eggplant"))

					Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(1))
					Expect(metricsSender.SendDurationCallCount()).To(Equal(0))
				})
			})

			Context("when the policy planner errors", func() {
				BeforeEach(func() {
					fakePolicyPlanner.GetPolicyRulesAndChainReturns(policyRulesWithChain, errors.New("eggplant"))
				})

				It("logs the error and returns", func() {
					err := p.DoPolicyCycle()
					Expect(err).To(MatchError("get-rules: eggplant"))

					Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(2))
					Expect(metricsSender.SendDurationCallCount()).To(Equal(0))
				})
			})

			Context("when policy enforcer errors", func() {
				BeforeEach(func() {
					fakeEnforcer.EnforceRulesAndChainReturns("professional tests", errors.New("eggplant"))
				})

				It("logs the error and returns", func() {
					err := p.DoPolicyCycle()
					Expect(err).To(MatchError("enforce: eggplant"))

					Expect(metricsSender.SendDurationCallCount()).To(Equal(0))
				})
			})
		})
	})

	Describe("DoASGCycle", func() {
		var (
			p                 *converger.SinglePollCycle
			fakeASGPlanner    *fakes.Planner
			fakeEnforcer      *fakes.RuleEnforcer
			fakeMetronClient  *diegologgingclientfakes.FakeIngressClient
			metricsSender     *fakes.MetricsSender
			ASGRulesWithChain []enforcer.RulesWithChain
			logger            *lagertest.TestLogger
		)

		BeforeEach(func() {
			fakeASGPlanner = &fakes.Planner{}
			fakeEnforcer = &fakes.RuleEnforcer{}
			metricsSender = &fakes.MetricsSender{}
			fakeMetronClient = &diegologgingclientfakes.FakeIngressClient{}
			fakePolicyClient := &fakes.PolicyClient{}
			logger = lagertest.NewTestLogger("test")

			fakeEnforcer.EnforceRulesAndChainStub = func(chain enforcer.RulesWithChain) (string, error) {
				return fmt.Sprintf("%s-with-suffix", chain.Chain.Prefix), nil
			}

			p = converger.NewSinglePollCycle(
				[]converger.Planner{fakeASGPlanner},
				fakeEnforcer,
				fakePolicyClient,
				metricsSender,
				fakeMetronClient,
				logger,
			)

			ASGRulesWithChain = []enforcer.RulesWithChain{
				{
					Rules: []rules.IPTablesRule{[]string{"asg-rule1"}},
					Chain: enforcer.Chain{
						Table:       "filter",
						ParentChain: "netout-1",
						Prefix:      "asg-1234",
					},
					LogConfig: executor.LogConfig{
						Guid:       "some-app-guid-1",
						Index:      1,
						SourceName: "some-source-name",
						Tags:       map[string]string{"some-tag-1": "some-value-1"},
					},
				}, {
					Rules: []rules.IPTablesRule{[]string{"asg-rule2"}},
					Chain: enforcer.Chain{
						Table:       "filter",
						ParentChain: "netout-2",
						Prefix:      "asg-2345",
					},
					LogConfig: executor.LogConfig{
						Guid:       "some-app-guid-2",
						Index:      2,
						SourceName: "some-source-name",
					},
				},
				{
					Rules: []rules.IPTablesRule{[]string{"asg-rule3"}},
					Chain: enforcer.Chain{
						Table:       "filter",
						ParentChain: "netout-3",
						Prefix:      "asg-3456",
					},
					LogConfig: executor.LogConfig{
						Guid:       "some-app-guid-3",
						Index:      3,
						SourceName: "some-source-name",
						Tags:       map[string]string{"some-tag-3": "some-value-3"},
					},
				},
			}

			fakeASGPlanner.GetASGRulesAndChainsReturns(ASGRulesWithChain, nil)
		})

		It("enforces ASG rules on configured interval", func() {
			err := p.DoASGCycle()
			Expect(err).NotTo(HaveOccurred())
			Expect(fakeASGPlanner.GetASGRulesAndChainsCallCount()).To(Equal(1))
			Expect(fakeASGPlanner.GetASGRulesAndChainsArgsForCall(0)).To(BeNil())
			Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))

			for i, ruleWithChain := range ASGRulesWithChain {
				rws := fakeEnforcer.EnforceRulesAndChainArgsForCall(i)
				Expect(rws).To(Equal(ruleWithChain))
			}

			Expect(fakeEnforcer.CleanChainsMatchingCallCount()).To(Equal(1))
			regex, chains := fakeEnforcer.CleanChainsMatchingArgsForCall(0)
			Expect(regex).To(Equal(regexp.MustCompile(planner.ASGManagedChainsRegex)))
			Expect(chains).To(Equal([]enforcer.LiveChain{
				{
					Table: "filter",
					Name:  "asg-1234-with-suffix",
				},
				{
					Table: "filter",
					Name:  "asg-2345-with-suffix",
				},
				{
					Table: "filter",
					Name:  "asg-3456-with-suffix",
				}}))
		})

		It("emits time metrics", func() {
			err := p.DoASGCycle()
			Expect(err).NotTo(HaveOccurred())
			Expect(metricsSender.SendDurationCallCount()).To(Equal(3))
			name, _ := metricsSender.SendDurationArgsForCall(0)
			Expect(name).To(Equal("asgIptablesEnforceTime"))
			name, _ = metricsSender.SendDurationArgsForCall(1)
			Expect(name).To(Equal("asgIptablesCleanupTime"))
			name, _ = metricsSender.SendDurationArgsForCall(2)
			Expect(name).To(Equal("asgTotalPollTime"))
		})

		Context("when a ruleset has not changed since the last poll cycle", func() {
			BeforeEach(func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))
			})

			It("does not re-write the ip tables rules", func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeASGPlanner.GetASGRulesAndChainsCallCount()).To(Equal(2))

				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))
			})

			It("does not send an app log", func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeMetronClient.SendAppLogCallCount()).To(Equal(3))
			})
		})

		Context("when a ruleset has changed since the last poll cycle", func() {
			BeforeEach(func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))
				ASGRulesWithChain[0].Rules = []rules.IPTablesRule{[]string{"new-rule"}}
				fakeASGPlanner.GetASGRulesAndChainsReturns(ASGRulesWithChain, nil)
			})

			It("re-writes the ip tables rules for that chain", func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeASGPlanner.GetASGRulesAndChainsCallCount()).To(Equal(2))

				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(4))
			})

			It("logs a message about writing ip tables rules", func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(logger).To(gbytes.Say("poll-cycle.*updating iptables rules.*new rules.*new-rule.*num new rules.*1.*num old rules.*1.*old rules.*asg-rule"))
			})

			It("sends app logs", func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeMetronClient.SendAppLogCallCount()).To(Equal(4))

				msg, sourceName, tags := fakeMetronClient.SendAppLogArgsForCall(0)
				Expect(msg).To(Equal("Security group rules were updated"))
				Expect(sourceName).To(Equal("some-source-name"))
				Expect(tags).To(Equal(map[string]string{"some-tag-1": "some-value-1", "source_id": "some-app-guid-1", "instance_id": "1"}))

				msg, sourceName, tags = fakeMetronClient.SendAppLogArgsForCall(1)
				Expect(msg).To(Equal("Security group rules were updated"))
				Expect(sourceName).To(Equal("some-source-name"))
				Expect(tags).To(Equal(map[string]string{"source_id": "some-app-guid-2", "instance_id": "2"}))

				msg, sourceName, tags = fakeMetronClient.SendAppLogArgsForCall(2)
				Expect(msg).To(Equal("Security group rules were updated"))
				Expect(sourceName).To(Equal("some-source-name"))
				Expect(tags).To(Equal(map[string]string{"some-tag-3": "some-value-3", "source_id": "some-app-guid-3", "instance_id": "3"}))

				msg, sourceName, tags = fakeMetronClient.SendAppLogArgsForCall(3)
				Expect(msg).To(Equal("Security group rules were updated"))
				Expect(sourceName).To(Equal("some-source-name"))
				Expect(tags).To(Equal(map[string]string{"some-tag-1": "some-value-1", "source_id": "some-app-guid-1", "instance_id": "1"}))
			})
		})

		Context("when an ASG ruleset is present when there are no containers associated with it", func() {
			BeforeEach(func() {
				// create some fake ASG iptables
				var orphanRulesWithChain []enforcer.RulesWithChain
				orphanRulesWithChain = append(ASGRulesWithChain, enforcer.RulesWithChain{
					Rules: []rules.IPTablesRule{[]string{"asg-rule"}},
					Chain: enforcer.Chain{
						Table:       "asg-table-orphan",
						ParentChain: "netout-orphan",
						Prefix:      "asg-orphaned",
					},
				})
				fakeASGPlanner.GetASGRulesAndChainsReturns(orphanRulesWithChain, nil)
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(4))
				Expect(p.CurrentlyAppliedChainNames()).To(ConsistOf([]string{
					"asg-1234-with-suffix",
					"asg-2345-with-suffix",
					"asg-3456-with-suffix",
					"asg-orphaned-with-suffix",
				}))
				fakeASGPlanner.GetASGRulesAndChainsReturns(ASGRulesWithChain, nil)
				fakeEnforcer.CleanChainsMatchingReturns([]enforcer.LiveChain{{
					Table: "asg-table-orphan", Name: "asg-orphaned-with-suffix"}},
					nil)
			})

			It("removes the fake ASG iptables/rules", func() {
				desiredChainsResult := []enforcer.LiveChain{
					{
						Table: "filter",
						Name:  "asg-1234-with-suffix",
					},
					{
						Table: "filter",
						Name:  "asg-2345-with-suffix",
					},
					{
						Table: "filter",
						Name:  "asg-3456-with-suffix",
					},
				}
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				By("only removing the orphaned rules", func() {
					Expect(fakeEnforcer.CleanChainsMatchingCallCount()).To(Equal(2))
					regex, desiredChains := fakeEnforcer.CleanChainsMatchingArgsForCall(1)
					Expect(regex).To(Equal(regexp.MustCompile(planner.ASGManagedChainsRegex)))
					Expect(desiredChains).To(Equal(desiredChainsResult))
					Expect(p.CurrentlyAppliedChainNames()).To(ConsistOf([]string{
						"asg-1234-with-suffix",
						"asg-2345-with-suffix",
						"asg-3456-with-suffix",
					}))
				})
			})

			Context("when errors occur deleting orphaned chains", func() {
				var metricsCount int
				BeforeEach(func() {
					fakeEnforcer.CleanChainsMatchingReturns([]enforcer.LiveChain{}, fmt.Errorf("eggplant"))
					metricsCount = metricsSender.SendDurationCallCount()
				})

				It("returns a error", func() {
					err := p.DoASGCycle()
					Expect(err).To(HaveOccurred())
					multiErr, ok := err.(*multierror.Error)
					Expect(ok).To(BeTrue())
					errors := multiErr.WrappedErrors()
					Expect(errors).To(HaveLen(1))
					Expect(errors[0]).To(MatchError("clean-up-orphaned-asg-chains: eggplant"))
					Expect(metricsSender.SendDurationCallCount()).To(Equal(metricsCount + 3))
				})
			})
		})

		Context("when a ruleset has all rules removed since the last poll cycle", func() {
			BeforeEach(func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))
				ASGRulesWithChain[0].Rules = []rules.IPTablesRule{}
				fakeASGPlanner.GetASGRulesAndChainsReturns(ASGRulesWithChain, nil)
			})

			It("re-writes the ip tables rules for that chain", func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeASGPlanner.GetASGRulesAndChainsCallCount()).To(Equal(2))

				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(4))
				Expect(fakeEnforcer.CleanChainsMatchingCallCount()).To(Equal(2))
			})
		})

		Context("when a new empty chain is created", func() {
			BeforeEach(func() {
				ASGRulesWithChain[0].Rules = []rules.IPTablesRule{}
				fakeASGPlanner.GetASGRulesAndChainsReturns(ASGRulesWithChain, nil)
			})

			It("enforces the rules for that chain", func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())

				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))
				Expect(fakeEnforcer.CleanChainsMatchingCallCount()).To(Equal(1))
				Expect(metricsSender.SendDurationCallCount()).To(Equal(3))
			})
		})

		Context("when the planner errors", func() {
			BeforeEach(func() {
				fakeASGPlanner.GetASGRulesAndChainsReturns(ASGRulesWithChain, errors.New("eggplant"))
			})

			It("logs the error and returns", func() {
				err := p.DoASGCycle()
				Expect(err).To(MatchError("get-asg-rules: eggplant"))

				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(0))
				Expect(fakeEnforcer.CleanChainsMatchingCallCount()).To(Equal(0))
				Expect(metricsSender.SendDurationCallCount()).To(Equal(0))
			})
		})

		Context("when the enforcer errors", func() {
			BeforeEach(func() {
				// set up an initial successful cycle to create the cache of container to asg mappings
				// fakeEnforcer.EnforceRulesAndChainStub = func(chain enforcer.RulesWithChain) (string, error) {
				// 	return fmt.Sprintf("%s-with-suffix", chain.Chain.Prefix), nil
				// }
				err := p.DoASGCycle()
				Expect(err).ToNot(HaveOccurred())

				//simulate changes to rules, so enforcer will get called again
				newFakeASGs := []enforcer.RulesWithChain{
					{
						Rules: []rules.IPTablesRule{[]string{"asg-rule3"}},
						Chain: enforcer.Chain{
							Table:       "filter",
							ParentChain: "netout-1",
							Prefix:      "asg-1234",
						},
					}, {
						Rules: []rules.IPTablesRule{[]string{"asg-rule4"}},
						Chain: enforcer.Chain{
							Table:       "filter",
							ParentChain: "netout-2",
							Prefix:      "asg-2345",
						},
					},
					{
						Rules: []rules.IPTablesRule{[]string{"asg-rule5"}},
						Chain: enforcer.Chain{
							Table:       "filter",
							ParentChain: "netout-3",
							Prefix:      "asg-3456",
						},
					},
				}
				fakeASGPlanner.GetASGRulesAndChainsReturns(newFakeASGs, nil)
			})

			Context("when enforcer errors with clean up error", func() {
				BeforeEach(func() {
					// have enforcerulesandchain return success for first call, and cleanup errors for the rest,
					// to validate that we get multiple errors returned, and also that we desire both
					// new ASG chains from successful enforces and from clean up errors
					i := 0
					fakeEnforcer.EnforceRulesAndChainStub = func(e enforcer.RulesWithChain) (string, error) {
						var err error
						if i > 0 {
							err = &enforcer.CleanupErr{Err: fmt.Errorf("zucchini")}
						}
						i++
						return fmt.Sprintf("%s-with-new-suffix", e.Chain.Prefix), err
					}
				})

				It("returns errors", func() {
					err := p.DoASGCycle()
					multiErr, ok := err.(*multierror.Error)
					Expect(ok).To(BeTrue())
					errors := multiErr.WrappedErrors()
					Expect(errors).To(HaveLen(2))
					Expect(errors[0]).To(MatchError("enforce-asg: cleaning up: zucchini"))
					Expect(errors[1]).To(MatchError("enforce-asg: cleaning up: zucchini"))

					Expect(metricsSender.SendDurationCallCount()).To(Equal(6))
				})

				It("does not try to update the rules again", func() {
					err := p.DoASGCycle()
					Expect(err).To(HaveOccurred())

					Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(6))

					err = p.DoASGCycle()
					Expect(err).NotTo(HaveOccurred())
					Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(6))
				})

				It("handles cleanup of orphaned chains properly", func() {
					err := p.DoASGCycle()
					Expect(err).To(HaveOccurred())
					Expect(fakeEnforcer.CleanChainsMatchingCallCount()).To(Equal(2))
					_, chains := fakeEnforcer.CleanChainsMatchingArgsForCall(1)
					By("enforcing that the new chain for successful enforces is desired", func() {
						Expect(chains[0]).To(Equal(enforcer.LiveChain{
							Table: "filter",
							Name:  "asg-1234-with-new-suffix",
						}))
					})
					By("enforcing that the new chains for failed enforces during clean up are still desired", func() {
						Expect(chains[1:]).To(Equal([]enforcer.LiveChain{{
							Table: "filter",
							Name:  "asg-2345-with-new-suffix",
						}, {
							Table: "filter",
							Name:  "asg-3456-with-new-suffix",
						}}))
					})
				})
			})

			Context("when enforcer errors with non cleanup error", func() {
				BeforeEach(func() {
					// have enforcerulesandchain return success for first call, and failures on the rest,
					// to validate that we get multiple errors returned, and also that we desire both
					// the old ASG chains from failed enforces, and new ASG chains from successful enforces
					// when cleaning up orphaned chains
					i := 0
					fakeEnforcer.EnforceRulesAndChainStub = func(e enforcer.RulesWithChain) (string, error) {
						var err error
						if i > 0 {
							err = fmt.Errorf("eggplant")
						}
						i++
						return fmt.Sprintf("%s-with-new-suffix", e.Chain.Prefix), err
					}
				})

				It("returns errors", func() {
					err := p.DoASGCycle()
					multiErr, ok := err.(*multierror.Error)
					Expect(ok).To(BeTrue())
					errors := multiErr.WrappedErrors()
					Expect(errors).To(HaveLen(2))
					Expect(errors[0]).To(MatchError("enforce-asg: eggplant"))
					Expect(errors[1]).To(MatchError("enforce-asg: eggplant"))

					Expect(metricsSender.SendDurationCallCount()).To(Equal(6))
				})

				It("tries to update the rules again", func() {
					err := p.DoASGCycle()
					Expect(err).To(HaveOccurred())

					Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(6))

					err = p.DoASGCycle()
					Expect(err).To(HaveOccurred())
					Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(8))
				})

				It("handles cleanup of orphaned chains properly", func() {
					err := p.DoASGCycle()
					Expect(err).To(HaveOccurred())
					Expect(fakeEnforcer.CleanChainsMatchingCallCount()).To(Equal(2))
					_, chains := fakeEnforcer.CleanChainsMatchingArgsForCall(1)
					By("enforcing that the new chain for successful enforces is desired", func() {
						Expect(chains[0]).To(Equal(enforcer.LiveChain{
							Table: "filter",
							Name:  "asg-1234-with-new-suffix",
						}))
					})
					By("enforcing that the old chains for failed enforces are still desired", func() {
						Expect(chains[1:]).To(Equal([]enforcer.LiveChain{{
							Table: "filter",
							Name:  "asg-2345-with-suffix",
						}, {
							Table: "filter",
							Name:  "asg-3456-with-suffix",
						}}))
					})
				})
			})
		})

		Context("when there are multiple planners", func() {
			var fakeOtherPlanner *fakes.Planner
			var otherRulesWithChain []enforcer.RulesWithChain
			BeforeEach(func() {
				fakeOtherPlanner = &fakes.Planner{}
				fakePolicyClient := &fakes.PolicyClient{}
				p = converger.NewSinglePollCycle(
					[]converger.Planner{fakeASGPlanner, fakeOtherPlanner},
					fakeEnforcer,
					fakePolicyClient,
					metricsSender,
					fakeMetronClient,
					logger,
				)
				otherRulesWithChain = []enforcer.RulesWithChain{
					{
						Rules: []rules.IPTablesRule{[]string{"rule1"}},
						Chain: enforcer.Chain{
							Table:       "mangle",
							ParentChain: "FORWARD",
							Prefix:      "other-mangle-rule",
						},
					},
				}
				fakeOtherPlanner.GetASGRulesAndChainsReturns(otherRulesWithChain, nil)
			})

			It("calls all the planners", func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeASGPlanner.GetASGRulesAndChainsCallCount()).To(Equal(1))
				Expect(fakeASGPlanner.GetASGRulesAndChainsArgsForCall(0)).To(BeNil())
				Expect(fakeOtherPlanner.GetASGRulesAndChainsCallCount()).To(Equal(1))
				Expect(fakeOtherPlanner.GetASGRulesAndChainsArgsForCall(0)).To(BeNil())
				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(4))

				allRulesWithChain := append(ASGRulesWithChain, otherRulesWithChain...)

				for i, ruleWithChain := range allRulesWithChain {
					rws := fakeEnforcer.EnforceRulesAndChainArgsForCall(i)
					Expect(rws).To(Equal(ruleWithChain))
				}

				Expect(fakeEnforcer.CleanChainsMatchingCallCount()).To(Equal(1))
				regex, chains := fakeEnforcer.CleanChainsMatchingArgsForCall(0)
				Expect(regex).To(Equal(regexp.MustCompile(planner.ASGManagedChainsRegex)))
				Expect(chains).To(Equal([]enforcer.LiveChain{
					{
						Table: "filter",
						Name:  "asg-1234-with-suffix",
					}, {
						Table: "filter",
						Name:  "asg-2345-with-suffix",
					}, {
						Table: "filter",
						Name:  "asg-3456-with-suffix",
					}, {
						Table: "mangle",
						Name:  "other-mangle-rule-with-suffix",
					}}))
			})

			Context("and a planner fails on GetASGRulesAndChains", func() {
				BeforeEach(func() {
					fakeASGPlanner.GetASGRulesAndChainsReturns(ASGRulesWithChain, fmt.Errorf("error on first planner"))
				})
				It("fails properly", func() {
					err := p.DoASGCycle()
					By("returning the error", func() {
						Expect(err).To(HaveOccurred())
						Expect(err).To(MatchError(fmt.Errorf("get-asg-rules: error on first planner")))
					})
					By("not planning anything else", func() {
						Expect(fakeOtherPlanner.GetASGRulesAndChainsCallCount()).To(Equal(0))
					})
					By("not enforcing anything", func() {
						Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(0))
					})
					By("not cleaning up orphaned chains", func() {
						Expect(fakeEnforcer.CleanChainsMatchingCallCount()).To(Equal(0))
					})
				})
			})
		})

		Describe("SyncASGsForContainer", func() {
			It("passes specified containers to the planner", func() {
				err := p.SyncASGsForContainers("container-1", "container-2")
				Expect(err).ToNot(HaveOccurred())
				Expect(fakeASGPlanner.GetASGRulesAndChainsArgsForCall(0)).To(Equal([]string{"container-1", "container-2"}))
			})

			It("does not clean up orphans when syncing specific containers", func() {
				err := p.SyncASGsForContainers("container-1", "container-2")
				Expect(err).ToNot(HaveOccurred())
				Expect(fakeEnforcer.CleanChainsMatchingCallCount()).To(Equal(0))
			})
		})

		Describe("CleanupOrphanedASGsChains", func() {
			It("cleans up asg chains with no desired chains", func() {
				err := p.CleanupOrphanedASGsChains("some-container-handle")
				Expect(err).ToNot(HaveOccurred())
				Expect(fakeEnforcer.CleanChainsMatchingCallCount()).To(Equal(1))
				asgRegex, desiredChains := fakeEnforcer.CleanChainsMatchingArgsForCall(0)
				Expect(asgRegex.String()).To(MatchRegexp("asg-[a-z0-9]{6}"))
				Expect(desiredChains).To(BeEmpty())
			})

			Context("the enforcer returns an error", func() {
				BeforeEach(func() {
					fakeEnforcer.CleanChainsMatchingReturns([]enforcer.LiveChain{}, errors.New("zucchini"))
				})

				It("returns the error", func() {
					err := p.CleanupOrphanedASGsChains("some-container-handle")
					Expect(err).To(MatchError("clean-up-orphaned-asg-chains: zucchini"))
				})
			})
		})
	})
})

type Locker struct {
	LockCallCount   int
	UnlockCallCount int
}

func (l *Locker) Lock() {
	l.LockCallCount++
}

func (l *Locker) Unlock() {
	l.UnlockCallCount++
}
