package converger_test

import (
	"errors"
	"fmt"
	"regexp"

	"code.cloudfoundry.org/lib/rules"
	"code.cloudfoundry.org/vxlan-policy-agent/converger"
	"code.cloudfoundry.org/vxlan-policy-agent/converger/fakes"
	"code.cloudfoundry.org/vxlan-policy-agent/enforcer"
	"code.cloudfoundry.org/vxlan-policy-agent/planner"

	"code.cloudfoundry.org/lager/lagertest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = Describe("Single Poll Cycle", func() {
	Describe("DoPolicyCycle", func() {
		var (
			p                    *converger.SinglePollCycle
			fakePolicyPlanner    *fakes.Planner
			fakeLocalPlanner     *fakes.Planner
			fakeRemotePlanner    *fakes.Planner
			fakeEnforcer         *fakes.RuleEnforcer
			metricsSender        *fakes.MetricsSender
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
			metricsSender = &fakes.MetricsSender{}
			logger = lagertest.NewTestLogger("test")

			p = converger.NewSinglePollCycle(
				[]converger.Planner{fakeLocalPlanner, fakeRemotePlanner, fakePolicyPlanner},
				fakeEnforcer,
				metricsSender,
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

		It("enforces local,remote and policy rules on configured interval", func() {
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
	Describe("DoASGCycle", func() {
		var (
			p                    *converger.SinglePollCycle
			fakeASGPlanner       *fakes.Planner
			fakeLocalPlanner     *fakes.Planner
			fakeRemotePlanner    *fakes.Planner
			fakeEnforcer         *fakes.RuleEnforcer
			metricsSender        *fakes.MetricsSender
			localRulesWithChain  []enforcer.RulesWithChain
			remoteRulesWithChain []enforcer.RulesWithChain
			ASGRulesWithChain    []enforcer.RulesWithChain
			logger               *lagertest.TestLogger
		)

		BeforeEach(func() {
			fakeASGPlanner = &fakes.Planner{}
			fakeLocalPlanner = &fakes.Planner{}
			fakeRemotePlanner = &fakes.Planner{}
			fakeEnforcer = &fakes.RuleEnforcer{}
			metricsSender = &fakes.MetricsSender{}
			logger = lagertest.NewTestLogger("test")

			fakeEnforcer.EnforceRulesAndChainStub = func(chain enforcer.RulesWithChain) (string, error) {
				return fmt.Sprintf("%s-with-suffix", chain.Chain.Prefix), nil
			}

			p = converger.NewSinglePollCycle(
				[]converger.Planner{fakeLocalPlanner, fakeRemotePlanner, fakeASGPlanner},
				fakeEnforcer,
				metricsSender,
				logger,
			)

			localRulesWithChain = []enforcer.RulesWithChain{
				{
					Rules: []rules.IPTablesRule{[]string{"local-rule"}},
					Chain: enforcer.Chain{
						Table:       "local-table",
						ParentChain: "local-1234",
						Prefix:      "local-prefix",
					},
				},
			}

			remoteRulesWithChain = []enforcer.RulesWithChain{
				{
					Rules: []rules.IPTablesRule{[]string{"remote-rule"}},
					Chain: enforcer.Chain{
						Table:       "remote-table",
						ParentChain: "remote-1234",
						Prefix:      "remote-prefix",
					},
				},
			}

			ASGRulesWithChain = []enforcer.RulesWithChain{
				{
					Rules: []rules.IPTablesRule{[]string{"asg-rule"}},
					Chain: enforcer.Chain{
						Table:       "asg-table",
						ParentChain: "asg-1234",
						Prefix:      "asg-prefix",
					},
				},
			}

			fakeLocalPlanner.GetASGRulesAndChainsReturns(localRulesWithChain, nil)
			fakeRemotePlanner.GetASGRulesAndChainsReturns(remoteRulesWithChain, nil)
			fakeASGPlanner.GetASGRulesAndChainsReturns(ASGRulesWithChain, nil)
		})
		It("enforces local,remote and ASG rules on configured interval", func() {
			err := p.DoASGCycle()
			Expect(err).NotTo(HaveOccurred())
			Expect(fakeLocalPlanner.GetASGRulesAndChainsCallCount()).To(Equal(1))
			Expect(fakeRemotePlanner.GetASGRulesAndChainsCallCount()).To(Equal(1))
			Expect(fakeASGPlanner.GetASGRulesAndChainsCallCount()).To(Equal(1))
			Expect(fakeASGPlanner.GetASGRulesAndChainsArgsForCall(0)).To(BeNil())
			Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))

			allRulesWithChains := append(localRulesWithChain, remoteRulesWithChain...)
			allRulesWithChains = append(allRulesWithChains, ASGRulesWithChain...)

			for i, ruleWithChain := range allRulesWithChains {
				rws := fakeEnforcer.EnforceRulesAndChainArgsForCall(i)
				Expect(rws).To(Equal(ruleWithChain))
			}

			Expect(fakeEnforcer.EnforceChainsMatchingCallCount()).To(Equal(1))
			regex, chains := fakeEnforcer.EnforceChainsMatchingArgsForCall(0)
			Expect(regex).To(Equal(regexp.MustCompile(planner.ASGManagedChainsRegex)))
			Expect(chains).To(Equal([]enforcer.LiveChain{
				{
					Table: "local-table",
					Name:  "local-prefix-with-suffix",
				},
				{
					Table: "remote-table",
					Name:  "remote-prefix-with-suffix",
				},
				{
					Table: "asg-table",
					Name:  "asg-prefix-with-suffix",
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
				Expect(fakeLocalPlanner.GetASGRulesAndChainsCallCount()).To(Equal(2))
				Expect(fakeRemotePlanner.GetASGRulesAndChainsCallCount()).To(Equal(2))
				Expect(fakeASGPlanner.GetASGRulesAndChainsCallCount()).To(Equal(2))

				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))
			})
		})

		Context("when a ruleset has changed since the last poll cycle", func() {
			BeforeEach(func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))
				localRulesWithChain[0].Rules = []rules.IPTablesRule{[]string{"new-rule"}}
				fakeLocalPlanner.GetASGRulesAndChainsReturns(localRulesWithChain, nil)
			})

			It("re-writes the ip tables rules for that chain", func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeLocalPlanner.GetASGRulesAndChainsCallCount()).To(Equal(2))
				Expect(fakeRemotePlanner.GetASGRulesAndChainsCallCount()).To(Equal(2))
				Expect(fakeASGPlanner.GetASGRulesAndChainsCallCount()).To(Equal(2))

				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(4))
			})

			It("logs a message about writing ip tables rules", func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(logger).To(gbytes.Say("poll-cycle.*updating iptables rules.*new rules.*new-rule.*num new rules.*1.*num old rules.*1.*old rules.*local-rule"))
			})
		})

		Context("when an ASG ruleset is  present when there are no contianers associated with it", func() {
			BeforeEach(func() {
				//				create some fake ASG iptables
				var orphanRulesWithChain []enforcer.RulesWithChain
				orphanRulesWithChain = append(localRulesWithChain, enforcer.RulesWithChain{
					Rules: []rules.IPTablesRule{[]string{"asg-rule"}},
					Chain: enforcer.Chain{
						Table:       "asg-table-orphan",
						ParentChain: "orphan-1234",
						Prefix:      "orphan-prefix",
					},
				})
				fakeLocalPlanner.GetASGRulesAndChainsReturns(orphanRulesWithChain, nil)
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(4))
				Expect(p.CurrentlyAppliedChainNames()).To(ConsistOf([]string{
					"local-prefix-with-suffix",
					"remote-prefix-with-suffix",
					"asg-prefix-with-suffix",
					"orphan-prefix-with-suffix",
				}))
				fakeLocalPlanner.GetASGRulesAndChainsReturns(localRulesWithChain, nil)
				fakeEnforcer.EnforceChainsMatchingReturns([]enforcer.LiveChain{{
					Table: "asg-table-orphan", Name: "orphan-prefix-with-suffix"}},
					nil)
			})

			It("removes the fake ASG iptables/rules", func() {
				desiredChainsResult := []enforcer.LiveChain{
					{
						Table: "local-table",
						Name:  "local-prefix-with-suffix",
					},
					{
						Table: "asg-table-orphan",
						Name:  "orphan-prefix-with-suffix",
					},
					{
						Table: "remote-table",
						Name:  "remote-prefix-with-suffix",
					},
					{
						Table: "asg-table",
						Name:  "asg-prefix-with-suffix",
					},
				}
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				By("only removing the orphaned rules", func() {
					Expect(fakeEnforcer.EnforceChainsMatchingCallCount()).To(Equal(2))
					regex, desiredChains := fakeEnforcer.EnforceChainsMatchingArgsForCall(0)
					Expect(regex).To(Equal(regexp.MustCompile(planner.ASGManagedChainsRegex)))
					Expect(desiredChains).To(Equal(desiredChainsResult))
					Expect(p.CurrentlyAppliedChainNames()).To(ConsistOf([]string{
						"local-prefix-with-suffix",
						"remote-prefix-with-suffix",
						"asg-prefix-with-suffix",
					}))
				})
			})

			Context("when errors occur deleting orphaned chains", func() {
				var metricsCount int
				BeforeEach(func() {
					fakeEnforcer.EnforceChainsMatchingReturns([]enforcer.LiveChain{}, fmt.Errorf("eggplant"))
					metricsCount = metricsSender.SendDurationCallCount()
				})
				It("returns a error", func() {
					err := p.DoASGCycle()
					Expect(err).To(HaveOccurred())
					Expect(err).To(MatchError("clean-up-orphaned-asg-chains: eggplant"))
					Expect(metricsSender.SendDurationCallCount()).To(Equal(metricsCount))
				})
			})

		})

		Context("when a ruleset has all rules removed since the last poll cycle", func() {
			BeforeEach(func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))
				localRulesWithChain[0].Rules = []rules.IPTablesRule{}
				fakeLocalPlanner.GetASGRulesAndChainsReturns(localRulesWithChain, nil)
			})

			It("re-writes the ip tables rules for that chain", func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeLocalPlanner.GetASGRulesAndChainsCallCount()).To(Equal(2))
				Expect(fakeRemotePlanner.GetASGRulesAndChainsCallCount()).To(Equal(2))
				Expect(fakeASGPlanner.GetASGRulesAndChainsCallCount()).To(Equal(2))

				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(4))
				Expect(fakeEnforcer.EnforceChainsMatchingCallCount()).To(Equal(2))
			})
		})

		Context("when a new empty chain is created", func() {
			BeforeEach(func() {
				localRulesWithChain[0].Rules = []rules.IPTablesRule{}
				fakeLocalPlanner.GetASGRulesAndChainsReturns(localRulesWithChain, nil)
			})

			It("enforces the rules for that chain", func() {
				err := p.DoASGCycle()
				Expect(err).NotTo(HaveOccurred())

				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(3))
				Expect(fakeEnforcer.EnforceChainsMatchingCallCount()).To(Equal(1))
				Expect(metricsSender.SendDurationCallCount()).To(Equal(3))
			})
		})

		Context("when the local planner errors", func() {
			BeforeEach(func() {
				fakeLocalPlanner.GetASGRulesAndChainsReturns(ASGRulesWithChain, errors.New("eggplant"))
			})

			It("logs the error and returns", func() {
				err := p.DoASGCycle()
				Expect(err).To(MatchError("get-asg-rules: eggplant"))

				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(0))
				Expect(fakeEnforcer.EnforceChainsMatchingCallCount()).To(Equal(0))
				Expect(metricsSender.SendDurationCallCount()).To(Equal(0))
			})
		})

		Context("when the remote planner errors", func() {
			BeforeEach(func() {
				fakeRemotePlanner.GetASGRulesAndChainsReturns(ASGRulesWithChain, errors.New("eggplant"))
			})

			It("logs the error and returns", func() {
				err := p.DoASGCycle()
				Expect(err).To(MatchError("get-asg-rules: eggplant"))

				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(1))
				Expect(fakeEnforcer.EnforceChainsMatchingCallCount()).To(Equal(0))
				Expect(metricsSender.SendDurationCallCount()).To(Equal(0))
			})
		})

		Context("when the ASG planner errors", func() {
			BeforeEach(func() {
				fakeASGPlanner.GetASGRulesAndChainsReturns(ASGRulesWithChain, errors.New("eggplant"))
			})

			It("logs the error and returns", func() {
				err := p.DoASGCycle()
				Expect(err).To(MatchError("get-asg-rules: eggplant"))

				Expect(fakeEnforcer.EnforceRulesAndChainCallCount()).To(Equal(2))
				Expect(fakeEnforcer.EnforceChainsMatchingCallCount()).To(Equal(0))
				Expect(metricsSender.SendDurationCallCount()).To(Equal(0))
			})
		})

		Context("when ASG enforcer errors", func() {
			BeforeEach(func() {
				fakeEnforcer.EnforceRulesAndChainReturns("word string", errors.New("eggplant"))
			})

			It("logs the error and returns", func() {
				err := p.DoASGCycle()
				Expect(err).To(MatchError("enforce-asg: eggplant"))

				Expect(metricsSender.SendDurationCallCount()).To(Equal(0))
			})
		})
		Describe("SyncASGsForContainer", func() {
			It("passes specified containers to the planner", func() {
				err := p.SyncASGsForContainer("container-1", "container-2")
				Expect(err).ToNot(HaveOccurred())
				Expect(fakeASGPlanner.GetASGRulesAndChainsArgsForCall(0)).To(Equal([]string{"container-1", "container-2"}))
			})

			It("only looks to clean up orphans that match the included containers", func() {
				err := p.SyncASGsForContainer("container-1", "container-2")
				Expect(err).ToNot(HaveOccurred())
				Expect(fakeEnforcer.EnforceChainsMatchingCallCount()).To(Equal(0))
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
