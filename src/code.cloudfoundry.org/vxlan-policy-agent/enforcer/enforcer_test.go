package enforcer_test

import (
	"errors"

	libfakes "code.cloudfoundry.org/lib/fakes"
	"code.cloudfoundry.org/lib/rules"
	"code.cloudfoundry.org/vxlan-policy-agent/enforcer"
	"code.cloudfoundry.org/vxlan-policy-agent/enforcer/fakes"

	"code.cloudfoundry.org/lager/lagertest"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = Describe("Enforcer", func() {
	Describe("Enforce", func() {
		var (
			fakeRule     rules.IPTablesRule
			fakeRule2    rules.IPTablesRule
			iptables     *libfakes.IPTablesAdapter
			timestamper  *fakes.TimeStamper
			logger       *lagertest.TestLogger
			ruleEnforcer *enforcer.Enforcer
		)

		BeforeEach(func() {
			fakeRule = rules.IPTablesRule{"rule1"}
			fakeRule2 = rules.IPTablesRule{"rule2"}

			timestamper = &fakes.TimeStamper{}
			logger = lagertest.NewTestLogger("test")
			iptables = &libfakes.IPTablesAdapter{}

			timestamper.CurrentTimeReturns(42)
			ruleEnforcer = enforcer.NewEnforcer(logger, timestamper, iptables, enforcer.EnforcerConfig{DisableContainerNetworkPolicy: false, OverlayNetwork: "10.10.0.0/16"})
		})

		It("enforces all the rules it receives on the correct chain", func() {
			rulesToAppend := []rules.IPTablesRule{fakeRule, fakeRule2}
			err := ruleEnforcer.Enforce("some-table", "some-chain", "foo", "foo", true, rulesToAppend...)
			Expect(err).NotTo(HaveOccurred())

			Expect(iptables.BulkAppendCallCount()).To(Equal(1))
			tbl, chain, rules := iptables.BulkAppendArgsForCall(0)
			Expect(tbl).To(Equal("some-table"))
			Expect(chain).To(Equal("foo42"))
			Expect(rules).To(Equal(rulesToAppend))
		})

		Context("when the bulk append fails", func() {
			BeforeEach(func() {
				iptables.BulkAppendReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				rulesToAppend := []rules.IPTablesRule{fakeRule, fakeRule2}
				err := ruleEnforcer.Enforce("some-table", "some-chain", "foo", "foo", false, rulesToAppend...)
				Expect(err).To(MatchError("bulk appending: banana"))
			})
		})

		It("creates a timestamped chain", func() {
			err := ruleEnforcer.Enforce("some-table", "some-chain", "foo", "foo", false, []rules.IPTablesRule{fakeRule}...)
			Expect(err).NotTo(HaveOccurred())

			Expect(iptables.NewChainCallCount()).To(Equal(1))
			tableName, chainName := iptables.NewChainArgsForCall(0)
			Expect(tableName).To(Equal("some-table"))
			Expect(chainName).To(Equal("foo42"))
		})

		It("inserts the new chain into the chain", func() {
			err := ruleEnforcer.Enforce("some-table", "some-chain", "foo", "foo", false, []rules.IPTablesRule{fakeRule}...)
			Expect(err).NotTo(HaveOccurred())

			Expect(iptables.BulkInsertCallCount()).To(Equal(1))
			tableName, chainName, pos, ruleSpec := iptables.BulkInsertArgsForCall(0)
			Expect(tableName).To(Equal("some-table"))
			Expect(chainName).To(Equal("some-chain"))
			Expect(pos).To(Equal(1))
			Expect(ruleSpec).To(Equal([]rules.IPTablesRule{{"-j", "foo42"}}))
		})

		Context("when there is an older timestamped chain", func() {
			BeforeEach(func() {
				timestamper.CurrentTimeReturns(9999999999111111)
				iptables.ListReturns([]string{
					"-A some-chain -j foo9999999999111110",
					"-A some-chain -j foo9999999999111116",
				}, nil)
			})

			It("gets deleted", func() {
				err := ruleEnforcer.Enforce("some-table", "some-chain", "foo", "foo", false, []rules.IPTablesRule{fakeRule}...)
				Expect(err).NotTo(HaveOccurred())

				Expect(iptables.DeleteCallCount()).To(Equal(1))
				table, chain, ruleSpec := iptables.DeleteArgsForCall(0)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("some-chain"))
				Expect(ruleSpec).To(Equal(rules.IPTablesRule{"-j", "foo9999999999111110"}))
				Expect(iptables.ClearChainCallCount()).To(Equal(1))
				table, chain = iptables.ClearChainArgsForCall(0)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("foo9999999999111110"))
				Expect(iptables.DeleteChainCallCount()).To(Equal(1))
				table, chain = iptables.DeleteChainArgsForCall(0)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("foo9999999999111110"))
			})
		})

		Context("when there is an older timestamped chain with a different prefix", func() {
			BeforeEach(func() {
				timestamper.CurrentTimeReturns(9999999999111111)
				iptables.ListReturns([]string{
					"-A some-chain -j asg-000-9999999999111110",
					"-A some-chain -j asg-001-9999999999111116",
				}, nil)
			})

			It("gets deleted", func() {
				err := ruleEnforcer.Enforce("some-table", "some-chain", "asg-001-", "asg-\\d\\d\\d-", false, []rules.IPTablesRule{fakeRule}...)
				Expect(err).NotTo(HaveOccurred())

				Expect(iptables.DeleteCallCount()).To(Equal(1))
				table, chain, ruleSpec := iptables.DeleteArgsForCall(0)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("some-chain"))
				Expect(ruleSpec).To(Equal(rules.IPTablesRule{"-j", "asg-000-9999999999111110"}))
				Expect(iptables.ClearChainCallCount()).To(Equal(1))
				table, chain = iptables.ClearChainArgsForCall(0)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("asg-000-9999999999111110"))
				Expect(iptables.DeleteChainCallCount()).To(Equal(1))
				table, chain = iptables.DeleteChainArgsForCall(0)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("asg-000-9999999999111110"))
			})
		})

		Context("when parent chain has other rules", func() {
			BeforeEach(func() {
				timestamper.CurrentTimeReturns(9999999999111111)
				iptables.ListReturns([]string{
					"-A some-chain -j asg-000-9999999999111110",
					"-A some-chain -j asg-001-9999999999111116",
					"-A some-chain -j some-chain--log",
					"-A some-chain -m state --state RELATED,ESTABLISHED -j ACCEPT",
					"-A some-chain -p tcp -m state --state INVALID -j DROP",
					"-A some-chain -m iprange --dst-range 0.0.0.0-9.255.255.255 -j ACCEPT",
					"-A some-chain -j REJECT --reject-with icmp-port-unreachable",
				}, nil)
			})

			It("deletes other rules in parent chain after the current chain if parent chain cleanup requested", func() {
				err := ruleEnforcer.Enforce("some-table", "some-chain", "asg-001-", "asg-\\d\\d\\d-", true, []rules.IPTablesRule{fakeRule}...)
				Expect(err).NotTo(HaveOccurred())

				Expect(iptables.DeleteCallCount()).To(Equal(6))
				table, chain, ruleSpec := iptables.DeleteArgsForCall(0)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("some-chain"))
				Expect(ruleSpec).To(Equal(rules.IPTablesRule{"-j", "asg-000-9999999999111110"}))
				Expect(iptables.ClearChainCallCount()).To(Equal(1))
				table, chain = iptables.ClearChainArgsForCall(0)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("asg-000-9999999999111110"))
				Expect(iptables.DeleteChainCallCount()).To(Equal(1))
				table, chain = iptables.DeleteChainArgsForCall(0)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("asg-000-9999999999111110"))

				table, chain, ruleSpec = iptables.DeleteArgsForCall(1)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("some-chain"))
				Expect(ruleSpec).To(Equal(rules.IPTablesRule{"-j", "some-chain--log"}))

				table, chain, ruleSpec = iptables.DeleteArgsForCall(2)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("some-chain"))
				Expect(ruleSpec).To(Equal(rules.IPTablesRule{"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}))

				table, chain, ruleSpec = iptables.DeleteArgsForCall(3)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("some-chain"))
				Expect(ruleSpec).To(Equal(rules.IPTablesRule{"-p", "tcp", "-m", "state", "--state", "INVALID", "-j", "DROP"}))

				table, chain, ruleSpec = iptables.DeleteArgsForCall(4)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("some-chain"))
				Expect(ruleSpec).To(Equal(rules.IPTablesRule{"-m", "iprange", "--dst-range", "0.0.0.0-9.255.255.255", "-j", "ACCEPT"}))

				table, chain, ruleSpec = iptables.DeleteArgsForCall(5)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("some-chain"))
				Expect(ruleSpec).To(Equal(rules.IPTablesRule{"-j", "REJECT", "--reject-with", "icmp-port-unreachable"}))
			})

			It("does not delete other rules in parent chain if parent chain cleanup is not requested", func() {
				err := ruleEnforcer.Enforce("some-table", "some-chain", "asg-001-", "asg-\\d\\d\\d-", false, []rules.IPTablesRule{fakeRule}...)
				Expect(err).NotTo(HaveOccurred())

				Expect(iptables.DeleteCallCount()).To(Equal(1))
				table, chain, ruleSpec := iptables.DeleteArgsForCall(0)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("some-chain"))
				Expect(ruleSpec).To(Equal(rules.IPTablesRule{"-j", "asg-000-9999999999111110"}))
				Expect(iptables.ClearChainCallCount()).To(Equal(1))
				table, chain = iptables.ClearChainArgsForCall(0)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("asg-000-9999999999111110"))
				Expect(iptables.DeleteChainCallCount()).To(Equal(1))
				table, chain = iptables.DeleteChainArgsForCall(0)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("asg-000-9999999999111110"))
			})
		})

		Context("when inserting the new chain fails", func() {
			BeforeEach(func() {
				iptables.BulkInsertReturns(errors.New("banana"))
			})

			It("it logs and returns a useful error", func() {
				err := ruleEnforcer.Enforce("some-table", "some-chain", "foo", "foo", false, []rules.IPTablesRule{fakeRule}...)
				Expect(err).To(MatchError("inserting chain: banana"))

				Expect(logger).To(gbytes.Say("insert-chain.*banana"))
			})
		})

		Context("when there are errors cleaning up old rules", func() {
			BeforeEach(func() {
				iptables.ListReturns(nil, errors.New("blueberry"))
			})

			It("it logs and returns a useful error", func() {
				err := ruleEnforcer.Enforce("some-table", "some-chain", "foo", "foo", false, []rules.IPTablesRule{fakeRule}...)
				Expect(err).To(MatchError("listing forward rules: blueberry"))
				Expect(logger).To(gbytes.Say("cleanup-rules.*blueberry"))
			})
		})

		Context("when there are errors cleaning up old chains", func() {
			BeforeEach(func() {
				iptables.DeleteReturns(errors.New("banana"))
				iptables.ListReturns([]string{"-A some-chain -j foo0000000001"}, nil)
			})

			It("returns a useful error", func() {
				err := ruleEnforcer.Enforce("some-table", "some-chain", "foo", "foo", false, []rules.IPTablesRule{fakeRule}...)
				Expect(err).To(MatchError("cleanup old chain: banana"))
			})
		})

		Context("when creating the new chain fails", func() {
			BeforeEach(func() {
				iptables.NewChainReturns(errors.New("banana"))
			})

			It("it logs and returns a useful error", func() {
				err := ruleEnforcer.Enforce("some-table", "some-chain", "foo", "foo", false, []rules.IPTablesRule{fakeRule}...)
				Expect(err).To(MatchError("creating chain: banana"))

				Expect(logger).To(gbytes.Say("create-chain.*banana"))
			})
		})

		Context("when network policy is disabled", func() {
			BeforeEach(func() {
				ruleEnforcer = enforcer.NewEnforcer(
					logger,
					timestamper,
					iptables,
					enforcer.EnforcerConfig{
						DisableContainerNetworkPolicy: true,
						OverlayNetwork:                "10.10.0.0/16",
					},
				)
			})

			It("allows all container connections", func() {
				err := ruleEnforcer.Enforce("some-table", "some-chain", "foo", "foo", false, []rules.IPTablesRule{fakeRule}...)
				Expect(err).NotTo(HaveOccurred())

				Expect(iptables.NewChainCallCount()).To(Equal(1))
				Expect(iptables.BulkInsertCallCount()).To(Equal(1))
				_, _, position, _ := iptables.BulkInsertArgsForCall(0)
				Expect(position).To(Equal(1))

				table, chain, rulespec := iptables.BulkAppendArgsForCall(0)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("foo42"))
				Expect(rulespec).To(Equal([]rules.IPTablesRule{{"-s", "10.10.0.0/16", "-d", "10.10.0.0/16", "-j", "ACCEPT"}, {"rule1"}}))
			})
		})
	})

	Describe("RulesWithChain", func() {
		Describe("Equals", func() {
			var ruleSet, otherRuleSet enforcer.RulesWithChain

			BeforeEach(func() {
				ruleSet = enforcer.RulesWithChain{
					Chain: enforcer.Chain{
						Table:       "table",
						ParentChain: "parent",
						Prefix:      "prefix",
					},
					Rules: []rules.IPTablesRule{[]string{"rule1"}},
				}
				otherRuleSet = enforcer.RulesWithChain{
					Chain: enforcer.Chain{
						Table:       "table",
						ParentChain: "parent",
						Prefix:      "prefix",
					},
					Rules: []rules.IPTablesRule{[]string{"rule1"}},
				}

			})

			Context("when the rule sets are the same", func() {
				It("returns true if the rules are the same", func() {
					Expect(ruleSet.Equals(otherRuleSet)).To(BeTrue())
				})
			})

			Context("when the chain names are different", func() {
				BeforeEach(func() {
					otherRuleSet.Chain.Table = "other"
				})
				It("returns false", func() {
					Expect(ruleSet.Equals(otherRuleSet)).To(BeFalse())
				})
			})

			Context("when the rule sets are different", func() {
				BeforeEach(func() {
					otherRuleSet.Rules = []rules.IPTablesRule{[]string{"other-rule"}}
				})
				It("returns false", func() {
					Expect(ruleSet.Equals(otherRuleSet)).To(BeFalse())
				})
			})

			Context("when the rule sets are both empty", func() {
				BeforeEach(func() {
					ruleSet.Rules = []rules.IPTablesRule{}
					otherRuleSet.Rules = []rules.IPTablesRule{}
				})
				It("returns true", func() {
					Expect(ruleSet.Equals(otherRuleSet)).To(BeTrue())
				})
			})

			Context("when the rule sets are different lengths", func() {
				BeforeEach(func() {
					otherRuleSet.Rules = []rules.IPTablesRule{[]string{"rule1", "other-rule"}}
				})
				It("returns false", func() {
					Expect(ruleSet.Equals(otherRuleSet)).To(BeFalse())
				})
			})
		})
	})
})
