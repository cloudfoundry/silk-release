package netrules_test

import (
	"errors"

	"code.cloudfoundry.org/cni-wrapper-plugin/fakes"
	"code.cloudfoundry.org/cni-wrapper-plugin/netrules"

	"code.cloudfoundry.org/garden"

	"code.cloudfoundry.org/lib/rules"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("NetOutChain", func() {
	var (
		netOutChain *netrules.NetOutChain
		converter   *fakes.RuleConverter
		chainNamer  *fakes.ChainNamer
	)
	BeforeEach(func() {
		chainNamer = &fakes.ChainNamer{}
		converter = &fakes.RuleConverter{}
		netOutChain = &netrules.NetOutChain{
			ChainNamer:       chainNamer,
			Converter:        converter,
			DeniedLogsPerSec: 3,
			Conn: netrules.OutConn{
				Limit: false,
				DryRun: false,
			},
		}
		chainNamer.PrefixStub = func(prefix, handle string) string {
			return prefix + "-" + handle
		}
		chainNamer.PostfixReturns("some-other-chain-name", nil)
	})

	Describe("DefaultRules", func() {
		It("writes the default netout and logging rules", func() {
			ruleSpec := netOutChain.DefaultRules("some-container-handle")

			Expect(ruleSpec).To(Equal([]rules.IPTablesRule{
				{"--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
			}))
		})

		Context("when global ASG logging is enabled", func() {
			BeforeEach(func() {
				netOutChain.ASGLogging = true
			})
			It("writes a log rule for denies", func() {
				ruleSpec := netOutChain.DefaultRules("some-container-handle")

				Expect(ruleSpec).To(Equal([]rules.IPTablesRule{
					{"-m", "limit", "--limit", "3/s", "--limit-burst", "3",
						"--jump", "LOG", "--log-prefix", `"DENY_some-container-handle "`},
					{"--jump", "REJECT",
						"--reject-with", "icmp-port-unreachable"},
				}))
			})
		})
	})

	Describe("IPTablesRules", func() {
		var (
			netOutRules  []garden.NetOutRule
			genericRules []rules.IPTablesRule
		)

		BeforeEach(func() {
			genericRules = []rules.IPTablesRule{
				{"rule1"},
				{"rule2"},
			}

			converter.BulkConvertReturns(genericRules)

		})

		It("prepends allow rules to the container's netout chain", func() {
			ruleSpec := netrules.NewRulesFromGardenNetOutRules(netOutRules)
			iptablesRules, err := netOutChain.IPTablesRules("some-container-handle", "app", ruleSpec)
			Expect(err).NotTo(HaveOccurred())

			Expect(chainNamer.PostfixCallCount()).To(Equal(1))
			body, suffix := chainNamer.PostfixArgsForCall(0)
			Expect(body).To(Equal("netout-some-container-handle"))
			Expect(suffix).To(Equal("log"))

			Expect(converter.BulkConvertCallCount()).To(Equal(1))
			convertedRules, logChainName, logging := converter.BulkConvertArgsForCall(0)
			Expect(convertedRules).To(Equal(ruleSpec))
			Expect(logChainName).To(Equal("some-other-chain-name"))
			Expect(logging).To(Equal(false))

			rulesWithDefaultAcceptReject := append(genericRules, []rules.IPTablesRule{
				{"-p", "tcp", "-m", "state", "--state", "INVALID", "-j", "DROP"},
				{"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
			}...)

			Expect(iptablesRules).To(Equal(rulesWithDefaultAcceptReject))
		})

		Context("when the chain namer fails", func() {
			BeforeEach(func() {
				chainNamer.PostfixReturns("", errors.New("banana"))
			})

			It("returns the error", func() {
				ruleSpec := netrules.NewRulesFromGardenNetOutRules(netOutRules)
				_, err := netOutChain.IPTablesRules("some-container-handle", "app", ruleSpec)
				Expect(err).To(MatchError("getting chain name: banana"))
			})
		})

		Context("when the global logging is enabled", func() {
			BeforeEach(func() {
				netOutChain.ASGLogging = true
			})

			It("calls BulkConvert with globalLogging set to true", func() {
				ruleSpec := netrules.NewRulesFromGardenNetOutRules(netOutRules)
				_, err := netOutChain.IPTablesRules("some-container-handle", "app", ruleSpec)
				Expect(err).NotTo(HaveOccurred())

				Expect(converter.BulkConvertCallCount()).To(Equal(1))
				convertedRules, logChainName, logging := converter.BulkConvertArgsForCall(0)
				Expect(convertedRules).To(Equal(ruleSpec))
				Expect(logChainName).To(Equal("some-other-chain-name"))
				Expect(logging).To(Equal(true))
			})
		})

		Context("when deny networks are specified", func() {
			BeforeEach(func() {
				netOutChain.DenyNetworks = netrules.DenyNetworks{}
			})

			DescribeTable(
				"it should deny the workload networks and the 'all' networks",
				func(workload string, denyNetworks netrules.DenyNetworks) {
					netOutChain.DenyNetworks = denyNetworks
					netOutChain.DenyNetworks.Always = []string{"172.16.0.0/12"}

					iptablesRules, err := netOutChain.IPTablesRules("some-container-handle", workload, netrules.NewRulesFromGardenNetOutRules(netOutRules))
					Expect(err).NotTo(HaveOccurred())

					rulesWithDenyNetworksAndDefaults := append(
						genericRules,
						[]rules.IPTablesRule{
							{"-d", "172.16.0.0/12", "--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
							{"-d", "192.168.0.0/16", "--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
							{"-p", "tcp", "-m", "state", "--state", "INVALID", "-j", "DROP"},
							{"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
						}...,
					)

					Expect(iptablesRules).To(Equal(rulesWithDenyNetworksAndDefaults))
				},
				Entry("when the workload is an app", "app", netrules.DenyNetworks{Running: []string{"192.168.0.0/16"}}),
				Entry("when the workload is a task", "task", netrules.DenyNetworks{Running: []string{"192.168.0.0/16"}}),
				Entry("when the workload is staging", "staging", netrules.DenyNetworks{Staging: []string{"192.168.0.0/16"}}),
			)

			DescribeTable(
				"it should only deny the workload networks and the 'all' networks",
				func(workload string, expectedDenyNetwork string) {
					netOutChain.DenyNetworks = netrules.DenyNetworks{
						Always:  []string{"1.1.1.1/32"},
						Running: []string{"2.2.2.2/32"},
						Staging: []string{"3.3.3.3/32"},
					}

					iptablesRules, err := netOutChain.IPTablesRules("some-container-handle", workload, netrules.NewRulesFromGardenNetOutRules(netOutRules))
					Expect(err).NotTo(HaveOccurred())

					rulesWithDenyNetworksAndDefaults := append(
						genericRules,
						[]rules.IPTablesRule{
							{"-d", "1.1.1.1/32", "--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
							{"-d", expectedDenyNetwork, "--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
							{"-p", "tcp", "-m", "state", "--state", "INVALID", "-j", "DROP"},
							{"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
						}...,
					)

					Expect(iptablesRules).To(Equal(rulesWithDenyNetworksAndDefaults))
				},
				Entry("when the workload is an app", "app", "2.2.2.2/32"),
				Entry("when the workload is a task", "task", "2.2.2.2/32"),
				Entry("when the workload is staging", "staging", "3.3.3.3/32"),
			)
		})

		Context("when outbound container connection limiting is enabled", func() {
			BeforeEach(func() {
				netOutChain.Conn.Limit = true
				netOutChain.Conn.Burst = 400
				netOutChain.Conn.RatePerSec = 99

				chainNamer.PostfixReturnsOnCall(1, "netout-some-container-handle-rl-log", nil)
			})

			Context("when denied outbound container connections logging is enabled", func() {
				BeforeEach(func() {
					netOutChain.Conn.Logging = true
				})

				It("inserts the outbound connection rate limit rule", func() {
					iptablesRules, err := netOutChain.IPTablesRules("some-container-handle", "app", netrules.NewRulesFromGardenNetOutRules(netOutRules))
					Expect(err).NotTo(HaveOccurred())

					Expect(chainNamer.PostfixCallCount()).To(Equal(2))

					By("specifying a jump condition to the respective logging chains")

					expectedRateLimitRule := rules.IPTablesRule{
						"-p", "tcp",
						"-m", "conntrack", "--ctstate", "NEW",
						"-m", "hashlimit", "--hashlimit-above", "99/sec", "--hashlimit-burst", "400",
						"--hashlimit-mode", "dstip,dstport", "--hashlimit-name", "some-container-handle",
						"--hashlimit-htable-expire", "5000", "-j", "netout-some-container-handle-rl-log",
					}
					expectedRules := append(genericRules, []rules.IPTablesRule{
						expectedRateLimitRule,
						{"-p", "tcp", "-m", "state", "--state", "INVALID", "-j", "DROP"},
						{"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
					}...)

					Expect(iptablesRules).To(Equal(expectedRules))
				})

				Context("when denied outbound container connections dry_run is enabled", func() {
					BeforeEach(func() {
						netOutChain.Conn.DryRun = true
					})
	
					It("inserts the outbound connection rate limit rule", func() {
						iptablesRules, err := netOutChain.IPTablesRules("some-container-handle", "app", netrules.NewRulesFromGardenNetOutRules(netOutRules))
						Expect(err).NotTo(HaveOccurred())
	
						Expect(chainNamer.PostfixCallCount()).To(Equal(2))
	
						By("specifying a jump condition to the respective logging chains")
	
						expectedRateLimitRule := rules.IPTablesRule{
							"-p", "tcp",
							"-m", "conntrack", "--ctstate", "NEW",
							"-m", "hashlimit", "--hashlimit-above", "99/sec", "--hashlimit-burst", "400",
							"--hashlimit-mode", "dstip,dstport", "--hashlimit-name", "some-container-handle",
							"--hashlimit-htable-expire", "5000", "-j", "netout-some-container-handle-rl-log",
						}
						expectedRules := append(genericRules, []rules.IPTablesRule{
							expectedRateLimitRule,
							{"-p", "tcp", "-m", "state", "--state", "INVALID", "-j", "DROP"},
							{"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
						}...)
	
						Expect(iptablesRules).To(Equal(expectedRules))
					})
				})

				Context("when the chain namer fails", func() {
					Context("when naming the rate limit chain", func() {
						BeforeEach(func() {
							chainNamer.PostfixReturnsOnCall(1, "", errors.New("guacamole"))
						})

						It("returns the error", func() {
							_, err := netOutChain.IPTablesRules("some-container-handle", "app", netrules.NewRulesFromGardenNetOutRules(netOutRules))
							Expect(err).To(MatchError("getting chain name: guacamole"))
						})
					})
				})
			})

			Context("when denied outbound container connections logging is disabled", func() {
				BeforeEach(func() {
					netOutChain.Conn.Logging = false
				})

				It("inserts the outbound connection rate limit rule", func() {
					iptablesRules, err := netOutChain.IPTablesRules("some-container-handle", "app", netrules.NewRulesFromGardenNetOutRules(netOutRules))
					Expect(err).NotTo(HaveOccurred())

					Expect(chainNamer.PostfixCallCount()).To(Equal(1))

					By("specifying a REJECT jump condition")

					expectedRateLimitRule := rules.IPTablesRule{
						"-p", "tcp",
						"-m", "conntrack", "--ctstate", "NEW",
						"-m", "hashlimit", "--hashlimit-above", "99/sec", "--hashlimit-burst", "400",
						"--hashlimit-mode", "dstip,dstport", "--hashlimit-name", "some-container-handle",
						"--hashlimit-htable-expire", "5000", "-j", "REJECT",
					}
					expectedRules := append(genericRules, []rules.IPTablesRule{
						expectedRateLimitRule,
						{"-p", "tcp", "-m", "state", "--state", "INVALID", "-j", "DROP"},
						{"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
					}...)

					Expect(iptablesRules).To(Equal(expectedRules))
				})

				Context("when denied outbound container connections dry_run is enabled", func() {
					BeforeEach(func() {
						netOutChain.Conn.DryRun = true
					})
	
					It("inserts the outbound connection rate limit rule", func() {
						iptablesRules, err := netOutChain.IPTablesRules("some-container-handle", "app", netrules.NewRulesFromGardenNetOutRules(netOutRules))
						Expect(err).NotTo(HaveOccurred())
	
						Expect(chainNamer.PostfixCallCount()).To(Equal(2))
	
						By("specifying a jump condition to the respective logging chains")
	
						expectedRateLimitRule := rules.IPTablesRule{
							"-p", "tcp",
							"-m", "conntrack", "--ctstate", "NEW",
							"-m", "hashlimit", "--hashlimit-above", "99/sec", "--hashlimit-burst", "400",
							"--hashlimit-mode", "dstip,dstport", "--hashlimit-name", "some-container-handle",
							"--hashlimit-htable-expire", "5000", "-j", "netout-some-container-handle-rl-log",
						}
						expectedRules := append(genericRules, []rules.IPTablesRule{
							expectedRateLimitRule,
							{"-p", "tcp", "-m", "state", "--state", "INVALID", "-j", "DROP"},
							{"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
						}...)
	
						Expect(iptablesRules).To(Equal(expectedRules))
					})
				})
			})
		})

		Context("when outbound container connection limiting is disabled", func() {
			BeforeEach(func() {
				netOutChain.Conn.Limit = false
				netOutChain.Conn.Burst = 400
				netOutChain.Conn.RatePerSec = 99

				chainNamer.PostfixReturnsOnCall(1, "netout-some-container-handle-rl-log", nil)
			})

			Context("when denied outbound container connections dry_run is enabled", func() {
				BeforeEach(func() {
					netOutChain.Conn.DryRun = true
				})

				It("inserts the outbound connection rate limit rule", func() {
					iptablesRules, err := netOutChain.IPTablesRules("some-container-handle", "app", netrules.NewRulesFromGardenNetOutRules(netOutRules))
					Expect(err).NotTo(HaveOccurred())

					Expect(chainNamer.PostfixCallCount()).To(Equal(2))

					By("specifying a jump condition to the respective logging chains")

					expectedRateLimitRule := rules.IPTablesRule{
						"-p", "tcp",
						"-m", "conntrack", "--ctstate", "NEW",
						"-m", "hashlimit", "--hashlimit-above", "99/sec", "--hashlimit-burst", "400",
						"--hashlimit-mode", "dstip,dstport", "--hashlimit-name", "some-container-handle",
						"--hashlimit-htable-expire", "5000", "-j", "netout-some-container-handle-rl-log",
					}
					expectedRules := append(genericRules, []rules.IPTablesRule{
						expectedRateLimitRule,
						{"-p", "tcp", "-m", "state", "--state", "INVALID", "-j", "DROP"},
						{"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
					}...)

					Expect(iptablesRules).To(Equal(expectedRules))
				})
			})
		})
	})
})
