package rules_test

import (
	"lib/rules"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-cf-experimental/gomegamatchers"
)

var _ = Describe("Rules", func() {
	Describe("AppendComment", func() {
		var originalRule rules.IPTablesRule
		BeforeEach(func() {
			originalRule = rules.IPTablesRule{"some", "rule"}
		})
		It("appends the comment to the iptables rule, replacing spaces with underscores", func() {
			rule := rules.AppendComment(originalRule, `some:comment statement`)
			Expect(rule).To(Equal(rules.IPTablesRule{
				"some", "rule", "-m", "comment", "--comment", `some:comment_statement`,
			}))
		})
	})

	Describe("NewDefaultEgressRule", func() {
		It("should generate a new rule from the source, not to the CIDR range, not to the device which causes a MASQUERADE", func() {
			rule := rules.NewDefaultEgressRule("10.255.27.5/32", "10.255.0.0/16", "silk-vtep")
			Expect(rule).To(Equal(rules.IPTablesRule{
				"--source", "10.255.27.5/32",
				"!", "-o", "silk-vtep",
				"!", "--destination", "10.255.0.0/16",
				"--jump", "MASQUERADE",
			}))
		})

		Context("when no masquerade cidr range is not provided", func() {
			It("should generate a rule that does not check the destination for the no masquerade cidr range", func() {
				rule := rules.NewDefaultEgressRule("10.255.27.5/32", "", "silk-vtep")
				Expect(rule).To(Equal(rules.IPTablesRule{
					"--source", "10.255.27.5/32",
					"!", "-o", "silk-vtep",
					"--jump", "MASQUERADE",
				}))
			})
		})
	})

	Describe("NewLogRule", func() {
		Context("when the log prefix is greater than 28 characters", func() {
			It("shortens the log-prefix to 28 characters and adds a space", func() {
				rule := rules.NewLogRule([]string{}, "some-very-very-very-long-app-guid")
				Expect(rule).To(ContainElement(`"some-very-very-very-long-app "`))
			})
		})
	})

	Describe("NewMarkAllowLogRule", func() {
		Context("when the log prefix is greater than 28 characters", func() {
			Context("when the protocol is not udp", func() {
				It("shortens the log-prefix to 28 characters and adds a space", func() {
					rule := rules.NewMarkAllowLogRule("10.255.0.1", "tcp", 80, 80, "0", "some-very-very-very-long-app-guid", -1)
					Expect(rule).To(Equal(rules.IPTablesRule{
						"-d", "10.255.0.1",
						"-p", "tcp",
						"--dport", "80:80",
						"-m", "mark", "--mark", "0x0",
						"-m", "conntrack", "--ctstate", "INVALID,NEW,UNTRACKED",
						"--jump", "LOG", "--log-prefix",
						`"OK_0_some-very-very-very-lon "`,
					}))
				})
			})
			Context("when the protocol is udp", func() {
				It("does not use conntrack", func() {
					rule := rules.NewMarkAllowLogRule("10.255.0.1", "udp", 80, 80, "0", "some-very-very-very-long-app-guid", 4)
					Expect(rule).To(Equal(rules.IPTablesRule{
						"-d", "10.255.0.1",
						"-p", "udp",
						"--dport", "80:80",
						"-m", "mark", "--mark", "0x0",
						"-m", "limit",
						"--limit", "4/s",
						"--limit-burst", "4",
						"--jump", "LOG", "--log-prefix",
						`"OK_0_some-very-very-very-lon "`,
					}))
				})

			})
		})
	})

	Describe("NewNetOutDefaultNonUDPLogRule", func() {
		Context("when the log prefix is greater than 28 characters", func() {
			It("shortens the log-prefix to 28 characters and adds a space", func() {
				rule := rules.NewNetOutDefaultNonUDPLogRule("some-very-very-very-long-app-guid")
				Expect(rule).To(Equal(rules.IPTablesRule{
					"!", "-p", "udp",
					"-m", "conntrack", "--ctstate", "INVALID,NEW,UNTRACKED",
					"-j", "LOG", "--log-prefix", `"OK_some-very-very-very-long- "`,
				},
				))
			})
		})
	})

	Describe("NewNetOutDefaultUDPLogRule", func() {
		Context("when the log prefix is greater than 28 characters", func() {
			It("shortens the log-prefix to 28 characters and adds a space", func() {
				rule := rules.NewNetOutDefaultUDPLogRule("some-very-very-very-long-app-guid", 5)
				Expect(rule).To(Equal(rules.IPTablesRule{
					"-p", "udp",
					"-m", "limit",
					"--limit", "5/s",
					"--limit-burst", "5",
					"-j", "LOG", "--log-prefix", `"OK_some-very-very-very-long- "`,
				}))
			})
		})
	})

	Describe("NewOverlayDefaultRejectLogRule", func() {
		Context("when the log prefix is greater than 28 characters", func() {
			It("shortens the log-prefix to 28 characters and adds a space", func() {
				rule := rules.NewOverlayDefaultRejectLogRule("some-very-very-very-long-app-guid", "", 5)
				Expect(rule).To(gomegamatchers.ContainSequence(rules.IPTablesRule{
					"-m", "limit", "--limit", "5/s", "--limit-burst", "5",
				}))
				Expect(rule).To(ContainElement(`"DENY_C2C_some-very-very-very "`))
			})
		})
	})

	Describe("NewNetOutDefaultRejectLogRule", func() {
		Context("when the log prefix is greater than 28 characters", func() {
			It("shortens the log-prefix to 28 characters and adds a space", func() {
				rule := rules.NewNetOutDefaultRejectLogRule("some-very-very-very-long-app-guid", 3)
				Expect(rule).To(gomegamatchers.ContainSequence(rules.IPTablesRule{
					"-m", "limit", "--limit", "3/s", "--limit-burst", "3",
				}))
				Expect(rule).To(ContainElement(`"DENY_some-very-very-very-lon "`))
			})
		})
	})

	Describe("NewIngressMarkRules", func() {
		It("creates a jump rule when given one interface", func() {
			jumpRule := rules.NewIngressMarkRules([]string{"eth0"}, 2000, "2.3.4.5", "1")
			Expect(jumpRule[0]).To(Equal(rules.IPTablesRule{
				"-i", "eth0", "-d", "2.3.4.5", "-p", "tcp",
				"-m", "tcp", "--dport", "2000",
				"--jump", "MARK",
				"--set-mark", "0x1",
			}))
		})
		It("creates the same jump rule for each interface", func() {
			jumpRules := rules.NewIngressMarkRules([]string{"eth0", "gandalf"}, 2000, "2.3.4.5", "1")
			Expect(jumpRules[0]).To(Equal(rules.IPTablesRule{
				"-i", "eth0", "-d", "2.3.4.5", "-p", "tcp",
				"-m", "tcp", "--dport", "2000",
				"--jump", "MARK",
				"--set-mark", "0x1",
			}))
			Expect(jumpRules[1]).To(Equal(rules.IPTablesRule{
				"-i", "gandalf", "-d", "2.3.4.5", "-p", "tcp",
				"-m", "tcp", "--dport", "2000",
				"--jump", "MARK",
				"--set-mark", "0x1",
			}))
		})
	})

	Describe("NewNetOutJumpConditions", func() {
		It("creates a jump rule when given one interface", func() {
			jumpRule := rules.NewNetOutJumpConditions([]string{"eth0"}, "1.2.3.4", "a-chain")
			Expect(jumpRule[0]).To(Equal(rules.IPTablesRule{
				"-s", "1.2.3.4",
				"-o", "eth0",
				"--jump", "a-chain",
			}))
		})

		It("creates the same jump rule for each interface", func() {
			jumpRules := rules.NewNetOutJumpConditions([]string{"eth0", "dumbledore"}, "1.2.3.4", "side-chain")
			Expect(jumpRules[0]).To(Equal(rules.IPTablesRule{
				"-s", "1.2.3.4",
				"-o", "eth0",
				"--jump", "side-chain",
			}))
			Expect(jumpRules[1]).To(Equal(rules.IPTablesRule{
				"-s", "1.2.3.4",
				"-o", "dumbledore",
				"--jump", "side-chain",
			}))
		})
	})

	Describe("NewIngressMarkAllowRule", func() {
		It("creates a jump rule for traffic from the overlay with a 0x0 mark", func() {
			jumpRule := rules.NewIngressMarkAllowRule(8080, "10.255.32.32")
			Expect(jumpRule).To(Equal(rules.IPTablesRule{
				"-p", "tcp",
				"-i", "silk-vtep",
				"-m", "mark", "--mark", "0x0",
				"-m", "iprange", "--dst-range", "10.255.32.32", "--dport", "8080",
				"--jump", "ACCEPT",
			}))
		})
	})
})
