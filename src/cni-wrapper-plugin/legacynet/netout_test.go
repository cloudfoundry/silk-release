package legacynet_test

import (
	"cni-wrapper-plugin/fakes"
	"cni-wrapper-plugin/legacynet"
	"errors"

	"code.cloudfoundry.org/garden"

	lib_fakes "lib/fakes"
	"lib/rules"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Netout", func() {
	var (
		netOut     *legacynet.NetOut
		converter  *fakes.NetOutRuleConverter
		chainNamer *fakes.ChainNamer
		ipTables   *lib_fakes.IPTablesAdapter
	)
	BeforeEach(func() {
		chainNamer = &fakes.ChainNamer{}
		converter = &fakes.NetOutRuleConverter{}
		ipTables = &lib_fakes.IPTablesAdapter{}
		netOut = &legacynet.NetOut{
			ChainNamer:            chainNamer,
			IPTables:              ipTables,
			Converter:             converter,
			IngressTag:            "FEEDBEEF",
			VTEPName:              "vtep-name",
			HostInterfaceNames:    []string{"some-device", "eth0"},
			DeniedLogsPerSec:      3,
			AcceptedUDPLogsPerSec: 6,
			ContainerIP:           "5.6.7.8",
			ContainerHandle:       "some-container-handle",
		}
		chainNamer.PrefixStub = func(prefix, handle string) string {
			return prefix + "-" + handle
		}
		chainNamer.PostfixReturns("some-other-chain-name", nil)
	})

	Describe("Initialize", func() {
		It("creates the input chain, netout forwarding chain, and the logging chain", func() {
			err := netOut.Initialize()
			Expect(err).NotTo(HaveOccurred())

			Expect(chainNamer.PrefixCallCount()).To(Equal(3))
			prefix, handle := chainNamer.PrefixArgsForCall(0)
			Expect(prefix).To(Equal("input"))
			Expect(handle).To(Equal("some-container-handle"))

			prefix, handle = chainNamer.PrefixArgsForCall(1)
			Expect(prefix).To(Equal("netout"))
			Expect(handle).To(Equal("some-container-handle"))

			prefix, handle = chainNamer.PrefixArgsForCall(2)
			Expect(prefix).To(Equal("overlay"))
			Expect(handle).To(Equal("some-container-handle"))

			Expect(chainNamer.PostfixCallCount()).To(Equal(1))
			body, suffix := chainNamer.PostfixArgsForCall(0)
			Expect(body).To(Equal("netout-some-container-handle"))
			Expect(suffix).To(Equal("log"))

			Expect(ipTables.NewChainCallCount()).To(Equal(4))
			table, chain := ipTables.NewChainArgsForCall(0)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("input-some-container-handle"))
			table, chain = ipTables.NewChainArgsForCall(1)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("netout-some-container-handle"))
			table, chain = ipTables.NewChainArgsForCall(2)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("overlay-some-container-handle"))
			table, chain = ipTables.NewChainArgsForCall(3)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("some-other-chain-name"))
		})

		It("writes the default netout and logging rules", func() {
			err := netOut.Initialize()
			Expect(err).NotTo(HaveOccurred())

			Expect(ipTables.BulkAppendCallCount()).To(Equal(7))
			table, chain, rulespec := ipTables.BulkAppendArgsForCall(0)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("INPUT"))
			Expect(rulespec).To(Equal([]rules.IPTablesRule{{"-s", "5.6.7.8", "--jump", "input-some-container-handle"}}))

			table, chain, rulespec = ipTables.BulkAppendArgsForCall(1)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("FORWARD"))
			Expect(rulespec).To(Equal([]rules.IPTablesRule{
				{"-s", "5.6.7.8", "-o", "some-device", "--jump", "netout-some-container-handle"},
				{"-s", "5.6.7.8", "-o", "eth0", "--jump", "netout-some-container-handle"},
			}))

			table, chain, rulespec = ipTables.BulkAppendArgsForCall(2)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("FORWARD"))
			Expect(rulespec).To(Equal([]rules.IPTablesRule{{"--jump", "overlay-some-container-handle"}}))

			table, chain, rulespec = ipTables.BulkAppendArgsForCall(3)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("input-some-container-handle"))
			Expect(rulespec).To(Equal([]rules.IPTablesRule{
				{"-m", "state", "--state", "RELATED,ESTABLISHED",
					"--jump", "ACCEPT"},
				{"--jump", "REJECT",
					"--reject-with", "icmp-port-unreachable"},
			}))

			table, chain, rulespec = ipTables.BulkAppendArgsForCall(4)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("netout-some-container-handle"))
			Expect(rulespec).To(Equal([]rules.IPTablesRule{
				{"--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
			}))

			table, chain, rulespec = ipTables.BulkAppendArgsForCall(5)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("overlay-some-container-handle"))
			Expect(rulespec).To(Equal([]rules.IPTablesRule{
				{"-s", "5.6.7.8",
					"-o", "vtep-name",
					"-m", "mark", "!", "--mark", "0x0",
					"--jump", "ACCEPT"},
				{"-d", "5.6.7.8",
					"-m", "state", "--state", "RELATED,ESTABLISHED",
					"--jump", "ACCEPT"},
				{"-d", "5.6.7.8",
					"-m", "mark", "--mark", "0xFEEDBEEF",
					"--jump", "ACCEPT"},
				{"-d", "5.6.7.8",
					"--jump", "REJECT",
					"--reject-with", "icmp-port-unreachable"},
			}))

			table, chain, rulespec = ipTables.BulkAppendArgsForCall(6)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("some-other-chain-name"))
			Expect(rulespec).To(Equal([]rules.IPTablesRule{
				{"!", "-p", "udp",
					"-m", "conntrack", "--ctstate", "INVALID,NEW,UNTRACKED",
					"-j", "LOG", "--log-prefix", `"OK_some-container-handle "`},
				{"-p", "udp",
					"-m", "limit", "--limit", "6/s", "--limit-burst", "6",
					"-j", "LOG", "--log-prefix", `"OK_some-container-handle "`},
				{"--jump", "ACCEPT"},
			}))
		})

		Context("when creating a new chain fails", func() {
			BeforeEach(func() {
				ipTables.NewChainReturns(errors.New("potata"))
			})
			It("returns the error", func() {
				err := netOut.Initialize()
				Expect(err).To(MatchError("creating chain: potata"))
			})
		})

		Context("when the chain namer fails", func() {
			BeforeEach(func() {
				chainNamer.PostfixReturns("", errors.New("banana"))
			})
			It("returns the error", func() {
				err := netOut.Initialize()
				Expect(err).To(MatchError("getting chain name: banana"))
			})
		})

		Context("when appending a new rule fails", func() {
			BeforeEach(func() {
				ipTables.BulkAppendReturns(errors.New("potato"))
			})
			It("returns the error", func() {
				err := netOut.Initialize()
				Expect(err).To(MatchError("appending rule to chain: potato"))
			})
		})

		Context("when writing the netout rule fails", func() {
			BeforeEach(func() {
				ipTables.BulkAppendStub = func(table, chain string, rulespec ...rules.IPTablesRule) error {
					if chain == "INPUT" || chain == "FORWARD" {
						return nil
					}
					return errors.New("potato")
				}
			})
			It("returns the error", func() {
				err := netOut.Initialize()
				Expect(err).To(MatchError("appending rule: potato"))
			})
		})

		Context("when global ASG logging is enabled", func() {
			BeforeEach(func() {
				netOut.ASGLogging = true
			})
			It("writes a log rule for denies", func() {
				err := netOut.Initialize()
				Expect(err).NotTo(HaveOccurred())

				Expect(ipTables.BulkAppendCallCount()).To(Equal(7))

				table, chain, rulespec := ipTables.BulkAppendArgsForCall(4)
				Expect(table).To(Equal("filter"))
				Expect(chain).To(Equal("netout-some-container-handle"))
				Expect(rulespec).To(Equal([]rules.IPTablesRule{
					{"-m", "limit", "--limit", "3/s", "--limit-burst", "3",
						"--jump", "LOG", "--log-prefix", `"DENY_some-container-handle "`},
					{"--jump", "REJECT",
						"--reject-with", "icmp-port-unreachable"},
				}))
			})
		})

		Context("when C2C logging is enabled", func() {
			BeforeEach(func() {
				netOut.C2CLogging = true
			})
			It("writes a log rule for denies", func() {
				err := netOut.Initialize()
				Expect(err).NotTo(HaveOccurred())

				Expect(ipTables.BulkAppendCallCount()).To(Equal(7))

				table, chain, rulespec := ipTables.BulkAppendArgsForCall(5)
				Expect(table).To(Equal("filter"))
				Expect(chain).To(Equal("overlay-some-container-handle"))
				Expect(rulespec).To(Equal([]rules.IPTablesRule{
					{"-s", "5.6.7.8",
						"-o", "vtep-name",
						"-m", "mark", "!", "--mark", "0x0",
						"--jump", "ACCEPT"},
					{"-d", "5.6.7.8",
						"-m", "state", "--state", "RELATED,ESTABLISHED",
						"--jump", "ACCEPT"},
					{"-d", "5.6.7.8",
						"-m", "mark", "--mark", "0xFEEDBEEF",
						"--jump", "ACCEPT"},
					{"-d", "5.6.7.8",
						"-m", "limit", "--limit", "3/s", "--limit-burst", "3",
						"--jump", "LOG", "--log-prefix", `"DENY_C2C_some-container-hand "`},
					{"-d", "5.6.7.8",
						"--jump", "REJECT",
						"--reject-with", "icmp-port-unreachable"},
				}))
			})
		})

		Context("when dns servers are specified", func() {
			BeforeEach(func() {
				netOut.DNSServers = []string{"8.8.4.4", "1.2.3.4"}
			})

			It("creates rules for the dns servers", func() {
				err := netOut.Initialize()
				Expect(err).NotTo(HaveOccurred())
				Expect(ipTables.BulkAppendCallCount()).To(Equal(7))

				table, chain, rulespec := ipTables.BulkAppendArgsForCall(3)
				Expect(table).To(Equal("filter"))
				Expect(chain).To(Equal("input-some-container-handle"))
				Expect(rulespec).To(Equal([]rules.IPTablesRule{
					{"-m", "state", "--state", "RELATED,ESTABLISHED", "--jump", "ACCEPT"},

					{"-p", "tcp", "-d", "8.8.4.4", "--destination-port", "53", "--jump", "ACCEPT"},
					{"-p", "udp", "-d", "8.8.4.4", "--destination-port", "53", "--jump", "ACCEPT"},
					{"-p", "tcp", "-d", "1.2.3.4", "--destination-port", "53", "--jump", "ACCEPT"},
					{"-p", "udp", "-d", "1.2.3.4", "--destination-port", "53", "--jump", "ACCEPT"},

					{"--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
				}))
			})

			Context("when host TCP services are specified", func() {
				BeforeEach(func() {
					netOut.HostTCPServices = []string{"169.125.0.4:9001", "169.125.0.9:8080"}
				})
				It("creates rules for both dns servers and the host TCP services", func() {
					err := netOut.Initialize()
					Expect(err).NotTo(HaveOccurred())
					Expect(ipTables.BulkAppendCallCount()).To(Equal(7))

					table, chain, rulespec := ipTables.BulkAppendArgsForCall(3)
					Expect(table).To(Equal("filter"))
					Expect(chain).To(Equal("input-some-container-handle"))
					Expect(rulespec).To(Equal([]rules.IPTablesRule{
						{"-m", "state", "--state", "RELATED,ESTABLISHED", "--jump", "ACCEPT"},

						{"-p", "tcp", "-d", "8.8.4.4", "--destination-port", "53", "--jump", "ACCEPT"},
						{"-p", "udp", "-d", "8.8.4.4", "--destination-port", "53", "--jump", "ACCEPT"},
						{"-p", "tcp", "-d", "1.2.3.4", "--destination-port", "53", "--jump", "ACCEPT"},
						{"-p", "udp", "-d", "1.2.3.4", "--destination-port", "53", "--jump", "ACCEPT"},

						{"-p", "tcp", "-d", "169.125.0.4", "--destination-port", "9001", "--jump", "ACCEPT"},
						{"-p", "tcp", "-d", "169.125.0.9", "--destination-port", "8080", "--jump", "ACCEPT"},

						{"--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
					}))
				})
			})

			Context("when host UDP services are specified", func() {
				BeforeEach(func() {
					netOut.HostUDPServices = []string{"169.125.0.4:9001", "169.125.0.9:8080"}
				})
				It("creates rules for both dns servers and the host UDP services", func() {
					err := netOut.Initialize()
					Expect(err).NotTo(HaveOccurred())
					Expect(ipTables.BulkAppendCallCount()).To(Equal(7))

					table, chain, rulespec := ipTables.BulkAppendArgsForCall(3)
					Expect(table).To(Equal("filter"))
					Expect(chain).To(Equal("input-some-container-handle"))
					Expect(rulespec).To(Equal([]rules.IPTablesRule{
						{"-m", "state", "--state", "RELATED,ESTABLISHED", "--jump", "ACCEPT"},

						{"-p", "tcp", "-d", "8.8.4.4", "--destination-port", "53", "--jump", "ACCEPT"},
						{"-p", "udp", "-d", "8.8.4.4", "--destination-port", "53", "--jump", "ACCEPT"},
						{"-p", "tcp", "-d", "1.2.3.4", "--destination-port", "53", "--jump", "ACCEPT"},
						{"-p", "udp", "-d", "1.2.3.4", "--destination-port", "53", "--jump", "ACCEPT"},

						{"-p", "udp", "-d", "169.125.0.4", "--destination-port", "9001", "--jump", "ACCEPT"},
						{"-p", "udp", "-d", "169.125.0.9", "--destination-port", "8080", "--jump", "ACCEPT"},

						{"--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
					}))
				})
			})

			Context("when host TCP services and host UDP services are specified", func() {
				BeforeEach(func() {
					netOut.HostTCPServices = []string{"169.125.0.4:9001", "169.125.0.9:8080"}
					netOut.HostUDPServices = []string{"169.251.0.4:9001", "169.251.0.9:8080"}
				})
				It("creates rules for dns servers, the host TCP services, and the host UDP services", func() {
					err := netOut.Initialize()
					Expect(err).NotTo(HaveOccurred())
					Expect(ipTables.BulkAppendCallCount()).To(Equal(7))

					table, chain, rulespec := ipTables.BulkAppendArgsForCall(3)
					Expect(table).To(Equal("filter"))
					Expect(chain).To(Equal("input-some-container-handle"))
					Expect(rulespec).To(Equal([]rules.IPTablesRule{
						{"-m", "state", "--state", "RELATED,ESTABLISHED", "--jump", "ACCEPT"},

						{"-p", "tcp", "-d", "8.8.4.4", "--destination-port", "53", "--jump", "ACCEPT"},
						{"-p", "udp", "-d", "8.8.4.4", "--destination-port", "53", "--jump", "ACCEPT"},
						{"-p", "tcp", "-d", "1.2.3.4", "--destination-port", "53", "--jump", "ACCEPT"},
						{"-p", "udp", "-d", "1.2.3.4", "--destination-port", "53", "--jump", "ACCEPT"},

						{"-p", "tcp", "-d", "169.125.0.4", "--destination-port", "9001", "--jump", "ACCEPT"},
						{"-p", "tcp", "-d", "169.125.0.9", "--destination-port", "8080", "--jump", "ACCEPT"},

						{"-p", "udp", "-d", "169.251.0.4", "--destination-port", "9001", "--jump", "ACCEPT"},
						{"-p", "udp", "-d", "169.251.0.9", "--destination-port", "8080", "--jump", "ACCEPT"},

						{"--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
					}))
				})
			})
		})

		Context("when host TCP services are specified", func() {
			BeforeEach(func() {
				netOut.HostTCPServices = []string{"169.125.0.4:9001", "169.125.0.9:8080"}
			})

			It("creates rules for the host TCP services", func() {
				err := netOut.Initialize()
				Expect(err).NotTo(HaveOccurred())
				Expect(ipTables.BulkAppendCallCount()).To(Equal(7))

				table, chain, rulespec := ipTables.BulkAppendArgsForCall(3)
				Expect(table).To(Equal("filter"))
				Expect(chain).To(Equal("input-some-container-handle"))
				Expect(rulespec).To(Equal([]rules.IPTablesRule{
					{"-m", "state", "--state", "RELATED,ESTABLISHED", "--jump", "ACCEPT"},

					{"-p", "tcp", "-d", "169.125.0.4", "--destination-port", "9001", "--jump", "ACCEPT"},
					{"-p", "tcp", "-d", "169.125.0.9", "--destination-port", "8080", "--jump", "ACCEPT"},

					{"--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
				}))
			})

			It("returns an error for improperly formatted host TCP services", func() {
				netOut.HostTCPServices = []string{"169.125.0.123"}
				err := netOut.Initialize()
				Expect(err).To(MatchError(MatchRegexp("host tcp services.*missing port in address")))

				netOut.HostTCPServices = []string{"169.125.0.123:port"}
				err = netOut.Initialize()
				Expect(err).To(MatchError(MatchRegexp("host tcp services.*parsing")))
			})
		})

		Context("when host UDP services are specified", func() {
			BeforeEach(func() {
				netOut.HostUDPServices = []string{"169.125.0.4:9001", "169.125.0.9:8080"}
			})

			It("creates rules for the host UDP services", func() {
				err := netOut.Initialize()
				Expect(err).NotTo(HaveOccurred())
				Expect(ipTables.BulkAppendCallCount()).To(Equal(7))

				table, chain, rulespec := ipTables.BulkAppendArgsForCall(3)
				Expect(table).To(Equal("filter"))
				Expect(chain).To(Equal("input-some-container-handle"))
				Expect(rulespec).To(Equal([]rules.IPTablesRule{
					{"-m", "state", "--state", "RELATED,ESTABLISHED", "--jump", "ACCEPT"},

					{"-p", "udp", "-d", "169.125.0.4", "--destination-port", "9001", "--jump", "ACCEPT"},
					{"-p", "udp", "-d", "169.125.0.9", "--destination-port", "8080", "--jump", "ACCEPT"},

					{"--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
				}))
			})

			It("returns an error for improperly formatted host UDP services", func() {
				netOut.HostUDPServices = []string{"169.125.0.123"}
				err := netOut.Initialize()
				Expect(err).To(MatchError(MatchRegexp("host udp services.*missing port in address")))

				netOut.HostUDPServices = []string{"169.125.0.123:port"}
				err = netOut.Initialize()
				Expect(err).To(MatchError(MatchRegexp("host udp services.*parsing")))
			})
		})

		Context("when deny networks are specified", func() {
			BeforeEach(func() {
				netOut.DenyNetworks = []string{"172.16.0.0/12", "192.168.0.0/16"}
			})

			It("creates rules to deny access", func() {
				err := netOut.Initialize()
				Expect(err).NotTo(HaveOccurred())
				Expect(ipTables.BulkAppendCallCount()).To(Equal(7))

				table, chain, rulespec := ipTables.BulkAppendArgsForCall(3)
				Expect(table).To(Equal("filter"))
				Expect(chain).To(Equal("input-some-container-handle"))
				Expect(rulespec).To(Equal([]rules.IPTablesRule{
					{"-m", "state", "--state", "RELATED,ESTABLISHED", "--jump", "ACCEPT"},

					{"-d", "172.16.0.0/12", "--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
					{"-d", "192.168.0.0/16", "--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},

					{"--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
				}))
			})

			It("returns an error for an incorrectly formatted deny network", func() {
				netOut.DenyNetworks = []string{"a.b.c.d", "192.168.0.0/16"}
				err := netOut.Initialize()
				Expect(err).To(MatchError(MatchRegexp("deny networks: invalid CIDR address: a.b.c.d")))

				netOut.DenyNetworks = []string{"1.2.3.4/abc", "192.168.0.0/16"}
				err = netOut.Initialize()
				Expect(err).To(MatchError(MatchRegexp("deny networks: invalid CIDR address: 1.2.3.4/abc")))
			})

			It("returns an error for an improperly bounded deny network", func() {
				netOut.DenyNetworks = []string{"256.256.256.1024/24", "192.168.0.0/16"}
				err := netOut.Initialize()
				Expect(err).To(MatchError(MatchRegexp("deny networks: invalid CIDR address: 256.256.256.1024/24")))

				netOut.DenyNetworks = []string{"172.16.0.0/35", "192.168.0.0/16"}
				err = netOut.Initialize()
				Expect(err).To(MatchError(MatchRegexp("deny networks: invalid CIDR address: 172.16.0.0/35")))
			})

			Context("when dns servers are specified", func() {
				BeforeEach(func() {
					netOut.DNSServers = []string{"8.8.4.4", "1.2.3.4"}
				})

				It("creates rules to deny access after the dns servers", func() {
					err := netOut.Initialize()
					Expect(err).NotTo(HaveOccurred())
					Expect(ipTables.BulkAppendCallCount()).To(Equal(7))

					table, chain, rulespec := ipTables.BulkAppendArgsForCall(3)
					Expect(table).To(Equal("filter"))
					Expect(chain).To(Equal("input-some-container-handle"))
					Expect(rulespec).To(Equal([]rules.IPTablesRule{
						{"-m", "state", "--state", "RELATED,ESTABLISHED", "--jump", "ACCEPT"},

						{"-p", "tcp", "-d", "8.8.4.4", "--destination-port", "53", "--jump", "ACCEPT"},
						{"-p", "udp", "-d", "8.8.4.4", "--destination-port", "53", "--jump", "ACCEPT"},
						{"-p", "tcp", "-d", "1.2.3.4", "--destination-port", "53", "--jump", "ACCEPT"},
						{"-p", "udp", "-d", "1.2.3.4", "--destination-port", "53", "--jump", "ACCEPT"},

						{"-d", "172.16.0.0/12", "--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
						{"-d", "192.168.0.0/16", "--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},

						{"--jump", "REJECT", "--reject-with", "icmp-port-unreachable"},
					}))
				})
			})
		})
	})

	Describe("Cleanup", func() {
		It("deletes the correct jump rules from the forward chain", func() {
			err := netOut.Cleanup()
			Expect(err).NotTo(HaveOccurred())

			Expect(chainNamer.PrefixCallCount()).To(Equal(3))
			prefix, handle := chainNamer.PrefixArgsForCall(0)
			Expect(prefix).To(Equal("input"))
			Expect(handle).To(Equal("some-container-handle"))

			prefix, handle = chainNamer.PrefixArgsForCall(1)
			Expect(prefix).To(Equal("netout"))
			Expect(handle).To(Equal("some-container-handle"))

			prefix, handle = chainNamer.PrefixArgsForCall(2)
			Expect(prefix).To(Equal("overlay"))
			Expect(handle).To(Equal("some-container-handle"))

			Expect(chainNamer.PostfixCallCount()).To(Equal(1))
			body, suffix := chainNamer.PostfixArgsForCall(0)
			Expect(body).To(Equal("netout-some-container-handle"))
			Expect(suffix).To(Equal("log"))

			Expect(ipTables.DeleteCallCount()).To(Equal(4))
			table, chain, extraArgs := ipTables.DeleteArgsForCall(0)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("INPUT"))
			Expect(extraArgs).To(Equal(rules.IPTablesRule{"-s", "5.6.7.8", "--jump", "input-some-container-handle"}))

			table, chain, extraArgs = ipTables.DeleteArgsForCall(1)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("FORWARD"))
			Expect(extraArgs).To(Equal(rules.IPTablesRule{"-s", "5.6.7.8", "-o", "some-device", "--jump", "netout-some-container-handle"}))

			table, chain, extraArgs = ipTables.DeleteArgsForCall(2)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("FORWARD"))
			Expect(extraArgs).To(Equal(rules.IPTablesRule{"-s", "5.6.7.8", "-o", "eth0", "--jump", "netout-some-container-handle"}))

			table, chain, extraArgs = ipTables.DeleteArgsForCall(3)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("FORWARD"))
			Expect(extraArgs).To(Equal(rules.IPTablesRule{"--jump", "overlay-some-container-handle"}))
		})

		It("clears the container chain", func() {
			err := netOut.Cleanup()
			Expect(err).NotTo(HaveOccurred())

			Expect(ipTables.ClearChainCallCount()).To(Equal(4))
			table, chain := ipTables.ClearChainArgsForCall(0)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("input-some-container-handle"))

			table, chain = ipTables.ClearChainArgsForCall(1)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("netout-some-container-handle"))

			table, chain = ipTables.ClearChainArgsForCall(2)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("overlay-some-container-handle"))

			table, chain = ipTables.ClearChainArgsForCall(3)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("some-other-chain-name"))

		})

		It("deletes the container chain", func() {
			err := netOut.Cleanup()
			Expect(err).NotTo(HaveOccurred())

			Expect(ipTables.DeleteChainCallCount()).To(Equal(4))
			table, chain := ipTables.DeleteChainArgsForCall(0)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("input-some-container-handle"))

			table, chain = ipTables.DeleteChainArgsForCall(1)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("netout-some-container-handle"))

			table, chain = ipTables.DeleteChainArgsForCall(2)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("overlay-some-container-handle"))

			table, chain = ipTables.DeleteChainArgsForCall(3)
			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("some-other-chain-name"))

		})

		Context("when the chain namer fails", func() {
			BeforeEach(func() {
				chainNamer.PostfixReturns("", errors.New("banana"))
			})
			It("returns the error", func() {
				err := netOut.Cleanup()
				Expect(err).To(MatchError("getting chain name: banana"))
			})
		})

		Context("when deleting the jump rule fails", func() {
			BeforeEach(func() {
				ipTables.DeleteReturns(errors.New("yukon potato"))
			})
			It("returns an error", func() {
				err := netOut.Cleanup()
				Expect(err).To(MatchError(ContainSubstring("delete rule: yukon potato")))
			})
		})

		Context("when clearing the container chain fails", func() {
			BeforeEach(func() {
				ipTables.ClearChainReturns(errors.New("idaho potato"))
			})
			It("returns an error", func() {
				err := netOut.Cleanup()
				Expect(err).To(MatchError(ContainSubstring("clear chain: idaho potato")))
			})
		})

		Context("when deleting the container chain fails", func() {
			BeforeEach(func() {
				ipTables.DeleteChainReturns(errors.New("purple potato"))
			})
			It("returns an error", func() {
				err := netOut.Cleanup()
				Expect(err).To(MatchError(ContainSubstring("delete chain: purple potato")))
			})
		})

		Context("when all the steps fail", func() {
			BeforeEach(func() {
				ipTables.DeleteReturns(errors.New("yukon potato"))
				ipTables.ClearChainReturns(errors.New("idaho potato"))
				ipTables.DeleteChainReturns(errors.New("purple potato"))
			})
			It("returns all the errors", func() {
				err := netOut.Cleanup()
				Expect(err).To(MatchError(ContainSubstring("delete rule: yukon potato")))
				Expect(err).To(MatchError(ContainSubstring("clear chain: idaho potato")))
				Expect(err).To(MatchError(ContainSubstring("delete chain: purple potato")))
			})
		})
	})

	Describe("BulkInsertRules", func() {
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
			err := netOut.BulkInsertRules(netOutRules)
			Expect(err).NotTo(HaveOccurred())

			Expect(chainNamer.PrefixCallCount()).To(Equal(1))
			prefix, handle := chainNamer.PrefixArgsForCall(0)
			Expect(prefix).To(Equal("netout"))
			Expect(handle).To(Equal("some-container-handle"))

			Expect(chainNamer.PostfixCallCount()).To(Equal(1))
			body, suffix := chainNamer.PostfixArgsForCall(0)
			Expect(body).To(Equal("netout-some-container-handle"))
			Expect(suffix).To(Equal("log"))

			Expect(converter.BulkConvertCallCount()).To(Equal(1))
			convertedRules, logChainName, logging := converter.BulkConvertArgsForCall(0)
			Expect(convertedRules).To(Equal(netOutRules))
			Expect(logChainName).To(Equal("some-other-chain-name"))
			Expect(logging).To(Equal(false))

			Expect(ipTables.BulkInsertCallCount()).To(Equal(1))
			table, chain, pos, rulespec := ipTables.BulkInsertArgsForCall(0)

			Expect(table).To(Equal("filter"))
			Expect(chain).To(Equal("netout-some-container-handle"))
			Expect(pos).To(Equal(1))

			rulesWithDefaultAcceptReject := append(genericRules, []rules.IPTablesRule{
				{"-p", "tcp", "-m", "state", "--state", "INVALID", "-j", "DROP"},
				{"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
			}...)

			Expect(rulespec).To(Equal(rulesWithDefaultAcceptReject))
		})

		Context("when the chain namer fails", func() {
			BeforeEach(func() {
				chainNamer.PostfixReturns("", errors.New("banana"))
			})
			It("returns the error", func() {
				err := netOut.BulkInsertRules(netOutRules)
				Expect(err).To(MatchError("getting chain name: banana"))
			})
		})

		Context("when bulk insert fails", func() {
			BeforeEach(func() {
				ipTables.BulkInsertReturns(errors.New("potato"))
			})
			It("returns an error", func() {
				err := netOut.BulkInsertRules(netOutRules)
				Expect(err).To(MatchError("bulk inserting net-out rules: potato"))
			})
		})

		Context("when the global logging is enabled", func() {
			BeforeEach(func() {
				netOut.ASGLogging = true
			})
			It("calls BulkConvert with globalLogging set to true", func() {
				err := netOut.BulkInsertRules(netOutRules)
				Expect(err).NotTo(HaveOccurred())

				Expect(converter.BulkConvertCallCount()).To(Equal(1))
				convertedRules, logChainName, logging := converter.BulkConvertArgsForCall(0)
				Expect(convertedRules).To(Equal(netOutRules))
				Expect(logChainName).To(Equal("some-other-chain-name"))
				Expect(logging).To(Equal(true))
			})
		})
	})
})
