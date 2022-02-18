//go:build !windows
// +build !windows

package linux_test

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"code.cloudfoundry.org/vxlan-policy-agent/config"

	"code.cloudfoundry.org/cf-networking-helpers/mutualtls"
	"code.cloudfoundry.org/cf-networking-helpers/testsupport/metrics"
	"code.cloudfoundry.org/cf-networking-helpers/testsupport/ports"
	cnilib "code.cloudfoundry.org/cni-wrapper-plugin/lib"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"

	"math"

	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/grouper"
	"github.com/tedsuo/ifrit/http_server"
	"github.com/tedsuo/ifrit/sigmon"
)

var _ = Describe("VXLAN Policy Agent", func() {
	var (
		session          *gexec.Session
		datastorePath    string
		conf             config.VxlanPolicyAgent
		configFilePath   string
		fakeMetron       metrics.FakeMetron
		mockPolicyServer ifrit.Process
		serverListenPort int
		serverListenAddr string
		serverTLSConfig  *tls.Config
	)

	BeforeEach(func() {
		var err error
		fakeMetron = metrics.NewFakeMetron()

		serverTLSConfig, err = mutualtls.NewServerTLSConfig(paths.ServerCertFile, paths.ServerKeyFile, paths.ClientCACertFile)
		Expect(err).NotTo(HaveOccurred())

		serverListenPort = ports.PickAPort()
		serverListenAddr = fmt.Sprintf("127.0.0.1:%d", serverListenPort)

		containerMetadata := `{
			"some-handle": {
				"handle":"some-handle",
				"ip":"10.255.100.21",
				"metadata": {
					"policy_group_id":"some-very-very-long-app-guid",
					"space_id": "some-space",
					"ports": "8080, 9090",
					"container_workload": "app"
				}
			},
			"some-other-handle": {
				"handle":"some-other-handle",
				"ip":"10.255.100.21",
				"metadata": {
					"policy_group_id":"some-app-guid-no-ports",
					"ports": "8080, 9090"
				}
			}
		}`
		containerMetadataFile, err := ioutil.TempFile("", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(ioutil.WriteFile(containerMetadataFile.Name(), []byte(containerMetadata), os.ModePerm))
		datastorePath = containerMetadataFile.Name()

		conf = config.VxlanPolicyAgent{
			PollInterval:                  1,
			ASGPollInterval:               10,
			PolicyServerURL:               fmt.Sprintf("https://%s", serverListenAddr),
			Datastore:                     datastorePath,
			VNI:                           42,
			MetronAddress:                 fakeMetron.Address(),
			ServerCACertFile:              paths.ServerCACertFile,
			ClientCertFile:                paths.ClientCertFile,
			ClientKeyFile:                 paths.ClientKeyFile,
			IPTablesLockFile:              GlobalIPTablesLockFile,
			ForcePolicyPollCycleHost:      "127.0.0.1",
			ForcePolicyPollCyclePort:      ports.PickAPort(),
			DebugServerHost:               "127.0.0.1",
			DebugServerPort:               ports.PickAPort(),
			LogPrefix:                     "testprefix",
			ClientTimeoutSeconds:          5,
			IPTablesAcceptedUDPLogsPerSec: 7,
			EnableOverlayIngressRules:     true,
			UnderlayIPs:                   []string{"10.0.0.1"},
			IPTablesASGLogging:            false,
			IPTablesDeniedLogsPerSec:      2,
			DenyNetworks:                  cnilib.DenyNetworksConfig{},
			OutConn: cnilib.OutConnConfig{
				Burst:      900,
				RatePerSec: 100,
			},
		}

	})

	JustBeforeEach(func() {
		configFilePath = WriteConfigFile(conf)
	})

	AfterEach(func() {
		stopServer(mockPolicyServer)
		session.Interrupt()
		Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit())

		runIptablesCommandOnTable("filter", "F")
		runIptablesCommandOnTable("filter", "X")
		runIptablesCommandOnTable("nat", "F")
		runIptablesCommandOnTable("nat", "X")

		Expect(fakeMetron.Close()).To(Succeed())
	})

	setIPTablesLogging := func(enabled bool) {
		endpoint := fmt.Sprintf("http://%s:%d/iptables-c2c-logging", conf.DebugServerHost, conf.DebugServerPort)
		req, err := http.NewRequest("PUT", endpoint, strings.NewReader(fmt.Sprintf(`{ "enabled": %t }`, enabled)))
		Expect(err).NotTo(HaveOccurred())
		resp, err := http.DefaultClient.Do(req)
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()

		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		Expect(ioutil.ReadAll(resp.Body)).To(MatchJSON(fmt.Sprintf(`{ "enabled": %t }`, enabled)))
	}

	Describe("policy agent", func() {
		Context("when underlay interface can't be found", func() {
			BeforeEach(func() {
				conf.UnderlayIPs = []string{"meow"}
			})
			It("exits with an error", func() {
				session = startAgent(paths.VxlanPolicyAgentPath, configFilePath)
				Eventually(session).Should(gexec.Exit(1))
				Eventually(session.Err).Should(Say("looking up interface names:"))
			})
		})

		Context("when the policy server is up and running", func() {
			getIPTablesLogging := func() (bool, error) {
				endpoint := fmt.Sprintf("http://%s:%d/iptables-c2c-logging", conf.DebugServerHost, conf.DebugServerPort)
				resp, err := http.DefaultClient.Get(endpoint)
				if err != nil {
					return false, err
				}
				defer resp.Body.Close()
				Expect(resp.StatusCode).To(Equal(http.StatusOK))
				var respStruct struct {
					Enabled bool `json:"enabled"`
				}
				Expect(json.NewDecoder(resp.Body).Decode(&respStruct)).To(Succeed())
				return respStruct.Enabled, nil
			}

			JustBeforeEach(func() {
				mockPolicyServer = startServer(serverListenAddr, serverTLSConfig)
				session = startAgent(paths.VxlanPolicyAgentPath, configFilePath)

				Eventually(func() error {
					_, err := getIPTablesLogging()
					return err
				}, "5s").Should(Succeed()) // wait until vxlan-policy-agent debug server is up
			})

			It("should boot and gracefully terminate", func() {
				Consistently(session).ShouldNot(gexec.Exit())
				session.Interrupt()
				Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit())
			})

			Describe("the debug server", func() {
				It("has a iptables logging endpoint", func() {
					Eventually(getIPTablesLogging).Should(BeFalse())
					setIPTablesLogging(LoggingEnabled)
					Expect(getIPTablesLogging()).To(BeTrue())
				})
			})

			Describe("c2c", func() {
				Describe("the force policy poll cycle endpoint", func() {
					BeforeEach(func() {
						conf.PollInterval = math.MaxInt32
					})
					It("should cause iptables to be updated", func() {
						Eventually(func() (int, error) {
							resp, err := http.Get(fmt.Sprintf("http://%s:%d/force-policy-poll-cycle", conf.ForcePolicyPollCycleHost, conf.ForcePolicyPollCyclePort))
							if err != nil {
								return -1, err
							}
							return resp.StatusCode, nil
						}).Should(Equal(http.StatusOK))

						Eventually(iptablesFilterRules, "4s", "1s").Should(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p tcp -m iprange --dst-range 10.27.1.1-10.27.1.2 -m tcp --dport 8080:8081 -j ACCEPT`))
						Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p tcp -m iprange --dst-range 10.27.1.3-10.27.1.4 -j ACCEPT`))
						Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p tcp -m iprange --dst-range 10.27.1.3-10.27.1.4 -j ACCEPT`))
						Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p tcp -m iprange --dst-range 10.27.2.1-10.27.2.2 -j ACCEPT`))
						Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p icmp -m iprange --dst-range 10.27.1.1-10.27.1.2 -m icmp --icmp-type 3/4 -j ACCEPT`))
						Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p icmp -m iprange --dst-range 10.27.1.1-10.27.1.2 -j ACCEPT`))
						Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p icmp -m iprange --dst-range 10.27.1.1-10.27.1.2 -m icmp --icmp-type 8 -j ACCEPT`))
						Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p tcp -m iprange --dst-range 10.28.2.3-10.28.2.5 -j ACCEPT`))
					})
				})

				It("supports enabling/disabling iptables logging at runtime", func() {
					By("checking that the logging rules are absent")
					Eventually(iptablesFilterRules, "4s", "0.5s").Should(MatchRegexp(PolicyRulesRegexp(LoggingDisabled)))

					By("enabling iptables logging")
					setIPTablesLogging(LoggingEnabled)

					By("checking that the logging rules are present")
					Eventually(iptablesFilterRules, "4s", "0.5s").Should(MatchRegexp(PolicyRulesRegexp(LoggingEnabled)))

					By("disabling iptables logging")
					setIPTablesLogging(LoggingDisabled)

					By("checking that the logging rules are absent")
					Eventually(iptablesFilterRules, "4s", "0.5s").Should(MatchRegexp(PolicyRulesRegexp(LoggingDisabled)))
				})

				It("writes the mark rule and enforces policies", func() {
					Eventually(iptablesFilterRules, "4s", "1s").Should(ContainSubstring(`-s 10.255.100.21/32 -m comment --comment "src:some-very-very-long-app-guid" -j MARK --set-xmark 0xa/0xffffffff`))
					Expect(iptablesFilterRules()).To(ContainSubstring(`-d 10.255.100.21/32 -p tcp -m tcp --dport 9999 -m mark --mark 0xc -m comment --comment "src:another-app-guid_dst:some-very-very-long-app-guid" -j ACCEPT`))
					Expect(iptablesFilterRules()).To(ContainSubstring(`-d 10.255.100.21/32 -p udp -m udp --dport 7000:8000 -m mark --mark 0xd -m comment --comment "src:yet-another-app-guid_dst:some-very-very-long-app-guid" -j ACCEPT`))
				})

				It("enforces egress policies", func() {
					Eventually(iptablesFilterRules, "4s", "1s").Should(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p tcp -m iprange --dst-range 10.27.1.1-10.27.1.2 -m tcp --dport 8080:8081 -j ACCEPT`))
					Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p tcp -m iprange --dst-range 10.27.1.3-10.27.1.4 -j ACCEPT`))
					Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p icmp -m iprange --dst-range 10.27.1.1-10.27.1.2 -m icmp --icmp-type 3/4 -j ACCEPT`))
					Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p icmp -m iprange --dst-range 10.27.1.1-10.27.1.2 -j ACCEPT`))
					Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p icmp -m iprange --dst-range 10.27.1.1-10.27.1.2 -m icmp --icmp-type 8 -j ACCEPT`))
					Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p tcp -m iprange --dst-range 10.27.2.1-10.27.2.2 -j ACCEPT`))
					Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p tcp -m iprange --dst-range 10.28.2.3-10.28.2.5 -j ACCEPT`))
				})

				Context("when the container is staging", func() {
					BeforeEach(func() {
						containerMetadata := `{
						"some-handle": {
							"handle":"some-handle",
							"ip":"10.255.100.21",
							"metadata": {
								"policy_group_id":"some-very-very-long-app-guid",
								"space_id": "some-space",
								"ports": "8080, 9090",
								"container_workload": "staging"
							}
						}
					}`
						Expect(ioutil.WriteFile(datastorePath, []byte(containerMetadata), os.ModePerm))
					})

					It("enforces the egress policies for staging", func() {
						Eventually(iptablesFilterRules, "4s", "1s").Should(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p tcp -m iprange --dst-range 10.27.1.1-10.27.1.2 -m tcp --dport 8080:8081 -j ACCEPT`))
						Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p icmp -m iprange --dst-range 10.27.1.1-10.27.1.2 -j ACCEPT`))
						Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p icmp -m iprange --dst-range 10.27.1.1-10.27.1.2 -m icmp --icmp-type 8 -j ACCEPT`))
						Expect(iptablesFilterRules()).To(ContainSubstring(`-s 10.255.100.21/32 -o underlay1 -p tcp -m iprange --dst-range 1.1.1.1-2.9.9.9 -m tcp --dport 8080:8081 -j ACCEPT`))
					})
				})

				It("writes only one mark rule for a single container", func() {
					Eventually(iptablesFilterRules, "4s", "1s").Should(ContainSubstring(`-s 10.255.100.21/32 -m comment --comment "src:some-very-very-long-app-guid" -j MARK --set-xmark 0xa/0xffffffff`))
					Expect(iptablesFilterRules()).NotTo(MatchRegexp(`.*--set-xmark.*\n.*--set-xmark.*`))
				})

				Context("when 'enable_overlay_ingress_rules' is true", func() {
					It("writes an ingress allow mark rule for a container to its exposed ports", func() {
						Eventually(iptablesFilterRules, "4s", "1s").Should(ContainSubstring(`-d 10.255.100.21/32 -p tcp -m tcp --dport 8080 -m mark --mark 0x6 -j ACCEPT`))
						Eventually(iptablesFilterRules, "4s", "1s").Should(ContainSubstring(`-d 10.255.100.21/32 -p tcp -m tcp --dport 9090 -m mark --mark 0x6 -j ACCEPT`))
					})
				})

				Context("when 'enable_overlay_ingress_rules' is false", func() {
					BeforeEach(func() {
						conf.EnableOverlayIngressRules = false
					})

					It("does not write an ingress allow mark rule for a container to its exposed ports", func() {
						Consistently(iptablesFilterRules, "4s", "1s").ShouldNot(ContainSubstring(`-d 10.255.100.21/32 -p tcp -m tcp --dport 8080 -m mark --mark 0x6 -j ACCEPT`))
						Consistently(iptablesFilterRules, "4s", "1s").ShouldNot(ContainSubstring(`-d 10.255.100.21/32 -p tcp -m tcp --dport 9090 -m mark --mark 0x6 -j ACCEPT`))
					})
				})

				It("emits metrics about durations", func() {
					gatherMetricNames := func() map[string]bool {
						events := fakeMetron.AllEvents()
						metrics := map[string]bool{}
						for _, event := range events {
							metrics[event.Name] = true
						}
						return metrics
					}
					Eventually(gatherMetricNames, "5s").Should(HaveKey("iptablesEnforceTime"))
					Eventually(gatherMetricNames, "5s").Should(HaveKey("totalPollTime"))
					Eventually(gatherMetricNames, "5s").Should(HaveKey("containerMetadataTime"))
					Eventually(gatherMetricNames, "5s").Should(HaveKey("policyServerPollTime"))
				})

				It("has a log level thats configurable at runtime", func() {
					Consistently(session).ShouldNot(gexec.Exit())
					Eventually(session.Out).Should(Say("testprefix.vxlan-policy-agent"))
					Consistently(session.Out).ShouldNot(Say("got-containers"))

					endpoint := fmt.Sprintf("http://%s:%d/log-level", conf.DebugServerHost, conf.DebugServerPort)
					req, err := http.NewRequest("POST", endpoint, strings.NewReader("debug"))
					Expect(err).NotTo(HaveOccurred())
					_, err = http.DefaultClient.Do(req)
					Expect(err).NotTo(HaveOccurred())

					Eventually(session.Out, "5s").Should(Say("testprefix.vxlan-policy-agent.*got-containers"))
				})
			})

			Describe("asgs", func() {
				BeforeEach(func() {
					conf.ASGPollInterval = 1
					conf.EnableASGSyncing = true
				})

				Context("when netout chain exists", func() {
					BeforeEach(func() {
						runIptablesCommand("-N", "netout--some-handle")
					})

					It("sets rules for asgs", func() {
						Eventually(iptablesFilterRules, "4s", "1s").Should(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -m state --state RELATED,ESTABLISHED -j ACCEPT`))
						Expect(iptablesFilterRules()).To(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -p tcp -m state --state INVALID -j DROP`))
						Expect(iptablesFilterRules()).To(MatchRegexp(`-A netout--some-handle -j asg-\d+`))
						Expect(iptablesFilterRules()).To(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -p icmp -m iprange --dst-range 0.0.0.0-255.255.255.255 -m icmp --icmp-type 0/0 -j ACCEPT`))
						Expect(iptablesFilterRules()).To(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -m iprange --dst-range 11.0.0.0-169.253.255.255 -j ACCEPT`))
						Expect(iptablesFilterRules()).To(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -m iprange --dst-range 0.0.0.0-9.255.255.255 -j ACCEPT`))
						Expect(iptablesFilterRules()).To(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -j REJECT --reject-with icmp-port-unreachable`))
					})

					Context("when the container is staging", func() {
						BeforeEach(func() {
							containerMetadata := `{
							"some-handle": {
								"handle":"some-handle",
								"ip":"10.255.100.21",
								"metadata": {
									"policy_group_id":"some-very-very-long-app-guid",
									"space_id": "some-other-space",
									"ports": "8080, 9090",
									"container_workload": "staging"
								}
							}
						}`
							Expect(ioutil.WriteFile(datastorePath, []byte(containerMetadata), os.ModePerm))
							runIptablesCommand("-N", "netout--some-handle--log")
						})

						It("enforces the egress policies for staging", func() {
							Eventually(iptablesFilterRules, "4s", "1s").Should(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -p tcp -m iprange --dst-range 10.0.11.0-10.0.11.255 -m tcp --dport 443 -g netout--some-handle--log`))
							Consistently(iptablesFilterRules, "2s", "1s").Should(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -p tcp -m iprange --dst-range 10.0.11.0-10.0.11.255 -m tcp --dport 80 -g netout--some-handle--log`))
							Consistently(iptablesFilterRules, "2s", "1s").Should(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -m iprange --dst-range 11.0.0.0-169.253.255.255 -j ACCEPT`))
							Consistently(iptablesFilterRules, "2s", "1s").Should(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -m iprange --dst-range 0.0.0.0-9.255.255.255 -j ACCEPT`))
						})
					})
					Describe("the force policy poll cycle endpoint", func() {
						BeforeEach(func() {
							conf.ASGPollInterval = math.MaxInt32
						})
						It("should cause iptables to be updated", func() {
							Eventually(func() (int, error) {
								resp, err := http.Get(fmt.Sprintf("http://%s:%d/force-asgs-for-container?container=some-handle", conf.ForcePolicyPollCycleHost, conf.ForcePolicyPollCyclePort))
								if err != nil {
									return -1, err
								}
								return resp.StatusCode, nil
							}).Should(Equal(http.StatusOK))

							Eventually(iptablesFilterRules, "4s", "1s").Should(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -m state --state RELATED,ESTABLISHED -j ACCEPT`))
							Expect(iptablesFilterRules()).To(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -p tcp -m state --state INVALID -j DROP`))
							Expect(iptablesFilterRules()).To(MatchRegexp(`-A netout--some-handle -j asg-\d+`))
							Expect(iptablesFilterRules()).To(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -p icmp -m iprange --dst-range 0.0.0.0-255.255.255.255 -m icmp --icmp-type 0/0 -j ACCEPT`))
							Expect(iptablesFilterRules()).To(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -m iprange --dst-range 11.0.0.0-169.253.255.255 -j ACCEPT`))
							Expect(iptablesFilterRules()).To(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -m iprange --dst-range 0.0.0.0-9.255.255.255 -j ACCEPT`))
							Expect(iptablesFilterRules()).To(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -j REJECT --reject-with icmp-port-unreachable`))
						})
						Context("when EnableASGSyncing is disabled", func() {
							BeforeEach(func() {
								conf.EnableASGSyncing = false
							})
							It("Doesn't update iptables", func() {
								Eventually(func() (int, error) {
									resp, err := http.Get(fmt.Sprintf("http://%s:%d/force-policy-poll-cycle", conf.ForcePolicyPollCycleHost, conf.ForcePolicyPollCyclePort))
									if err != nil {
										return -1, err
									}
									return resp.StatusCode, nil
								}).Should(Equal(http.StatusOK))

								Eventually(iptablesFilterRules, "1s", "100ms").ShouldNot(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -m state --state RELATED,ESTABLISHED -j ACCEPT`))
								Expect(iptablesFilterRules()).ToNot(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -p tcp -m state --state INVALID -j DROP`))
								Expect(iptablesFilterRules()).ToNot(MatchRegexp(`-A netout--some-handle -j asg-\d+`))
								Expect(iptablesFilterRules()).ToNot(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -p icmp -m iprange --dst-range 0.0.0.0-255.255.255.255 -m icmp --icmp-type 0/0 -j ACCEPT`))
								Expect(iptablesFilterRules()).ToNot(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -m iprange --dst-range 11.0.0.0-169.253.255.255 -j ACCEPT`))
								Expect(iptablesFilterRules()).ToNot(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -m iprange --dst-range 0.0.0.0-9.255.255.255 -j ACCEPT`))
								Expect(iptablesFilterRules()).ToNot(MatchRegexp(`-A asg-[a-zA-Z0-9]+ -j REJECT --reject-with icmp-port-unreachable`))

							})
						})
					})
				})

				Context("when netout chain does not exist", func() {
					It("does not create asg chain", func() {
						Eventually(iptablesFilterRules, "4s", "1s").ShouldNot(MatchRegexp(`-N netout--some-handle`))
						Consistently(iptablesFilterRules, "2s", "1s").ShouldNot(MatchRegexp(`-A netout--some-handle -j asg-\d+`))
						Consistently(iptablesFilterRules, "2s", "1s").ShouldNot(MatchRegexp(`-A FORWARD -s \d+\.\d+\.\d+.\d+/\d+ -o eth0 -j netout--some-handle`))
					})
				})
			})
		})

		Context("when the policy server is unavailable", func() {
			JustBeforeEach(func() {
				session = startAgent(paths.VxlanPolicyAgentPath, configFilePath)
			})

			It("does not write the mark rule or enforces policies", func() {
				Expect(iptablesFilterRules()).NotTo(ContainSubstring(`-s 10.255.100.21/32 -m comment --comment "src:some-very-very-long-app-guid" -j MARK --set-xmark 0xa/0xffffffff`))
				Expect(iptablesFilterRules()).NotTo(ContainSubstring(`-d 10.255.100.21/32 -p tcp -m udp --dport 9999 -m mark --mark 0xc -m comment --comment "src:another-app-guid_dst:some-very-very-long-app-guid" -j ACCEPT`))
				Expect(iptablesFilterRules()).NotTo(ContainSubstring(`-d 10.255.100.21/32 -p udp -m tcp --dport 7000:8000 -m mark --mark 0xd -m comment --comment "src:yet-another-app-guid_dst:some-very-very-long-app-guid" -j ACCEPT`))
			})

			It("writes the mark rule or enforces policies when the policy server becomes available again", func() {
				mockPolicyServer = startServer(serverListenAddr, serverTLSConfig)
				Eventually(iptablesFilterRules, "10s", "1s").Should(ContainSubstring(`-s 10.255.100.21/32 -m comment --comment "src:some-very-very-long-app-guid" -j MARK --set-xmark 0xa/0xffffffff`))
				Expect(iptablesFilterRules()).To(ContainSubstring(`-d 10.255.100.21/32 -p tcp -m tcp --dport 9999 -m mark --mark 0xc -m comment --comment "src:another-app-guid_dst:some-very-very-long-app-guid" -j ACCEPT`))
				Expect(iptablesFilterRules()).To(ContainSubstring(`-d 10.255.100.21/32 -p udp -m udp --dport 7000:8000 -m mark --mark 0xd -m comment --comment "src:yet-another-app-guid_dst:some-very-very-long-app-guid" -j ACCEPT`))
			})
		})
		Context("when requests to the policy server time out", func() {
			BeforeEach(func() {
				conf.ClientTimeoutSeconds = 1
				mustSucceed("iptables", "-A", "INPUT", "-p", "tcp", "--dport", strconv.Itoa(serverListenPort), "-j", "DROP")
			})

			AfterEach(func() {
				mustSucceed("iptables", "-D", "INPUT", "-p", "tcp", "--dport", strconv.Itoa(serverListenPort), "-j", "DROP")
			})

			It("times out requests", func() {
				session = startAgent(paths.VxlanPolicyAgentPath, configFilePath)
				msg := "policy-client-get-policies.*context deadline exceeded \\(Client.Timeout exceeded while awaiting headers\\)"
				Eventually(session.Out, "3s").Should(Say(msg))
				session.Kill()
			})
		})
		Context("when vxlan policy agent is deployed with iptables logging enabled", func() {
			BeforeEach(func() {
				conf.IPTablesLogging = true
				Expect(conf.Validate()).To(Succeed())
			})

			JustBeforeEach(func() {
				mockPolicyServer = startServer(serverListenAddr, serverTLSConfig)
				session = startAgent(paths.VxlanPolicyAgentPath, configFilePath)
			})

			It("supports enabling/disabling iptables logging at runtime", func() {
				Consistently(session).ShouldNot(gexec.Exit())

				By("checking that the logging rules are present")
				Eventually(iptablesFilterRules, "2s", "0.5s").Should(MatchRegexp(PolicyRulesRegexp(LoggingEnabled)))

				By("disabling iptables logging")
				setIPTablesLogging(LoggingDisabled)

				By("checking that the logging rules are absent")
				Eventually(iptablesFilterRules, "2s", "0.5s").Should(MatchRegexp(PolicyRulesRegexp(LoggingDisabled)))

				By("enabling iptables logging")
				setIPTablesLogging(LoggingEnabled)

				By("checking that the logging rules are present")
				Eventually(iptablesFilterRules, "2s", "0.5s").Should(MatchRegexp(PolicyRulesRegexp(LoggingEnabled)))
			})
		})
	})

	Describe("errors", func() {
		Context("when the vxlan policy agent cannot connect to the server upon start", func() {
			BeforeEach(func() {
				conf.PolicyServerURL = "some-bad-url"
			})

			JustBeforeEach(func() {
				session = startAgent(paths.VxlanPolicyAgentPath, configFilePath)
			})

			It("crashes and logs a useful error message", func() {
				Eventually(session).Should(gexec.Exit())
				Expect(string(session.Out.Contents())).To(MatchRegexp("policy-client-get-policies.*http client do.*unsupported protocol scheme"))
			})
		})

		Context("when vxlan policy agent has invalid certs", func() {
			BeforeEach(func() {
				conf.ClientCertFile = "totally"
				conf.ClientKeyFile = "not-cool"
			})

			It("does not start", func() {
				session = startAgent(paths.VxlanPolicyAgentPath, configFilePath)
				Eventually(session).Should(gexec.Exit(1))
				Eventually(session.Out).Should(Say("unable to load cert or key"))
			})
		})

		Context("when the config file is invalid", func() {
			BeforeEach(func() {
				conf.PollInterval = 0
			})

			It("crashes and logs a useful error message", func() {
				session = startAgent(paths.VxlanPolicyAgentPath, configFilePath)
				Eventually(session).Should(gexec.Exit(1))
				Eventually(session.Err).Should(Say("cfnetworking: could not read config file"))
			})
		})

		Context("when datastore directory does not exist", func() {
			BeforeEach(func() {
				conf.Datastore = "/garbage/path"
			})

			JustBeforeEach(func() {
				session = startAgent(paths.VxlanPolicyAgentPath, configFilePath)
			})

			It("does not start", func() {
				Eventually(session).Should(gexec.Exit())
				Expect(string(session.Out.Contents())).To(MatchRegexp("datastore-directory-stat"))
			})
		})
	})
})

func mustSucceed(binary string, args ...string) string {
	cmd := exec.Command(binary, args...)
	sess, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, DEFAULT_TIMEOUT).Should(gexec.Exit(0))
	return string(sess.Out.Contents())
}

func iptablesFilterRules() string {
	return runIptablesCommandOnTable("filter", "S")
}

func iptablesNATRules() string {
	return runIptablesCommandOnTable("nat", "S")
}

func runIptablesCommandOnTable(table, flag string) string {
	return runIptablesCommand("-w", "-t", table, "-"+flag)
}

func runIptablesCommand(args ...string) string {
	iptCmd := exec.Command("iptables", args...)
	iptablesSession, err := gexec.Start(iptCmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(iptablesSession, DEFAULT_TIMEOUT).Should(gexec.Exit(0))
	return string(iptablesSession.Out.Contents())
}

func startAgent(binaryPath, configPath string) *gexec.Session {
	cmd := exec.Command(binaryPath, "-config-file", configPath)
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	return session
}

func startServer(serverListenAddr string, tlsConfig *tls.Config) ifrit.Process {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/networking/v1/internal/policies" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"total_policies": 4,
				"policies": [
					{
						"source": {"id":"some-very-very-long-app-guid", "tag":"A"},
						"destination": {"id": "some-other-app-guid", "tag":"B", "protocol":"tcp", "ports":{"start":3333, "end":3333}}
					},
					{
						"source": {"id":"some-very-very-long-app-guid", "tag":"A"},
						"destination": {"id": "some-other-app-guid", "tag":"B", "protocol":"tcp", "ports":{"start":3334, "end":3334}}
					},
					{
						"source": {"id":"another-app-guid", "tag":"C"},
						"destination": {"id": "some-very-very-long-app-guid", "tag":"A", "protocol":"tcp", "ports":{"start":9999, "end":9999}}
					},
					{
						"source": {"id":"yet-another-app-guid", "tag":"D"},
						"destination": {"id": "some-very-very-long-app-guid", "tag":"A", "protocol":"udp", "ports":{"start":7000, "end":8000}}
					}
				],
				"total_egress_policies": 7,
				"egress_policies": [
					{
						"source": {"id": "some-space", "type": "space" },
						"destination": {"ips": [{"start": "10.27.2.1", "end": "10.27.2.2"}], "protocol": "tcp"},
						"app_lifecycle": "running"
					},
					{
						"source": {"id": "some-very-very-long-app-guid" },
						"destination": {"ips": [{"start": "10.27.1.1", "end": "10.27.1.2"}], "protocol": "icmp", "icmp_type": 3, "icmp_code": 4},
						"app_lifecycle": "running"
					},
					{
						"source": {"id": "some-very-very-long-app-guid" },
						"destination": {"ips": [{"start": "1.1.1.1", "end": "2.9.9.9"}], "ports": [{"start": 8080, "end": 8081}], "protocol": "tcp"},
						"app_lifecycle": "staging"
					},
					{
						"source": {"id": "some-very-very-long-app-guid" },
						"destination": {"ips": [{"start": "10.27.1.1", "end": "10.27.1.2"}], "protocol": "icmp", "icmp_type": -1, "icmp_code": -1},
						"app_lifecycle": "all"
					},
					{
						"source": {"id": "some-very-very-long-app-guid" },
						"destination": {"ips": [{"start": "10.27.1.1", "end": "10.27.1.2"}], "protocol": "icmp", "icmp_type": 8, "icmp_code": -1},
						"app_lifecycle": "all"
					},
					{
						"source": {"id": "some-very-very-long-app-guid" },
						"destination": {"ips": [{"start": "10.27.1.1", "end": "10.27.1.2"}], "ports": [{"start": 8080, "end": 8081}], "protocol": "tcp"},
						"app_lifecycle": "all"
					},
					{
						"source": {"id": "some-app-guid-no-ports" },
						"destination": {"ips": [{"start": "10.27.1.3", "end": "10.27.1.4"}], "protocol": "tcp"},
						"app_lifecycle": "all"
					},
					{
						"source": {"id": "not-deployed-on-this-cell-why-did-you-query-for-this-id" },
						"destination": {"ips": [{"start": "10.27.2.3", "end": "10.27.2.5"}], "protocol": "udp"},
						"app_lifecycle": "all"
					},
					{
						"source": {"id": "", "type": "default" },
						"destination": {"ips": [{"start": "10.28.2.3", "end": "10.28.2.5"}], "protocol": "tcp"},
						"app_lifecycle": "all"
					}
				]
			}`))
			return
		}

		if r.URL.Path == "/networking/v1/internal/tags" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte((`{
					"id": "some-id",
					"type": "some-type",
					"tag": "6"
				}`)))
			return
		}

		if r.URL.Path == "/networking/v1/internal/security_groups" {
			w.WriteHeader(http.StatusOK)
			from, ok := r.URL.Query()["from"]
			if ok && from[0] == "2" {
				w.Write([]byte((`{
				  "next": 0,
				  "security_groups": [
					{
					  "guid": "sg-2-guid",
					  "name": "security-group-2",
					  "rules": "[{\"protocol\":\"tcp\",\"destination\":\"10.0.11.0/24\",\"ports\":\"80,443\",\"type\":0,\"code\":0,\"description\":\"Allow http and https traffic to ZoneA\",\"log\":true}]",
					  "staging_default": false,
					  "running_default": false,
					  "staging_space_guids": [
						"some-other-space"
					  ],
					  "running_space_guids": []
					}
				  ]
				}`)))

			} else {
				w.Write([]byte((`{
				  "next": 2,
				  "security_groups": [
					{
					  "guid": "public-asg-guid",
					  "name": "public_networks",
					  "rules": "[{\"protocol\":\"all\",\"destination\":\"0.0.0.0-9.255.255.255\",\"ports\":\"\",\"type\":0,\"code\":0,\"description\":\"\",\"log\":false},{\"protocol\":\"all\",\"destination\":\"11.0.0.0-169.253.255.255\",\"ports\":\"\",\"type\":0,\"code\":0,\"description\":\"\",\"log\":false}]",
					  "staging_default": true,
					  "running_default": true,
					  "staging_space_guids": [],
					  "running_space_guids": []
					},
					{
					  "guid": "sg-1-guid",
					  "name": "security-group-1",
					  "rules": "[{\"protocol\":\"icmp\",\"destination\":\"0.0.0.0/0\",\"ports\":\"\",\"type\":0,\"code\":0,\"description\":\"\",\"log\":false}]",
					  "staging_default": false,
					  "running_default": false,
					  "staging_space_guids": [],
					  "running_space_guids": [
						"some-space"
					  ]
					}
				  ]
				}`)))
			}
			return
		}

		w.WriteHeader(http.StatusNotFound)
		return
	})
	someServer := http_server.NewTLSServer(serverListenAddr, testHandler, tlsConfig)

	members := grouper.Members{{
		Name:   "http_server",
		Runner: someServer,
	}}
	group := grouper.NewOrdered(os.Interrupt, members)
	monitor := ifrit.Invoke(sigmon.New(group))

	Eventually(monitor.Ready()).Should(BeClosed())
	return monitor
}

func stopServer(server ifrit.Process) {
	if server == nil {
		return
	}
	server.Signal(os.Interrupt)
	Eventually(server.Wait()).Should(Receive())
}

const (
	LoggingDisabled = false
	LoggingEnabled  = true
)

func PolicyRulesRegexp(loggingEnabled bool) string {
	policyRules := ""
	if loggingEnabled {
		policyRules += `-A vpa--[0-9]+ -d 10.255.100.21/32 -p udp -m udp --dport 7000:8000 -m mark --mark 0xd -m limit --limit 7/sec --limit-burst 7 -j LOG --log-prefix "OK_D_some-very-very-long-app "\n`
	}
	policyRules += `-A vpa--[0-9]+ -d 10.255.100.21/32 -p udp -m udp --dport 7000:8000 -m mark --mark 0xd -m comment --comment "src:yet-another-app-guid_dst:some-very-very-long-app-guid" -j ACCEPT\n`
	if loggingEnabled {
		policyRules += `.*-A vpa--[0-9]+ -d 10.255.100.21/32 -p tcp -m tcp --dport 9999 -m mark --mark 0xc -m conntrack --ctstate INVALID,NEW,UNTRACKED -j LOG --log-prefix "OK_C_some-very-very-long-app "\n`
	}
	policyRules += `-A vpa--[0-9]+ -d 10.255.100.21/32 -p tcp -m tcp --dport 9999 -m mark --mark 0xc -m comment --comment "src:another-app-guid_dst:some-very-very-long-app-guid" -j ACCEPT`
	return policyRules
}
