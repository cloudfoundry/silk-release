package main_test

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"code.cloudfoundry.org/cni-wrapper-plugin/lib"

	"code.cloudfoundry.org/garden"

	"net/http"
	"syscall"

	"code.cloudfoundry.org/cf-networking-helpers/testsupport/ports"
	noop_debug "github.com/containernetworking/cni/plugins/test/noop/debug"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/pivotal-cf-experimental/gomegamatchers"
	"github.com/vishvananda/netlink"
)

type InputStruct struct {
	Name       string                 `json:"name"`
	CNIVersion string                 `json:"cniVersion"`
	Type       string                 `json:"type"`
	Delegate   map[string]interface{} `json:"delegate"`
	Metadata   map[string]interface{} `json:"metadata"`
	lib.WrapperConfig
}

const (
	UnprivilegedUserId  = uint32(65534)
	UnprivilegedGroupId = uint32(65534)
)

// Always run serially, this is setup in the test.sh file
// Test writes to disk and modifies iptables
var _ = Describe("CniWrapperPlugin", func() {

	var (
		cmd                    *exec.Cmd
		debugFileName          string
		datastorePath          string
		iptablesLockFilePath   string
		input                  string
		debug                  *noop_debug.Debug
		inputStruct            InputStruct
		containerID            string
		netinChainName         string
		netoutChainName        string
		inputChainName         string
		overlayChainName       string
		netoutLoggingChainName string
		underlayName1          string
		underlayName2          string
		underlayIpAddr1        string
		underlayIpAddr2        string
		policyAgentAddress     string
		policyAgentServer      mockPolicyAgentServer
	)

	var cniCommand = func(command, input string) *exec.Cmd {
		toReturn := exec.Command(paths.PathToPlugin)
		toReturn.Env = []string{
			"CNI_COMMAND=" + command,
			"CNI_CONTAINERID=" + containerID,
			"CNI_NETNS=/some/netns/path",
			"CNI_IFNAME=some-eth0",
			"CNI_PATH=" + paths.CNIPath,
			"CNI_ARGS=DEBUG=" + debugFileName,
			"PATH=/sbin",
		}
		toReturn.Stdin = strings.NewReader(input)

		return toReturn
	}

	AllIPTablesRules := func(tableName string) []string {
		iptablesSession, err := gexec.Start(exec.Command("iptables", "-w", "-S", "-t", tableName), GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		Eventually(iptablesSession).Should(gexec.Exit(0))
		return strings.Split(string(iptablesSession.Out.Contents()), "\n")
	}

	GetInput := func(i InputStruct) string {
		inputBytes, err := json.Marshal(i)
		Expect(err).NotTo(HaveOccurred())
		return string(inputBytes)
	}

	BeforeEach(func() {
		// iptables 1.8+ takes longer to finish so the 1 second timeout is no longer sufficient
		SetDefaultEventuallyTimeout(3 * time.Second)

		underlayName1 = fmt.Sprintf("u-%x", rand.Int31())
		underlayIpAddr1 = "169.254.169.253"

		underlayName2 = fmt.Sprintf("u-%x", rand.Int31())
		underlayIpAddr2 = "169.254.169.254"

		createDummyInterface(underlayName1, underlayIpAddr1)
		createDummyInterface(underlayName2, underlayIpAddr2)

		debugFile, err := os.CreateTemp("", "cni_debug")
		Expect(err).NotTo(HaveOccurred())
		Expect(debugFile.Close()).To(Succeed())
		debugFileName = debugFile.Name()

		debug = &noop_debug.Debug{
			ReportResult:         `{ "cniVersion": "1.0.0", "ips": [{ "interface": -1, "address": "1.2.3.4/32" }]}`,
			ReportVersionSupport: []string{"1.0.0"},
		}
		Expect(debug.WriteDebug(debugFileName)).To(Succeed())

		tmpDir, err := os.MkdirTemp("", "cni-wrapper-integration")
		Expect(err).NotTo(HaveOccurred())
		datastoreFile, err := os.CreateTemp(tmpDir, "datastore")
		Expect(err).NotTo(HaveOccurred())
		Expect(datastoreFile.Close()).To(Succeed())
		datastorePath = datastoreFile.Name()

		iptablesLockFile, err := os.CreateTemp(tmpDir, "iptables-lock")
		Expect(err).NotTo(HaveOccurred())
		Expect(iptablesLockFile.Close()).To(Succeed())
		iptablesLockFilePath = iptablesLockFile.Name()

		policyAgentAddress = fmt.Sprintf("%s:%v", "127.0.0.1", ports.PickAPort())
		policyAgentServer = mockPolicyAgentServer{
			ReturnCode:                            200,
			ASGReturnCode:                         405,
			ASGReturnErrorMessage:                 "",
			ReturnErrorMessage:                    "",
			Address:                               policyAgentAddress,
			CleanupOrphanedASGsReturnCode:         200,
			CleanupOrphanedASGsReturnErrorMessage: "",
		}
		policyAgentServer.start()

		var code garden.ICMPCode = 0
		inputStruct = InputStruct{
			Name:       "cni-wrapper",
			CNIVersion: "1.0.0",
			Type:       "wrapper",
			Delegate: map[string]interface{}{
				"type":       "noop",
				"some":       "other data",
				"name":       "name",
				"cniVersion": "1.0.0",
			},
			Metadata: map[string]interface{}{
				"key1": "value1",
				"key2": []string{"some", "data"},
			},
			WrapperConfig: lib.WrapperConfig{
				DatastoreFileOwner: "nobody",
				DatastoreFileGroup: "nogroup",
				Datastore:          datastorePath,
				IPTablesLockFile:   iptablesLockFilePath,
				Delegate: map[string]interface{}{
					"type":       "noop",
					"some":       "other data",
					"cniVersion": "1.0.0",
				},
				InstanceAddress:               "10.244.2.3",
				IPTablesASGLogging:            false,
				IngressTag:                    "FFFF0000",
				VTEPName:                      "some-device",
				NoMasqueradeCIDRRange:         "10.255.0.0/16",
				UnderlayIPs:                   []string{underlayIpAddr1, underlayIpAddr2},
				IPTablesDeniedLogsPerSec:      5,
				IPTablesAcceptedUDPLogsPerSec: 7,
				PolicyAgentForcePollAddress:   policyAgentAddress,
				RuntimeConfig: lib.RuntimeConfig{
					PortMappings: []garden.NetIn{
						{
							HostPort:      1000,
							ContainerPort: 1001,
						},
						{
							HostPort:      2000,
							ContainerPort: 2001,
						},
					},
					NetOutRules: []garden.NetOutRule{
						{
							Protocol: garden.ProtocolAll,
							Networks: []garden.IPRange{
								{
									Start: net.ParseIP("3.3.3.3"),
									End:   net.ParseIP("4.4.4.4"),
								},
							},
						},
						{
							Protocol: garden.ProtocolTCP,
							Networks: []garden.IPRange{
								{
									Start: net.ParseIP("8.8.8.8"),
									End:   net.ParseIP("9.9.9.9"),
								},
							},
							Ports: []garden.PortRange{
								{
									Start: 53,
									End:   54,
								},
							},
						},
						{
							Protocol: garden.ProtocolUDP,
							Networks: []garden.IPRange{
								{
									Start: net.ParseIP("11.11.11.11"),
									End:   net.ParseIP("22.22.22.22"),
								},
							},
							Ports: []garden.PortRange{
								{
									Start: 53,
									End:   54,
								},
							},
						},
						{
							Protocol: garden.ProtocolICMP,
							Networks: []garden.IPRange{
								{
									Start: net.ParseIP("5.5.5.5"),
									End:   net.ParseIP("6.6.6.6"),
								},
							},
							ICMPs: &garden.ICMPControl{
								Type: 8,
								Code: &code,
							},
						},
					},
				},
				OutConn: lib.OutConnConfig{
					Limit:      false,
					Burst:      999,
					RatePerSec: 100,
				},
			},
		}

		input = GetInput(inputStruct)

		containerID = "some-container-id-that-is-long"
		netinChainName = ("netin--" + containerID)[:28]
		netoutChainName = ("netout--" + containerID)[:28]
		inputChainName = ("input--" + containerID)[:28]
		overlayChainName = ("overlay--" + containerID)[:28]
		netoutLoggingChainName = fmt.Sprintf("%s--log", netoutChainName[:23])

		cmd = cniCommand("ADD", input)
	})

	AfterEach(func() {
		By("Deleting things")
		cmd := cniCommand("DEL", input)
		session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		Eventually(session, "5s").Should(gexec.Exit(0))

		By("checking that ip masquerade rule is removed")
		Expect(AllIPTablesRules("nat")).ToNot(ContainElement("-A POSTROUTING -s 1.2.3.4/32 ! -d 10.255.0.0/16 ! -o some-device -j MASQUERADE"))

		By("checking that iptables netin rules are removed")
		Expect(AllIPTablesRules("nat")).ToNot(ContainElement(`-N ` + netinChainName))
		Expect(AllIPTablesRules("nat")).ToNot(ContainElement(`-A PREROUTING -j ` + netinChainName))
		Expect(AllIPTablesRules("mangle")).ToNot(ContainElement(`-N ` + netinChainName))
		Expect(AllIPTablesRules("mangle")).ToNot(ContainElement(`-A PREROUTING -j ` + netinChainName))

		By("checking that all port forwarding rules were removed from the netin chain")
		Expect(AllIPTablesRules("nat")).ToNot(ContainElement(ContainSubstring(netinChainName)))
		Expect(AllIPTablesRules("nat")).ToNot(ContainElement(ContainSubstring(netinChainName)))

		By("checking that all mark rules were removed from the netin chain")
		Expect(AllIPTablesRules("mangle")).ToNot(ContainElement(ContainSubstring(netinChainName)))

		By("checking that there are no more netout rules for this container")
		Expect(AllIPTablesRules("filter")).ToNot(ContainElement(ContainSubstring(inputChainName)))
		Expect(AllIPTablesRules("filter")).ToNot(ContainElement(ContainSubstring(netoutChainName)))
		Expect(AllIPTablesRules("filter")).ToNot(ContainElement(ContainSubstring(netoutLoggingChainName)))

		By("checking that there are no more overlay rules for this container")
		Expect(AllIPTablesRules("filter")).ToNot(ContainElement(ContainSubstring(overlayChainName)))

		os.Remove(debugFileName)
		os.Remove(datastorePath)
		os.Remove(iptablesLockFilePath)

		removeDummyInterface(underlayName1, underlayIpAddr1)
		removeDummyInterface(underlayName2, underlayIpAddr2)

		err = policyAgentServer.stop()
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("state lifecycle", func() {
		It("stores and removes metadata with the lifetime of the container", func() {
			By("calling ADD")
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			By("check that metadata is stored")
			stateFileBytes, err := os.ReadFile(datastorePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(stateFileBytes)).To(ContainSubstring("1.2.3.4"))
			Expect(string(stateFileBytes)).To(ContainSubstring("value1"))

			By("calling DEL")
			cmd = cniCommand("DEL", input)
			session, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			By("check that metadata is has been removed")
			stateFileBytes, err = os.ReadFile(datastorePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(stateFileBytes)).NotTo(ContainSubstring("1.2.3.4"))
			Expect(string(stateFileBytes)).NotTo(ContainSubstring("value1"))
		})
	})

	Describe("iptables lifecycle", func() {
		It("adds and removes ip masquerade rules with the lifetime of the container", func() {
			By("calling ADD")
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			By("check that ip masquerade rule is created")
			Expect(AllIPTablesRules("nat")).To(ContainElement("-A POSTROUTING -s 1.2.3.4/32 ! -d 10.255.0.0/16 ! -o some-device -j MASQUERADE"))

			By("calling DEL")
			cmd = cniCommand("DEL", input)
			session, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			By("check that ip masquerade rule is removed")
			Expect(AllIPTablesRules("nat")).NotTo(ContainElement("-A POSTROUTING -s 1.2.3.4/32 ! -d 10.255.0.0/16 ! -o some-device -j MASQUERADE"))
		})
	})

	Context("When call with command ADD", func() {
		It("passes the delegate result back to the caller", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))
			Expect(session.Out.Contents()).To(MatchJSON(`{ "cniVersion": "1.0.0", "ips": [{ "interface": -1, "address": "1.2.3.4/32" }], "dns":{} }`))
		})

		It("passes the correct stdin to the delegate plugin", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			debug, err := noop_debug.ReadDebug(debugFileName)
			Expect(err).NotTo(HaveOccurred())
			Expect(debug.Command).To(Equal("ADD"))

			Expect(debug.CmdArgs.StdinData).To(MatchJSON(`{
						"cniVersion": "1.0.0",
						"type": "noop",
						"some": "other data",
						"name": "name"
					}`))
		})

		It("ensures the container masquerade rule is created", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))
			Expect(session.Out.Contents()).To(MatchJSON(`{ "cniVersion": "1.0.0", "ips": [{ "interface": -1, "address": "1.2.3.4/32" }], "dns":{} }`))
			Expect(AllIPTablesRules("nat")).To(ContainElement("-A POSTROUTING -s 1.2.3.4/32 ! -d 10.255.0.0/16 ! -o some-device -j MASQUERADE"))
		})

		It("writes default deny input chain rules to prevent connecting to things on the host", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			By("checking that the input chain jumps to the container's input chain")
			Expect(AllIPTablesRules("filter")).To(ContainElement("-A INPUT -s 1.2.3.4/32 -j " + inputChainName))

			By("checking that the default deny rules in the container's input chain are created")
			Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
				"-A " + inputChainName + " -m state --state RELATED,ESTABLISHED -j ACCEPT",
				"-A " + inputChainName + " -j REJECT --reject-with icmp-port-unreachable",
			}))
		})

		It("writes default deny forward chain rules to prevent ingress, but allows specially marked packets", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			By("checking that the forward chain jumps to the container's overlay chain")
			Expect(AllIPTablesRules("filter")).To(ContainElement("-A FORWARD -j " + overlayChainName))

			By("checking that the default rules in the container's overlay chain are created")
			Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
				"-A " + overlayChainName + " -s 1.2.3.4/32 -o some-device -m mark ! --mark 0x0 -j ACCEPT",
				"-A " + overlayChainName + " -d 1.2.3.4/32 -m state --state RELATED,ESTABLISHED -j ACCEPT",
				"-A " + overlayChainName + " -d 1.2.3.4/32 -m mark --mark 0xffff0000 -j ACCEPT",
				"-A " + overlayChainName + " -d 1.2.3.4/32 -j REJECT --reject-with icmp-port-unreachable",
			}))
		})

		It("calls the policy agent poller", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			Expect(policyAgentServer.PolicyPollEndpointCallCount).To(Equal(1))
		})

		It("calls the policy agent asg updater", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))
			Expect(policyAgentServer.SyncASGEndpointCallCount).To(Equal(1))
			Expect(policyAgentServer.SyncASGEndpointContainerRequested).To(Equal("some-container-id-that-is-long"))
		})

		It("ensures the iptables.lock file is chowned", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			fileInfo, err := os.Stat(iptablesLockFilePath)
			Expect(err).NotTo(HaveOccurred())

			statInfo, ok := fileInfo.Sys().(*syscall.Stat_t)
			Expect(ok).To(BeTrue(), "unable to get the stat_t struct")

			Expect(statInfo.Uid).To(Equal(UnprivilegedUserId))
			Expect(statInfo.Gid).To(Equal(UnprivilegedGroupId))
		})

		Context("when the policy agent poller returns an error", func() {
			It("returns an error", func() {
				policyAgentServer.ReturnCode = 500
				policyAgentServer.ReturnErrorMessage = "an error occurred in the vpa"

				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))
				Expect(session.Out).Should(gbytes.Say(".*vpa response code: 500 with message: an error occurred in the vpa.*"))

				Expect(policyAgentServer.PolicyPollEndpointCallCount).To(Equal(1))
			})
		})
		Context("when the policy agent asg updater returns a 405", func() {
			It("ignores and moves on, since dynamic asgs have been disabled", func() {
				policyAgentServer.ASGReturnCode = 405
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))
				Expect(policyAgentServer.SyncASGEndpointCallCount).To(Equal(1))
				Expect(policyAgentServer.SyncASGEndpointContainerRequested).To(Equal("some-container-id-that-is-long"))
			})
		})

		Context("when the policy agent asg updater returns 200 (Dynamic ASGs enabled)", func() {
			It("does not add additional iptables rules to the netout-chain", func() {
				policyAgentServer.ASGReturnCode = 200
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))
				Expect(policyAgentServer.SyncASGEndpointCallCount).To(Equal(1))
				Expect(policyAgentServer.SyncASGEndpointContainerRequested).To(Equal("some-container-id-that-is-long"))
				Expect(strings.Join(AllIPTablesRules("filter"), "\n")).ToNot(ContainSubstring("11.11.11.11-22.22.22.22"))
			})
		})
		Context("when the policy agent asg updater returns 405 (Dynamic ASGs disabled)", func() {
			It("adds additional iptables rules to the netout-chain", func() {
				policyAgentServer.ASGReturnCode = 405
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))
				Expect(policyAgentServer.SyncASGEndpointCallCount).To(Equal(1))
				Expect(policyAgentServer.SyncASGEndpointContainerRequested).To(Equal("some-container-id-that-is-long"))
				Expect(strings.Join(AllIPTablesRules("filter"), "\n")).To(ContainSubstring("11.11.11.11-22.22.22.22"))
			})
		})

		Context("when the policy agent asg updater returns an error", func() {
			It("returns an error", func() {
				policyAgentServer.ASGReturnCode = 500
				policyAgentServer.ASGReturnErrorMessage = "an error occurred in the vpa"

				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))
				Expect(session.Out).Should(gbytes.Say(".*asg sync returned 500 with message: an error occurred in the vpa.*"))

				Expect(policyAgentServer.PolicyPollEndpointCallCount).To(Equal(1))
			})
		})

		Context("when an iptables rule is already present on the INPUT chain", func() {
			BeforeEach(func() {
				iptablesSession, err := gexec.Start(exec.Command("iptables", "-I", "INPUT", "1", "--destination", "127.0.0.1", "-j", "ACCEPT"), GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(iptablesSession).Should(gexec.Exit(0))
			})
			AfterEach(func() {
				iptablesSession, err := gexec.Start(exec.Command("iptables", "-D", "INPUT", "--destination", "127.0.0.1", "-j", "ACCEPT"), GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(iptablesSession).Should(gexec.Exit(0))
			})
			It("appends to the INPUT chain", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				By("checking that the container's input chain comes after the already present iptables rule")
				Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
					"-A INPUT -d 127.0.0.1/32 -j ACCEPT",
					"-A INPUT -s 1.2.3.4/32 -j " + inputChainName,
				}))
			})
		})

		Context("when DNS servers are configured", func() {
			BeforeEach(func() {
				inputStruct.DNSServers = []string{"169.254.0.1", "8.8.4.4", "169.254.0.2"}
				input = GetInput(inputStruct)

				cmd = cniCommand("ADD", input)
			})
			It("returns DNS info in the output", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				By("returning all DNS servers")
				Expect(session.Out.Contents()).To(MatchJSON(`{
						"cniVersion": "1.0.0",
						"ips": [{ "interface": -1, "address": "1.2.3.4/32" }],
						"dns": {"nameservers": ["169.254.0.1", "8.8.4.4", "169.254.0.2"]}
					}`))
			})

			It("writes input chain rules for local DNS servers", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				By("checking that the rules in the container's input chain are created for each local dns server")
				Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
					"-A " + inputChainName + " -m state --state RELATED,ESTABLISHED -j ACCEPT",
					"-A " + inputChainName + " -d 169.254.0.1/32 -p tcp -m tcp --dport 53 -j ACCEPT",
					"-A " + inputChainName + " -d 169.254.0.1/32 -p udp -m udp --dport 53 -j ACCEPT",
					"-A " + inputChainName + " -d 169.254.0.2/32 -p tcp -m tcp --dport 53 -j ACCEPT",
					"-A " + inputChainName + " -d 169.254.0.2/32 -p udp -m udp --dport 53 -j ACCEPT",
					"-A " + inputChainName + " -j REJECT --reject-with icmp-port-unreachable",
				}))

				By("checking that no rules are created for public dns servers")
				Expect(AllIPTablesRules("filter")).NotTo(ContainElement(
					"-A " + inputChainName + " -d 8.8.4.4/32 -p tcp -m tcp --dport 53 -j ACCEPT",
				))
				Expect(AllIPTablesRules("filter")).NotTo(ContainElement(
					"-A " + inputChainName + " -d 8.8.4.4/32 -p udp -m udp --dport 53 -j ACCEPT",
				))
			})
		})

		Context("when some of the DNS servers are not valid IPs", func() {
			BeforeEach(func() {
				inputStruct.DNSServers = []string{"1.2.3.4", "banana"}
				input = GetInput(inputStruct)

				cmd = cniCommand("ADD", input)
			})
			It("returns an error", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))

				var errData map[string]interface{}
				Expect(json.Unmarshal(session.Out.Contents(), &errData)).To(Succeed())
				Expect(errData["code"]).To(BeEquivalentTo(999))
				Expect(errData["msg"]).To(ContainSubstring(`invalid DNS server "banana", must be valid IP address`))
			})
		})

		Context("when host TCP services are configured", func() {
			BeforeEach(func() {
				inputStruct.HostTCPServices = []string{"169.254.0.5:9001", "169.254.0.8:8080"}
				input = GetInput(inputStruct)

				cmd = cniCommand("ADD", input)
			})
			It("writes input chain rules for host TCP services", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
					"-A " + inputChainName + " -m state --state RELATED,ESTABLISHED -j ACCEPT",
					"-A " + inputChainName + " -d 169.254.0.5/32 -p tcp -m tcp --dport 9001 -j ACCEPT",
					"-A " + inputChainName + " -d 169.254.0.8/32 -p tcp -m tcp --dport 8080 -j ACCEPT",
					"-A " + inputChainName + " -j REJECT --reject-with icmp-port-unreachable",
				}))
			})
		})

		Context("when host UDP services are configured", func() {
			BeforeEach(func() {
				inputStruct.HostUDPServices = []string{"169.254.0.5:9001", "169.254.0.8:8080"}
				input = GetInput(inputStruct)

				cmd = cniCommand("ADD", input)
			})
			It("writes input chain rules for host UDP services", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
					"-A " + inputChainName + " -m state --state RELATED,ESTABLISHED -j ACCEPT",
					"-A " + inputChainName + " -d 169.254.0.5/32 -p udp -m udp --dport 9001 -j ACCEPT",
					"-A " + inputChainName + " -d 169.254.0.8/32 -p udp -m udp --dport 8080 -j ACCEPT",
					"-A " + inputChainName + " -j REJECT --reject-with icmp-port-unreachable",
				}))
			})
		})

		Context("when no runtime config is passed in", func() {
			BeforeEach(func() {
				inputStruct.RuntimeConfig = lib.RuntimeConfig{}
				input = GetInput(inputStruct)

				cmd = cniCommand("ADD", input)
			})
			It("still writes the default netout rules", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				By("checking that the default forwarding rules are created for that container")
				Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
					`-A ` + netoutChainName + ` -m state --state RELATED,ESTABLISHED -j ACCEPT`,
					`-A ` + netoutChainName + ` -p tcp -m state --state INVALID -j DROP`,
					`-A ` + netoutChainName + ` -j REJECT --reject-with icmp-port-unreachable`,
				}))

				By("checking that the default input rules are created for that container")
				Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
					`-A ` + inputChainName + ` -m state --state RELATED,ESTABLISHED -j ACCEPT`,
					`-A ` + inputChainName + ` -j REJECT --reject-with icmp-port-unreachable`,
				}))
			})
		})

		Describe("PortMapping", func() {
			It("creates iptables portmapping rules", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				By("checking that a netin chain was created for the container")
				Expect(AllIPTablesRules("nat")).To(ContainElement(`-N ` + netinChainName))
				Expect(AllIPTablesRules("nat")).To(ContainElement(`-A PREROUTING -j ` + netinChainName))

				By("checking that port forwarding rules were added to the netin chain")
				Expect(AllIPTablesRules("nat")).To(ContainElement("-A " + netinChainName + " -d 10.244.2.3/32 -p tcp -m tcp --dport 1000 -j DNAT --to-destination 1.2.3.4:1001"))
				Expect(AllIPTablesRules("nat")).To(ContainElement("-A " + netinChainName + " -d 10.244.2.3/32 -p tcp -m tcp --dport 2000 -j DNAT --to-destination 1.2.3.4:2001"))
			})

			It("creates mark rules for each port mapping rule", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				By("checking that a netin chain was created for the container")
				Expect(AllIPTablesRules("mangle")).To(ContainElement(`-N ` + netinChainName))
				Expect(AllIPTablesRules("mangle")).To(ContainElement(`-A PREROUTING -j ` + netinChainName))

				By("checking that mark rules were added to the netin chain")
				Expect(AllIPTablesRules("mangle")).To(ContainElement("-A " + netinChainName + " -d 10.244.2.3/32 -i " + underlayName1 + " -p tcp -m tcp --dport 1000 -j MARK --set-xmark 0xffff0000/0xffffffff"))
				Expect(AllIPTablesRules("mangle")).To(ContainElement("-A " + netinChainName + " -d 10.244.2.3/32 -i " + underlayName1 + " -p tcp -m tcp --dport 2000 -j MARK --set-xmark 0xffff0000/0xffffffff"))
				Expect(AllIPTablesRules("mangle")).To(ContainElement("-A " + netinChainName + " -d 10.244.2.3/32 -i " + underlayName2 + " -p tcp -m tcp --dport 1000 -j MARK --set-xmark 0xffff0000/0xffffffff"))
				Expect(AllIPTablesRules("mangle")).To(ContainElement("-A " + netinChainName + " -d 10.244.2.3/32 -i " + underlayName2 + " -p tcp -m tcp --dport 2000 -j MARK --set-xmark 0xffff0000/0xffffffff"))
			})

			Context("when temporary.underlay_interface_names is provided", func() {
				var (
					temporaryUnderlayName string
				)

				BeforeEach(func() {
					temporaryUnderlayName = "meow-temporary"
					inputStruct.TemporaryUnderlayInterfaceNames = []string{temporaryUnderlayName}
					input = GetInput(inputStruct)
					cmd = cniCommand("ADD", input)
				})

				It("creates mark rules for each port mapping rule", func() {
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					By("checking that a netin chain was created for the container")
					Expect(AllIPTablesRules("mangle")).To(ContainElement(`-N ` + netinChainName))
					Expect(AllIPTablesRules("mangle")).To(ContainElement(`-A PREROUTING -j ` + netinChainName))

					By("checking that mark rules were added to the netin chain")
					Expect(AllIPTablesRules("mangle")).To(ContainElement("-A " + netinChainName + " -d 10.244.2.3/32 -i " + temporaryUnderlayName + " -p tcp -m tcp --dport 1000 -j MARK --set-xmark 0xffff0000/0xffffffff"))
					Expect(AllIPTablesRules("mangle")).To(ContainElement("-A " + netinChainName + " -d 10.244.2.3/32 -i " + temporaryUnderlayName + " -p tcp -m tcp --dport 2000 -j MARK --set-xmark 0xffff0000/0xffffffff"))
				})
			})

			Context("when a port mapping with hostport 0 is given", func() {
				BeforeEach(func() {
					inputStruct.WrapperConfig.RuntimeConfig.PortMappings = []garden.NetIn{
						{
							HostPort:      0,
							ContainerPort: 1001,
						},
					}

					input = GetInput(inputStruct)
				})
				It("refuses to allocate", func() {
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(1))
				})
			})

			Context("when adding netin rule fails", func() {
				BeforeEach(func() {
					inputStruct.WrapperConfig.InstanceAddress = "asdf"
					input = GetInput(inputStruct)
				})
				It("exit status 1", func() {
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(1))
					Expect(session.Out.Contents()).To(MatchJSON(`{ "code": 999, "msg": "adding netin rule: invalid ip: asdf" }`))
				})
			})
		})

		Describe("NetOutRules", func() {
			It("creates iptables netout rules", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				By("checking that the jump rules are created for that container's netout chain")
				Expect(AllIPTablesRules("filter")).To(ContainElement("-A FORWARD -s 1.2.3.4/32 -o " + underlayName1 + " -j " + netoutChainName))
				Expect(AllIPTablesRules("filter")).To(ContainElement("-A FORWARD -s 1.2.3.4/32 -o " + underlayName2 + " -j " + netoutChainName))

				By("checking that the default forwarding rules are created for that container")
				Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
					`-A ` + netoutChainName + ` -m state --state RELATED,ESTABLISHED -j ACCEPT`,
					`-A ` + netoutChainName + ` -p tcp -m state --state INVALID -j DROP`,
					`-A ` + netoutChainName + ` -p icmp -m iprange --dst-range 5.5.5.5-6.6.6.6 -m icmp --icmp-type 8/0 -j ACCEPT`,
					`-A ` + netoutChainName + ` -p udp -m iprange --dst-range 11.11.11.11-22.22.22.22 -m udp --dport 53:54 -j ACCEPT`,
					`-A ` + netoutChainName + ` -p tcp -m iprange --dst-range 8.8.8.8-9.9.9.9 -m tcp --dport 53:54 -j ACCEPT`,
					`-A ` + netoutChainName + ` -m iprange --dst-range 3.3.3.3-4.4.4.4 -j ACCEPT`,
					`-A ` + netoutChainName + ` -j REJECT --reject-with icmp-port-unreachable`,
				}))

				By("checking that the default input rules are created for that container")
				Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
					`-A ` + inputChainName + ` -m state --state RELATED,ESTABLISHED -j ACCEPT`,
					`-A ` + inputChainName + ` -j REJECT --reject-with icmp-port-unreachable`,
				}))

				By("checking that the rules are written")
				Expect(AllIPTablesRules("filter")).To(ContainElement(`-A ` + netoutChainName + ` -m iprange --dst-range 3.3.3.3-4.4.4.4 -j ACCEPT`))
				Expect(AllIPTablesRules("filter")).To(ContainElement(`-A ` + netoutChainName + ` -p tcp -m iprange --dst-range 8.8.8.8-9.9.9.9 -m tcp --dport 53:54 -j ACCEPT`))
				Expect(AllIPTablesRules("filter")).To(ContainElement(`-A ` + netoutChainName + ` -p udp -m iprange --dst-range 11.11.11.11-22.22.22.22 -m udp --dport 53:54 -j ACCEPT`))
				Expect(AllIPTablesRules("filter")).To(ContainElement(`-A ` + netoutChainName + ` -p icmp -m iprange --dst-range 5.5.5.5-6.6.6.6 -m icmp --icmp-type 8/0 -j ACCEPT`))

			})

			Context("when iptables_c2c_logging is enabled", func() {
				BeforeEach(func() {
					inputStruct.WrapperConfig.IPTablesC2CLogging = true
					input = GetInput(inputStruct)
				})

				It("writes iptables overlay logging rules", func() {
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					By("checking that the default deny rules in the container's overlay chain are created")
					Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
						"-A " + overlayChainName + " -s 1.2.3.4/32 -o some-device -m mark ! --mark 0x0 -j ACCEPT",
						"-A " + overlayChainName + " -d 1.2.3.4/32 -m state --state RELATED,ESTABLISHED -j ACCEPT",
						"-A " + overlayChainName + " -d 1.2.3.4/32 -m mark --mark 0xffff0000 -j ACCEPT",
						"-A " + overlayChainName + ` -d 1.2.3.4/32 -m limit --limit 5/sec -j LOG --log-prefix "DENY_C2C_` + containerID[:19] + ` "`,
						"-A " + overlayChainName + " -d 1.2.3.4/32 -j REJECT --reject-with icmp-port-unreachable",
					}))
				})
			})

			Context("when iptables_asg_logging is enabled", func() {
				BeforeEach(func() {
					inputStruct.WrapperConfig.RuntimeConfig.NetOutRules[0].Log = false
					inputStruct.WrapperConfig.RuntimeConfig.NetOutRules[1].Log = false
					inputStruct.WrapperConfig.RuntimeConfig.NetOutRules[2].Log = false
					inputStruct.WrapperConfig.IPTablesASGLogging = true
					input = GetInput(inputStruct)
				})

				It("writes iptables asg logging rules", func() {
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					By("checking that the filter rule was installed and that logging can be enabled")
					Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
						`-A ` + netoutChainName + ` -m state --state RELATED,ESTABLISHED -j ACCEPT`,
						`-A ` + netoutChainName + ` -p tcp -m state --state INVALID -j DROP`,
						`-A ` + netoutChainName + ` -p icmp -m iprange --dst-range 5.5.5.5-6.6.6.6 -m icmp --icmp-type 8/0 -g ` + netoutLoggingChainName,
						`-A ` + netoutChainName + ` -p udp -m iprange --dst-range 11.11.11.11-22.22.22.22 -m udp --dport 53:54 -g ` + netoutLoggingChainName,
						`-A ` + netoutChainName + ` -p tcp -m iprange --dst-range 8.8.8.8-9.9.9.9 -m tcp --dport 53:54 -g ` + netoutLoggingChainName,
					}))

					By("checking that it writes the logging rules")
					Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
						`-A ` + netoutLoggingChainName + ` ! -p udp -m conntrack --ctstate INVALID,NEW,UNTRACKED -j LOG --log-prefix "OK_` + containerID[:25] + ` "`,
						`-A ` + netoutLoggingChainName + ` -p udp -m limit --limit 7/sec --limit-burst 7 -j LOG --log-prefix "OK_` + containerID[:25] + ` "`,
					}))
				})

				It("always writes a rate limited default deny log rule", func() {
					expectedDenyLogRule := `-A netout--some-container-id-th -m limit --limit 5/sec -j LOG --log-prefix "DENY_` + containerID[:23] + ` "`

					By("by starting the CNI plugin")
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					By("checking that a default deny log rule was written")
					Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
						expectedDenyLogRule,
						`-A ` + netoutChainName + ` -j REJECT --reject-with icmp-port-unreachable`,
					}))
				})
			})

			Context("when outbound container connection limiting with logging is enabled", func() {
				BeforeEach(func() {
					inputStruct.WrapperConfig.OutConn.Limit = true
					inputStruct.WrapperConfig.OutConn.Logging = true
					input = GetInput(inputStruct)
				})

				It("additionally writes iptables netout connection rate limit artifacts", func() {
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					By("creating a rate limit logging chain")
					Expect(AllIPTablesRules("filter")).To(ContainElement(`-N netout--some-contain--rl-log`))

					By("writing the default forwarding and outbound connection rate limit rule for that container")

					expectedRateLimitCfg := "-m hashlimit --hashlimit-above 100/sec --hashlimit-burst 999 --hashlimit-mode dstip,dstport"
					expectedRateLimitCfg += " --hashlimit-name " + containerID + " --hashlimit-htable-expire 10000"

					Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
						`-A ` + netoutChainName + ` -m state --state RELATED,ESTABLISHED -j ACCEPT`,
						`-A ` + netoutChainName + ` -p tcp -m state --state INVALID -j DROP`,
						`-A ` + netoutChainName + ` -p tcp -m conntrack --ctstate NEW ` + expectedRateLimitCfg + ` -j netout--some-contain--rl-log`,
						`-A ` + netoutChainName + ` -p icmp -m iprange --dst-range 5.5.5.5-6.6.6.6 -m icmp --icmp-type 8/0 -j ACCEPT`,
						`-A ` + netoutChainName + ` -p udp -m iprange --dst-range 11.11.11.11-22.22.22.22 -m udp --dport 53:54 -j ACCEPT`,
						`-A ` + netoutChainName + ` -p tcp -m iprange --dst-range 8.8.8.8-9.9.9.9 -m tcp --dport 53:54 -j ACCEPT`,
						`-A ` + netoutChainName + ` -m iprange --dst-range 3.3.3.3-4.4.4.4 -j ACCEPT`,
						`-A ` + netoutChainName + ` -j REJECT --reject-with icmp-port-unreachable`,
					}))

					By("writing the rate limit logging rules")
					Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
						`-A netout--some-contain--rl-log -m limit --limit 5/sec -j LOG --log-prefix "DENY_ORL_` + containerID[:19] + ` "`,
						`-A netout--some-contain--rl-log -j REJECT --reject-with icmp-port-unreachable`,
					}))
				})
			})

			Context("when outbound container connection limiting with logging and dry_run is enabled", func() {
				BeforeEach(func() {
					inputStruct.WrapperConfig.OutConn.Limit = true
					inputStruct.WrapperConfig.OutConn.Logging = true
					inputStruct.WrapperConfig.OutConn.DryRun = true
					input = GetInput(inputStruct)
				})

				It("additionally writes iptables netout connection rate limit artifacts", func() {
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					By("creating a rate limit logging chain")
					Expect(AllIPTablesRules("filter")).To(ContainElement(`-N netout--some-contain--rl-log`))

					By("writing the default forwarding and outbound connection rate limit rule for that container")

					expectedRateLimitCfg := "-m hashlimit --hashlimit-above 100/sec --hashlimit-burst 999 --hashlimit-mode dstip,dstport"
					expectedRateLimitCfg += " --hashlimit-name " + containerID + " --hashlimit-htable-expire 10000"

					Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
						`-A ` + netoutChainName + ` -m state --state RELATED,ESTABLISHED -j ACCEPT`,
						`-A ` + netoutChainName + ` -p tcp -m state --state INVALID -j DROP`,
						`-A ` + netoutChainName + ` -p tcp -m conntrack --ctstate NEW ` + expectedRateLimitCfg + ` -j netout--some-contain--rl-log`,
						`-A ` + netoutChainName + ` -p icmp -m iprange --dst-range 5.5.5.5-6.6.6.6 -m icmp --icmp-type 8/0 -j ACCEPT`,
						`-A ` + netoutChainName + ` -p udp -m iprange --dst-range 11.11.11.11-22.22.22.22 -m udp --dport 53:54 -j ACCEPT`,
						`-A ` + netoutChainName + ` -p tcp -m iprange --dst-range 8.8.8.8-9.9.9.9 -m tcp --dport 53:54 -j ACCEPT`,
						`-A ` + netoutChainName + ` -m iprange --dst-range 3.3.3.3-4.4.4.4 -j ACCEPT`,
						`-A ` + netoutChainName + ` -j REJECT --reject-with icmp-port-unreachable`,
					}))

					By("writing the rate limit logging rules")
					Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
						`-A netout--some-contain--rl-log -m limit --limit 5/sec -j LOG --log-prefix "DENY_ORL_` + containerID[:19] + ` "`,
					}))
				})
			})

			Context("when a TCP rule has logging enabled", func() {
				BeforeEach(func() {
					inputStruct.WrapperConfig.RuntimeConfig.NetOutRules[1].Log = true
					inputStruct.WrapperConfig.IPTablesASGLogging = false
					input = GetInput(inputStruct)
				})
				It("writes iptables asg logging rules for that rule", func() {
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					By("checking that the filter rule was installed and that logging can be enabled")
					Expect(AllIPTablesRules("filter")).To(ContainElement(`-A ` + netoutChainName + ` -p tcp -m iprange --dst-range 8.8.8.8-9.9.9.9 -m tcp --dport 53:54 -g ` + netoutLoggingChainName))

					By("checking that it writes the logging rules")
					Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
						`-A ` + netoutLoggingChainName + ` ! -p udp -m conntrack --ctstate INVALID,NEW,UNTRACKED -j LOG --log-prefix "OK_` + containerID[:25] + ` "`,
						`-A ` + netoutLoggingChainName + ` -p udp -m limit --limit 7/sec --limit-burst 7 -j LOG --log-prefix "OK_` + containerID[:25] + ` "`,
					}))
				})
			})

			Context("when a UDP rule has logging enabled", func() {
				BeforeEach(func() {
					inputStruct.WrapperConfig.RuntimeConfig.NetOutRules[2].Log = true
					inputStruct.WrapperConfig.IPTablesASGLogging = false
					input = GetInput(inputStruct)
				})
				It("writes iptables asg logging rules for that rule", func() {
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					By("checking that the filter rule was installed and that logging can be enabled")
					Expect(AllIPTablesRules("filter")).To(ContainElement(`-A ` + netoutChainName + ` -p udp -m iprange --dst-range 11.11.11.11-22.22.22.22 -m udp --dport 53:54 -g ` + netoutLoggingChainName))

					By("checking that it writes the logging rules")
					Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
						`-A ` + netoutLoggingChainName + ` ! -p udp -m conntrack --ctstate INVALID,NEW,UNTRACKED -j LOG --log-prefix "OK_` + containerID[:25] + ` "`,
						`-A ` + netoutLoggingChainName + ` -p udp -m limit --limit 7/sec --limit-burst 7 -j LOG --log-prefix "OK_` + containerID[:25] + ` "`,
					}))

				})
			})

			Context("when an ICMP rule has logging enabled", func() {
				BeforeEach(func() {
					inputStruct.WrapperConfig.RuntimeConfig.NetOutRules[3].Log = true
					inputStruct.WrapperConfig.IPTablesASGLogging = false
					input = GetInput(inputStruct)
				})
				It("writes iptables asg logging rules for that rule", func() {
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					By("checking that the filter rule was installed and that logging can be enabled")
					Expect(AllIPTablesRules("filter")).To(ContainElement(`-A ` + netoutChainName + ` -p icmp -m iprange --dst-range 5.5.5.5-6.6.6.6 -m icmp --icmp-type 8/0 -g ` + netoutLoggingChainName))

					By("checking that it writes the logging rules")
					Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
						`-A ` + netoutLoggingChainName + ` ! -p udp -m conntrack --ctstate INVALID,NEW,UNTRACKED -j LOG --log-prefix "OK_` + containerID[:25] + ` "`,
						`-A ` + netoutLoggingChainName + ` -p udp -m limit --limit 7/sec --limit-burst 7 -j LOG --log-prefix "OK_` + containerID[:25] + ` "`,
					}))

				})
			})

			Context("when deny networks are configured", func() {
				BeforeEach(func() {
					inputStruct.Metadata["container_workload"] = "app"
					inputStruct.DenyNetworks = lib.DenyNetworksConfig{
						Always:  []string{"172.16.0.0/12"},
						Running: []string{"192.168.0.0/16"},
					}
					input = GetInput(inputStruct)

					cmd = cniCommand("ADD", input)
				})
				It("writes input chain rules for deny networks", func() {
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					By("checking that the default filter rules are installed before the deny")
					Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
						`-A ` + netoutChainName + ` -m state --state RELATED,ESTABLISHED -j ACCEPT`,
						`-A ` + netoutChainName + ` -p tcp -m state --state INVALID -j DROP`,

						`-A ` + netoutChainName + ` -d 192.168.0.0/16 -j REJECT --reject-with icmp-port-unreachable`,
						`-A ` + netoutChainName + ` -d 172.16.0.0/12 -j REJECT --reject-with icmp-port-unreachable`,
					}))

					By("checking that the default filter rules are installed before the container rules")
					Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
						`-A ` + netoutChainName + ` -d 192.168.0.0/16 -j REJECT --reject-with icmp-port-unreachable`,
						`-A ` + netoutChainName + ` -d 172.16.0.0/12 -j REJECT --reject-with icmp-port-unreachable`,

						`-A ` + netoutChainName + ` -p icmp -m iprange --dst-range 5.5.5.5-6.6.6.6 -m icmp --icmp-type 8/0 -j ACCEPT`,
						`-A ` + netoutChainName + ` -p udp -m iprange --dst-range 11.11.11.11-22.22.22.22 -m udp --dport 53:54 -j ACCEPT`,
						`-A ` + netoutChainName + ` -p tcp -m iprange --dst-range 8.8.8.8-9.9.9.9 -m tcp --dport 53:54 -j ACCEPT`,
						`-A ` + netoutChainName + ` -m iprange --dst-range 3.3.3.3-4.4.4.4 -j ACCEPT`,

						`-A ` + netoutChainName + ` -j REJECT --reject-with icmp-port-unreachable`,
					}))
				})
			})
		})

		Context("When the delegate plugin returns an error", func() {
			BeforeEach(func() {
				debug.ReportError = "banana"
				Expect(debug.WriteDebug(debugFileName)).To(Succeed())
			})

			It("wraps and returns the error", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))

				Expect(session.Out.Contents()).To(MatchJSON(`{ "code": 999, "msg": "delegate call: banana" }`))
			})
		})

		Context("when the container id is not specified", func() {
			BeforeEach(func() {
				cmd.Env[1] = "CNI_CONTAINERID="
			})

			It("wraps and returns the error", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))

				Expect(session.Out.Contents()).To(MatchJSON(`{ "code": 4, "msg": "required env variables [CNI_CONTAINERID] missing" }`))
			})

			It("does not leave any iptables rules behind", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))

				Expect(AllIPTablesRules("nat")).NotTo(ContainElement("-A POSTROUTING -s 1.2.3.4/32 ! -d 10.255.0.0/16 ! -o some-device -j MASQUERADE"))
			})
		})

		Context("when the datastore add fails", func() {
			BeforeEach(func() {
				err := os.WriteFile(datastorePath, []byte("banana"), os.ModePerm)
				Expect(err).NotTo(HaveOccurred())
			})

			It("wraps and returns the error", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))

				Expect(session.Out.Contents()).To(MatchJSON(`{ "code": 999, "msg": "store add: decoding file: invalid character 'b' looking for beginning of value" }`))
			})

			It("does not leave any iptables rules behind", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))

				Expect(AllIPTablesRules("nat")).NotTo(ContainElement("-A POSTROUTING -s 1.2.3.4/32 ! -d 10.255.0.0/16 ! -o some-device -j MASQUERADE"))
			})
		})
	})

	Context("When call with command DEL", func() {
		BeforeEach(func() {
			cmd.Env[0] = "CNI_COMMAND=DEL"
		})

		It("passes the correct stdin to the delegate plugin", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			debug, err := noop_debug.ReadDebug(debugFileName)
			Expect(err).NotTo(HaveOccurred())
			Expect(debug.Command).To(Equal("DEL"))

			Expect(debug.CmdArgs.StdinData).To(MatchJSON(`{
						"cniVersion": "1.0.0",
						"type": "noop",
						"some": "other data",
						"name": "name"
					}`))
		})

		It("ensures the iptables.lock file is chowned", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			fileInfo, err := os.Stat(iptablesLockFilePath)
			Expect(err).NotTo(HaveOccurred())

			statInfo, ok := fileInfo.Sys().(*syscall.Stat_t)
			Expect(ok).To(BeTrue(), "unable to get the stat_t struct")

			Expect(statInfo.Uid).To(Equal(UnprivilegedUserId))
			Expect(statInfo.Gid).To(Equal(UnprivilegedGroupId))
		})

		It("calls the policy agent orphaned asg cleanup", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))
			Expect(policyAgentServer.CleanupOrphanedASGsEndpointCallCount).To(Equal(1))
			Expect(policyAgentServer.CleanupOrphanedASGsEndpointContainerRequested).To(Equal(containerID))
		})

		Context("when the policy agent asg cleanup returns a 405", func() {
			It("ignores and moves on, since dynamic asgs have been disabled", func() {
				policyAgentServer.CleanupOrphanedASGsReturnCode = 405
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))
				Expect(policyAgentServer.CleanupOrphanedASGsEndpointCallCount).To(Equal(1))
			})
		})

		Context("when the policy agent asg updater returns an error", func() {
			AfterEach(func() {
				policyAgentServer.CleanupOrphanedASGsReturnCode = 200
				policyAgentServer.CleanupOrphanedASGsReturnErrorMessage = ""
			})

			It("returns an error", func() {
				policyAgentServer.CleanupOrphanedASGsReturnCode = 500
				policyAgentServer.CleanupOrphanedASGsReturnErrorMessage = "an error occurred in the vpa"

				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))
				Expect(session.Out).Should(gbytes.Say(".*asg cleanup returned 500 with message: an error occurred in the vpa.*"))

				Expect(policyAgentServer.CleanupOrphanedASGsEndpointCallCount).To(Equal(1))
			})
		})

		Context("When the delegate plugin return an error", func() {
			BeforeEach(func() {
				debug.ReportError = "banana"
				Expect(debug.WriteDebug(debugFileName)).To(Succeed())
			})

			It("logs the wrapped error to stderr and return the success status code (for idempotency)", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				Expect(session.Err.Contents()).To(ContainSubstring("delegate delete: banana"))
			})
		})

		Context("when the datastore delete fails", func() {
			BeforeEach(func() {
				file, err := os.OpenFile(datastorePath, os.O_RDWR, 0600)
				Expect(err).ToNot(HaveOccurred())
				_, err = io.WriteString(file, "}{blarg")
				Expect(err).ToNot(HaveOccurred())
			})

			It("wraps and logs the error, and returns the success status code (for idempotency)", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				Expect(string(session.Err.Contents())).To(ContainSubstring("store delete: decoding file: invalid character"))
			})

			It("still calls plugin delete (so that DEL is idempotent)", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				debug, err := noop_debug.ReadDebug(debugFileName)
				Expect(err).NotTo(HaveOccurred())
				Expect(debug.Command).To(Equal("DEL"))

				Expect(debug.CmdArgs.StdinData).To(MatchJSON(`{
							"type": "noop",
							"some": "other data",
							"name": "name",
							"cniVersion": "1.0.0"
						}`))
			})
		})

	})

})

type mockPolicyAgentServer struct {
	ReturnCode                  int
	ReturnErrorMessage          string
	Address                     string
	PolicyPollEndpointCallCount int

	SyncASGEndpointCallCount          int
	SyncASGEndpointContainerRequested string
	ASGReturnCode                     int
	ASGReturnErrorMessage             string

	CleanupOrphanedASGsEndpointCallCount          int
	CleanupOrphanedASGsEndpointContainerRequested string
	CleanupOrphanedASGsReturnCode                 int
	CleanupOrphanedASGsReturnErrorMessage         string

	server *http.Server
}

func (a *mockPolicyAgentServer) PolicyPollEndpoint(w http.ResponseWriter, r *http.Request) {
	a.PolicyPollEndpointCallCount++
	w.WriteHeader(a.ReturnCode)
	if a.ReturnErrorMessage != "" {
		w.Write([]byte(a.ReturnErrorMessage))
	}
}
func (a *mockPolicyAgentServer) SyncASGEndpoint(w http.ResponseWriter, r *http.Request) {
	a.SyncASGEndpointCallCount++
	a.SyncASGEndpointContainerRequested = r.URL.Query().Get("container")
	w.WriteHeader(a.ASGReturnCode)
	if a.ASGReturnErrorMessage != "" {
		w.Write([]byte(a.ASGReturnErrorMessage))
	}
}
func (a *mockPolicyAgentServer) CleanupOrphanedASGsEndpoint(w http.ResponseWriter, r *http.Request) {
	a.CleanupOrphanedASGsEndpointCallCount++
	a.CleanupOrphanedASGsEndpointContainerRequested = r.URL.Query().Get("container")
	w.WriteHeader(a.CleanupOrphanedASGsReturnCode)
	if a.CleanupOrphanedASGsReturnErrorMessage != "" {
		w.Write([]byte(a.CleanupOrphanedASGsReturnErrorMessage))
	}
}

func (a *mockPolicyAgentServer) start() {
	mux := http.NewServeMux()
	mux.Handle("/force-policy-poll-cycle", http.HandlerFunc(a.PolicyPollEndpoint))
	mux.Handle("/force-asgs-for-container", http.HandlerFunc(a.SyncASGEndpoint))
	mux.Handle("/force-orphaned-asgs-cleanup", http.HandlerFunc(a.CleanupOrphanedASGsEndpoint))

	a.server = &http.Server{Addr: a.Address, Handler: mux}
	go a.server.ListenAndServe()
}

func (a *mockPolicyAgentServer) stop() error {
	return a.server.Close()
}

func createDummyInterface(interfaceName, ipAddress string) {
	err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: interfaceName}})
	Expect(err).ToNot(HaveOccurred())

	link, err := netlink.LinkByName(interfaceName)
	Expect(err).ToNot(HaveOccurred())

	addr, err := netlink.ParseAddr(ipAddress + "/32")
	Expect(err).ToNot(HaveOccurred())

	err = netlink.AddrAdd(link, addr)
	Expect(err).ToNot(HaveOccurred())
}

func removeDummyInterface(interfaceName, ipAddress string) {
	link, err := netlink.LinkByName(interfaceName)
	Expect(err).ToNot(HaveOccurred())

	addr, err := netlink.ParseAddr(ipAddress + "/32")
	Expect(err).ToNot(HaveOccurred())

	err = netlink.AddrDel(link, addr)
	Expect(err).ToNot(HaveOccurred())

	err = netlink.LinkDel(link)
	Expect(err).ToNot(HaveOccurred())
}
