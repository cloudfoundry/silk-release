// +build windows

package windows_test

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"vxlan-policy-agent/config"

	"code.cloudfoundry.org/cf-networking-helpers/mutualtls"
	"code.cloudfoundry.org/cf-networking-helpers/testsupport/metrics"
	"code.cloudfoundry.org/cf-networking-helpers/testsupport/ports"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"

	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/grouper"
	"github.com/tedsuo/ifrit/http_server"
	"github.com/tedsuo/ifrit/sigmon"
)

var _ = Describe("VXLAN Policy Agent Windows", func() {
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
					"policy_group_id":"some-app-on-this-cell",
					"space_id": "some-space",
					"ports": "8080, 9090",
					"container_workload": "app"
				}
			},
			"some-other-handle": {
				"handle":"some-other-handle",
				"ip":"10.255.100.21",
				"metadata": {
					"policy_group_id":"some-space-on-this-cell",
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
			PolicyServerURL:               fmt.Sprintf("https://%s", serverListenAddr),
			Datastore:                     datastorePath,
			VNI:                           42,
			MetronAddress:                 fakeMetron.Address(),
			ServerCACertFile:              paths.ServerCACertFile,
			ClientCertFile:                paths.ClientCertFile,
			ClientKeyFile:                 paths.ClientKeyFile,
			IPTablesLockFile:              "REMOVE", // TODO: consider removing this property
			ForcePolicyPollCycleHost:      "127.0.0.1",
			ForcePolicyPollCyclePort:      ports.PickAPort(),
			DebugServerHost:               "127.0.0.1",
			DebugServerPort:               ports.PickAPort(),
			LogPrefix:                     "testprefix",
			ClientTimeoutSeconds:          5,
			IPTablesAcceptedUDPLogsPerSec: 7,
			EnableOverlayIngressRules:     true,
		}
	})

	JustBeforeEach(func() {
		configFilePath = WriteConfigFile(conf)
		mockPolicyServer = startServer(serverListenAddr, serverTLSConfig)
		session = startAgent(paths.VxlanPolicyAgentPath, configFilePath)
	})

	AfterEach(func() {
		stopServer(mockPolicyServer)
		session.Interrupt()
		Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit())
	})

	Describe("policy agent", func() {
		Context("when the policy server is up and running", func() {
			It("should boot and gracefully terminate", func() {
				Consistently(session).ShouldNot(gexec.Exit())
				session.Interrupt()
				Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit())
			})

			It("should parse the config file and get dynamic egress policies", func() {
				Eventually(session.Out, "2s").Should(Say("cfnetworking.vxlan-policy-agent.parsed-config"))
				Eventually(session.Out, "2s").Should(Say(conf.PolicyServerURL))
				Eventually(session.Out, "2s").Should(Say("cfnetworking.vxlan-policy-agent.starting"))
				Eventually(session.Out, "3s").Should(Say("cfnetworking.vxlan-policy-agent.egress_policies.*some-space-on-this-cell"))
				Eventually(session.Out, "3s").Should(Say("some-app-on-this-cell"))
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

		Context("when GetRules fails", func() {
			JustBeforeEach(func() {
				containerMetadata := `{some - : invalid json :) }`
				Expect(ioutil.WriteFile(datastorePath, []byte(containerMetadata), os.ModePerm))
			})

			It("crashes and logs a useful error message", func() {
				session = startAgent(paths.VxlanPolicyAgentPath, configFilePath)
				Eventually(session).Should(gexec.Exit(1))
				Eventually(session.Out).Should(Say("dynamic-planner-get-rules"))
			})
		})
	})
})

func startAgent(binaryPath, configPath string) *gexec.Session {
	cmd := exec.Command(binaryPath, "-config-file", configPath)
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	return session
}

func startServer(serverListenAddr string, tlsConfig *tls.Config) ifrit.Process {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if strings.HasPrefix(r.URL.Path, "/networking/v1/internal/policies") {
			idQuery := r.URL.Query()["id"]
			if len(idQuery) > 0 {
				ids := strings.Split(idQuery[0], ",")
				if len(ids) == 3 && contains(ids, "some-app-on-this-cell") &&
					contains(ids, "some-space") && contains(ids, "some-space-on-this-cell") {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
					"total_policies": 1,
					"policies": [
						{
							"source": {"id":"some-very-very-long-app-guid", "tag":"A"},
							"destination": {"id": "some-other-app-guid", "tag":"B", "protocol":"tcp", "ports":{"start":3333, "end":3333}}
						}
					],
					"total_egress_policies": 2,
					"egress_policies": [
						{
							"source": {"id": "some-space-on-this-cell", "type": "space" },
							"destination": {"ips": [{"start": "10.27.2.1", "end": "10.27.2.2"}], "protocol": "tcp"},
							"app_lifecycle": "running"
						},
						{
							"source": {"id": "some-app-on-this-cell" },
							"destination": {"ips": [{"start": "1.1.1.1", "end": "2.9.9.9"}], "ports": [{"start": 8080, "end": 8081}], "protocol": "tcp"},
							"app_lifecycle": "staging"
						}
					]
				}`))
					return
				}
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{
					"total_policies": 0,
					"policies": [],
					"total_egress_policies": 0,
					"egress_policies": []
				}`))
			}
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

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
