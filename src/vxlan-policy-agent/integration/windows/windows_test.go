package windows_test

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
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
		}

	})

	JustBeforeEach(func() {
		configFilePath = WriteConfigFile(conf)
	})

	AfterEach(func() {
		stopServer(mockPolicyServer)
		session.Interrupt()
		Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit())
	})

	Describe("policy agent", func() {
		Context("when the policy server is up and running", func() {
			JustBeforeEach(func() {
				mockPolicyServer = startServer(serverListenAddr, serverTLSConfig)
				session = startAgent(paths.VxlanPolicyAgentPath, configFilePath)
			})

			It("should boot and gracefully terminate", func() {
				Consistently(session).ShouldNot(gexec.Exit())
				session.Interrupt()
				Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit())
			})

			It("should parse the config file", func() {
				Eventually(session.Out, "2s").Should(Say("cfnetworking.vxlan-policy-agent.parsed-config"))
				Eventually(session.Out, "2s").Should(Say(conf.PolicyServerURL))
				Eventually(session.Out, "2s").Should(Say("cfnetworking.vxlan-policy-agent.starting"))
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
