package config_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"code.cloudfoundry.org/vxlan-policy-agent/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	Describe("New", func() {
		var (
			file *os.File
			err  error
		)

		BeforeEach(func() {
			file, err = ioutil.TempFile(os.TempDir(), "config-")
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when config file is valid", func() {
			It("returns the config", func() {
				file.WriteString(`{
					"poll_interval": 1234,
					"asg_poll_interval": 5678,
					"cni_datastore_path": "/some/datastore/path",
					"policy_server_url": "https://some-url:1234",
					"vni": 42,
					"metron_address": "http://1.2.3.4:1234",
					"ca_cert_file": "/some/ca/file",
					"client_cert_file": "/some/client/cert/file",
					"client_key_file": "/some/client/key/file",
					"iptables_lock_file":  "/var/vcap/data/lock",
					"debug_server_host": "http://5.6.7.8",
					"debug_server_port": 5678,
					"log_level": "debug",
					"log_prefix": "cfnetworking",
					"iptables_c2c_logging": true,
					"client_timeout_seconds":5,
					"iptables_accepted_udp_logs_per_sec":4,
					"enable_overlay_ingress_rules": true,
					"force_policy_poll_cycle_port": 6789,
					"force_policy_poll_cycle_host": "http://6.7.8.9",
					"disable_container_network_policy": false,
					"underlay_ips": ["123.1.2.3"],
					"iptables_asg_logging": true,
					"iptables_denied_logs_per_sec": 2,
					"deny_networks": {
						"always": ["10.0.0.0/24"],
						"running": ["10.0.1.0/24"],
						"staging": ["10.0.2.0/24"]
					},
					"outbound_connections": {
						"limit": true,
						"logging": true,
						"burst": 900,
						"rate_per_sec": 100
					}
				}`)
				c, err := config.New(file.Name())
				Expect(err).NotTo(HaveOccurred())
				Expect(c.PollInterval).To(Equal(1234))
				Expect(c.ASGPollInterval).To(Equal(5678))
				Expect(c.Datastore).To(Equal("/some/datastore/path"))
				Expect(c.PolicyServerURL).To(Equal("https://some-url:1234"))
				Expect(c.VNI).To(Equal(42))
				Expect(c.MetronAddress).To(Equal("http://1.2.3.4:1234"))
				Expect(c.ServerCACertFile).To(Equal("/some/ca/file"))
				Expect(c.ClientCertFile).To(Equal("/some/client/cert/file"))
				Expect(c.ClientKeyFile).To(Equal("/some/client/key/file"))
				Expect(c.IPTablesLockFile).To(Equal("/var/vcap/data/lock"))
				Expect(c.DebugServerHost).To(Equal("http://5.6.7.8"))
				Expect(c.DebugServerPort).To(Equal(5678))
				Expect(c.LogLevel).To(Equal("debug"))
				Expect(c.LogPrefix).To(Equal("cfnetworking"))
				Expect(c.IPTablesLogging).To(Equal(true))
				Expect(c.ClientTimeoutSeconds).To(Equal(5))
				Expect(c.IPTablesAcceptedUDPLogsPerSec).To(Equal(4))
				Expect(c.EnableOverlayIngressRules).To(Equal(true))
				Expect(c.ForcePolicyPollCyclePort).To(Equal(6789))
				Expect(c.ForcePolicyPollCycleHost).To(Equal("http://6.7.8.9"))
				Expect(c.DisableContainerNetworkPolicy).To(BeFalse())
				Expect(c.UnderlayIPs).To(Equal([]string{"123.1.2.3"}))
				Expect(c.IPTablesASGLogging).To(BeTrue())
				Expect(c.IPTablesDeniedLogsPerSec).To(Equal(2))
				Expect(c.DenyNetworks.Always).To(Equal([]string{"10.0.0.0/24"}))
				Expect(c.DenyNetworks.Running).To(Equal([]string{"10.0.1.0/24"}))
				Expect(c.DenyNetworks.Staging).To(Equal([]string{"10.0.2.0/24"}))
				Expect(c.OutConn.Limit).To(BeTrue())
				Expect(c.OutConn.Logging).To(BeTrue())
				Expect(c.OutConn.Burst).To(Equal(900))
				Expect(c.OutConn.RatePerSec).To(Equal(100))
			})
		})

		Context("when config file path does not exist", func() {
			It("returns the error", func() {
				_, err := config.New("not-exists")
				Expect(err).To(MatchError(ContainSubstring("file does not exist:")))
			})
		})

		Context("when config file is bad format", func() {
			It("returns the error", func() {
				file.WriteString("bad-format")
				_, err = config.New(file.Name())
				Expect(err).To(MatchError(ContainSubstring("parsing config")))
			})
		})

		Context("when config file contents blank", func() {
			It("returns the error", func() {
				_, err = config.New(file.Name())
				Expect(err).To(MatchError(ContainSubstring("parsing config")))
			})
		})

		DescribeTable("when config file is missing a member",
			func(missingFlag, errorMsg string) {
				allData := map[string]interface{}{
					"poll_interval":                      1234,
					"asg_poll_interval":                  5678,
					"cni_datastore_path":                 "/some/datastore/path",
					"policy_server_url":                  "https://some-url:1234",
					"vni":                                42,
					"metron_address":                     "http://1.2.3.4:1234",
					"ca_cert_file":                       "/some/ca/file",
					"client_cert_file":                   "/some/client/cert/file",
					"client_key_file":                    "/some/client/key/file",
					"iptables_lock_file":                 "/var/vcap/data/lock",
					"debug_server_host":                  "http://5.6.7.8",
					"debug_server_port":                  5678,
					"log_prefix":                         "cfnetworking",
					"client_timeout_seconds":             5,
					"iptables_accepted_udp_logs_per_sec": 4,
					"force_policy_poll_cycle_port":       6789,
					"force_policy_poll_cycle_host":       "http://6.7.8.9",
					"iptables_asg_logging":               true,
					"iptables_denied_logs_per_sec":       2,
					"deny_networks": map[string]interface{}{
						"always":  []string{"10.0.0.0/24"},
						"running": []string{"10.0.1.0/24"},
						"staging": []string{"10.0.2.0/24"},
					},
					"outbound_connections": map[string]interface{}{
						"limit":        true,
						"logging":      true,
						"burst":        900,
						"rate_per_sec": 100,
					},
				}
				delete(allData, missingFlag)
				Expect(json.NewEncoder(file).Encode(allData)).To(Succeed())

				_, err = config.New(file.Name())
				Expect(err).To(MatchError(fmt.Sprintf("invalid config: %s", errorMsg)))
			},
			Entry("missing poll interval", "poll_interval", "PollInterval: zero value"),
			Entry("missing asg poll interval", "asg_poll_interval", "ASGPollInterval: less than min"),
			Entry("missing datastore path", "cni_datastore_path", "Datastore: zero value"),
			Entry("missing policy server url", "policy_server_url", "PolicyServerURL: less than min"),
			Entry("missing vni", "vni", "VNI: zero value"),
			Entry("missing metron address", "metron_address", "MetronAddress: zero value"),
			Entry("missing ca cert", "ca_cert_file", "ServerCACertFile: zero value"),
			Entry("missing client cert file", "client_cert_file", "ClientCertFile: zero value"),
			Entry("missing client key file", "client_key_file", "ClientKeyFile: zero value"),
			Entry("missing iptables lock file", "iptables_lock_file", "IPTablesLockFile: zero value"),
			Entry("missing debug server host", "debug_server_host", "DebugServerHost: zero value"),
			Entry("missing debug server port", "debug_server_port", "DebugServerPort: zero value"),
			Entry("missing log prefix", "log_prefix", "LogPrefix: zero value"),
			Entry("missing client timeout", "client_timeout_seconds", "ClientTimeoutSeconds: zero value"),
			Entry("missing iptables accepted udp logs per sec", "iptables_accepted_udp_logs_per_sec", "IPTablesAcceptedUDPLogsPerSec: less than min"),
			Entry("missing force policy poll cycle host", "force_policy_poll_cycle_host", "ForcePolicyPollCycleHost: zero value"),
			Entry("missing force policy poll cycle port", "force_policy_poll_cycle_port", "ForcePolicyPollCyclePort: zero value"),
		)
	})
})
