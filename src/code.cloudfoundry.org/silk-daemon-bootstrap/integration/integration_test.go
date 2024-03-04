package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	"code.cloudfoundry.org/silk-daemon-bootstrap/config"
	"code.cloudfoundry.org/testsupport"

	"crypto/tls"
	"fmt"

	"code.cloudfoundry.org/cf-networking-helpers/mutualtls"
	"code.cloudfoundry.org/cf-networking-helpers/testsupport/ports"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

const (
	DEFAULT_TIMEOUT = "10s"
)

func AllIPTablesRules(tableName string) []string {
	iptablesSession, err := gexec.Start(exec.Command("iptables", "-w", "-S", "-t", tableName), GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(iptablesSession).Should(gexec.Exit(0))
	return strings.Split(string(iptablesSession.Out.Contents()), "\n")
}

var _ = Describe("Bootstrap", func() {
	var (
		bootstrapConfig  config.SilkDaemonBootstrap
		policyServer     *testsupport.FakePolicyServer
		tag              string
		serverTLSConfig  *tls.Config
		serverListenPort int
		serverListenAddr string
	)

	BeforeEach(func() {
		mustSucceed("iptables", "-F")
		gexec.Start(exec.Command("iptables", "-X", "istio-ingress"), GinkgoWriter, GinkgoWriter)
		tag = "0009"

		var err error
		serverTLSConfig, err = mutualtls.NewServerTLSConfig(paths.ServerCertFile, paths.ServerKeyFile, paths.ClientCACertFile)
		Expect(err).NotTo(HaveOccurred())

		serverListenPort = ports.PickAPort()
		serverListenAddr = fmt.Sprintf("127.0.0.1:%d", serverListenPort)

		policyServer = &testsupport.FakePolicyServer{
			ReturnedTag: tag,
		}
		policyServer.Start(serverListenAddr, serverTLSConfig)
		Eventually(policyServer.Server.Ready()).Should(BeClosed())

		bootstrapConfig = config.SilkDaemonBootstrap{
			IPTablesLockFile:       "/tmp/someLockWhoReallyCares.lock",
			PolicyServerURL:        fmt.Sprintf("https://%s", serverListenAddr),
			PolicyServerCACertFile: paths.ServerCACertFile,
			PolicyClientCertFile:   paths.ClientCertFile,
			PolicyClientKeyFile:    paths.ClientKeyFile,
		}
	})

	AfterEach(func() {
		policyServer.Stop()
		Eventually(policyServer.Server.Wait()).Should(Receive())
	})

	Context("when running in single ip mode", func() {
		BeforeEach(func() {
			bootstrapConfig.SingleIPOnly = true
		})

		It("adds the iptables rule that marks overlay destined traffic", func() {
			session := runBootstrap(bootstrapConfig)
			Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit(0))

			rules := AllIPTablesRules("filter")
			Expect(rules).To(ConsistOf(
				"-P INPUT ACCEPT",
				"-P FORWARD ACCEPT",
				"-P OUTPUT ACCEPT",
				"-N istio-ingress",
				"-A OUTPUT -j istio-ingress",
				"-A istio-ingress -o silk-vtep -j MARK --set-xmark 0x9/0xffffffff",
				"-A istio-ingress -o silk-vtep -j ACCEPT",
				"",
			))
		})

		Context("when the iptables already exists", func() {
			BeforeEach(func() {
				mustSucceed("iptables", "-N", "istio-ingress")
				mustSucceed("iptables", "-A", "OUTPUT", "-j", "istio-ingress")
				mustSucceed("iptables", "-A", "istio-ingress", "-o", "silk-vtep", "-j", "MARK", "--set-xmark", "0x9/0xffffffff")
				mustSucceed("iptables", "-A", "istio-ingress", "-o", "silk-vtep", "-j", "ACCEPT")
			})

			It("runs successfully", func() {
				session := runBootstrap(bootstrapConfig)
				Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit(0))

				rules := AllIPTablesRules("filter")
				Expect(rules).To(ConsistOf(
					"-P INPUT ACCEPT",
					"-P FORWARD ACCEPT",
					"-P OUTPUT ACCEPT",
					"-N istio-ingress",
					"-A OUTPUT -j istio-ingress",
					"-A istio-ingress -o silk-vtep -j MARK --set-xmark 0x9/0xffffffff",
					"-A istio-ingress -o silk-vtep -j ACCEPT",
					"",
				))
			})
		})

		Context("when the client has the different certs", func() {
			BeforeEach(func() {
				bootstrapConfig.PolicyServerCACertFile = paths.OtherServerCACertFile
			})

			It("should fail to make a connection", func() {
				session := runBootstrap(bootstrapConfig)
				Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit(1))
				Expect(string(session.Err.Contents())).To(ContainSubstring("certificate signed by unknown authority"))
			})
		})
	})

	Context("when not running in single ip mode", func() {
		BeforeEach(func() {
			bootstrapConfig.SingleIPOnly = false
		})

		It("does not add any iptables rules", func() {
			session := runBootstrap(bootstrapConfig)
			Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit(0))

			rules := AllIPTablesRules("filter")
			Expect(rules).To(ConsistOf(
				"-P INPUT ACCEPT",
				"-P FORWARD ACCEPT",
				"-P OUTPUT ACCEPT",
				"",
			))
		})
	})
})

func runBootstrap(bootstrapConfig config.SilkDaemonBootstrap) *gexec.Session {
	configFile, err := os.CreateTemp("", "")
	Expect(err).NotTo(HaveOccurred())

	contents, err := json.Marshal(&bootstrapConfig)
	Expect(err).NotTo(HaveOccurred())

	_, err = configFile.Write(contents)
	Expect(err).NotTo(HaveOccurred())

	startCmd := exec.Command(paths.BoostrapBin,
		"--config", configFile.Name(),
	)
	session, err := gexec.Start(startCmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	return session
}

func mustSucceed(binary string, args ...string) string {
	cmd := exec.Command(binary, args...)
	sess, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, "10s").Should(gexec.Exit(0))
	return string(sess.Out.Contents())
}
