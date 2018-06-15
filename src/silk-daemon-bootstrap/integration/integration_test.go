package integration_test

import (
	"os/exec"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

var (
	DEFAULT_TIMEOUT = "10s"
)

func AllIPTablesRules(tableName string) []string {
	iptablesSession, err := gexec.Start(exec.Command("iptables", "-w", "-S", "-t", tableName), GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(iptablesSession).Should(gexec.Exit(0))
	return strings.Split(string(iptablesSession.Out.Contents()), "\n")
}

var _ = Describe("Bootstrap", func() {

	BeforeEach(func() {
		mustSucceed("iptables", "-F")
	})

	Context("when running in single ip mode", func() {
		It("adds the iptables rule that marks overlay destined traffic", func() {
			session := runBootstrap(true)
			Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit(0))

			rules := AllIPTablesRules("filter")
			Expect(rules).To(ConsistOf(
				"-P INPUT ACCEPT",
				"-P FORWARD ACCEPT",
				"-P OUTPUT ACCEPT",
				ContainSubstring("-A OUTPUT -o silk-vtep -j MARK --set-xmark 0xffff/0xffffffff"),
				"",
			))
		})

		Context("when the iptables already exists", func() {
			BeforeEach(func() {
				mustSucceed("iptables", "-A", "OUTPUT", "-o", "silk-vtep", "-j", "MARK", "--set-xmark", "0xffff/0xffffffff")
			})

			It("runs successfully", func() {
				session := runBootstrap(true)
				Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit(0))

				rules := AllIPTablesRules("filter")
				Expect(rules).To(ConsistOf(
					"-P INPUT ACCEPT",
					"-P FORWARD ACCEPT",
					"-P OUTPUT ACCEPT",
					ContainSubstring("-A OUTPUT -o silk-vtep -j MARK --set-xmark 0xffff/0xffffffff"),
					"",
				))
			})
		})
	})

	Context("when not running in single ip mode", func() {
		It("does not add any iptables rules", func() {
			session := runBootstrap(false)
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

func runBootstrap(singleIpOnly bool) *gexec.Session {
	bootstrapArgs := []string{
		"--iptablesLockFile", "/tmp/someLockWhoReallyCares.lock",
		"--singleIpOnly", strconv.FormatBool(singleIpOnly),
	}
	startCmd := exec.Command(paths.BoostrapBin, bootstrapArgs...)
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
