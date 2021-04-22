package integration_test

import (
	"fmt"
	"os/exec"

	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/onsi/gomega/ghttp"
)

var (
	fakeSilkDaemonServer      *ghttp.Server
	tempPidFile               *os.File
	fakeContainerMetadataFile *os.File
	fakeSilkDaemonSession     *gexec.Session
	tag                       string
)

const DEFAULT_TIMEOUT = "10s"

var _ = BeforeEach(func() {
	fakeSilkDaemonServer = ghttp.NewUnstartedServer()
	fakeSilkDaemonServer.AllowUnhandledRequests = true
	fakeSilkDaemonServer.UnhandledRequestStatusCode = 500

	fakeSilkDaemonServer.AppendHandlers(ghttp.RespondWith(200, "", nil))
})

var _ = JustBeforeEach(func() {
	fakeSilkDaemonServer.Start()
})

var _ = AfterEach(func() {
	fakeSilkDaemonServer.Close()

	if tempPidFile != nil {
		os.RemoveAll(tempPidFile.Name())
	}
})

var _ = Describe("Teardown", func() {
	AllIPTablesRules := func(tableName string) []string {
		iptablesSession, err := gexec.Start(exec.Command("iptables", "-w", "-S", "-t", tableName), GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		Eventually(iptablesSession).Should(gexec.Exit(0))
		return strings.Split(string(iptablesSession.Out.Contents()), "\n")
	}

	BeforeEach(func() {
		var err error
		tempPidFile, err = ioutil.TempFile(os.TempDir(), "pid")
		Expect(err).NotTo(HaveOccurred())
		sleepCommand := exec.Command("sleep", "60")

		fakeSilkDaemonSession, err = gexec.Start(sleepCommand, GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())

		Expect(ioutil.WriteFile(tempPidFile.Name(), []byte(strconv.Itoa(sleepCommand.Process.Pid)+"\n"), 0777)).To(Succeed())

		// setup fake silk/store.json file
		fakeContainerMetadataFile, err = ioutil.TempFile(os.TempDir(), "store.json")
		Expect(err).NotTo(HaveOccurred())
		// write fake app contents
		fakeContainerMetadataFileContents := []byte(`{"some-app-guid": {"handle": "some-app-guid","ip": "1.2.3.4","metadata": null}}`)
		Expect(ioutil.WriteFile(fakeContainerMetadataFile.Name(), fakeContainerMetadataFileContents, 0777)).To(Succeed())

	})

	Context("when all containers are drained", func() {
		BeforeEach(func() {
			go func() {
				// Wait an arbitrary amount of time to allow the teardown script to
				// read a populated metadata file before emptying.
				time.Sleep(2 * time.Second)
				emptyfakeContainerMetadataFileContents := []byte(`{}`)
				Expect(ioutil.WriteFile(fakeContainerMetadataFile.Name(), emptyfakeContainerMetadataFileContents, 0777)).To(Succeed())
				Expect(ioutil.WriteFile(fmt.Sprintf("%s_version", fakeContainerMetadataFile.Name()), []byte("2"), 0777)).To(Succeed())
			}()

			fakeSilkDaemonServer.AppendHandlers(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				go func() {
					fakeSilkDaemonServer.Close()
				}()
			}))
		})

		It("kills the silk-daemon and pings the silk daemon until it stops responding", func() {
			// Needs to be at least 1 second so we get a least one read of the file
			// with contents in it before it gets overwritten
			checkContainerMetadataTimeout := 1
			session := runTeardown(fakeContainerMetadataFile.Name(), fakeSilkDaemonServer.URL(), tempPidFile.Name(), checkContainerMetadataTimeout)
			Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit(0))

			Expect(session.Out).To(gbytes.Say(fmt.Sprintf("waiting for the %s to become empty", fakeContainerMetadataFile.Name())))
			Expect(session.Out).To(gbytes.Say(fmt.Sprintf("reading %s, now empty. There are no containers on the cell.", fakeContainerMetadataFile.Name())))

			Expect(session.Out).To(gbytes.Say("sending TERM signal to silk-daemon"))
			Expect(session.Out).To(gbytes.Say("waiting for the silk daemon to exit"))
			Eventually(fakeSilkDaemonSession.ExitCode(), "5s").Should(Equal(143))
		})
	})

	Context("when running in single ip mode", func() {
		BeforeEach(func() {
			iptablesSession, err := gexec.Start(exec.Command("iptables", "-N", "istio-ingress"), GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(iptablesSession).Should(gexec.Exit(0))
			iptablesSession, err = gexec.Start(exec.Command("iptables", "-A", "OUTPUT", "-j", "istio-ingress"), GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(iptablesSession).Should(gexec.Exit(0))
			iptablesSession, err = gexec.Start(exec.Command("iptables", "-A", "istio-ingress", "-o", "silk-vtep", "-j", "MARK", "--set-mark", "0"), GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(iptablesSession).Should(gexec.Exit(0))
			iptablesSession, err = gexec.Start(exec.Command("iptables", "-A", "istio-ingress", "-o", "silk-vtep", "-j", "ACCEPT"), GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(iptablesSession).Should(gexec.Exit(0))
		})

		It("deletes the iptables rule that marks overlay destined traffic", func() {
			session := runTeardown(fakeContainerMetadataFile.Name(), fakeSilkDaemonServer.URL(), tempPidFile.Name(), 0)
			Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit(0))

			rules := AllIPTablesRules("filter")
			Expect(rules).ToNot(ContainElement(ContainSubstring("-N istio-ingress")))
			Expect(rules).ToNot(ContainElement(ContainSubstring("-A OUTPUT -j istio-ingress")))
			Expect(rules).ToNot(ContainElement(ContainSubstring(fmt.Sprintf("-A istio-ingress -o silk-vtep -j MARK --set-xmark 0x%s/0xffffffff", tag))))
			Expect(rules).ToNot(ContainElement(ContainSubstring("-A istio-ingress -o silk-vtep -j ACCEPT")))
		})
	})

	Context("when the directory of the provided container metadata file does not exist", func() {
		It("returns an error", func() {
			session := runTeardown("some/bad/filepath", fakeSilkDaemonServer.URL(), tempPidFile.Name(), 0)
			Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit(1))

			Expect(session.Err).To(gbytes.Say("silk-daemon-shutdown: stat some/bad: no such file or directory"))
		})
	})

	Context("when connecting to the silk-daemon fails due to a bad url", func() {
		It("returns an error", func() {
			session := runTeardown(fakeContainerMetadataFile.Name(), "some/bad/url", tempPidFile.Name(), 0)
			Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit(1))

			Expect(session.Err).To(gbytes.Say(`silk-daemon-shutdown: parse "some/bad/url": invalid URI for request`))
		})
	})

	Context("When silk daemon will not exit", func() {
		BeforeEach(func() {
			fakeSilkDaemonServer.UnhandledRequestStatusCode = 200
		})

		It("pings the silk daemon server 5 times and fails gracefully", func() {
			session := runTeardown(fakeContainerMetadataFile.Name(), fakeSilkDaemonServer.URL(), tempPidFile.Name(), 0)
			Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit(1))

			Expect(fakeSilkDaemonServer.ReceivedRequests()).To(HaveLen(5))
			Expect(session.Err).To(gbytes.Say("silk-daemon-shutdown: Silk Daemon Server did not exit after 5 ping attempts"))
		})
	})

	Context("When the container metadata file will not become empty", func() {
		It("checks the container metadata file a number times and then continues to tear down", func() {
			session := runTeardown(fakeContainerMetadataFile.Name(), fakeSilkDaemonServer.URL(), tempPidFile.Name(), 0)
			Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit(0))

			Expect(session.Out).To(gbytes.Say(fmt.Sprintf("reading %s, not empty after [0-9]+? check attempts", fakeContainerMetadataFile.Name())))
		})
	})

	Context("when silk daemon pid file does not exist", func() {
		It("returns an error", func() {
			session := runTeardown(fakeContainerMetadataFile.Name(), fakeSilkDaemonServer.URL(), "/some-invalid/file-path", 0)
			Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit(1))

			Expect(session.Err).To(gbytes.Say("silk-daemon-shutdown: open /some-invalid/file-path: no such file or directory"))
		})
	})

	Context("when the silk daemon is not running", func() {
		BeforeEach(func() {
			fakeSilkDaemonSession.Kill()
			Eventually(fakeSilkDaemonSession).Should(gexec.Exit())
		})

		It("returns with exit code 0", func() {
			session := runTeardown(fakeContainerMetadataFile.Name(), fakeSilkDaemonServer.URL(), tempPidFile.Name(), 0)
			Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit(0))
		})
	})

	Context("when silk daemon pid file does not contain a number", func() {
		BeforeEach(func() {
			Expect(ioutil.WriteFile(tempPidFile.Name(), []byte("not-a-number"), 0777)).To(Succeed())
		})

		It("returns an error", func() {
			session := runTeardown(fakeContainerMetadataFile.Name(), fakeSilkDaemonServer.URL(), tempPidFile.Name(), 0)
			Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit(1))

			Expect(session.Err).To(gbytes.Say("silk-daemon-shutdown: strconv.Atoi: parsing \"not-a-number\": invalid syntax"))
		})
	})
})

func runTeardown(containerMetadataFile, silkDaemonUrl, silkDaemonPidFile string, fileCheckInterval int) *gexec.Session {
	startCmd := exec.Command(paths.TeardownBin,
		"--containerMetadataFile", containerMetadataFile,
		"--containerMetadataFileCheckInterval", strconv.Itoa(fileCheckInterval),
		"--silkDaemonUrl", silkDaemonUrl,
		"--silkDaemonTimeout", "0",
		"--silkDaemonPidPath", silkDaemonPidFile,
		"--iptablesLockFile", "/tmp/someLockWhoReallyCares.lock")
	session, err := gexec.Start(startCmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	return session
}
