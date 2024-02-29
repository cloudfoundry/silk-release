package integration_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"code.cloudfoundry.org/cni-teardown/config"

	"strings"
	"time"

	"code.cloudfoundry.org/silk/lib/adapter"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

const (
	DEFAULT_TIMEOUT = "5s"
)

var _ = Describe("Teardown", func() {
	var (
		teardownConfig        *config.Config
		configFilePath        string
		datastorePath         string
		delegateDataDirPath   string
		delegateDatastorePath string
	)

	BeforeEach(func() {
		var err error

		// /var/vcap/data/container-metadata
		datastorePath, err = os.MkdirTemp(os.TempDir(), fmt.Sprintf("container-metadata-%d", GinkgoParallelProcess()))
		Expect(err).NotTo(HaveOccurred())

		// /var/vcap/data/host-local
		delegateDataDirPath, err = os.MkdirTemp(os.TempDir(), fmt.Sprintf("host-local-%d", GinkgoParallelProcess()))
		Expect(err).NotTo(HaveOccurred())

		// /var/vcap/data/silk/store.json
		delegateDatastorePath, err = os.MkdirTemp(os.TempDir(), fmt.Sprintf("silk-%d", GinkgoParallelProcess()))
		Expect(err).NotTo(HaveOccurred())

		teardownConfig = &config.Config{
			PathsToDelete: []string{
				datastorePath,
				delegateDataDirPath,
				delegateDatastorePath,
			},
		}

		// write config, pass it as flag to when we call teardown
		configFilePath = writeConfigFile(*teardownConfig)
	})

	AfterEach(func() {
		Expect(os.RemoveAll(configFilePath)).To(Succeed())
		Expect(os.RemoveAll(datastorePath))
		Expect(os.RemoveAll(delegateDataDirPath))
		Expect(os.RemoveAll(delegateDatastorePath))
	})

	Context("when an ifb device exists", func() {
		var (
			ifbName               string
			notSilkCreatedIFBName string
			netlinkAdapter        *adapter.NetlinkAdapter
			dummyName             string
		)

		BeforeEach(func() {
			cmd := exec.Command("lsmod")
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			session.Wait(5 * time.Second)
			if !strings.Contains(string(session.Out.Contents()), "ifb") {
				Skip("Docker for Mac does not contain IFB kernel module")
			}

			ifbName = fmt.Sprintf("i-some-ifb-%d", GinkgoParallelProcess())
			notSilkCreatedIFBName = fmt.Sprintf("other-ifb-%d", GinkgoParallelProcess())
			dummyName = fmt.Sprintf("ilololol-%d", GinkgoParallelProcess())

			netlinkAdapter = &adapter.NetlinkAdapter{}

			mustSucceed("ip", "link", "add", ifbName, "type", "ifb")
			mustSucceed("ip", "link", "add", notSilkCreatedIFBName, "type", "ifb")
			mustSucceed("ip", "link", "add", dummyName, "type", "dummy")
		})

		AfterEach(func() {
			exec.Command("ip", "link", "del", ifbName).Run()
			mustSucceed("ip", "link", "del", notSilkCreatedIFBName)
			mustSucceed("ip", "link", "del", dummyName)
		})

		It("destroys only leftover IFB devices", func() {
			By("running teardown")
			session := runTeardown(configFilePath)
			Expect(session).To(gexec.Exit(0))
			Expect(session.Out.Contents()).To(ContainSubstring("cni-teardown.starting"))

			By("verifying that the ifb is no longer present")
			_, err := netlinkAdapter.LinkByName(ifbName)
			Expect(err).To(MatchError("Link not found"))

			By("verifying that the other devices are not cleaned up")
			_, err = netlinkAdapter.LinkByName(dummyName)
			Expect(err).NotTo(HaveOccurred())

			_, err = netlinkAdapter.LinkByName(notSilkCreatedIFBName)
			Expect(err).NotTo(HaveOccurred())

			Expect(session.Out.Contents()).To(ContainSubstring("cni-teardown.complete"))
		})

		Context("when we fail to clean up the directories", func() {
			var silkJsonPath, metadataJsonPath, hostLocalJsonPath string

			BeforeEach(func() {
				silkJsonPath = filepath.Join(delegateDatastorePath, "store.json")
				metadataJsonPath = filepath.Join(datastorePath, "store.json")
				hostLocalJsonPath = filepath.Join(delegateDataDirPath, "store.json")

				makeImmutableFile(silkJsonPath)
				makeImmutableFile(metadataJsonPath)
				makeImmutableFile(hostLocalJsonPath)
			})

			AfterEach(func() {
				changeFileToMutable(silkJsonPath)
				changeFileToMutable(metadataJsonPath)
				changeFileToMutable(hostLocalJsonPath)

				Expect(os.Remove(silkJsonPath)).To(Succeed())
				Expect(os.Remove(metadataJsonPath)).To(Succeed())
				Expect(os.Remove(hostLocalJsonPath)).To(Succeed())
			})

			It("logs the errors but still cleans up devices", func() {
				By("running teardown")
				session := runTeardown(configFilePath)
				Expect(session).To(gexec.Exit(0))

				By("verifying that the ifb is no longer present")
				_, err := netlinkAdapter.LinkByName(ifbName)
				Expect(err).To(MatchError("Link not found"))

				By("checking the logs")
				Expect(string(session.Out.Contents())).To(ContainSubstring("cni-teardown.starting"))
				Expect(string(session.Out.Contents())).To(ContainSubstring("cni-teardown.failed-to-remove-path"))
				Expect(string(session.Out.Contents())).To(ContainSubstring(datastorePath))
				Expect(string(session.Out.Contents())).To(ContainSubstring(delegateDataDirPath))
				Expect(string(session.Out.Contents())).To(ContainSubstring(delegateDatastorePath))
				Expect(string(session.Out.Contents())).To(ContainSubstring("cni-teardown.complete"))
			})
		})

		Context("when unable to delete an ifb device", func() {
			BeforeEach(func() {
				err := os.Chmod(configFilePath, 0777)
				Expect(err).NotTo(HaveOccurred())

				createUserCmd := exec.Command("useradd", "test-user")
				session, err := gexec.Start(createUserCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit())
			})

			AfterEach(func() {
				delUserCmd := exec.Command("deluser", "test-user")
				session, err := gexec.Start(delUserCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit())
			})

			It("logs the errors", func() {
				By("running teardown")
				session := runTeardownNonRoot("test-user", configFilePath)
				Expect(session).To(gexec.Exit(0))

				By("checking the logs")
				Expect(string(session.Out.Contents())).To(ContainSubstring("cni-teardown.starting"))
				Expect(string(session.Out.Contents())).To(ContainSubstring("cni-teardown.failed-to-remove-ifb"))
			})
		})
	})

	It("removes the unneeded directories", func() {
		By("running teardown")
		session := runTeardown(configFilePath)
		Expect(session).To(gexec.Exit(0))
		Expect(session.Out.Contents()).To(ContainSubstring("cni-teardown.starting"))

		By("verifying that the relevant directories no longer exist")
		Expect(fileExists(datastorePath)).To(BeFalse())
		Expect(fileExists(delegateDataDirPath)).To(BeFalse())
		Expect(fileExists(delegateDatastorePath)).To(BeFalse())

		Expect(session.Out.Contents()).To(ContainSubstring("cni-teardown.complete"))
	})

	Context("when the config file exists but cannot be read", func() {
		BeforeEach(func() {
			err := os.WriteFile(configFilePath, []byte("some-bad-data"), os.ModePerm)
			Expect(err).NotTo(HaveOccurred())
		})

		It("logs the errors but still cleans up devices", func() {
			session := runTeardown(configFilePath)
			Expect(session).To(gexec.Exit(1))
			Expect(string(session.Out.Contents())).To(ContainSubstring("cni-teardown.starting"))
			Expect(string(session.Out.Contents())).To(ContainSubstring("cni-teardown.read-config-file"))
			Expect(string(session.Out.Contents())).NotTo(ContainSubstring("cni-teardown.complete"))
		})
	})

	Context("when we fail to clean up the directories", func() {
		var silkJsonPath, metadataJsonPath, hostLocalJsonPath string

		BeforeEach(func() {
			silkJsonPath = filepath.Join(delegateDatastorePath, "store.json")
			metadataJsonPath = filepath.Join(datastorePath, "store.json")
			hostLocalJsonPath = filepath.Join(delegateDataDirPath, "store.json")

			makeImmutableFile(silkJsonPath)
			makeImmutableFile(metadataJsonPath)
			makeImmutableFile(hostLocalJsonPath)
		})

		AfterEach(func() {
			changeFileToMutable(silkJsonPath)
			changeFileToMutable(metadataJsonPath)
			changeFileToMutable(hostLocalJsonPath)

			Expect(os.Remove(silkJsonPath)).To(Succeed())
			Expect(os.Remove(metadataJsonPath)).To(Succeed())
			Expect(os.Remove(hostLocalJsonPath)).To(Succeed())
		})

		It("logs the errors", func() {
			By("running teardown")
			session := runTeardown(configFilePath)
			Expect(session).To(gexec.Exit(0))

			By("checking the logs")
			Expect(string(session.Out.Contents())).To(ContainSubstring("cni-teardown.starting"))
			Expect(string(session.Out.Contents())).To(ContainSubstring("cni-teardown.failed-to-remove-path"))
			Expect(string(session.Out.Contents())).To(ContainSubstring(datastorePath))
			Expect(string(session.Out.Contents())).To(ContainSubstring(delegateDataDirPath))
			Expect(string(session.Out.Contents())).To(ContainSubstring(delegateDatastorePath))
			Expect(string(session.Out.Contents())).To(ContainSubstring("cni-teardown.complete"))
		})
	})
})

func makeImmutableFile(fileName string) {
	_, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0400)
	Expect(err).NotTo(HaveOccurred())

	cmd := exec.Command("chattr", "+i", fileName)
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session, 5*time.Second).Should(gexec.Exit(0))
}

func changeFileToMutable(fileName string) {
	cmd := exec.Command("chattr", "-i", fileName)
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session, 5*time.Second).Should(gexec.Exit(0))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}

func writeConfigFile(teardownConfig config.Config) string {
	configFile, err := os.CreateTemp("", "test-config")
	Expect(err).NotTo(HaveOccurred())

	configBytes, err := json.Marshal(teardownConfig)
	Expect(err).NotTo(HaveOccurred())

	err = os.WriteFile(configFile.Name(), configBytes, os.ModePerm)
	Expect(err).NotTo(HaveOccurred())

	return configFile.Name()
}

func mustSucceed(binary string, args ...string) string {
	cmd := exec.Command(binary, args...)
	sess, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, "10s").Should(gexec.Exit(0))
	return string(sess.Out.Contents())
}

func runTeardown(configFilePath string) *gexec.Session {
	startCmd := exec.Command(paths.TeardownBin, "--config", configFilePath)
	session, err := gexec.Start(startCmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit())
	return session
}

func runTeardownNonRoot(user, configFilePath string) *gexec.Session {
	startCmd := exec.Command("su", user, "-c", fmt.Sprintf("%s --config %s", paths.TeardownBin, configFilePath))
	session, err := gexec.Start(startCmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit())
	return session
}
