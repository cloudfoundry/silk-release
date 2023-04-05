//go:build !windows
// +build !windows

package linux_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"

	"code.cloudfoundry.org/vxlan-policy-agent/config"

	"code.cloudfoundry.org/cf-networking-helpers/testsupport"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	"github.com/vishvananda/netlink"

	"testing"
)

var DEFAULT_TIMEOUT = "5s"

const GlobalIPTablesLockFile = "/tmp/netman/iptables.lock"

var (
	certDir string
	paths   testPaths
)

type testPaths struct {
	ServerCACertFile     string
	ClientCACertFile     string
	ServerCertFile       string
	ServerKeyFile        string
	ClientCertFile       string
	ClientKeyFile        string
	VxlanPolicyAgentPath string
}

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Suite")
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

var _ = SynchronizedBeforeSuite(func() []byte {
	var err error
	certDir, err = ioutil.TempDir("", "netman-certs")
	Expect(err).NotTo(HaveOccurred())

	certWriter, err := testsupport.NewCertWriter(certDir)
	Expect(err).NotTo(HaveOccurred())

	paths.ServerCACertFile, err = certWriter.WriteCA("server-ca")
	Expect(err).NotTo(HaveOccurred())
	paths.ServerCertFile, paths.ServerKeyFile, err = certWriter.WriteAndSign("server", "server-ca")
	Expect(err).NotTo(HaveOccurred())

	paths.ClientCACertFile, err = certWriter.WriteCA("client-ca")
	Expect(err).NotTo(HaveOccurred())
	paths.ClientCertFile, paths.ClientKeyFile, err = certWriter.WriteAndSign("client", "client-ca")
	Expect(err).NotTo(HaveOccurred())

	fmt.Fprintf(GinkgoWriter, "building binary...")
	paths.VxlanPolicyAgentPath, err = gexec.Build("code.cloudfoundry.org/vxlan-policy-agent/cmd/vxlan-policy-agent", "-race", "-buildvcs=false")
	fmt.Fprintf(GinkgoWriter, "done")
	Expect(err).NotTo(HaveOccurred())

	data, err := json.Marshal(paths)
	Expect(err).NotTo(HaveOccurred())

	createDummyInterface("underlay1", "10.0.0.1")
	createDummyInterface("underlay2", "169.254.169.254")
	return data
}, func(data []byte) {
	Expect(json.Unmarshal(data, &paths)).To(Succeed())

	suiteConfig, _ := GinkgoConfiguration()
	rand.Seed(suiteConfig.RandomSeed + int64(GinkgoParallelProcess()))
})

var _ = SynchronizedAfterSuite(func() {}, func() {
	gexec.CleanupBuildArtifacts()
	os.Remove(certDir)
	removeDummyInterface("underlay1", "10.0.0.1")
	removeDummyInterface("underlay2", "169.254.169.254")
})

func WriteConfigFile(Config config.VxlanPolicyAgent) string {
	configFile, err := ioutil.TempFile("", "test-config")
	Expect(err).NotTo(HaveOccurred())

	configBytes, err := json.Marshal(Config)
	Expect(err).NotTo(HaveOccurred())

	err = ioutil.WriteFile(configFile.Name(), configBytes, os.ModePerm)
	Expect(err).NotTo(HaveOccurred())

	return configFile.Name()
}
