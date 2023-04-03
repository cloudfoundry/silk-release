package integration_test

import (
	"encoding/json"
	"fmt"
	"math/rand"

	. "github.com/onsi/ginkgo"
	ginkgoConfig "github.com/onsi/ginkgo/config"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"

	"io/ioutil"
	"testing"

	"code.cloudfoundry.org/cf-networking-helpers/testsupport"
)

var (
	certDir string
	paths   testPaths
)

type testPaths struct {
	BoostrapBin           string
	ServerCACertFile      string
	OtherServerCACertFile string
	ClientCACertFile      string
	ServerCertFile        string
	ServerKeyFile         string
	ClientCertFile        string
	ClientKeyFile         string
}

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Silk Daemon Bootstrap Integration Suite")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	var err error
	certDir, err = ioutil.TempDir("", "policy-server-certs")
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

	paths.OtherServerCACertFile, err = certWriter.WriteCA("other-server-ca")
	Expect(err).NotTo(HaveOccurred())

	fmt.Fprintf(GinkgoWriter, "building binary...")
	paths.BoostrapBin, err = gexec.Build("code.cloudfoundry.org/silk-daemon-bootstrap", "-buildvcs=false")
	fmt.Fprintf(GinkgoWriter, "done")
	Expect(err).NotTo(HaveOccurred())

	data, err := json.Marshal(paths)
	Expect(err).NotTo(HaveOccurred())

	return data
}, func(data []byte) {
	Expect(json.Unmarshal(data, &paths)).To(Succeed())

	rand.Seed(ginkgoConfig.GinkgoConfig.RandomSeed + int64(GinkgoParallelNode()))
})

var _ = SynchronizedAfterSuite(func() {}, func() {
	gexec.CleanupBuildArtifacts()
})
