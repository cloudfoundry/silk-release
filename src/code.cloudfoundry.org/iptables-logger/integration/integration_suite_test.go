package integration_test

import (
	"encoding/json"
	"fmt"
	"os"

	"code.cloudfoundry.org/iptables-logger/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"

	"testing"
)

var binaryPath string

const DEFAULT_TIMEOUT = "5s"

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Suite")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	fmt.Fprintf(GinkgoWriter, "building binary...")
	var err error
	binaryPath, err = gexec.Build("code.cloudfoundry.org/iptables-logger/cmd/iptables-logger", "-race", "-buildvcs=false")
	fmt.Fprintf(GinkgoWriter, "done")
	Expect(err).NotTo(HaveOccurred())

	return []byte(binaryPath)
}, func(data []byte) {
	binaryPath = string(data)
})

var _ = SynchronizedAfterSuite(func() {}, func() {
	gexec.CleanupBuildArtifacts()
})

func WriteConfigFile(conf config.Config) string {
	configFile, err := os.CreateTemp("", "test-config")
	Expect(err).NotTo(HaveOccurred())

	configBytes, err := json.Marshal(conf)
	Expect(err).NotTo(HaveOccurred())

	err = os.WriteFile(configFile.Name(), configBytes, os.ModePerm)
	Expect(err).NotTo(HaveOccurred())

	return configFile.Name()
}
