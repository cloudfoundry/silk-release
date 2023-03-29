package integration_test

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"

	"testing"
)

var binaryPath string

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Silk Datastore Syncer Suite")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	fmt.Fprintf(GinkgoWriter, "building binary...")
	binaryPath, err := gexec.Build("code.cloudfoundry.org/silk-datastore-syncer")
	fmt.Fprintf(GinkgoWriter, "done")
	Expect(err).NotTo(HaveOccurred())
	return []byte(binaryPath)
}, func(data []byte) {
	binaryPath = string(data)
})

var _ = SynchronizedAfterSuite(func() {}, func() {
	gexec.CleanupBuildArtifacts()
})
