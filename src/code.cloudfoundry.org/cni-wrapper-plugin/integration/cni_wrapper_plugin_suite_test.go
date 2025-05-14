package main_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"

	"testing"
)

func TestNoop(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration: CNI wrapper plugin Suite")
}

const packagePath = "code.cloudfoundry.org/cni-wrapper-plugin"
const noopPath = "github.com/containernetworking/cni/plugins/test/noop"

var (
	paths    testPaths
	testIPv6 bool
)

type testPaths struct {
	PathToPlugin string
	CNIPath      string
}

func init() {
	if os.Getenv("GINKGO_TEST_IPV6") == "true" {
		testIPv6 = true
	}
}

func skipIfIPv4() {
	if !testIPv6 {
		Skip("Skipping test because IPv6 is disabled")
	}
}

var _ = SynchronizedBeforeSuite(func() []byte {

	noopBin, err := gexec.Build(noopPath)
	Expect(err).NotTo(HaveOccurred())
	Expect(os.Chown(noopBin, 65534, 65534)).To(Succeed())
	noopDir, _ := filepath.Split(noopBin)

	pathToPlugin, err := gexec.Build(packagePath, "-buildvcs=false")
	Expect(err).NotTo(HaveOccurred())
	Expect(os.Chown(pathToPlugin, 65534, 65534)).To(Succeed())
	wrapperDir, _ := filepath.Split(pathToPlugin)

	paths := testPaths{
		PathToPlugin: pathToPlugin,
		CNIPath:      fmt.Sprintf("%s:%s", wrapperDir, noopDir),
	}

	data, err := json.Marshal(paths)
	Expect(err).NotTo(HaveOccurred())
	return data
}, func(data []byte) {
	Expect(json.Unmarshal(data, &paths)).To(Succeed())
})

var _ = SynchronizedAfterSuite(func() {}, func() {
	// gexec.CleanupBuildArtifacts()
})
