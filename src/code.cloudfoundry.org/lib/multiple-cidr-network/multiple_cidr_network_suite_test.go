package multiple_cidr_network_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMultipleCidrNetwork(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "MultipleCidrNetwork Suite")
}
