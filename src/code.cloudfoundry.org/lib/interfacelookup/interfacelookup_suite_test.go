package interfacelookup_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestInterfaceLookup(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Interface Lookup Suite")
}
