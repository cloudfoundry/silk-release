package netrules_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
)

func TestNetrules(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Netrules Suite")
}
