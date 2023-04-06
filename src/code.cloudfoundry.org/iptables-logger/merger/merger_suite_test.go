package merger_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
)

func TestMerger(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Merger Suite")
}
