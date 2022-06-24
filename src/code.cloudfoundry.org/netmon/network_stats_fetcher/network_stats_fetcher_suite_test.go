package network_stats_fetcher_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestNetworkStatsFetcher(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "NetworkStatsFetcher Suite")
}
