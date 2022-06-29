package pollers_test

import (
	"os"
	"time"

	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/netmon/fakes"
	"code.cloudfoundry.org/netmon/network_stats"
	"code.cloudfoundry.org/netmon/pollers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Poller Run", func() {
	var (
		networkStatsFetcher *fakes.NetworkStatsFetcher
		logger              *lagertest.TestLogger

		metrics      *pollers.SystemMetrics
		pollInterval time.Duration

		statsAggregator *network_stats.IntAggregator
	)

	BeforeEach(func() {
		networkStatsFetcher = &fakes.NetworkStatsFetcher{}
		logger = lagertest.NewTestLogger("test")
		pollInterval = 1 * time.Second
		statsAggregator = network_stats.NewIntAggregator()

		networkStatsFetcher.CountIPTablesRulesReturnsOnCall(0, 4, nil)
		networkStatsFetcher.CountIPTablesRulesReturnsOnCall(1, 2, nil)
		networkStatsFetcher.CountIPTablesRulesReturnsOnCall(2, 6, nil)

		metrics = &pollers.SystemMetrics{
			Logger:              logger,
			PollInterval:        pollInterval,
			InterfaceName:       "meow",
			NetworkStatsFetcher: networkStatsFetcher,
			RuleCountAggregator: statsAggregator,
		}
	})

	It("should report measurements once within single interval", func() {
		runTest(metrics, pollInterval)
		Expect(logger.LogMessages()).To(Equal([]string{
			"test.measure.measure-start",
			"test.measure.metric-sent",
			"test.measure.metric-sent",
			"test.measure.read-tx-bytes",
			"test.measure.measure-complete",
		}))
	})

	It("should use the network stats fetcher when checking the rules", func() {
		runTest(metrics, pollInterval)

		iptablesLog := logger.Logs()[2]
		Expect(iptablesLog.Data["IPTablesRuleCount"]).To(Equal(float64(4)))
	})

	It("updates the stats aggregator with IPTablesRuleCount data", func() {
		Expect(metrics.RuleCountAggregator.Maximum).To(Equal(0))
		Expect(metrics.RuleCountAggregator.Average).To(Equal(0))
		Expect(metrics.RuleCountAggregator.Minimum).To(Equal(0))

		runTest(metrics, pollInterval)
		runTest(metrics, pollInterval)
		runTest(metrics, pollInterval)

		Expect(metrics.RuleCountAggregator.Maximum).To(Equal(6))
		Expect(metrics.RuleCountAggregator.Average).To(Equal(4))
		Expect(metrics.RuleCountAggregator.Minimum).To(Equal(2))
	})
})

type poller interface {
	Run(<-chan os.Signal, chan<- struct{}) error
}

func runTest(metrics poller, pollInterval time.Duration) {
	doneCh := make(chan os.Signal)
	readyCh := make(chan struct{})

	go metrics.Run(doneCh, readyCh)

	<-readyCh
	<-time.After(pollInterval + 10*time.Millisecond)
	doneCh <- os.Interrupt
}
