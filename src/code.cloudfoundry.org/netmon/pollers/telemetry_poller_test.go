package pollers_test

import (
	"errors"
	"time"

	"code.cloudfoundry.org/lager/v3/lagertest"
	"code.cloudfoundry.org/netmon/fakes"
	"code.cloudfoundry.org/netmon/network_stats"
	"code.cloudfoundry.org/netmon/pollers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Telemetry Poller", func() {
	var (
		logger              *lagertest.TestLogger
		networkStatsFetcher *fakes.NetworkStatsFetcher
		pollInterval        time.Duration
		telemetryLogger     *lagertest.TestLogger
		telemetryPoller     *pollers.TelemetryMetrics
		ruleCountAggregator *network_stats.IntAggregator
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
		telemetryLogger = lagertest.NewTestLogger("telemetry-test")
		networkStatsFetcher = &fakes.NetworkStatsFetcher{}
		pollInterval = 1 * time.Second
		ruleCountAggregator = network_stats.NewIntAggregator()

		networkStatsFetcher.CountIPTablesRulesReturnsOnCall(0, 2, nil)

		telemetryPoller = &pollers.TelemetryMetrics{
			Logger:              logger,
			TelemetryLogger:     telemetryLogger,
			PollInterval:        pollInterval,
			NetworkStatsFetcher: networkStatsFetcher,
			RuleCountAggregator: ruleCountAggregator,
		}

		networkStatsFetcher.CountIPTablesRulesReturnsOnCall(0, 2, nil)
		ruleCountAggregator.UpdateStats(2)
		ruleCountAggregator.UpdateStats(4)
		ruleCountAggregator.UpdateStats(6)
	})

	It("should log telemetry metrics once within in a poll interval", func() {
		runTest(telemetryPoller, pollInterval)

		Expect(telemetryLogger.LogMessages()).To(Equal([]string{"telemetry-test.count-iptables-rules"}))
		Expect(telemetryLogger.Logs()).To(HaveLen(1))
		Expect(telemetryLogger.Logs()[0].Data["telemetry-source"]).To(Equal("netmon"))
		Expect(telemetryLogger.Logs()[0].Data["telemetry-time"]).NotTo(BeEmpty())
		Expect(telemetryLogger.Logs()[0].Data["IPTablesRuleCount"]).To(BeNumerically("==", 2))
		Expect(telemetryLogger.Logs()[0].Data["IPTablesRuleCountInterval"]).To(BeNumerically("==", 1))
		Expect(telemetryLogger.Logs()[0].Data["IPTablesRuleMaxiumum"]).To(BeNumerically("==", 6))
		Expect(telemetryLogger.Logs()[0].Data["IPTablesRuleAverage"]).To(BeNumerically("==", 4))
		Expect(telemetryLogger.Logs()[0].Data["IPTablesRuleMinimum"]).To(BeNumerically("==", 2))
	})

	It("flushes the stats aggregator", func() {
		Expect(ruleCountAggregator.Average).To(Equal(4))
		Expect(ruleCountAggregator.AverageRaw).To(Equal(4.0))
		Expect(ruleCountAggregator.Maximum).To(Equal(6))
		Expect(ruleCountAggregator.Minimum).To(Equal(2))
		Expect(ruleCountAggregator.Total).To(Equal(12))
		Expect(ruleCountAggregator.UpdateCount).To(Equal(3))

		runTest(telemetryPoller, pollInterval)

		Expect(ruleCountAggregator.Average).To(Equal(0))
		Expect(ruleCountAggregator.AverageRaw).To(Equal(0.0))
		Expect(ruleCountAggregator.Maximum).To(Equal(0))
		Expect(ruleCountAggregator.Minimum).To(Equal(0))
		Expect(ruleCountAggregator.Total).To(Equal(0))
		Expect(ruleCountAggregator.UpdateCount).To(Equal(0))
	})

	Context("when fetching network stats fails", func() {
		BeforeEach(func() {
			networkStatsFetcher.CountIPTablesRulesReturnsOnCall(0, 0, errors.New("error fetching iptables rules"))
		})

		It("logs an error and waits for the subsequent poll loop", func() {
			runTest(telemetryPoller, pollInterval)
			Expect(telemetryLogger.Logs()).To(HaveLen(0))
			Expect(logger.Logs()).To(HaveLen(1))
			Expect(logger.Logs()[0].Message).To(Equal("test.failed-fetching-network-stats"))
			Expect(logger.Errors).To(HaveLen(1))
			Expect(logger.Errors[0].Error()).To(Equal("error fetching iptables rules"))
		})
	})
})
