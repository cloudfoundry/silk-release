package pollers_test

import (
	"errors"
	"time"

	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/netmon/fakes"
	"code.cloudfoundry.org/netmon/pollers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Telemetry Poller", func() {
	var (
		logger              *lagertest.TestLogger
		networkStatsFetcher *fakes.NetworkStatsFetcher
		pollInterval        time.Duration
		telemetryLogger     *lagertest.TestLogger
		telemetryPoller     *pollers.TelemetryMetrics
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
		telemetryLogger = lagertest.NewTestLogger("telemetry-test")
		networkStatsFetcher = &fakes.NetworkStatsFetcher{}
		pollInterval = 1 * time.Second

		networkStatsFetcher.CountIPTablesRulesReturnsOnCall(0, 2, nil)

		telemetryPoller = &pollers.TelemetryMetrics{
			Logger:              logger,
			TelemetryLogger:     telemetryLogger,
			PollInterval:        pollInterval,
			NetworkStatsFetcher: networkStatsFetcher,
		}
	})

	It("should log telemetry metrics once within in a poll interval", func() {
		networkStatsFetcher.CountIPTablesRulesReturnsOnCall(0, 2, nil)

		runTest(telemetryPoller, pollInterval)
		Expect(telemetryLogger.LogMessages()).To(Equal([]string{"telemetry-test.count-iptables-rules"}))
		Expect(telemetryLogger.Logs()).To(HaveLen(1))
		Expect(telemetryLogger.Logs()[0].Data["telemetry-source"]).To(Equal("netmon"))
		Expect(telemetryLogger.Logs()[0].Data["telemetry-time"]).NotTo(BeEmpty())
		Expect(telemetryLogger.Logs()[0].Data["IPTablesRuleCount"]).To(BeNumerically("==", 2))
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
