package poller_test

import (
	libfakes "lib/fakes"

	"code.cloudfoundry.org/lager/lagertest"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"netmon/poller"
	"os"
	"time"
)

var _ = Describe("Poller Run", func() {
	var (
		iptables *libfakes.IPTablesAdapter
		logger   *lagertest.TestLogger
	)

	BeforeEach(func() {
		iptables = &libfakes.IPTablesAdapter{}
		logger = lagertest.NewTestLogger("test")
		pollInterval := 1 * time.Second

		filterRules := []string {"rule 1", "meow rule"}
		natRules := []string {"rule fish", "hampster rule"}
		iptables.ListAllReturnsOnCall(0, filterRules, nil)
		iptables.ListAllReturnsOnCall(1, natRules, nil)

		metrics := &poller.SystemMetrics{
			Logger:          logger,
			PollInterval:    pollInterval,
			InterfaceName:   "meow",
			IPTablesAdapter: iptables,
		}

		doneCh := make(chan os.Signal)
		readyCh := make(chan struct{})

		go metrics.Run(doneCh, readyCh)

		<-readyCh
		<-time.After(pollInterval)
		doneCh <- os.Interrupt
	})

	It("should report measurements once within single interval", func() {
		Expect(logger.LogMessages()).To(Equal([]string{
			"test.measure.measure-start",
			"test.measure.metric-sent",
			"test.measure.metric-sent",
			"test.measure.read-tx-bytes",
			"test.measure.measure-complete",
		}))
	})

	It("should use the iptables adapter when checking the rules", func() {
		Expect(iptables.ListAllCallCount()).To(Equal(2))

		table := iptables.ListAllArgsForCall(0)
		Expect(table).To(Equal("filter"))
		table = iptables.ListAllArgsForCall(1)
		Expect(table).To(Equal("nat"))

		iptablesLog := logger.Logs()[2]
		Expect(iptablesLog.Data["IPTablesRuleCount"]).To(Equal(float64(4)))
	})
})
