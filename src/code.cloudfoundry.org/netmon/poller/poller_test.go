package poller_test

import (
	libfakes "code.cloudfoundry.org/lib/fakes"

	"os"
	"time"

	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/netmon/poller"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
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

		iptables.RuleCountReturnsOnCall(0, 2, nil)
		iptables.RuleCountReturnsOnCall(1, 2, nil)

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
		<-time.After(pollInterval + 10*time.Millisecond)
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
		Expect(iptables.RuleCountCallCount()).To(Equal(2))

		table := iptables.RuleCountArgsForCall(0)
		Expect(table).To(Equal("filter"))
		table = iptables.RuleCountArgsForCall(1)
		Expect(table).To(Equal("nat"))

		iptablesLog := logger.Logs()[2]
		Expect(iptablesLog.Data["IPTablesRuleCount"]).To(Equal(float64(4)))
	})
})
