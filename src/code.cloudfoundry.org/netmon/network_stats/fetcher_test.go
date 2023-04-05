package network_stats_test

import (
	"errors"

	"code.cloudfoundry.org/lager/v3/lagertest"
	libfakes "code.cloudfoundry.org/lib/fakes"
	network_stats "code.cloudfoundry.org/netmon/network_stats"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Fetcher", func() {
	Describe("CountIPTablesRules", func() {
		var (
			iptables *libfakes.IPTablesAdapter
			logger   *lagertest.TestLogger
		)

		BeforeEach(func() {
			iptables = &libfakes.IPTablesAdapter{}
			logger = lagertest.NewTestLogger("test")

			iptables.RuleCountReturnsOnCall(0, 2, nil)
			iptables.RuleCountReturnsOnCall(1, 3, nil)
		})

		It("returns the combined number of filter rules and NAT rules", func() {
			stats := network_stats.NewFetcher(iptables, logger)

			ruleCount, err := stats.CountIPTablesRules()
			Expect(err).NotTo(HaveOccurred())

			Expect(iptables.RuleCountCallCount()).To(Equal(2))
			table := iptables.RuleCountArgsForCall(0)
			Expect(table).To(Equal("filter"))
			table = iptables.RuleCountArgsForCall(1)
			Expect(table).To(Equal("nat"))

			Expect(ruleCount).To(Equal(5))
		})

		Context("when the iptables adapter fails to count filter rules", func() {
			BeforeEach(func() {
				iptables.RuleCountReturnsOnCall(0, 0, errors.New("error getting filter rules"))
			})

			It("logs and returns an error", func() {
				stats := network_stats.NewFetcher(iptables, logger)

				ruleCount, err := stats.CountIPTablesRules()
				Expect(ruleCount).To(Equal(0))

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("error getting filter rules"))

				Expect(logger.LogMessages()).To(HaveLen(1))
				Expect(logger.LogMessages()[0]).To(Equal("test.failed-getting-filter-rules"))
			})
		})

		Context("when the iptables adapter fails to count nat rules", func() {
			BeforeEach(func() {
				iptables.RuleCountReturnsOnCall(1, 0, errors.New("error getting nat rules"))
			})

			It("logs and returns an error", func() {
				stats := network_stats.NewFetcher(iptables, logger)

				ruleCount, err := stats.CountIPTablesRules()
				Expect(ruleCount).To(Equal(0))

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("error getting nat rules"))

				Expect(logger.LogMessages()).To(HaveLen(1))
				Expect(logger.LogMessages()[0]).To(Equal("test.failed-getting-nat-rules"))
			})
		})
	})
})
