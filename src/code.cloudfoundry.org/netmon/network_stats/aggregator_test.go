package network_stats_test

import (
	networkStats "code.cloudfoundry.org/netmon/network_stats"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Aggregator", func() {
	var (
		ipTablesAggregator *networkStats.IntAggregator
	)

	BeforeEach(func() {
		ipTablesAggregator = networkStats.NewIntAggregator()
	})

	Describe("UpdateStats", func() {
		Context("when the statistics have zero value or are unset", func() {
			It("initializes the values", func() {
				Expect(ipTablesAggregator.Average).To(Equal(0))
				Expect(ipTablesAggregator.AverageRaw).To(Equal(0.0))
				Expect(ipTablesAggregator.Maximum).To(Equal(0))
				Expect(ipTablesAggregator.Minimum).To(Equal(0))
				Expect(ipTablesAggregator.Total).To(Equal(0))
				Expect(ipTablesAggregator.UpdateCount).To(Equal(0))

				ipTablesAggregator.UpdateStats(4)

				Expect(ipTablesAggregator.Average).To(Equal(4))
				Expect(ipTablesAggregator.AverageRaw).To(Equal(4.0))
				Expect(ipTablesAggregator.Maximum).To(Equal(4))
				Expect(ipTablesAggregator.Minimum).To(Equal(4))
				Expect(ipTablesAggregator.Total).To(Equal(4))
				Expect(ipTablesAggregator.UpdateCount).To(Equal(1))
			})
		})

		Context("when the statistics have values", func() {
			BeforeEach(func() {
				ipTablesAggregator.UpdateStats(4)
			})

			It("updates the total", func() {
				Expect(ipTablesAggregator.Total).To(Equal(4))
				ipTablesAggregator.UpdateStats(2)
				Expect(ipTablesAggregator.Total).To(Equal(6))
			})

			It("updates the raw average", func() {
				Expect(ipTablesAggregator.AverageRaw).To(Equal(4.0))
				ipTablesAggregator.UpdateStats(2)
				Expect(ipTablesAggregator.AverageRaw).To(Equal(3.0))
			})

			It("updates the average", func() {
				Expect(ipTablesAggregator.Average).To(Equal(4))
				ipTablesAggregator.UpdateStats(2)
				Expect(ipTablesAggregator.Average).To(Equal(3))
			})

			It("updates the update count", func() {
				Expect(ipTablesAggregator.UpdateCount).To(Equal(1))
				ipTablesAggregator.UpdateStats(2)
				Expect(ipTablesAggregator.UpdateCount).To(Equal(2))
			})

			Describe("maxiumum", func() {
				Context("when the current value is less than the maximum value", func() {
					It("does NOT update the maximum value", func() {
						Expect(ipTablesAggregator.Maximum).To(Equal(4))
						ipTablesAggregator.UpdateStats(2)
						Expect(ipTablesAggregator.Maximum).To(Equal(4))
					})
				})

				Context("when the current value is equal to the maximum value", func() {
					It("updates the maximum value", func() {
						Expect(ipTablesAggregator.Maximum).To(Equal(4))
						ipTablesAggregator.UpdateStats(6)
						Expect(ipTablesAggregator.Maximum).To(Equal(6))
					})

				})
			})

			Describe("minimum", func() {
				Context("when the current value is greater than the minimum value", func() {
					It("does NOT update the minimum value", func() {
						Expect(ipTablesAggregator.Minimum).To(Equal(4))
						ipTablesAggregator.UpdateStats(6)
						Expect(ipTablesAggregator.Minimum).To(Equal(4))
					})
				})

				Context("when the current value is less than the minimum value", func() {
					It("updates the minimum value", func() {
						Expect(ipTablesAggregator.Minimum).To(Equal(4))
						ipTablesAggregator.UpdateStats(2)
						Expect(ipTablesAggregator.Minimum).To(Equal(2))
					})
				})
			})
		})
	})

	Describe("Flush", func() {
		BeforeEach(func() {
			ipTablesAggregator.UpdateStats(4)
		})

		It("resets the values to zero", func() {
			Expect(ipTablesAggregator.Average).To(Equal(4))
			Expect(ipTablesAggregator.AverageRaw).To(Equal(4.0))
			Expect(ipTablesAggregator.Maximum).To(Equal(4))
			Expect(ipTablesAggregator.Minimum).To(Equal(4))
			Expect(ipTablesAggregator.Total).To(Equal(4))
			Expect(ipTablesAggregator.UpdateCount).To(Equal(1))

			ipTablesAggregator.Flush()

			Expect(ipTablesAggregator.Average).To(Equal(0))
			Expect(ipTablesAggregator.AverageRaw).To(Equal(0.0))
			Expect(ipTablesAggregator.Maximum).To(Equal(0))
			Expect(ipTablesAggregator.Minimum).To(Equal(0))
			Expect(ipTablesAggregator.Total).To(Equal(0))
			Expect(ipTablesAggregator.UpdateCount).To(Equal(0))
		})
	})
})
