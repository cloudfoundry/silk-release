package multiple_cidr_network_test

import (
	. "code.cloudfoundry.org/lib/multiple-cidr-network"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("MultipleCIDRNetwork", func() {
	var (
		network                            MultipleCIDRNetwork
		validCIDR1, validCIDR2, validCIDR3 string
	)

	BeforeEach(func() {
		validCIDR1 = "10.20.0.0/16"  // 10.20.0.0 - 10.20.255.255
		validCIDR2 = "10.50.50.0/24" // 10.50.50.0 - 10.50.50.255
		validCIDR3 = "10.255.0.0/16" // 10.255.0.0 - 10.255.255.255
	})

	Context("NewMultipleCIDRNetwork", func() {
		DescribeTable("when the cidrs provided are invalid",
			func(cidrs []string) {
				_, err := NewMultipleCIDRNetwork(cidrs)
				Expect(err).To(HaveOccurred())
			},
			Entry("When the 'CIDR' isn't remotely even a CIDR", []string{"meow"}),
			Entry("When the 'CIDR' has an invalid IP", []string{"10.999.0.0/16"}),
			Entry("When the 'CIDR' has an invalid mask", []string{"10.99.0.0/99"}),
			Entry("When the second 'CIDR' is invalid", []string{"10.255.0.0/24, 10.99.0.0/99"}),
		)

		Context("when the cidrs provided are valid", func() {
			BeforeEach(func() {
				var err error
				cidr1 := "10.20.0.0/16"  // 10.20.0.0 - 10.20.255.255
				cidr2 := "10.50.50.0/24" // 10.50.50.0 - 10.50.50.255
				cidr3 := "10.255.0.0/16" // 10.255.0.0 - 10.255.255.255
				network, err = NewMultipleCIDRNetwork([]string{cidr1, cidr2, cidr3})
				Expect(err).ToNot(HaveOccurred())
			})

			It("creates an array of net.IPNet's", func() {
				Expect(network.Length()).To(Equal(3))
				Expect(network.Networks[0].IP).To(Equal(net.IP{10, 20, 0, 0}))
				Expect(network.Networks[0].Mask).To(Equal(net.IPv4Mask(255, 255, 0, 0)))
				Expect(network.Networks[1].IP).To(Equal(net.IP{10, 50, 50, 0}))
				Expect(network.Networks[1].Mask).To(Equal(net.IPv4Mask(255, 255, 255, 0)))
				Expect(network.Networks[2].IP).To(Equal(net.IP{10, 255, 0, 0}))
				Expect(network.Networks[2].Mask).To(Equal(net.IPv4Mask(255, 255, 0, 0)))
			})
		})
	})

	Context("SmallestMask", func() {
		DescribeTable("it returns the size of the smallest mask",
			func(cidrs []string, expectedSize int) {
				n, err := NewMultipleCIDRNetwork(cidrs)
				Expect(err).ToNot(HaveOccurred())
				Expect(n.SmallestMask).To(Equal(expectedSize))
			},
			Entry("When the cidrs have different masks", []string{"10.255.0.0/16", "10.255.0.0/24", "10.255.0.0/32"}, 32),
			Entry("When the cidrs have the same masks", []string{"10.255.0.0/24", "10.255.0.0/24", "10.255.0.0/24"}, 24),
		)
	})

	Context("Contains", func() {
		BeforeEach(func() {
			var err error
			network, err = NewMultipleCIDRNetwork([]string{validCIDR1, validCIDR2, validCIDR3})
			Expect(err).ToNot(HaveOccurred())
		})

		Context("when the IP is contained in a network", func() {
			DescribeTable("it returns true",
				func(check string) {
					ip := net.ParseIP(check)
					Expect(ip).ToNot(BeNil())

					found := network.Contains(ip)
					Expect(found).To(BeTrue())
				},
				Entry("When it is in the first network", "10.20.0.0"),
				Entry("When it is in the second network", "10.50.50.50"),
				Entry("When it is in the third network", "10.255.255.255"),
			)
		})

		Context("when the IP is not contained in a network", func() {
			DescribeTable("it returns false",
				func(check string) {
					ip := net.ParseIP(check)
					Expect(ip).ToNot(BeNil())

					found := network.Contains(ip)
					Expect(found).To(BeFalse())
				},
				Entry("When it is not in any network", "10.10.0.0"),
				Entry("When it is not in any network", "10.30.50.50"),
				Entry("When it is not in any network", "10.200.255.255"),
			)
		})
	})

	Context("WhichNetworkContains", func() {
		BeforeEach(func() {
			var err error
			network, err = NewMultipleCIDRNetwork([]string{validCIDR1, validCIDR2, validCIDR3})
			Expect(err).ToNot(HaveOccurred())
		})

		Context("when the IP is contained in a network", func() {
			DescribeTable("it returns the single network it is in",
				func(check string, firstIPOfExpectedNetwork net.IP) {
					ip := net.ParseIP(check)
					Expect(ip).ToNot(BeNil())

					n := network.WhichNetworkContains(ip)
					Expect(n).ToNot(BeNil())
					Expect(n.IP).To(Equal(firstIPOfExpectedNetwork))

				},
				Entry("When it is in the first network", "10.20.0.0", net.IP{10, 20, 0, 0}),
				Entry("When it is in the second network", "10.50.50.50", net.IP{10, 50, 50, 0}),
				Entry("When it is in the third network", "10.255.255.255", net.IP{10, 255, 0, 0}),
			)
		})

		Context("when the IP is NOT contained in a network", func() {
			DescribeTable("it returns nil",
				func(check string) {
					ip := net.ParseIP(check)
					Expect(ip).ToNot(BeNil())

					network := network.WhichNetworkContains(ip)
					Expect(network).To(BeNil())
				},
				Entry("When it is not in any network", "10.10.0.0"),
				Entry("When it is not in any network", "10.30.50.50"),
				Entry("When it is not in any network", "10.200.255.255"),
			)
		})
	})
})
