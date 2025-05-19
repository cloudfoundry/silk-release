package leaser_test

import (
	"net"

	"code.cloudfoundry.org/silk/controller/leaser"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CIDRPool", func() {

	Describe("NewCIDRPool", func() {
		DescribeTable("panics when invalid CIDRs are provided",
			func(subnetRange []string, subnetMask, expectedSize int) {
				shouldPanic := func() {
					leaser.NewCIDRPool(subnetRange, subnetMask)
				}
				Expect(shouldPanic).To(PanicWith(MatchError(ContainSubstring("invalid CIDR address"))))
			},
			Entry("when the first ip is invalid", []string{"10.255.999.0/16"}, 24, 255),
			Entry("when an ip in the array is invalid", []string{"10.255.99.0/16", "10.250.999.0/16"}, 24, 255),
			Entry("when the first ip has an invalid mask", []string{"10.255.99.0/60", "10.250.99.0/16"}, 24, 255),
			Entry("when an ip in the array has an invalid mask", []string{"10.255.99.0/16", "10.250.99.0/199"}, 24, 255),
		)

		DescribeTable("panics when invalid subnetMask is provided",
			func(subnetRange []string, subnetMask, expectedSize int) {
				shouldPanic := func() {
					leaser.NewCIDRPool(subnetRange, subnetMask)
				}
				Expect(shouldPanic).To(PanicWith(MatchError(ContainSubstring("subnet mask must be between [0-32]"))))
			},
			Entry("when subnet mask is > 32", []string{"10.255.99.0/16"}, 40, 255),
			Entry("when subnet mask is < 0 ", []string{"10.255.99.0/16"}, -1, 255),
		)

		Context("when there are no networks provided", func() {
			It("panics", func() {
				shouldPanic := func() {
					leaser.NewCIDRPool([]string{}, 24)
				}
				Expect(shouldPanic).To(PanicWith(MatchError(ContainSubstring("network must be provided"))))
			})
		})
	})

	Describe("BlockPoolSize", func() {
		DescribeTable("returns the number of subnets that can be allocated",
			func(subnetRange []string, subnetMask, expectedSize int) {
				cidrPool := leaser.NewCIDRPool(subnetRange, subnetMask)
				Expect(cidrPool.BlockPoolSize()).To(Equal(expectedSize))
			},
			// /16 = 65536 ; /24 = 256 ; 65536 / 256 = 256 ; 256 - 1 (first block is excluded) = 255
			Entry("when the range is /16 and mask is /24", []string{"10.255.0.0/16"}, 24, 255),

			// /16 = 65536 ; /20 = 4096 ; 65536 / 4096 = 16 ; 16 - 1 (first block is excluded) = 15
			Entry("when the range is /16 and mask is /20", []string{"10.255.0.0/16"}, 20, 15),

			// /16 = 65536 ; /16 = 65536 ; 65536 / 65536 = 1 ; 1 - 1 (first block is excluded) = 0
			Entry("when the range is /16 and mask is /16", []string{"10.255.0.0/16"}, 16, 0),

			// /16 x2 = 65536 x2 = 131072 ; /24 = 256 ; 131072 / 256 = 512
			// 512 - 2 (first block of each network is excluded) = 510
			Entry("when there are multiple /16 ranges and mask is /24", []string{"10.255.0.0/16", "10.250.0.0/16"}, 24, 510),

			// /16 = 65536 ; /23 = 512 ; 65536 + 512 = 66048 ; /24 = 256 ;
			// 66048 / 256 = 258 ; 258 - 2 (first block of each network is excluded) = 256
			Entry("when there are multiple different sized ranges and mask is /24", []string{"10.255.0.0/16", "10.250.0.0/23"}, 24, 256),
		)

		DescribeTable("produces valid subnets within the correct range",
			func(overlayCIDR []string, subnetMask, expectedNumBlockPools int) {
				networks := getNetworks(overlayCIDR)
				cidrPool := leaser.NewCIDRPool(overlayCIDR, subnetMask)

				numCheckedBlockPools := 0
				for blockDividedCIDR := range cidrPool.GetBlockPool() {
					numCheckedBlockPools++
					_, blockNetwork, _ := net.ParseCIDR(blockDividedCIDR)
					Expect(oneNetworkContains(networks, blockNetwork.IP)).Should(BeTrue())
				}

				Expect(numCheckedBlockPools).To(Equal(expectedNumBlockPools))
			},

			// /12 = 1048576 ; /24 = 256 ; 1048576 / 256 = 4096 ; 4096 - 1 (first block is excluded) = 4095
			Entry("when ip is in the start of the cidr range", []string{"10.240.0.0/12"}, 24, 4095),
			Entry("when ip is in the middle of the cidr range", []string{"10.255.0.0/12"}, 24, 4095),
			Entry("when ip is in the end of the cidr range", []string{"10.255.255.255/12"}, 24, 4095),

			// /16 x2 = 65536 x2 = 131072 ; /24 = 256 ; 131072 / 256 = 512
			// 512 - 2 (first block of each network is excluded) = 510
			Entry("when there is an array of networks", []string{"10.255.0.0/16", "10.250.0.0/16"}, 24, 510),
		)
	})

	Describe("SingleIPPoolSize", func() {
		DescribeTable("returns the number of subnets that can be allocated",
			func(subnetRange []string, subnetMask, expectedSize int) {
				cidrPool := leaser.NewCIDRPool(subnetRange, subnetMask)
				Expect(cidrPool.SingleIPPoolSize()).To(Equal(expectedSize))
			},
			// /25 = 128, -1 for the first IP which is never allocated.
			Entry("when the range is /16 and mask is /25", []string{"10.255.0.0/16"}, 25, 127),

			// /26 = 64, -1 for the first IP which is never allocated.
			Entry("when the range is /16 and mask is /26", []string{"10.255.0.0/16"}, 26, 63),

			// /27 = 32, -1 for the first IP which is never allocated.
			Entry("when the range is /16 and mask is /27", []string{"10.255.0.0/16"}, 27, 31),

			// /27 = 32, because we get one single IP subnet block from the first overlay network.
			// -1 for the first IP of the single IP subnet block which is never allocated.
			Entry("when there are multiple ranges and mask is /27", []string{"10.255.0.0/24", "10.250.0.0/16"}, 27, 31),
		)

		It("produces valid subnet starting with the first IP of the first provided cidr", func() {
			firstNetwork := "10.240.0.0/12" // 10.240.0.0 - 10.255.255.255
			secondNetwork := "10.20.0.0/16" // 10.20.0.0 - 10.20.255.255
			overlayCIDR := []string{firstNetwork, secondNetwork}
			subnetMask := 24
			firstSubnetOfFirstNetwork := "10.240.0.0/24"
			firstSubnetOfSecondNetwork := "10.20.0.0/24"

			cidrPool := leaser.NewCIDRPool(overlayCIDR, subnetMask)
			_, expectedSingleIPNetworkPart1, _ := net.ParseCIDR(firstSubnetOfFirstNetwork)
			_, expectedSingleIPNetworkPart2, _ := net.ParseCIDR(firstSubnetOfSecondNetwork)

			for singleIPCIDR := range cidrPool.GetSinglePool() {
				_, singleIPNetwork, _ := net.ParseCIDR(singleIPCIDR)

				inFirstSubnetOfFirstNetwork := expectedSingleIPNetworkPart1.Contains(singleIPNetwork.IP)
				inFirstSubnetOfSecondNetwork := expectedSingleIPNetworkPart2.Contains(singleIPNetwork.IP)

				Expect(inFirstSubnetOfFirstNetwork).To(BeTrue())
				Expect(inFirstSubnetOfSecondNetwork).To(BeFalse())
			}
		})
	})

	DescribeTable("GetAvailableBlock",
		func(subnetMaskSize, expectedNumBlockLeases int, expectedLeaseMask net.IPMask) {

			overlayNetwork1String := "10.255.0.0/16"
			overlayNetwork2String := "10.250.0.0/16"
			overlayNetworkStrings := []string{overlayNetwork1String, overlayNetwork2String}
			overlayNetwork1 := getNetworks(overlayNetworkStrings)[0]
			overlayNetwork2 := getNetworks(overlayNetworkStrings)[1]
			cidrPool := leaser.NewCIDRPool(overlayNetworkStrings, subnetMaskSize)

			var taken []string
			for i := 1; i <= expectedNumBlockLeases; i++ {
				By("testing that there are still leases left")
				lease := cidrPool.GetAvailableBlock(taken)
				Expect(lease).ToNot(Equal(""))

				By("testing that the lease is a valid subnet")
				leaseIP, leaseSubnet, err := net.ParseCIDR(lease)
				Expect(err).NotTo(HaveOccurred())

				By("testing that the leaseIP is in the first or second overlayNetwork")
				inOverlayNetwork1 := overlayNetwork1.Contains(leaseIP)
				inOverlayNetwork2 := overlayNetwork2.Contains(leaseIP)
				Expect([]bool{inOverlayNetwork1, inOverlayNetwork2}).To(ContainElements([]bool{true, false}))

				By("testing the mask size")
				Expect(leaseSubnet.Mask).To(Equal(expectedLeaseMask))

				By("testing that the first IP is never allocated")
				Expect(leaseIP.To4()).NotTo(Equal(overlayNetwork1.IP.To4()))
				Expect(leaseIP.To4()).NotTo(Equal(overlayNetwork2.IP.To4()))

				taken = append(taken, lease)
			}

			By("double checking that there are the correct number of leases")
			Expect(taken).To(HaveLen(expectedNumBlockLeases))

			By("testing that there are no more leases left")
			lease := cidrPool.GetAvailableBlock(taken)
			Expect(lease).To(Equal(""))

			By("testing that all of the leases are unique")
			for index1, i := range taken {
				for index2, j := range taken {
					if index1 == index2 {
						continue
					}
					Expect(i).ToNot(Equal(j))
				}
			}
		},
		// /16 x2 = 65536 x2 = 131072 ; /24 = 256 ; 131072 / 256 = 512
		// 512 - 2 (first block of each network is excluded) = 510
		Entry("When the subnet mask is 24", 24, 510, net.IPMask{255, 255, 255, 0}),
		// /16 x2 = 65536 x2 = 131072 ; /20 = 4096 ; 131072 / 4096 = 32
		// 32 - 2 (first block of each network is excluded) = 30
		Entry("When the subnet mask is 20", 20, 30, net.IPMask{255, 255, 240, 0}),
	)

	DescribeTable("GetAvailableSingleIP",
		func(subnetMaskSize, expectedNumSingleIPLeases int) {

			overlayNetwork1String := "10.255.0.0/16"
			overlayNetwork2String := "10.250.0.0/16"
			overlayNetworkStrings := []string{overlayNetwork1String, overlayNetwork2String}
			overlayNetwork1 := getNetworks(overlayNetworkStrings)[0]
			overlayNetwork2 := getNetworks(overlayNetworkStrings)[1]
			cidrPool := leaser.NewCIDRPool(overlayNetworkStrings, subnetMaskSize)

			var taken []string
			for i := 1; i <= expectedNumSingleIPLeases; i++ {
				By("testing that there are still leases left")
				lease := cidrPool.GetAvailableSingleIP(taken)
				Expect(lease).ToNot(Equal(""))

				By("testing that the lease is a valid subnet")
				leaseIP, leaseSubnet, err := net.ParseCIDR(lease)
				Expect(err).NotTo(HaveOccurred())

				By("testing that the leaseIP is in the first overlayNetwork")
				Expect(overlayNetwork1.Contains(leaseIP)).To(BeTrue())

				By("testing that the leaseIP is not in the second overlayNetwork")
				Expect(overlayNetwork2.Contains(leaseIP)).To(BeFalse())

				By("testing that the mask is always /32")
				Expect(leaseSubnet.Mask).To(Equal(net.IPMask{255, 255, 255, 255}))

				By("testing that the first IP is never allocated")
				Expect(leaseIP.To4()).NotTo(Equal(overlayNetwork1.IP.To4()))

				taken = append(taken, lease)
			}

			By("double checking that there are the correct number of leases")
			Expect(taken).To(HaveLen(expectedNumSingleIPLeases))

			By("testing that there are no more leases left")
			lease := cidrPool.GetAvailableSingleIP(taken)
			Expect(lease).To(Equal(""))

			By("testing that all of the leases are unique")
			for index1, i := range taken {
				for index2, j := range taken {
					if index1 == index2 {
						continue
					}
					Expect(i).ToNot(Equal(j))
				}
			}
		},
		Entry("When the subnet mask is 24", 24, 255),
		Entry("When the subnet mask is 29", 29, 7),
	)

	Describe("IsMember", func() {
		var cidrPool *leaser.CIDRPool
		BeforeEach(func() {
			subnetRange := []string{"10.255.0.0/16", "10.250.0.0/16"}
			cidrPool = leaser.NewCIDRPool(subnetRange, 24)
		})

		Context("when the subnet is in the block pool and not in the single pool", func() {
			Context("when it is in the first cidr", func() {
				It("returns true", func() {
					Expect(cidrPool.IsMember("10.255.30.0/24")).To(BeTrue())
				})
			})

			Context("when it is in the second cidr", func() {
				It("returns true", func() {
					Expect(cidrPool.IsMember("10.250.30.0/24")).To(BeTrue())
				})
			})
		})

		Context("when the IP is in the first subnet of the first overlayNetwork", func() {
			It("is in the singleIP pool and returns true", func() {
				Expect(cidrPool.IsMember("10.255.0.5/32")).To(BeTrue())
			})
		})

		Context("when the IP is in the first subnet of the 2nd+ overlayNetwork", func() {
			It("is not in either the singleIP pool or block pool and returns false", func() {
				Expect(cidrPool.IsMember("10.250.0.5/32")).To(BeFalse())
			})
		})

		Context("when the subnet start is not a match for an entry", func() {
			It("returns false", func() {
				Expect(cidrPool.IsMember("10.255.30.10/24")).To(BeFalse())
			})
		})

		Context("when the subnet size is not a match", func() {
			It("returns false", func() {
				Expect(cidrPool.IsMember("10.255.30.0/20")).To(BeFalse())
			})
		})
	})
})

func getNetworks(cidrStrings []string) []*net.IPNet {
	networks := []*net.IPNet{}
	for _, c := range cidrStrings {
		_, overlayNetwork, _ := net.ParseCIDR(c)
		networks = append(networks, overlayNetwork)
	}
	return networks
}

func oneNetworkContains(networks []*net.IPNet, ip net.IP) bool {
	found := false

	for _, network := range networks {
		if network.Contains(ip) {
			if found == true {
				panic("ip should not be in multipe blocks")
			}
			found = true
		}
	}

	return found
}
