package vtep_test

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/lager/v3/lagertest"
	mcn "code.cloudfoundry.org/lib/multiple-cidr-network"
	"code.cloudfoundry.org/silk/controller"
	"code.cloudfoundry.org/silk/daemon/vtep"
	"code.cloudfoundry.org/silk/daemon/vtep/fakes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var _ = Describe("Converger", func() {
	var (
		fakeNetlink                                                  *fakes.NetlinkAdapter
		converger                                                    *vtep.Converger
		leases                                                       []controller.Lease
		overlayNetworks                                              mcn.MultipleCIDRNetwork
		logger                                                       *lagertest.TestLogger
		localMac                                                     net.HardwareAddr
		remoteMac                                                    net.HardwareAddr
		remoteMacOnSecondNetwork                                     net.HardwareAddr
		singleIPMacOnFirstNetwork                                    net.HardwareAddr
		singleIPMacOnSecondNetwork                                   net.HardwareAddr
		localVTEP                                                    net.Interface
		remoteLeaseOnNetwork1, remoteLeaseOnNetwork2                 controller.Lease
		remoteSingleIPLeaseOnNetwork1, remoteSingleIPLeaseOnNetwork2 controller.Lease
	)

	Describe("Converge", func() {
		BeforeEach(func() {
			var err error
			fakeNetlink = &fakes.NetlinkAdapter{}

			overlayNetworks, err = mcn.NewMultipleCIDRNetwork([]string{"10.255.0.0/16", "10.250.0.0/16"})
			Expect(err).ToNot(HaveOccurred())

			logger = lagertest.NewTestLogger("test")
			localVTEP = net.Interface{
				Index: 42,
				Name:  "silk-vtep",
			}

			localMac, _ = net.ParseMAC("ee:ee:aa:bb:cc:dd")
			remoteMac, _ = net.ParseMAC("ee:ee:aa:aa:aa:ff")
			remoteMacOnSecondNetwork, _ = net.ParseMAC("cc:cc:cc:cc:cc:cc")
			singleIPMacOnFirstNetwork, _ = net.ParseMAC("aa:bb:bb:bb:bb:bb")
			singleIPMacOnSecondNetwork, _ = net.ParseMAC("ab:bb:bb:bb:bb:bb")

			remoteLeaseOnNetwork1 = controller.Lease{
				UnderlayIP:          "10.10.0.5",
				OverlaySubnet:       "10.255.19.0/24", // on network 1 - 10.255.0.0/16
				OverlayHardwareAddr: remoteMac.String(),
			}
			remoteLeaseOnNetwork2 = controller.Lease{
				UnderlayIP:          "10.10.0.7",
				OverlaySubnet:       "10.250.50.0/24", // on network 2 - 10.250.0.0/16
				OverlayHardwareAddr: remoteMacOnSecondNetwork.String(),
			}
			remoteSingleIPLeaseOnNetwork1 = controller.Lease{
				UnderlayIP:          "10.10.0.9",
				OverlaySubnet:       "10.255.1.11/32", // single IP lease on network 1 - 10.255.0.0/16
				OverlayHardwareAddr: singleIPMacOnFirstNetwork.String(),
			}
			remoteSingleIPLeaseOnNetwork2 = controller.Lease{
				UnderlayIP:          "10.10.0.11",
				OverlaySubnet:       "10.255.50.11/32", // single IP lease on network 2 - 10.250.0.0/16
				OverlayHardwareAddr: singleIPMacOnSecondNetwork.String(),
			}

		})

		Context("when the local lease is SingleIP", func() {
			var (
				localOverlayIP    string
				localOverlayLease *net.IPNet
			)
			BeforeEach(func() {
				localOverlayIP = "10.255.0.66"
				_, localOverlayLease, _ = net.ParseCIDR(fmt.Sprintf("%s/32", localOverlayIP))

				converger = &vtep.Converger{
					OverlayNetwork: overlayNetworks,
					LocalSubnet:    localOverlayLease,
					LocalVTEP:      localVTEP,
					NetlinkAdapter: fakeNetlink,
					Logger:         logger,
					IsSingleIP:     true,
				}

				localLease := controller.Lease{
					UnderlayIP:          "10.10.0.4",
					OverlaySubnet:       fmt.Sprintf("%s/32", localOverlayIP),
					OverlayHardwareAddr: localMac.String(),
				}

				leases = []controller.Lease{
					localLease,
					remoteLeaseOnNetwork1,
					remoteLeaseOnNetwork2,
					remoteSingleIPLeaseOnNetwork1,
					remoteSingleIPLeaseOnNetwork2,
				}
			})

			It("adds routing rule for each non-single IP remote lease with a src", func() {
				err := converger.Converge(leases)
				Expect(err).NotTo(HaveOccurred())

				// RouteReplace Call count is called once for each non-SingleIP lease
				Expect(fakeNetlink.RouteReplaceCallCount()).To(Equal(2))

				addedRoute := fakeNetlink.RouteReplaceArgsForCall(0)
				destGW, destNet, _ := net.ParseCIDR(remoteLeaseOnNetwork1.OverlaySubnet)
				Expect(addedRoute).To(Equal(&netlink.Route{
					LinkIndex: 42,
					Scope:     netlink.SCOPE_UNIVERSE,
					Dst:       destNet, // 10.255.19.0/24
					Gw:        destGW,  // 10.255.19.0
					Flags:     unix.RTNH_F_ONLINK,
					Src:       localOverlayLease.IP, // in the same overlay cidr, so it gets the local IP
				}))

				_, network2cidr, _ := net.ParseCIDR("10.250.0.0/16")
				addedRoute = fakeNetlink.RouteReplaceArgsForCall(1)
				destGW, destNet, _ = net.ParseCIDR(remoteLeaseOnNetwork2.OverlaySubnet)
				Expect(addedRoute).To(Equal(&netlink.Route{
					LinkIndex: 42,
					Scope:     netlink.SCOPE_UNIVERSE,
					Dst:       destNet, // 10.250.50.0/24
					Gw:        destGW,  // 10.250.50.0
					Flags:     unix.RTNH_F_ONLINK,
					Src:       network2cidr.IP, // on a different overlay idr, so it gets the first IP of the entire cidr
				}))
			})
		})

		Context("when the local lease is non-SingleIP", func() {
			var (
				localOverlayLease *net.IPNet
			)
			BeforeEach(func() {
				_, localOverlayLease, _ = net.ParseCIDR("10.255.32.0/24")
				converger = &vtep.Converger{
					OverlayNetwork: overlayNetworks,
					LocalSubnet:    localOverlayLease,
					LocalVTEP:      localVTEP,
					NetlinkAdapter: fakeNetlink,
					Logger:         logger,
					IsSingleIP:     false,
				}

				localLease := controller.Lease{
					UnderlayIP:          "10.10.0.4",
					OverlaySubnet:       "10.255.32.0/24", // local subnet on network 1
					OverlayHardwareAddr: localMac.String(),
				}

				leases = []controller.Lease{
					localLease,
					remoteLeaseOnNetwork1,
					remoteLeaseOnNetwork2,
					remoteSingleIPLeaseOnNetwork1,
					remoteSingleIPLeaseOnNetwork2,
				}
			})

			It("adds routing rule for each non-single IP remote lease", func() {
				err := converger.Converge(leases)
				Expect(err).NotTo(HaveOccurred())

				By("testing that the remote leases are added")
				Expect(fakeNetlink.RouteReplaceCallCount()).To(Equal(2))
				addedRoute := fakeNetlink.RouteReplaceArgsForCall(0)
				destGW, destNet, _ := net.ParseCIDR("10.255.19.0/24")
				Expect(addedRoute).To(Equal(&netlink.Route{
					LinkIndex: 42,
					Scope:     netlink.SCOPE_UNIVERSE,
					Dst:       destNet,              // 10.255.19.0/24
					Gw:        destGW,               // 10.255.19.0
					Src:       localOverlayLease.IP, //10.255.32.0 - local IP because it is in the same overlay CIDR
				}))

				addedRoute = fakeNetlink.RouteReplaceArgsForCall(1)
				destGW, destNet, _ = net.ParseCIDR("10.250.50.0/24")
				Expect(addedRoute).To(Equal(&netlink.Route{
					LinkIndex: 42,
					Scope:     netlink.SCOPE_UNIVERSE,
					Dst:       destNet,                        // 10.250.50.0/24
					Gw:        destGW,                         // 10.250.50.0
					Src:       overlayNetworks.Networks[1].IP, // in a different CIDR - so use the IP of that CIDR
				}))
			})

			It("adds an ARP and FDB rule for each remote lease, including singleIP leases", func() {
				err := converger.Converge(leases)
				Expect(err).NotTo(HaveOccurred())

				Expect(fakeNetlink.NeighSetCallCount()).To(Equal(8)) // called twice per remote lease
				neighs := []*netlink.Neigh{
					fakeNetlink.NeighSetArgsForCall(0),
					fakeNetlink.NeighSetArgsForCall(1),
					fakeNetlink.NeighSetArgsForCall(2),
					fakeNetlink.NeighSetArgsForCall(3),
					fakeNetlink.NeighSetArgsForCall(4),
					fakeNetlink.NeighSetArgsForCall(5),
					fakeNetlink.NeighSetArgsForCall(6),
					fakeNetlink.NeighSetArgsForCall(7),
				}
				Expect(neighs).To(ConsistOf(
					&netlink.Neigh{
						LinkIndex:    42,
						State:        netlink.NUD_PERMANENT,
						Type:         syscall.RTN_UNICAST,
						IP:           net.ParseIP("10.255.19.0"),
						HardwareAddr: remoteMac,
					},
					&netlink.Neigh{
						LinkIndex:    42,
						State:        netlink.NUD_PERMANENT,
						Family:       syscall.AF_BRIDGE,
						Flags:        netlink.NTF_SELF,
						IP:           net.ParseIP("10.10.0.5"),
						HardwareAddr: remoteMac,
					},
					&netlink.Neigh{
						LinkIndex:    42,
						State:        netlink.NUD_PERMANENT,
						Type:         syscall.RTN_UNICAST,
						IP:           net.ParseIP("10.250.50.0"),
						HardwareAddr: remoteMacOnSecondNetwork,
					},
					&netlink.Neigh{
						LinkIndex:    42,
						State:        netlink.NUD_PERMANENT,
						Family:       syscall.AF_BRIDGE,
						Flags:        netlink.NTF_SELF,
						IP:           net.ParseIP("10.10.0.7"),
						HardwareAddr: remoteMacOnSecondNetwork,
					},
					&netlink.Neigh{ // singleIP on network 1 - ARP
						LinkIndex:    42,
						State:        netlink.NUD_PERMANENT,
						Type:         syscall.RTN_UNICAST,
						IP:           net.ParseIP("10.255.1.11"),
						HardwareAddr: singleIPMacOnFirstNetwork,
					},
					&netlink.Neigh{ // singleIP on network 1 - Bridge
						LinkIndex:    42,
						State:        netlink.NUD_PERMANENT,
						Family:       syscall.AF_BRIDGE,
						Flags:        netlink.NTF_SELF,
						IP:           net.ParseIP("10.10.0.9"),
						HardwareAddr: singleIPMacOnFirstNetwork,
					},
					&netlink.Neigh{ // singleIP on network 2 - ARP
						LinkIndex:    42,
						State:        netlink.NUD_PERMANENT,
						Type:         syscall.RTN_UNICAST,
						IP:           net.ParseIP("10.255.50.11"),
						HardwareAddr: singleIPMacOnSecondNetwork,
					},
					&netlink.Neigh{ // singleIP on network 2 - Bridge
						LinkIndex:    42,
						State:        netlink.NUD_PERMANENT,
						Family:       syscall.AF_BRIDGE,
						Flags:        netlink.NTF_SELF,
						IP:           net.ParseIP("10.10.0.11"),
						HardwareAddr: singleIPMacOnSecondNetwork,
					},
				))
			})

			It("does not log anything about non-routable leases", func() {
				err := converger.Converge(leases)
				Expect(err).NotTo(HaveOccurred())

				Expect(logger.Logs()).To(HaveLen(0))
			})

			Context("when a non-single IP remote lease is removed", func() {
				var (
					deletedNeighs []netlink.Neigh
					oldDestMac    net.HardwareAddr
				)
				BeforeEach(func() {
					destGW, destNet, _ := net.ParseCIDR("10.255.19.0/24")
					destGWOnSecondNetwork, destNetOnSecondNetwork, _ := net.ParseCIDR("10.250.50.0/24")

					oldDestMac, _ = net.ParseMAC("ee:ee:0a:ff:14:00")
					oldDestGW, oldDestNet, _ := net.ParseCIDR("10.250.20.0/24")

					fakeNetlink.FDBListReturns([]netlink.Neigh{
						netlink.Neigh{
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Family:       syscall.AF_BRIDGE,
							Flags:        netlink.NTF_SELF,
							IP:           net.ParseIP("10.10.0.5"),
							HardwareAddr: remoteMac,
						},
						netlink.Neigh{
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Family:       syscall.AF_BRIDGE,
							Flags:        netlink.NTF_SELF,
							IP:           net.ParseIP("10.10.0.7"),
							HardwareAddr: remoteMacOnSecondNetwork,
						},
						netlink.Neigh{
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Family:       syscall.AF_BRIDGE,
							Flags:        netlink.NTF_SELF,
							IP:           net.ParseIP("10.10.0.6"),
							HardwareAddr: oldDestMac,
						},
						netlink.Neigh{ // singleIP on network 1 - Bridge
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Family:       syscall.AF_BRIDGE,
							Flags:        netlink.NTF_SELF,
							IP:           net.ParseIP("10.10.0.9"),
							HardwareAddr: singleIPMacOnFirstNetwork,
						},
						netlink.Neigh{ // singleIP on network 2 - Bridge
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Family:       syscall.AF_BRIDGE,
							Flags:        netlink.NTF_SELF,
							IP:           net.ParseIP("10.10.0.11"),
							HardwareAddr: singleIPMacOnSecondNetwork,
						},
					}, nil)

					fakeNetlink.ARPListReturns([]netlink.Neigh{
						netlink.Neigh{
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Type:         syscall.RTN_UNICAST,
							IP:           net.ParseIP("10.255.19.0"),
							HardwareAddr: remoteMac,
						},
						netlink.Neigh{
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Type:         syscall.RTN_UNICAST,
							IP:           net.ParseIP("10.250.50.0"),
							HardwareAddr: remoteMacOnSecondNetwork,
						},
						netlink.Neigh{
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Type:         syscall.RTN_UNICAST,
							IP:           net.ParseIP("10.250.20.0"),
							HardwareAddr: oldDestMac,
						},
						netlink.Neigh{ // singleIP on network 1 - ARP
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Type:         syscall.RTN_UNICAST,
							IP:           net.ParseIP("10.255.1.11"),
							HardwareAddr: singleIPMacOnFirstNetwork,
						},
						netlink.Neigh{ // singleIP on network 2 - ARP
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Type:         syscall.RTN_UNICAST,
							IP:           net.ParseIP("10.255.50.11"),
							HardwareAddr: singleIPMacOnSecondNetwork,
						},
					}, nil)

					fakeNetlink.RouteListReturns([]netlink.Route{
						netlink.Route{
							LinkIndex: 42,
							Scope:     netlink.SCOPE_UNIVERSE,
							Dst:       destNet,
							Gw:        destGW,
							Src:       localOverlayLease.IP,
						},
						netlink.Route{
							LinkIndex: 42,
							Scope:     netlink.SCOPE_UNIVERSE,
							Dst:       overlayNetworks.Networks[0],
							Gw:        nil,
							Src:       localOverlayLease.IP,
						},
						netlink.Route{
							LinkIndex: 42,
							Scope:     netlink.SCOPE_UNIVERSE,
							Dst:       destNetOnSecondNetwork,
							Gw:        destGWOnSecondNetwork,
							Src:       overlayNetworks.Networks[1].IP,
						},
						netlink.Route{
							LinkIndex: 42,
							Scope:     netlink.SCOPE_UNIVERSE,
							Dst:       oldDestNet,
							Gw:        oldDestGW,
							Src:       overlayNetworks.Networks[1].IP,
						},
					}, nil)

					deletedNeighs = []netlink.Neigh{}
					fakeNetlink.NeighDelStub = func(neigh *netlink.Neigh) error {
						deletedNeighs = append(deletedNeighs, *neigh)
						return nil
					}
				})

				It("deletes the routing, ARP, and FDB rules related to the removed lease", func() {
					err := converger.Converge(leases)
					Expect(err).NotTo(HaveOccurred())

					By("checking that the route is deleted")
					Expect(fakeNetlink.RouteDelCallCount()).To(Equal(1))
					deletedRoute := fakeNetlink.RouteDelArgsForCall(0)
					destGW, destNet, _ := net.ParseCIDR("10.250.20.0/24")
					Expect(deletedRoute).To(Equal(&netlink.Route{
						LinkIndex: 42,
						Scope:     netlink.SCOPE_UNIVERSE,
						Dst:       destNet,
						Gw:        destGW,
						Src:       overlayNetworks.Networks[1].IP,
					}))

					By("checking that the ARP and FDB rules is deleted")
					Expect(fakeNetlink.NeighDelCallCount()).To(Equal(2))

					Expect(deletedNeighs).To(ConsistOf(
						// ARP
						netlink.Neigh{
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Type:         syscall.RTN_UNICAST,
							IP:           net.ParseIP("10.250.20.0"),
							HardwareAddr: oldDestMac,
						},
						// FDB
						netlink.Neigh{
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Family:       syscall.AF_BRIDGE,
							Flags:        netlink.NTF_SELF,
							IP:           net.ParseIP("10.10.0.6"),
							HardwareAddr: oldDestMac,
						},
					))
				})
			})

			Context("when a single IP remote lease is removed", func() {
				var (
					deletedNeighs []netlink.Neigh
					oldDestMac    net.HardwareAddr
					oldDestGW     net.IP
				)

				BeforeEach(func() {
					// Info for lease to be deleted
					// var oldDestNet *net.IPNet
					oldDestMac, _ = net.ParseMAC("cc:bb:bb:bb:bb:bb")
					oldDestGW, _, _ = net.ParseCIDR("10.250.0.55/32")

					fakeNetlink.FDBListReturns([]netlink.Neigh{
						netlink.Neigh{
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Family:       syscall.AF_BRIDGE,
							Flags:        netlink.NTF_SELF,
							IP:           net.ParseIP("10.10.0.5"),
							HardwareAddr: remoteMac,
						},
						netlink.Neigh{
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Family:       syscall.AF_BRIDGE,
							Flags:        netlink.NTF_SELF,
							IP:           net.ParseIP("10.10.0.7"),
							HardwareAddr: remoteMacOnSecondNetwork,
						},
						netlink.Neigh{ // singleIP to be deleted
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Family:       syscall.AF_BRIDGE,
							Flags:        netlink.NTF_SELF,
							IP:           net.ParseIP("10.10.0.55"),
							HardwareAddr: oldDestMac,
						},
						netlink.Neigh{ // singleIP on network 1 - Bridge
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Family:       syscall.AF_BRIDGE,
							Flags:        netlink.NTF_SELF,
							IP:           net.ParseIP("10.10.0.9"),
							HardwareAddr: singleIPMacOnFirstNetwork,
						},
						netlink.Neigh{ // singleIP on network 2 - Bridge
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Family:       syscall.AF_BRIDGE,
							Flags:        netlink.NTF_SELF,
							IP:           net.ParseIP("10.10.0.11"),
							HardwareAddr: singleIPMacOnSecondNetwork,
						},
					}, nil)

					fakeNetlink.ARPListReturns([]netlink.Neigh{
						netlink.Neigh{
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Type:         syscall.RTN_UNICAST,
							IP:           net.ParseIP("10.255.19.0"),
							HardwareAddr: remoteMac,
						},
						netlink.Neigh{
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Type:         syscall.RTN_UNICAST,
							IP:           net.ParseIP("10.250.50.0"),
							HardwareAddr: remoteMacOnSecondNetwork,
						},
						netlink.Neigh{ // Single IP to be deleted
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Type:         syscall.RTN_UNICAST,
							IP:           net.ParseIP("10.250.0.55"),
							HardwareAddr: oldDestMac,
						},
						netlink.Neigh{ // singleIP on network 1 - ARP
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Type:         syscall.RTN_UNICAST,
							IP:           net.ParseIP("10.255.1.11"),
							HardwareAddr: singleIPMacOnFirstNetwork,
						},
						netlink.Neigh{ // singleIP on network 2 - ARP
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Type:         syscall.RTN_UNICAST,
							IP:           net.ParseIP("10.255.50.11"),
							HardwareAddr: singleIPMacOnSecondNetwork,
						},
					}, nil)

					lease1IP, lease1CIDR, err := net.ParseCIDR("10.255.19.0/24")
					Expect(err).NotTo(HaveOccurred())
					lease2IP, lease2CIDR, err := net.ParseCIDR("10.250.50.0/24")
					Expect(err).NotTo(HaveOccurred())

					fakeNetlink.RouteListReturns([]netlink.Route{
						netlink.Route{
							LinkIndex: 42,
							Scope:     netlink.SCOPE_UNIVERSE,
							Dst:       lease1CIDR,
							Gw:        lease1IP,
							Src:       localOverlayLease.IP,
						},
						netlink.Route{
							LinkIndex: 42,
							Scope:     netlink.SCOPE_UNIVERSE,
							Dst:       lease2CIDR,
							Gw:        lease2IP,
							Src:       overlayNetworks.Networks[1].IP,
						},
					}, nil)

					deletedNeighs = []netlink.Neigh{}
					fakeNetlink.NeighDelStub = func(neigh *netlink.Neigh) error {
						deletedNeighs = append(deletedNeighs, *neigh)
						return nil
					}
				})

				It("deletes the ARP and FDB rules related to the removed lease", func() {
					err := converger.Converge(leases)
					Expect(err).NotTo(HaveOccurred())

					By("checking that no routes are deleted")
					Expect(fakeNetlink.RouteDelCallCount()).To(Equal(0))

					By("checking that the ARP and FDB rules is deleted")
					Expect(fakeNetlink.NeighDelCallCount()).To(Equal(2))

					Expect(deletedNeighs).To(ConsistOf(
						// ARP
						netlink.Neigh{
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Type:         syscall.RTN_UNICAST,
							IP:           oldDestGW,
							HardwareAddr: oldDestMac,
						},
						// FDB
						netlink.Neigh{
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Family:       syscall.AF_BRIDGE,
							Flags:        netlink.NTF_SELF,
							IP:           net.ParseIP("10.10.0.55"),
							HardwareAddr: oldDestMac,
						},
					))
				})
			})

			Context("when there are other routing rules", func() {
				BeforeEach(func() {
					fakeNetlink.RouteListReturns([]netlink.Route{
						netlink.Route{
							LinkIndex: 42,
							Scope:     netlink.SCOPE_UNIVERSE,
							Dst:       overlayNetworks.Networks[0],
							Gw:        nil,
						},
					}, nil)
				})

				It("does not delete rules it did not create", func() {
					err := converger.Converge(leases)
					Expect(err).NotTo(HaveOccurred())

					Expect(fakeNetlink.RouteDelCallCount()).To(Equal(0))
				})
			})

			Context("when the link cannot be found", func() {
				BeforeEach(func() {
					fakeNetlink.LinkByIndexReturns(nil, errors.New("passionfruit"))
				})

				It("breaks early and returns a meaningful error", func() {
					err := converger.Converge(leases)
					Expect(err).To(MatchError("link by index: passionfruit"))
				})
			})

			Context("when previous routes cannot be found", func() {
				BeforeEach(func() {
					fakeNetlink.RouteListReturns(nil, errors.New("peach"))
				})

				It("breaks early and returns a meaningful error", func() {
					err := converger.Converge(leases)
					Expect(err).To(MatchError("list routes: peach"))
				})
			})

			Context("when previous fdb entries cannot be found", func() {
				BeforeEach(func() {
					fakeNetlink.FDBListReturns(nil, errors.New("kiwi"))
				})

				It("breaks early and returns a meaningful error", func() {
					err := converger.Converge(leases)
					Expect(err).To(MatchError("list fdb: kiwi"))
				})
			})

			Context("when previous arp entries cannot be found", func() {
				BeforeEach(func() {
					fakeNetlink.ARPListReturns(nil, errors.New("lychee"))
				})

				It("breaks early and returns a meaningful error", func() {
					err := converger.Converge(leases)
					Expect(err).To(MatchError("list arp: lychee"))
				})
			})

			Context("when the lease subnet is malformed", func() {
				BeforeEach(func() {
					leases[1].OverlaySubnet = "banana"
				})
				It("breaks early and returns a meaningful error", func() {
					err := converger.Converge(leases)
					Expect(err).To(MatchError("parse lease: invalid CIDR address: banana"))
				})
			})

			Context("when the underlay IP is malformed", func() {
				BeforeEach(func() {
					leases[1].UnderlayIP = "kumquat"
				})
				It("breaks early and returns a meaningful error", func() {
					err := converger.Converge(leases)
					Expect(err).To(MatchError("invalid underlay ip: kumquat"))
				})
			})

			Context("when adding the route fails", func() {
				BeforeEach(func() {
					fakeNetlink.RouteReplaceReturns(errors.New("apricot"))
				})
				It("returns a meaningful error", func() {
					err := converger.Converge(leases)
					Expect(err).To(MatchError("add route: apricot"))
				})
			})

			Context("when adding a neigh fails", func() {
				BeforeEach(func() {
					fakeNetlink.NeighSetReturns(errors.New("pear"))
				})
				It("returns a meaningful error", func() {
					err := converger.Converge(leases)
					Expect(err).To(MatchError("set neigh: pear"))
				})
			})

			Context("when deleting the route fails", func() {
				BeforeEach(func() {
					fakeNetlink.RouteDelReturns(errors.New("durian"))

					destGW, destNet, _ := net.ParseCIDR("10.255.19.0/24")
					fakeNetlink.RouteListReturns([]netlink.Route{
						netlink.Route{
							LinkIndex: 42,
							Scope:     netlink.SCOPE_UNIVERSE,
							Dst:       destNet,
							Gw:        destGW,
						},
					}, nil)
				})
				It("returns a meaningful error", func() {
					err := converger.Converge([]controller.Lease{})
					Expect(err).To(MatchError("del route: durian"))
				})
			})

			Context("when deleting a neigh fails", func() {
				BeforeEach(func() {
					fakeNetlink.NeighDelReturns(errors.New("mango"))

					fakeNetlink.ARPListReturns([]netlink.Neigh{
						netlink.Neigh{
							LinkIndex:    42,
							State:        netlink.NUD_PERMANENT,
							Type:         syscall.RTN_UNICAST,
							IP:           net.ParseIP("10.255.19.0"),
							HardwareAddr: remoteMac,
						},
					}, nil)
				})
				It("returns a meaningful error", func() {
					err := converger.Converge([]controller.Lease{})
					Expect(err).To(MatchError("del neigh with ip/hwaddr 10.255.19.0 ee:ee:aa:aa:aa:ff: mango"))
				})
			})

			Context("when there are remote leases that are not in any overlay network CIDR", func() {
				BeforeEach(func() {
					leases = []controller.Lease{
						{ // local, skipped
							UnderlayIP:          "10.10.0.2",
							OverlaySubnet:       "10.255.32.0/24",
							OverlayHardwareAddr: "aa:aa:00:00:00:00",
						},
						{ // not in overlay, skipped
							UnderlayIP:          "10.10.0.3",
							OverlaySubnet:       "10.254.11.0/24",
							OverlayHardwareAddr: "aa:aa:00:00:00:01",
						},
						{ // not in overlay, skipped
							UnderlayIP:          "10.10.0.4",
							OverlaySubnet:       "10.254.12.0/24",
							OverlayHardwareAddr: "aa:aa:00:00:00:02",
						},
						{ // in overlay network 1: 10.255.0.0/16"
							UnderlayIP:          "10.10.0.5",
							OverlaySubnet:       "10.255.19.0/24",
							OverlayHardwareAddr: "aa:aa:00:00:00:03",
						},
						{ // in overlay network 2: 10.250.0.0/16"
							UnderlayIP:          "10.10.0.6",
							OverlaySubnet:       "10.250.19.0/24",
							OverlayHardwareAddr: "aa:aa:00:00:00:04",
						},
					}
				})

				It("does not touch them and adds only the leases in the overlay network", func() {
					err := converger.Converge(leases)
					Expect(err).NotTo(HaveOccurred())

					By("testing that routes were updated")
					Expect(fakeNetlink.RouteReplaceCallCount()).To(Equal(2))
					addedRoute := fakeNetlink.RouteReplaceArgsForCall(0)
					Expect(addedRoute.Dst.IP).To(Equal(net.ParseIP("10.255.19.0").To4()))
					addedRoute = fakeNetlink.RouteReplaceArgsForCall(1)
					Expect(addedRoute.Dst.IP).To(Equal(net.ParseIP("10.250.19.0").To4()))

					By("testing that ARP and FDB were updated")
					Expect(fakeNetlink.NeighSetCallCount()).To(Equal(4))
					addedARP := fakeNetlink.NeighSetArgsForCall(0)
					Expect(addedARP.IP).To(Equal(net.ParseIP("10.255.19.0")))
					addedFDB := fakeNetlink.NeighSetArgsForCall(1)
					Expect(addedFDB.IP).To(Equal(net.ParseIP("10.10.0.5")))
					addedARP = fakeNetlink.NeighSetArgsForCall(2)
					Expect(addedARP.IP).To(Equal(net.ParseIP("10.250.19.0")))
					addedFDB = fakeNetlink.NeighSetArgsForCall(3)
					Expect(addedFDB.IP).To(Equal(net.ParseIP("10.10.0.6")))

					Expect(logger.Logs()).To(HaveLen(1))
					Expect(logger.Logs()[0].LogLevel).To(Equal(lager.INFO))
					Expect(logger.Logs()[0].ToJSON()).To(MatchRegexp("converger.*non-routable-lease-count.*2"))
				})
			})

			Context("when a lease has an invalid MAC", func() {
				BeforeEach(func() {
					leases = []controller.Lease{
						{
							UnderlayIP:          "10.10.0.5",
							OverlaySubnet:       "10.255.19.0/24",
							OverlayHardwareAddr: "banana",
						},
					}
				})
				It("returns an error", func() {
					err := converger.Converge(leases)
					Expect(err).To(MatchError("invalid hardware addr: banana"))
				})
			})
		})
	})
})
