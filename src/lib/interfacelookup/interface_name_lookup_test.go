package interfacelookup_test

import (
	"cni-wrapper-plugin/fakes"
	"errors"
	"lib/interfacelookup"
	"net"

	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("InterfaceNameLookup", func() {
	var (
		interfaceNameLookup interfacelookup.InterfaceNameLookup

		netlinkLinkEth0 *fakes.NetlinkLink
		netlinkLinkEth1 *fakes.NetlinkLink
		eth0Addr        netlink.Addr
		eth1Addr        netlink.Addr

		netlinkAdapter *fakes.NetlinkAdapter
	)

	BeforeEach(func() {
		netlinkLinkEth0 = &fakes.NetlinkLink{}
		netlinkLinkEth0.AttrsReturns(&netlink.LinkAttrs{
			Name: "eth0",
		})
		netlinkLinkEth1 = &fakes.NetlinkLink{}
		netlinkLinkEth1.AttrsReturns(&netlink.LinkAttrs{
			Name: "eth1",
		})

		eth0Addr = netlink.Addr{
			IPNet: &net.IPNet{
				IP: net.IPv4(10, 0, 0, 0),
			},
		}
		eth1Addr = netlink.Addr{
			IPNet: &net.IPNet{
				IP: net.IPv4(10, 0, 0, 1),
			},
		}

		netlinkAdapter = &fakes.NetlinkAdapter{}
		netlinkAdapter.LinkListReturns([]netlink.Link{
			netlinkLinkEth0,
			netlinkLinkEth1,
		}, nil)
		netlinkAdapter.AddrListStub = func(link netlink.Link, family int) ([]netlink.Addr, error) {
			if link.Attrs().Name == "eth0" {
				return []netlink.Addr{eth0Addr}, nil
			}
			if link.Attrs().Name == "eth1" {
				return []netlink.Addr{eth1Addr}, nil
			}

			return []netlink.Addr{}, nil
		}

		interfaceNameLookup = interfacelookup.InterfaceNameLookup{
			NetlinkAdapter: netlinkAdapter,
		}
	})

	Describe("GetNameFromIP", func() {
		It("returns an interface name provided an ip", func() {
			interfaceName, err := interfaceNameLookup.GetNameFromIP("10.0.0.0")
			Expect(err).NotTo(HaveOccurred())

			Expect(netlinkAdapter.LinkListCallCount()).To(Equal(1))

			linkArg, familyArg := netlinkAdapter.AddrListArgsForCall(0)
			Expect(linkArg).To(Equal(netlinkLinkEth0))
			Expect(familyArg).To(Equal(netlink.FAMILY_V4))
			Expect(interfaceName).To(Equal("eth0"))
		})

		Context("when an interface with the provided ip address cannot be found", func() {
			It("returns an error", func() {
				_, err := interfaceNameLookup.GetNameFromIP("10.0.0.2")
				Expect(err).To(MatchError("unable to find link with ip addr: 10.0.0.2"))
			})
		})

		Context("when it fails to fetch the LinkList", func() {
			BeforeEach(func() {
				netlinkAdapter.LinkListReturnsOnCall(0, []netlink.Link{}, errors.New("sad meow"))
			})

			It("returns an error", func() {
				_, err := interfaceNameLookup.GetNameFromIP("10.0.0.0")
				Expect(err).To(MatchError("discover interface names: sad meow"))
			})
		})

		Context("when it fails to fetch the AddrList", func() {
			BeforeEach(func() {
				netlinkAdapter.AddrListReturnsOnCall(0, []netlink.Addr{}, errors.New("sad meow"))
			})

			It("returns an error", func() {
				_, err := interfaceNameLookup.GetNameFromIP("10.0.0.0")
				Expect(err).To(MatchError("failed to get underlay interface name by link for eth0: sad meow"))
			})
		})
	})

	Describe("GetNamesFromIPs", func() {
		It("returns a list of names", func() {
			names, err := interfaceNameLookup.GetNamesFromIPs([]string{"10.0.0.0", "10.0.0.1"})
			Expect(err).NotTo(HaveOccurred())
			Expect(names).To(Equal([]string{"eth0", "eth1"}))
		})

		Context("when GetNameFromIP fails", func() {
			It("returns an error", func() {
				_, err := interfaceNameLookup.GetNamesFromIPs([]string{"10.0.0.2"})
				Expect(err).To(MatchError("unable to find link with ip addr: 10.0.0.2"))
			})
		})
	})
})
