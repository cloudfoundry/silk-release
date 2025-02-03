package lib_test

import (
	"errors"
	"net"

	"code.cloudfoundry.org/lager/v3/lagertest"
	"code.cloudfoundry.org/silk/cni/config"
	"code.cloudfoundry.org/silk/cni/lib"
	"code.cloudfoundry.org/silk/cni/lib/fakes"
	"github.com/containernetworking/cni/pkg/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Container Setup", func() {
	var (
		containerNS        *fakes.NetNS
		cfg                *config.Config
		fakeLinkOperations *fakes.LinkOperations
		fakeCommon         *fakes.Common
		containerSetup     *lib.Container
		containerAddr      config.DualAddress
		hostAddr           config.DualAddress
		fakeLogger         *lagertest.TestLogger
	)

	BeforeEach(func() {
		fakeLinkOperations = &fakes.LinkOperations{}
		fakeCommon = &fakes.Common{}
		fakeLogger = lagertest.NewTestLogger("test")
		containerNS = &fakes.NetNS{}
		containerNS.DoStub = lib.NetNsDoStub

		containerAddr = config.DualAddress{IP: net.IP{10, 255, 30, 4}}
		hostAddr = config.DualAddress{IP: net.IP{169, 254, 0, 1}}

		cfg = &config.Config{}
		cfg.Container.DeviceName = "eth0"
		cfg.Container.Namespace = containerNS
		cfg.Container.TemporaryDeviceName = "someTemporaryDeviceName"
		cfg.Container.Address = containerAddr
		cfg.Host.Address = hostAddr
		cfg.Container.Routes = []*types.Route{
			&types.Route{
				Dst: net.IPNet{
					IP:   []byte{50, 51, 52, 53},
					Mask: []byte{255, 255, 255, 255},
				},
			},
			&types.Route{
				Dst: net.IPNet{
					IP:   []byte{150, 151, 152, 153},
					Mask: []byte{255, 255, 255, 255},
				},
				GW: net.IP{10, 150, 25, 2},
			},
			&types.Route{
				Dst: net.IPNet{
					IP:   []byte{250, 251, 252, 0},
					Mask: []byte{255, 255, 255, 0},
				},
				GW: net.IP{10, 250, 25, 2},
			},
		}

		containerSetup = &lib.Container{
			Common:         fakeCommon,
			LinkOperations: fakeLinkOperations,
			Logger:         fakeLogger,
		}
	})

	Describe("Setup", func() {
		It("renames the device and calls basic setup in the container namespace", func() {
			err := containerSetup.Setup(cfg)
			Expect(err).NotTo(HaveOccurred())

			Expect(fakeLinkOperations.RenameLinkCallCount()).To(Equal(1))
			oldName, newName := fakeLinkOperations.RenameLinkArgsForCall(0)
			Expect(oldName).To(Equal("someTemporaryDeviceName"))
			Expect(newName).To(Equal("eth0"))

			Expect(fakeCommon.BasicSetupCallCount()).To(Equal(1))
			device, local, peer := fakeCommon.BasicSetupArgsForCall(0)
			Expect(device).To(Equal("eth0"))
			Expect(local).To(Equal(containerAddr))
			Expect(peer).To(Equal(hostAddr))

			By("Adding all the routes")
			Expect(fakeLinkOperations.RouteAddAllCallCount()).To(Equal(1))
			routes, srcIP := fakeLinkOperations.RouteAddAllArgsForCall(0)
			Expect(routes).To(Equal(cfg.Container.Routes))
			Expect(srcIP).To(Equal(cfg.Container.Address.IP))
		})

		Context("when renaming the link fails", func() {
			BeforeEach(func() {
				fakeLinkOperations.RenameLinkReturns(errors.New("asparagus"))
			})
			It("returns a meaningful error", func() {
				err := containerSetup.Setup(cfg)
				Expect(err).To(MatchError("renaming link in container: asparagus"))
			})
		})

		Context("when the basic device setup fails", func() {
			BeforeEach(func() {
				fakeCommon.BasicSetupReturns(errors.New("lettuce"))
			})
			It("returns a meaningful error", func() {
				err := containerSetup.Setup(cfg)
				Expect(err).To(MatchError("setting up device in container: lettuce"))
			})
		})

		Context("when adding the routes fails", func() {
			BeforeEach(func() {
				fakeLinkOperations.RouteAddAllReturns(errors.New("lettuce"))
			})
			It("returns a meaningful error", func() {
				err := containerSetup.Setup(cfg)
				Expect(err).To(MatchError("adding route in container: lettuce"))
			})
		})
	})

	Describe("SetupIPv6", func() {
		var (
			containerAddrIPv6 config.DualAddress
			hostAddrIPv6      config.DualAddress
		)

		BeforeEach(func() {
			containerAddrIPv6 = config.DualAddress{IP: net.ParseIP("2001:db8::1")}
			hostAddrIPv6 = config.DualAddress{IP: net.ParseIP("fe80::1")}

			cfg.Container.AddressIPv6 = containerAddrIPv6
			cfg.Host.AddressIPv6 = hostAddrIPv6
			cfg.Container.RoutesIPv6 = []*types.Route{
				{
					GW: net.ParseIP("fe80::1"),
				},
				{
					GW: net.ParseIP("fe80::2"),
				},
				{
					GW: net.ParseIP("fe80::3"),
				},
			}
		})

		It("calls basic setup in the container namespace", func() {
			err := containerSetup.SetupIPv6(cfg)
			Expect(err).NotTo(HaveOccurred())

			Expect(fakeCommon.BasicSetupIPv6CallCount()).To(Equal(1))
			device, local, peer := fakeCommon.BasicSetupIPv6ArgsForCall(0)
			Expect(device).To(Equal("eth0"))
			Expect(local).To(Equal(containerAddrIPv6))
			Expect(peer).To(Equal(hostAddrIPv6))

			By("Adding all the routes")
			Expect(fakeLinkOperations.Route6AddAllCallCount()).To(Equal(1))
			routes, deviceName := fakeLinkOperations.Route6AddAllArgsForCall(0)
			Expect(routes).To(Equal(cfg.Container.RoutesIPv6))
			Expect(deviceName).To(Equal(cfg.Container.DeviceName))
		})

		Context("when the basic device setup fails", func() {
			BeforeEach(func() {
				fakeCommon.BasicSetupIPv6Returns(errors.New("lettuce"))
			})

			It("returns a meaningful error", func() {
				err := containerSetup.SetupIPv6(cfg)
				Expect(err).To(MatchError("setting up IPv6 device in container: lettuce"))
			})
		})

		Context("when adding the routes fails", func() {
			BeforeEach(func() {
				fakeLinkOperations.Route6AddAllReturns(errors.New("lettuce"))
			})

			It("returns a meaningful error", func() {
				err := containerSetup.SetupIPv6(cfg)
				Expect(err).To(MatchError("adding IPv6 route in container: lettuce"))
			})
		})
	})

	Describe("Teardown", func() {
		It("deletes the link in the specified namespace and device name", func() {
			err := containerSetup.Teardown(containerNS, "eth0")
			Expect(err).NotTo(HaveOccurred())

			Expect(fakeLinkOperations.DeleteLinkByNameCallCount()).To(Equal(1))
			Expect(fakeLinkOperations.DeleteLinkByNameArgsForCall(0)).To(Equal("eth0"))
		})

		Context("when deleting the link fails", func() {
			BeforeEach(func() {
				fakeLinkOperations.DeleteLinkByNameReturns(errors.New("eggplant"))
			})
			It("returns a meaningul error", func() {
				err := containerSetup.Teardown(containerNS, "eth0")
				Expect(err).To(MatchError("deleting link: eggplant"))
			})
		})
	})
})
