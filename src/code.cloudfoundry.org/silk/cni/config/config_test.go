package config_test

import (
	"net"

	"code.cloudfoundry.org/silk/cni/config"
	"code.cloudfoundry.org/silk/cni/lib/fakes"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func expectValidIPv4Result(result *current.Result, cfg *config.Config) {
	Expect(result.Interfaces).To(HaveLen(2))
	Expect(result.Interfaces[0]).To(Equal(&current.Interface{
		Name:    cfg.Host.DeviceName,
		Mac:     cfg.Host.Address.Hardware.String(),
		Sandbox: "",
	}))
	Expect(result.Interfaces[1]).To(Equal(&current.Interface{
		Name:    cfg.Container.DeviceName,
		Mac:     cfg.Container.Address.Hardware.String(),
		Sandbox: cfg.Container.Namespace.Path(),
	}))

	if !cfg.IPV6Enabled() {
		Expect(result.IPs).To(HaveLen(1))
	} else {
		Expect(result.IPs).To(HaveLen(2))
	}

	index := result.IPs[0].Interface
	Expect(result.Interfaces[*index].Name).To(Equal(cfg.Container.DeviceName))
	Expect(result.IPs[0].Address.String()).To(Equal(cfg.Container.Address.IP.String() + "/32"))
	Expect(result.IPs[0].Gateway.String()).To(Equal(cfg.Host.Address.IP.String()))

	Expect(result.Routes).To(ContainElements(cfg.Container.Routes))
}

var _ = Describe("Config", func() {
	var (
		enableIPv6      bool
		containerConfig *config.ContainerConfig
		hostConfig      *config.HostConfig
		cfg             *config.Config
	)

	BeforeEach(func() {
		fakeNamespace := &fakes.NetNS{}
		fakeNamespace.PathReturns("/some/namespace")
		containerConfig = &config.ContainerConfig{
			DeviceName: "container-device-name",
			Namespace:  fakeNamespace,
			Address: config.DualAddress{
				IP:       net.IP{10, 255, 30, 5},
				Hardware: net.HardwareAddr{0x01, 0x02, 0x03, 0x0A, 0xBC, 0xDE},
			},
			MTU: 1234,
			Routes: []*types.Route{
				&types.Route{
					Dst: net.IPNet{
						IP:   net.IP{1, 1, 0, 0},
						Mask: []byte{255, 255, 255, 255},
					},
					GW: net.IP{1, 1, 0, 0},
				},
			},
		}

		hostConfig = &config.HostConfig{
			DeviceName: "host-device-name",
			Address: config.DualAddress{
				IP:       net.IP{169, 254, 0, 1},
				Hardware: net.HardwareAddr{0xdd, 0xdd, 0x03, 0x0A, 0xBC, 0xDE},
			},
		}
	})

	JustBeforeEach(func() {
		cfg = config.NewConfig(*containerConfig, *hostConfig, enableIPv6)
	})

	AfterEach(func() {
		cfg.Container.Namespace.Close()
	})

	Describe("AsCNIResult", func() {
		It("returns a CNI v0.3.0 result that represents the config", func() {
			result := cfg.AsCNIResult()
			expectValidIPv4Result(result, cfg)
		})

		Context("when IPv6 is enabled", func() {
			BeforeEach(func() {
				enableIPv6 = true
				containerConfig.AddressIPv6.IP = net.ParseIP("2001::1")
				containerConfig.AddressIPv6.Hardware = net.HardwareAddr{0x01, 0x02, 0x03, 0x0A, 0xBC, 0xDE}
				hostConfig.AddressIPv6.IP = net.ParseIP("fe80::1")
				containerConfig.RoutesIPv6 = []*types.Route{
					{
						Dst: net.IPNet{
							IP:   net.IPv6zero,
							Mask: net.CIDRMask(0, 128),
						},
						GW: hostConfig.AddressIPv6.IP,
					}}
			})

			It("returns a CNI v0.3.0 result with correct IPv4 config", func() {
				result := cfg.AsCNIResult()
				// Make sure enabling IPv6 doesnt break IPv4
				expectValidIPv4Result(result, cfg)
			})

			It("returns a CNI v0.3.0 result with correct IPv6 addresses", func() {
				result := cfg.AsCNIResult()
				Expect(result.IPs[1].Address.String()).To(Equal(cfg.Container.AddressIPv6.IP.String() + "/128"))
				Expect(result.IPs[1].Gateway.String()).To(Equal(cfg.Host.AddressIPv6.IP.String()))
				Expect(result.Routes).To(ContainElements(cfg.Container.RoutesIPv6))
			})
		})
	})
})
