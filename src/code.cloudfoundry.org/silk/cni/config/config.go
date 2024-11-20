package config

import (
	"net"

	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
)

//go:generate counterfeiter -o fakes/netNS.go --fake-name NetNS . netNS
type netNS interface {
	ns.NetNS
}

type DualAddress struct {
	Hardware net.HardwareAddr
	IP       net.IP
}

type Config struct {
	Container struct {
		DeviceName          string
		TemporaryDeviceName string
		Namespace           netNS
		Address             DualAddress
		AddressIPv6         DualAddress
		MTU                 int
		Routes              []*types.Route
		RoutesIPv6          []*types.Route
	}
	Host struct {
		DeviceName  string
		Namespace   netNS
		Address     DualAddress
		AddressIPv6 DualAddress
	}
	ipv6Enabled bool
}

func (c *Config) AsCNIResult() *current.Result {
	ipInterface := 1

	result := &current.Result{
		Interfaces: []*current.Interface{
			{
				Name:    c.Host.DeviceName,
				Mac:     c.Host.Address.Hardware.String(),
				Sandbox: "",
			},
			{
				Name:    c.Container.DeviceName,
				Mac:     c.Container.Address.Hardware.String(),
				Sandbox: c.Container.Namespace.Path(),
			},
		},
		IPs: []*current.IPConfig{
			{
				Interface: &ipInterface,
				Address: net.IPNet{
					IP:   c.Container.Address.IP,
					Mask: []byte{255, 255, 255, 255},
				},
				Gateway: c.Host.Address.IP,
			},
		},
		Routes: c.Container.Routes,
		DNS:    types.DNS{},
	}

	if c.ipv6Enabled {
		ipv6 := &current.IPConfig{
			Interface: &ipInterface,
			Address: net.IPNet{
				IP:   c.Container.AddressIPv6.IP,
				Mask: net.CIDRMask(128, 128),
			},
			Gateway: c.Host.AddressIPv6.IP,
		}

		result.IPs = append(result.IPs, ipv6)
	}

	return result
}

func (c *Config) IPV6Enabled() bool {
	return c.ipv6Enabled
}
