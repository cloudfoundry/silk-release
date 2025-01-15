package multiple_cidr_network

import (
	"net"
)

type MultipleCIDRNetwork struct {
	Networks     []*net.IPNet
	SmallestMask int
}

func NewMultipleCIDRNetwork(cidrs []string) (MultipleCIDRNetwork, error) {
	var networks []*net.IPNet
	smallestMask := 0
	for i, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return MultipleCIDRNetwork{}, err
		}
		networks = append(networks, n)

		maskSize, _ := n.Mask.Size()
		if i == 0 {
			smallestMask = maskSize
		} else if maskSize > smallestMask { // because masks are backwards 32 is smaller than 24
			smallestMask = maskSize
		}
	}

	return MultipleCIDRNetwork{
		Networks:     networks,
		SmallestMask: smallestMask,
	}, nil
}

func (m *MultipleCIDRNetwork) Contains(ip net.IP) bool {
	for _, n := range m.Networks {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

func (m *MultipleCIDRNetwork) Length() int {
	return len(m.Networks)
}

func (m *MultipleCIDRNetwork) WhichNetworkContains(ip net.IP) *net.IPNet {
	for _, n := range m.Networks {
		if n.Contains(ip) {
			return n
		}
	}
	return nil
}
