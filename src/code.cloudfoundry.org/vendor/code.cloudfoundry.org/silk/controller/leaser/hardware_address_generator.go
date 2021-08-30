package leaser

import (
	"net"

	"github.com/containernetworking/plugins/pkg/utils/hwaddr"
)

type HardwareAddressGenerator struct{}

func (g *HardwareAddressGenerator) GenerateForVTEP(containerIP net.IP) (net.HardwareAddr, error) {
	return hwaddr.GenerateHardwareAddr4(containerIP, []byte{0xee, 0xee})
}
