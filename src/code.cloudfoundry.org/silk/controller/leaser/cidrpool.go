package leaser

import (
	"fmt"
	mathRand "math/rand"
	"net"

	"github.com/ziutek/utils/netaddr"
)

type CIDRPool struct {
	blockPool  map[string]struct{}
	singlePool map[string]struct{}
}

func NewCIDRPool(subnetRange string, subnetMask int) *CIDRPool {
	_, ipCIDR, err := net.ParseCIDR(subnetRange)
	if err != nil {
		panic(err)
	}
	cidrMask, _ := ipCIDR.Mask.Size()

	if cidrMask > 32 || cidrMask < 0 {
		panic(fmt.Errorf("subnet range's CIDR mask must be between [0-32]"))
	}
	if subnetMask > 32 || subnetMask < 0 {
		panic(fmt.Errorf("subnet mask must be between [0-32]"))
	}

	return &CIDRPool{
		// #nosec - G115 - we check valid values above for IPv4 subnet masks
		blockPool: generateBlockPool(ipCIDR.IP, uint(cidrMask), uint(subnetMask)),
		// #nosec - G115 - we check valid values above for IPv4 subnet masks
		singlePool: generateSingleIPPool(ipCIDR.IP, uint(subnetMask)),
	}
}

func (c *CIDRPool) GetBlockPool() map[string]struct{} {
	return c.blockPool
}

func (c *CIDRPool) GetSinglePool() map[string]struct{} {
	return c.singlePool
}

func (c *CIDRPool) BlockPoolSize() int {
	return len(c.blockPool)
}

func (c *CIDRPool) SingleIPPoolSize() int {
	return len(c.singlePool)
}

func (c *CIDRPool) GetAvailableBlock(taken []string) string {
	return getAvailable(taken, c.blockPool)
}

func (c *CIDRPool) GetAvailableSingleIP(taken []string) string {
	return getAvailable(taken, c.singlePool)
}

func (c *CIDRPool) IsMember(subnet string) bool {
	_, blockOk := c.blockPool[subnet]
	_, singleOk := c.singlePool[subnet]
	return blockOk || singleOk
}

func getAvailable(taken []string, pool map[string]struct{}) string {
	available := make(map[string]struct{})
	for k, v := range pool {
		available[k] = v
	}
	for _, subnet := range taken {
		delete(available, subnet)
	}
	if len(available) == 0 {
		return ""
	}
	i := mathRand.Intn(len(available))
	n := 0
	for subnet := range available {
		if i == n {
			return subnet
		}
		n++
	}
	return ""
}

func generateBlockPool(ipStart net.IP, cidrMask, cidrMaskBlock uint) map[string]struct{} {
	pool := make(map[string]struct{})
	fullRange := 1 << (32 - cidrMask)
	blockSize := 1 << (32 - cidrMaskBlock)
	for i := blockSize; i < fullRange; i += blockSize {
		subnet := fmt.Sprintf("%s/%d", netaddr.IPAdd(ipStart, i), cidrMaskBlock)
		pool[subnet] = struct{}{}
	}
	return pool
}

func generateSingleIPPool(ipStart net.IP, cidrMaskBlock uint) map[string]struct{} {
	pool := make(map[string]struct{})
	blockSize := 1 << (32 - cidrMaskBlock)
	for i := 1; i < blockSize; i++ {
		singleCIDR := fmt.Sprintf("%s/32", netaddr.IPAdd(ipStart, i))
		pool[singleCIDR] = struct{}{}
	}
	return pool
}
