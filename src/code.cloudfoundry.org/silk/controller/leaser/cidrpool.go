package leaser

import (
	mcn "code.cloudfoundry.org/lib/multiple-cidr-network"
	"fmt"
	mathRand "math/rand"

	"github.com/ziutek/utils/netaddr"
)

type CIDRPool struct {
	blockPool  map[string]struct{}
	singlePool map[string]struct{}
}

func NewCIDRPool(subnetRanges []string, subnetMask int) *CIDRPool {

	if len(subnetRanges) == 0 {
		panic(fmt.Errorf("network must be provided"))
	}

	overlayNetworks, err := mcn.NewMultipleCIDRNetwork(subnetRanges)
	if err != nil {
		panic(fmt.Errorf("invalid overlay network: %s", err))
	}

	if subnetMask > 32 || subnetMask < 0 {
		panic(fmt.Errorf("subnet mask must be between [0-32]"))
	}

	return &CIDRPool{
		// #nosec - G115 - we check valid values above for IPv4 subnet masks
		blockPool: generateBlockPool(overlayNetworks, uint(subnetMask)),
		// #nosec - G115 - we check valid values above for IPv4 subnet masks
		singlePool: generateSingleIPPool(overlayNetworks, uint(subnetMask)),
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

func generateBlockPool(overlayNetworks mcn.MultipleCIDRNetwork, cidrMaskBlock uint) map[string]struct{} {
	pool := make(map[string]struct{})
	blockSize := 1 << (32 - cidrMaskBlock)

	// loop over all subnets
	for _, subnet := range overlayNetworks.Networks {
		// get the starting IP
		ipStart := subnet.IP

		// get the size of the mask
		cidrMask, _ := subnet.Mask.Size()
		fullRange := 1 << (32 - cidrMask)

		// for all subnets, skip over the first block, it is reserved for the
		// single IP pool and for setting up the networking between cells
		for i := blockSize; i < fullRange; i += blockSize {
			subnet := fmt.Sprintf("%s/%d", netaddr.IPAdd(ipStart, i), cidrMaskBlock)
			pool[subnet] = struct{}{}
		}
	}
	return pool
}

func generateSingleIPPool(overlayNetworks mcn.MultipleCIDRNetwork, cidrMaskBlock uint) map[string]struct{} {
	// Only use IPs from the 1st network. SingleIPs from different networks
	// can't talk to each other. We check above to make sure there is at leas
	// one, so it is safe to use the 0 index.
	firstNetwork := overlayNetworks.Networks[0]

	pool := make(map[string]struct{})
	blockSize := 1 << (32 - cidrMaskBlock)

	// Never create a lease from the first IP. This is used for setting up the
	// networking between the cells. That is why this starts at i := 1.
	for i := 1; i < blockSize; i++ {
		singleCIDR := fmt.Sprintf("%s/32", netaddr.IPAdd(firstNetwork.IP, i))
		pool[singleCIDR] = struct{}{}
	}

	return pool
}
