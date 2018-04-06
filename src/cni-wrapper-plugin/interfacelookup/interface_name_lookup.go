package interfacelookup

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

//go:generate counterfeiter -o ../fakes/netlinklink.go --fake-name NetlinkLink . netlinkLink
type netlinkLink interface {
	Attrs() *netlink.LinkAttrs
	Type() string
}

//go:generate counterfeiter -o ../fakes/netlinkadapter.go --fake-name NetlinkAdapter . netlinkAdapter
type netlinkAdapter interface {
	LinkList() ([]netlink.Link, error)
	AddrList(link netlink.Link, family int) ([]netlink.Addr, error)
}

type InterfaceNameLookup struct {
	NetlinkAdapter netlinkAdapter
}

func (i InterfaceNameLookup) GetNameFromIP(ip string) (string, error) {
	links, err := i.NetlinkAdapter.LinkList()
	if err != nil {
		return "", fmt.Errorf("discover interface names: %s", err)
	}

	for _, link := range links {
		addresses, err := i.NetlinkAdapter.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return "", fmt.Errorf("failed to get underlay interface name by link for %s: %s", link.Attrs().Name, err)
		}

		for _, addr := range addresses {
			if net.ParseIP(ip).Equal(addr.IP) {
				return link.Attrs().Name, nil
			}
		}
	}

	return "", fmt.Errorf("unable to find link with ip addr: %s", ip)
}
