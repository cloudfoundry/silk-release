package adapter

import "github.com/vishvananda/netlink"

type NetlinkAdapter struct{}

func (a *NetlinkAdapter) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return netlink.RouteList(link, family)
}

func (a *NetlinkAdapter) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return netlink.AddrList(link, family)
}

func (a *NetlinkAdapter) LinkList() ([]netlink.Link, error) {
	return netlink.LinkList()
}
