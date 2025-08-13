package daemon

type NetworkInfo struct {
	OverlaySubnet string `json:"overlay_subnet"`
	MTU           int    `json:"mtu"`
	IPv6Prefix    string `json:"ipv6_prefix,omitempty"`
}
