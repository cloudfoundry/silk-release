package policy_client

type Policies struct {
	TotalPolicies int      `json:"total_policies"`
	Policies      []Policy `json:"policies"`
}

type Policy struct {
	Source      Source      `json:"source"`
	Destination Destination `json:"destination"`
}

type EgressPolicy struct {
	Source       *EgressSource      `json:"source"`
	Destination  *EgressDestination `json:"destination"`
	AppLifecycle string             `json:"app_lifecycle"`
}

type EgressSource struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type EgressDestination struct {
	Protocol string    `json:"protocol"`
	Ports    []Ports   `json:"ports"`
	IPRanges []IPRange `json:"ips"`
	ICMPType int       `json:"icmp_type"`
	ICMPCode int       `json:"icmp_code"`
}

type IPRange struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type Source struct {
	ID  string `json:"id"`
	Tag string `json:"tag,omitempty"`
}

type Destination struct {
	ID       string `json:"id"`
	Tag      string `json:"tag,omitempty"`
	Protocol string `json:"protocol"`
	Ports    Ports  `json:"ports"`
}

type Ports struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type Tag struct {
	ID  string `json:"id"`
	Tag string `json:"tag"`
}

type Space struct {
	Name    string `json:"name"`
	OrgGUID string `json:"organization_guid"`
}
