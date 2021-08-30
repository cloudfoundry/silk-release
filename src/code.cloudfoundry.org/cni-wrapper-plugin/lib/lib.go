package lib

import (
	"encoding/json"
	"fmt"
	"code.cloudfoundry.org/lib/rules"

	"code.cloudfoundry.org/garden"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
	"gopkg.in/validator.v2"
)

type RuntimeConfig struct {
	PortMappings []garden.NetIn      `json:"portMappings"`
	NetOutRules  []garden.NetOutRule `json:"netOutRules"`
}

type DenyNetworksConfig struct {
	Always  []string `json:"always"`
	Running []string `json:"running"`
	Staging []string `json:"staging"`
}

type WrapperConfig struct {
	Datastore                       string                 `json:"datastore"`
	DatastoreFileOwner              string                 `json:"datastore_file_owner"`
	DatastoreFileGroup              string                 `json:"datastore_file_group"`
	IPTablesLockFile                string                 `json:"iptables_lock_file"`
	Delegate                        map[string]interface{} `json:"delegate"`
	InstanceAddress                 string                 `json:"instance_address"`
	NoMasqueradeCIDRRange           string                 `json:"no_masquerade_cidr_range"`
	DNSServers                      []string               `json:"dns_servers"`
	HostTCPServices                 []string               `json:"host_tcp_services"`
	HostUDPServices                 []string               `json:"host_udp_services"`
	DenyNetworks                    DenyNetworksConfig     `json:"deny_networks"`
	UnderlayIPs                     []string               `json:"underlay_ips"`
	TemporaryUnderlayInterfaceNames []string               `json:"temporary_underlay_interface_names"`
	IPTablesASGLogging              bool                   `json:"iptables_asg_logging"`
	IPTablesC2CLogging              bool                   `json:"iptables_c2c_logging"`
	IPTablesDeniedLogsPerSec        int                    `json:"iptables_denied_logs_per_sec" validate:"min=1"`
	IPTablesAcceptedUDPLogsPerSec   int                    `json:"iptables_accepted_udp_logs_per_sec" validate:"min=1"`
	IngressTag                      string                 `json:"ingress_tag"`
	VTEPName                        string                 `json:"vtep_name"`
	RuntimeConfig                   RuntimeConfig          `json:"runtimeConfig,omitempty"`
	PolicyAgentForcePollAddress     string                 `json:"policy_agent_force_poll_address" validate:"nonzero"`
}

func LoadWrapperConfig(bytes []byte) (*WrapperConfig, error) {
	n := &WrapperConfig{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("loading wrapper config: %v", err)
	}

	if n.Datastore == "" {
		return nil, fmt.Errorf("missing datastore path")
	}

	if n.IPTablesLockFile == "" {
		return nil, fmt.Errorf("missing iptables lock file path")
	}

	if n.InstanceAddress == "" {
		return nil, fmt.Errorf("missing instance address")
	}

	if len(n.UnderlayIPs) < 1 {
		return nil, fmt.Errorf("missing underlay ips")
	}

	if n.IngressTag == "" {
		return nil, fmt.Errorf("missing ingress tag")
	}

	if n.VTEPName == "" {
		return nil, fmt.Errorf("missing vtep device name")
	}

	if n.IPTablesDeniedLogsPerSec <= 0 {
		return nil, fmt.Errorf("invalid denied logs per sec")
	}

	if n.IPTablesAcceptedUDPLogsPerSec <= 0 {
		return nil, fmt.Errorf("invalid accepted udp logs per sec")
	}

	if _, ok := n.Delegate["cniVersion"]; !ok {
		n.Delegate["cniVersion"] = version.Current()
	}

	validator.Validate(n)

	return n, nil
}

type PluginController struct {
	Delegator Delegator
	IPTables  rules.IPTablesAdapter
}

func getDelegateParams(netconf map[string]interface{}) (string, []byte, error) {
	netconfBytes, err := json.Marshal(netconf)
	if err != nil {
		return "", nil, fmt.Errorf("serializing delegate netconf: %v", err)
	}

	delegateType, ok := (netconf["type"]).(string)
	if !ok {
		return "", nil, fmt.Errorf("delegate config is missing type")
	}

	return delegateType, netconfBytes, nil
}

func (c *PluginController) DelegateAdd(netconf map[string]interface{}) (types.Result, error) {
	delegateType, netconfBytes, err := getDelegateParams(netconf)
	if err != nil {
		return nil, err
	}

	return c.Delegator.DelegateAdd(delegateType, netconfBytes)
}

func (c *PluginController) DelegateDel(netconf map[string]interface{}) error {
	delegateType, netconfBytes, err := getDelegateParams(netconf)
	if err != nil {
		return err
	}

	return c.Delegator.DelegateDel(delegateType, netconfBytes)
}

func (c *PluginController) AddIPMasq(ip, noMasqueradeCIDRRange, deviceName string) error {
	rule := rules.NewDefaultEgressRule(ip, noMasqueradeCIDRRange, deviceName)

	if err := c.IPTables.BulkAppend("nat", "POSTROUTING", rule); err != nil {
		return err
	}

	return nil
}

func (c *PluginController) DelIPMasq(ip, noMasqueradeCIDRRange, deviceName string) error {
	rule := rules.NewDefaultEgressRule(ip, noMasqueradeCIDRRange, deviceName)

	if err := c.IPTables.Delete("nat", "POSTROUTING", rule); err != nil {
		return err
	}

	return nil
}
