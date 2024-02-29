package config

import (
	"encoding/json"
	"fmt"
	"os"

	cnilib "code.cloudfoundry.org/cni-wrapper-plugin/lib"
	loggingclient "code.cloudfoundry.org/diego-logging-client"
	validator "gopkg.in/validator.v2"
)

type VxlanPolicyAgent struct {
	PollInterval                  int                       `json:"poll_interval" validate:"nonzero"`
	EnableASGSyncing              bool                      `json:"enable_asg_syncing"`
	ASGPollInterval               int                       `json:"asg_poll_interval" validate:"min=1"`
	Datastore                     string                    `json:"cni_datastore_path" validate:"nonzero"`
	PolicyServerURL               string                    `json:"policy_server_url" validate:"min=1"`
	VNI                           int                       `json:"vni" validate:"nonzero"`
	MetronAddress                 string                    `json:"metron_address" validate:"nonzero"`
	ServerCACertFile              string                    `json:"ca_cert_file" validate:"nonzero"`
	ClientCertFile                string                    `json:"client_cert_file" validate:"nonzero"`
	ClientKeyFile                 string                    `json:"client_key_file" validate:"nonzero"`
	ClientTimeoutSeconds          int                       `json:"client_timeout_seconds" validate:"nonzero"`
	IPTablesLockFile              string                    `json:"iptables_lock_file" validate:"nonzero"`
	DebugServerHost               string                    `json:"debug_server_host" validate:"nonzero"`
	DebugServerPort               int                       `json:"debug_server_port" validate:"nonzero"`
	LogLevel                      string                    `json:"log_level"`
	LogPrefix                     string                    `json:"log_prefix" validate:"nonzero"`
	IPTablesLogging               bool                      `json:"iptables_c2c_logging"`
	IPTablesAcceptedUDPLogsPerSec int                       `json:"iptables_accepted_udp_logs_per_sec" validate:"min=1"`
	EnableOverlayIngressRules     bool                      `json:"enable_overlay_ingress_rules"`
	ForcePolicyPollCyclePort      int                       `json:"force_policy_poll_cycle_port" validate:"nonzero"`
	ForcePolicyPollCycleHost      string                    `json:"force_policy_poll_cycle_host" validate:"nonzero"`
	DisableContainerNetworkPolicy bool                      `json:"disable_container_network_policy"`
	OverlayNetwork                string                    `json:"overlay_network"`
	UnderlayIPs                   []string                  `json:"underlay_ips"`
	IPTablesASGLogging            bool                      `json:"iptables_asg_logging"`
	IPTablesDeniedLogsPerSec      int                       `json:"iptables_denied_logs_per_sec"`
	DenyNetworks                  cnilib.DenyNetworksConfig `json:"deny_networks"`
	OutConn                       cnilib.OutConnConfig      `json:"outbound_connections"`
	LoggregatorConfig             loggingclient.Config      `json:"loggregator"`
}

func (c *VxlanPolicyAgent) Validate() error {
	return validator.Validate(c)
}

func New(configFilePath string) (*VxlanPolicyAgent, error) {
	cfg := &VxlanPolicyAgent{}
	if _, err := os.Stat(configFilePath); err != nil {
		return cfg, fmt.Errorf("file does not exist: %s", err)
	}

	configBytes, err := os.ReadFile(configFilePath)
	if err != nil {
		return cfg, fmt.Errorf("reading config file: %s", err)
	}

	err = json.Unmarshal(configBytes, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("parsing config (%s): %s", configFilePath, err)
	}

	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("invalid config: %s", err)
	}

	return cfg, nil
}
