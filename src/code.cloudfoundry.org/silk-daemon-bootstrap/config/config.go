package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type SilkDaemonBootstrap struct {
	PolicyServerURL        string `json:"policy_server_url"`
	PolicyServerCACertFile string `json:"policy_server_ca_cert_file"`
	PolicyClientCertFile   string `json:"policy_client_cert_file"`
	PolicyClientKeyFile    string `json:"policy_client_key_file"`
	IPTablesLockFile       string `json:"iptables_lock_file"`
	SingleIPOnly           bool   `json:"single_ip_only"`
}

func New(configFilePath string) (*SilkDaemonBootstrap, error) {
	contents, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, fmt.Errorf("file does not exist: %s", err)
	}

	var silkDaemonBootstrap SilkDaemonBootstrap
	err = json.Unmarshal(contents, &silkDaemonBootstrap)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %s", err)
	}

	return &silkDaemonBootstrap, nil
}
