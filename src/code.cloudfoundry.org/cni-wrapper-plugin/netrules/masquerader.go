package netrules

import (
	"fmt"
	"net/http"
	"time"

	"code.cloudfoundry.org/cf-networking-helpers/json_client"
	"code.cloudfoundry.org/cni-wrapper-plugin/lib"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/silk/daemon"
)

type Masquerader struct {
	ContainerIP                 string
	CustomNoMasqueradeCIDRRange string
	DaemonPort                  string
	VTEPName                    string
	PluginController            *lib.PluginController
	lease                       string
}

func (m *Masquerader) AddIPMasq() error {
	noMasqCidr, err := m.getNoMasqueradeCIDRRange()
	if err != nil {
		return err
	}
	return m.PluginController.AddIPMasq(m.ContainerIP, noMasqCidr, m.VTEPName)
}

func (m *Masquerader) DelIPMasq() error {
	noMasqCidr, err := m.getNoMasqueradeCIDRRange()
	if err != nil {
		return err
	}
	return m.PluginController.DelIPMasq(m.ContainerIP, noMasqCidr, m.VTEPName)
}

func (m *Masquerader) getNoMasqueradeCIDRRange() (string, error) {
	if m.CustomNoMasqueradeCIDRRange != "" {
		return m.CustomNoMasqueradeCIDRRange, nil
	}
	return m.getLease()
}

func (m *Masquerader) getLease() (string, error) {
	if m.lease == "" {
		lease, err := m.getLeaseFromDaemon()
		if err == nil {
			m.lease = lease
		}
		return lease, err
	}

	return m.lease, nil
}

func (m *Masquerader) getLeaseFromDaemon() (string, error) {
	daemonClient := json_client.New(lager.NewLogger("masquerader"), http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%s", m.DaemonPort))
	maxAttempts := 5
	attemptDelay := 500 * time.Millisecond
	respData := daemon.NetworkInfo{}
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = daemonClient.Do("GET", "/", nil, &respData, "")
		if err == nil {
			break
		}

		if attempt == maxAttempts {
			return "", fmt.Errorf("failed to get lease from silk daemon after %d attempts: %s", attempt, err)
		}

		time.Sleep(attemptDelay)
	}
	return respData.OverlaySubnet, nil
}
