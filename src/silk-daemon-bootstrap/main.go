package main

import (
	"flag"
	"fmt"
	"lib/common"
	policyClient "lib/policy_client"
	"lib/rules"
	"log"
	"net/http"
	"silk-daemon-bootstrap/config"
	"sync"
	"time"

	"code.cloudfoundry.org/cf-networking-helpers/mutualtls"
	"code.cloudfoundry.org/filelock"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lager/lagerflags"
	"github.com/coreos/go-iptables/iptables"
)

const (
	ClientTimeoutSeconds = 5 * time.Second
	IngressChainName     = "istio-ingress"
	jobPrefix            = "silk-daemon-bootstrap"
	logPrefix            = "cfnetworking"
)

func main() {
	if err := mainWithError(); err != nil {
		log.Fatalf("silk-daemon-bootstrap: %s", err)
	}
}

func mainWithError() error {
	configFilePath := flag.String("config", "", "path to config file")
	flag.Parse()

	bootstrapConfig, err := config.New(*configFilePath)
	if err != nil {
		return err
	}

	logger, _ := lagerflags.NewFromConfig(fmt.Sprintf("%s.%s", logPrefix, jobPrefix), common.GetLagerConfig())

	if bootstrapConfig.SingleIPOnly {
		internalClient, err := createPolicyClient(bootstrapConfig, logger.Session("policy-client"))
		if err != nil {
			return err
		}

		tag, err := getTagFromPolicyServer(internalClient)
		if err != nil {
			return err
		}

		ipTablesAdapter, err := createIpTablesAdapter(bootstrapConfig.IPTablesLockFile)
		if err != nil {
			return err
		}

		err = createNewChain(ipTablesAdapter)
		if err != nil {
			return err
		}

		return addOverlayAccessMarkRule(ipTablesAdapter, tag)
	}

	return nil
}

func createNewChain(ipTablesAdapter rules.IPTablesAdapter) error {
	// NewChain only returns an error if the chain already exists, so we ignore it :(
	ipTablesAdapter.NewChain("filter", IngressChainName)

	jumpRule := rules.IPTablesRule{
		"-j", IngressChainName,
	}
	exists, err := ipTablesAdapter.Exists("filter", "OUTPUT", jumpRule)
	if err == nil && !exists {
		return ipTablesAdapter.BulkInsert("filter", "OUTPUT", 1, jumpRule)
	}

	return err
}

func createPolicyClient(bootstrapConfig *config.SilkDaemonBootstrap, logger lager.Logger) (*policyClient.InternalClient, error) {
	clientTLSConfig, err := mutualtls.NewClientTLSConfig(bootstrapConfig.PolicyClientCertFile, bootstrapConfig.PolicyClientKeyFile, bootstrapConfig.PolicyServerCACertFile)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
		},
		Timeout: ClientTimeoutSeconds,
	}

	return policyClient.NewInternal(
		logger,
		httpClient,
		bootstrapConfig.PolicyServerURL,
	), nil
}

func getTagFromPolicyServer(policyClient *policyClient.InternalClient) (string, error) {
	tag, err := policyClient.CreateOrGetTag("INGRESS_ROUTER", "router")
	if err != nil {
		return "", err
	}
	return tag, nil
}

func createIpTablesAdapter(iptablesLockFile string) (rules.IPTablesAdapter, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}

	iptLocker := &filelock.Locker{
		FileLocker: filelock.NewLocker(iptablesLockFile),
		Mutex:      &sync.Mutex{},
	}

	tables := &rules.LockedIPTables{
		IPTables: ipt,
		Locker:   iptLocker,
		Restorer: &rules.Restorer{},
	}

	return tables, nil
}

func addOverlayAccessMarkRule(iptables rules.IPTablesAdapter, tag string) error {
	overlayAccessMarkRule := rules.NewOverlayAccessMarkRule(tag)
	exists, err := iptables.Exists("filter", IngressChainName, overlayAccessMarkRule)
	if err == nil && !exists {
		err = iptables.BulkAppend("filter", IngressChainName, overlayAccessMarkRule)
		if err != nil {
			return err
		}
	}
	overlayAccessAllowRule := rules.IPTablesRule{"-o", "silk-vtep", "-j", "ACCEPT"}
	exists, err = iptables.Exists("filter", IngressChainName, overlayAccessAllowRule)
	if err == nil && !exists {
		err = iptables.BulkAppend("filter", IngressChainName, overlayAccessAllowRule)
		if err != nil {
			return err
		}
	}

	return err
}
