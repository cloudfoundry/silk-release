package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"code.cloudfoundry.org/lib/common"
	"code.cloudfoundry.org/lib/datastore"
	"code.cloudfoundry.org/lib/serial"
	"code.cloudfoundry.org/policy_client"

	"code.cloudfoundry.org/vxlan-policy-agent/config"
	"code.cloudfoundry.org/vxlan-policy-agent/planner"

	"code.cloudfoundry.org/cf-networking-helpers/metrics"
	"code.cloudfoundry.org/cf-networking-helpers/mutualtls"
	"code.cloudfoundry.org/filelock"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lager/lagerflags"
)

const (
	jobPrefix = "vxlan-policy-agent"
)

var (
	logPrefix = "cfnetworking"
)

func die(logger lager.Logger, action string, err error) {
	logger.Error(action, err)
	os.Exit(1)
}

func main() {
	configFilePath := flag.String("config-file", "", "path to config file")
	flag.Parse()

	conf, err := config.New(*configFilePath)
	if err != nil {
		log.Fatalf("%s: could not read config file %s", logPrefix, err)
	}

	logger, _ := lagerflags.NewFromConfig(fmt.Sprintf("%s.%s", logPrefix, jobPrefix), common.GetLagerConfig())

	logger.Info("parsed-config", lager.Data{"config": conf})

	logger.Info("starting")

	clientTLSConfig, err := mutualtls.NewClientTLSConfig(conf.ClientCertFile, conf.ClientKeyFile, conf.ServerCACertFile)
	if err != nil {
		die(logger, "mutual tls config", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
		},
		Timeout: time.Duration(conf.ClientTimeoutSeconds) * time.Second,
	}

	policyClient := policy_client.NewInternal(
		logger.Session("policy-client"),
		httpClient,
		conf.PolicyServerURL,
	)

	_, _, err = policyClient.GetPolicies()

	if err != nil {
		die(logger, "policy-client-get-policies", err)
	}

	store := &datastore.Store{
		Serializer: &serial.Serial{},
		Locker: &filelock.Locker{
			FileLocker: filelock.NewLocker(conf.Datastore + "_lock"),
			Mutex:      new(sync.Mutex),
		},
		DataFilePath:    conf.Datastore,
		VersionFilePath: conf.Datastore + "_version",
		LockedFilePath:  conf.Datastore + "_lock",
		CacheMutex:      new(sync.RWMutex),
	}

	metricsSender := &metrics.MetricsSender{
		Logger: logger.Session("time-metric-emitter"),
	}

	dynamicPlanner := &planner.VxlanPolicyPlanner{
		Datastore:                     store,
		PolicyClient:                  policyClient,
		Logger:                        logger.Session("rules-updater"),
		VNI:                           conf.VNI,
		MetricsSender:                 metricsSender,
		LoggingState:                  &planner.LoggingState{},
		IPTablesAcceptedUDPLogsPerSec: conf.IPTablesAcceptedUDPLogsPerSec,
	}

	egressPolicies, err := dynamicPlanner.GetRules()
	if err != nil {
		die(logger, "dynamic-planner-get-rules", err)
	}

	logger.Info("egress_policies", lager.Data{"egress_policies": egressPolicies})
}
