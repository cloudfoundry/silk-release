package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"lib/common"
	"lib/policy_client"

	"vxlan-policy-agent/config"

	"code.cloudfoundry.org/cf-networking-helpers/mutualtls"
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

	policies, egressPolicies, err := policyClient.GetPolicies()
	if err != nil {
		die(logger, "policy-client-get-policies", err)
	}

	logger.Info("policies", lager.Data{"policies": policies})
	logger.Info("policies", lager.Data{"egress_policies": egressPolicies})
}
