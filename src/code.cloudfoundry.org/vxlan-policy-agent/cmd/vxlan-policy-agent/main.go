package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"code.cloudfoundry.org/cni-wrapper-plugin/adapter"
	"code.cloudfoundry.org/cni-wrapper-plugin/netrules"
	loggingclient "code.cloudfoundry.org/diego-logging-client"
	"code.cloudfoundry.org/lib/common"
	"code.cloudfoundry.org/lib/datastore"
	"code.cloudfoundry.org/lib/interfacelookup"
	"code.cloudfoundry.org/lib/poller"
	"code.cloudfoundry.org/lib/rules"
	"code.cloudfoundry.org/lib/serial"
	"code.cloudfoundry.org/policy_client"
	"code.cloudfoundry.org/vxlan-policy-agent/config"
	"code.cloudfoundry.org/vxlan-policy-agent/converger"
	"code.cloudfoundry.org/vxlan-policy-agent/enforcer"
	"code.cloudfoundry.org/vxlan-policy-agent/handlers"
	"code.cloudfoundry.org/vxlan-policy-agent/planner"

	"code.cloudfoundry.org/cf-networking-helpers/metrics"
	"code.cloudfoundry.org/cf-networking-helpers/mutualtls"
	"code.cloudfoundry.org/debugserver"
	"code.cloudfoundry.org/filelock"
	"code.cloudfoundry.org/go-loggregator/v8/runtimeemitter"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/lager/v3/lagerflags"
	"github.com/cloudfoundry/dropsonde"
	"github.com/coreos/go-iptables/iptables"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/grouper"
	"github.com/tedsuo/ifrit/http_server"
	"github.com/tedsuo/ifrit/sigmon"
)

const (
	dropsondeOrigin = "vxlan-policy-agent"
	emitInterval    = 30 * time.Second
	jobPrefix       = "vxlan-policy-agent"
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

	if conf.LogPrefix != "" {
		logPrefix = conf.LogPrefix
	}

	loggerConfig := common.GetLagerConfig()

	if conf.LogLevel != "" {
		loggerConfig.LogLevel = conf.LogLevel
	}

	logger, reconfigurableSink := lagerflags.NewFromConfig(fmt.Sprintf("%s.%s", logPrefix, jobPrefix), loggerConfig)

	logger.Info("parsed-config", lager.Data{"config": conf})

	_, err = os.Stat(filepath.Dir(conf.Datastore))
	if err != nil {
		die(logger, "datastore-directory-stat", err)
	}

	interfaceNameLookup := interfacelookup.InterfaceNameLookup{
		NetlinkAdapter: &adapter.NetlinkAdapter{},
	}

	interfaceNames, err := interfaceNameLookup.GetNamesFromIPs(conf.UnderlayIPs)
	if err != nil {
		log.Fatalf("%s: looking up interface names: %s", logPrefix, err)
	}

	pollInterval := time.Duration(conf.PollInterval) * time.Second
	if pollInterval == 0 {
		pollInterval = time.Second
	}

	asgPollInterval := time.Duration(conf.ASGPollInterval) * time.Second

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
		policy_client.DefaultConfig,
	)

	_, err = policyClient.GetPolicies()

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

	ipt, err := iptables.New()
	if err != nil {
		die(logger, "iptables-new", err)
	}

	iptLocker := &filelock.Locker{
		FileLocker: filelock.NewLocker(conf.IPTablesLockFile),
		Mutex:      &sync.Mutex{},
	}
	restorer := &rules.Restorer{}
	lockedIPTables := &rules.LockedIPTables{
		IPTables: ipt,
		Locker:   iptLocker,
		Restorer: restorer,
	}

	metricsSender := &metrics.MetricsSender{
		Logger: logger.Session("time-metric-emitter"),
	}

	iptablesLoggingState := &planner.LoggingState{}
	if conf.IPTablesLogging {
		iptablesLoggingState.Enable()
	}
	chainNamer := &netrules.ChainNamer{
		MaxLength: 28,
	}
	outConn := netrules.OutConn{
		Limit:      conf.OutConn.Limit,
		Logging:    conf.OutConn.Logging,
		Burst:      conf.OutConn.Burst,
		RatePerSec: conf.OutConn.RatePerSec,
	}

	netOutChain := &netrules.NetOutChain{
		ChainNamer: chainNamer,
		Converter:  &netrules.RuleConverter{Logger: logger},
		ASGLogging: conf.IPTablesASGLogging,
		DenyNetworks: netrules.DenyNetworks{
			Always:  conf.DenyNetworks.Always,
			Running: conf.DenyNetworks.Running,
			Staging: conf.DenyNetworks.Staging,
		},
		DeniedLogsPerSec: conf.IPTablesDeniedLogsPerSec,
		Conn:             outConn,
	}

	dynamicPlanner := &planner.VxlanPolicyPlanner{
		Datastore:     store,
		PolicyClient:  policyClient,
		Logger:        logger.Session("rules-updater"),
		VNI:           conf.VNI,
		MetricsSender: metricsSender,
		Chain: enforcer.Chain{
			Table:       "filter",
			ParentChain: "FORWARD",
			Prefix:      "vpa--",
		},
		LoggingState:                  iptablesLoggingState,
		IPTablesAcceptedUDPLogsPerSec: conf.IPTablesAcceptedUDPLogsPerSec,
		EnableOverlayIngressRules:     conf.EnableOverlayIngressRules,
		HostInterfaceNames:            interfaceNames,
		NetOutChain:                   netOutChain,
	}

	timestamper := &enforcer.Timestamper{}
	ruleEnforcer := enforcer.NewEnforcer(
		logger.Session("rules-enforcer"),
		timestamper,
		lockedIPTables,
		enforcer.EnforcerConfig{
			DisableContainerNetworkPolicy: conf.DisableContainerNetworkPolicy,
			OverlayNetwork:                conf.OverlayNetwork,
		},
	)

	err = dropsonde.Initialize(conf.MetronAddress, dropsondeOrigin)
	if err != nil {
		log.Fatalf("%s: initializing dropsonde: %s", logPrefix, err)
	}

	uptimeSource := metrics.NewUptimeSource()
	metricsEmitter := metrics.NewMetricsEmitter(logger, emitInterval, uptimeSource)

	metronClient, err := loggingclient.NewIngressClient(conf.LoggregatorConfig)
	if err != nil {
		log.Fatalf("%s: initializing ingress client: %s", logPrefix, err)
	}

	if conf.LoggregatorConfig.UseV2API {
		emitter := runtimeemitter.NewV1(metronClient)
		go emitter.Run()
	}

	singlePollCycle := converger.NewSinglePollCycle(
		[]converger.Planner{dynamicPlanner},
		ruleEnforcer,
		policyClient,
		metricsSender,
		metronClient,
		logger,
	)

	policyPoller := &poller.Poller{
		Logger:          logger,
		PollInterval:    pollInterval,
		SingleCycleFunc: singlePollCycle.DoPolicyCycleWithLastUpdatedCheck,
	}

	asgPoller := &poller.Poller{
		Logger:          logger,
		PollInterval:    asgPollInterval,
		SingleCycleFunc: singlePollCycle.DoASGCycle,
	}

	forcePolicyPollCycleServerAddress := fmt.Sprintf("%s:%d", conf.ForcePolicyPollCycleHost, conf.ForcePolicyPollCyclePort)

	forceHandlers := map[string]http.Handler{
		"/force-policy-poll-cycle": &handlers.ForcePolicyPollCycle{
			PollCycleFunc: singlePollCycle.DoPolicyCycle,
		},
		"/force-asgs-for-container": &handlers.ForceASGsForContainer{
			ASGUpdateFunc:    singlePollCycle.SyncASGsForContainers,
			EnableASGSyncing: conf.EnableASGSyncing,
		},
		"/force-orphaned-asgs-cleanup": &handlers.ForceOrphanedASGsCleanup{
			ASGCleanupFunc:   singlePollCycle.CleanupOrphanedASGsChains,
			EnableASGSyncing: conf.EnableASGSyncing,
		},
	}

	forcePolicyPollCycleServer := createForceUpdateServer(forcePolicyPollCycleServerAddress, forceHandlers)

	debugServerAddress := fmt.Sprintf("%s:%d", conf.DebugServerHost, conf.DebugServerPort)
	debugServer := createCustomDebugServer(debugServerAddress, reconfigurableSink, iptablesLoggingState)
	members := grouper.Members{
		{Name: "metrics_emitter", Runner: metricsEmitter},
		{Name: "policy_poller", Runner: policyPoller},
		{Name: "debug-server", Runner: debugServer},
		{Name: "force-policy-poll-cycle-server", Runner: forcePolicyPollCycleServer},
	}

	if conf.EnableASGSyncing {
		members = append(members, grouper.Member{Name: "asg_poller", Runner: asgPoller})
	}

	monitor := ifrit.Invoke(sigmon.New(grouper.NewOrdered(os.Interrupt, members)))
	logger.Info("starting")
	err = <-monitor.Wait()
	if err != nil {
		die(logger, "ifrit monitor", err)
	}
}

const (
	DEBUG = "debug"
	INFO  = "info"
	ERROR = "error"
	FATAL = "fatal"
)

func initLoggerSink(logger lager.Logger, level string) *lager.ReconfigurableSink {
	var logLevel lager.LogLevel
	switch strings.ToLower(level) {
	case DEBUG:
		logLevel = lager.DEBUG
	case INFO:
		logLevel = lager.INFO
	case ERROR:
		logLevel = lager.ERROR
	case FATAL:
		logLevel = lager.FATAL
	default:
		logLevel = lager.INFO
	}
	w := lager.NewWriterSink(os.Stdout, lager.DEBUG)
	return lager.NewReconfigurableSink(w, logLevel)
}

func createCustomDebugServer(listenAddress string, sink *lager.ReconfigurableSink, iptablesLoggingState *planner.LoggingState) ifrit.Runner {
	mux := debugserver.Handler(sink).(*http.ServeMux)
	mux.Handle("/iptables-c2c-logging", &handlers.IPTablesLogging{
		LoggingState: iptablesLoggingState,
	})
	return http_server.New(listenAddress, mux)
}

func createForceUpdateServer(listenAddress string, handlers map[string]http.Handler) ifrit.Runner {
	mux := http.NewServeMux()

	for url, handler := range handlers {
		mux.Handle(url, handler)
	}

	return http_server.New(listenAddress, mux)
}
