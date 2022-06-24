package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"code.cloudfoundry.org/netmon/config"
	"code.cloudfoundry.org/netmon/network_stats_fetcher"
	"code.cloudfoundry.org/netmon/poller"

	"os/exec"
	"sync"

	"code.cloudfoundry.org/lib/common"
	"code.cloudfoundry.org/lib/rules"

	"code.cloudfoundry.org/cf-networking-helpers/runner"
	"code.cloudfoundry.org/filelock"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lager/lagerflags"
	"github.com/cloudfoundry/dropsonde"
	"github.com/coreos/go-iptables/iptables"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/grouper"
	"github.com/tedsuo/ifrit/sigmon"
)

var (
	jobPrefix = "netmon"
	logPrefix = "cfnetworking"
)

func main() {
	configFilePath := flag.String("config-file", "", "path to config file")
	flag.Parse()
	conf, err := config.New(*configFilePath)
	if err != nil {
		log.Fatalf("%s.netmon: reading config: %s", logPrefix, err)
	}

	if conf.LogPrefix != "" {
		logPrefix = conf.LogPrefix
	}

	component := fmt.Sprintf("%s.%s", logPrefix, jobPrefix)

	logger, sink := lagerflags.NewFromConfig(component, common.GetLagerConfig())
	logger.Info("parsed-config", lager.Data{"config": conf})

	logLevel, err := conf.ParseLogLevel()
	if err != nil {
		logger.Fatal("parsing-log-level", err)
	}

	sink.SetMinLevel(logLevel)

	pollInterval := time.Duration(conf.PollInterval) * time.Second
	if pollInterval == 0 {
		pollInterval = time.Second
	}

	ipt, err := iptables.New()
	if err != nil {
		logger.Fatal("iptables-new", err)
	}

	iptLocker := &filelock.Locker{
		FileLocker: filelock.NewLocker(conf.IPTablesLockFile),
		Mutex:      &sync.Mutex{},
	}
	restorer := &rules.Restorer{}

	executablePath, err := exec.LookPath("iptables")
	if err != nil {
		logger.Fatal("commandrunner-new", err)
	}

	iptablesCommandRunner := runner.CommandRunner{
		Executable: executablePath,
	}

	lockedIPTables := &rules.LockedIPTables{
		IPTables:       ipt,
		Locker:         iptLocker,
		Restorer:       restorer,
		IPTablesRunner: iptablesCommandRunner,
	}

	dropsonde.Initialize(conf.MetronAddress, "netmon")

	networkStatsFetcher := network_stats_fetcher.New(lockedIPTables, logger)

	systemMetrics := &poller.SystemMetrics{
		Logger:              logger,
		PollInterval:        pollInterval,
		InterfaceName:       conf.InterfaceName,
		NetworkStatsFetcher: networkStatsFetcher,
	}

	if conf.TelemetryEnabled {
		telemetryLogFile, err := os.Create("/var/vcap/sys/log/netmon/telemetry.log")
		if err != nil {
			logger.Fatal("creating-telemetry-log", err)
		}

		telemetrySink := lager.NewWriterSink(telemetryLogFile, lager.INFO)
		telemetryLogger := lager.NewLogger("netmon")
		telemetryLogger.RegisterSink(telemetrySink)
		systemMetrics.TelemetryLogger = telemetryLogger
	}

	members := grouper.Members{
		{"metric_poller", systemMetrics},
	}

	monitor := ifrit.Invoke(sigmon.New(grouper.NewOrdered(os.Interrupt, members)))
	logger.Info("starting")
	err = <-monitor.Wait()
	if err != nil {
		logger.Fatal("ifrit monitor", err)
	}
}
