package pollers

import (
	"os"
	"time"

	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/netmon/network_stats"
)

type TelemetryMetrics struct {
	Logger              lager.Logger
	TelemetryLogger     lager.Logger
	PollInterval        time.Duration
	NetworkStatsFetcher network_stats.Fetcher
	RuleCountAggregator *network_stats.IntAggregator
}

func (m *TelemetryMetrics) Run(signals <-chan os.Signal, ready chan<- struct{}) error {
	close(ready)
	for {
		select {
		case <-signals:
			return nil
		case <-time.After(m.PollInterval):
			m.measure(m.Logger.Session("telemetry-measure"))
		}
	}
}

func (m *TelemetryMetrics) measure(logger lager.Logger) {
	nIpTablesRule, err := m.NetworkStatsFetcher.CountIPTablesRules()
	if err != nil {
		m.Logger.Error("failed-fetching-network-stats", err)
		return
	}

	m.TelemetryLogger.Info("count-iptables-rules", map[string]interface{}{
		"telemetry-source":          "netmon",
		"telemetry-time":            time.Now(),
		"IPTablesRuleCount":         nIpTablesRule,
		"IPTablesRuleCountInterval": m.PollInterval.Seconds(),
		"IPTablesRuleMaxiumum":      m.RuleCountAggregator.Maximum,
		"IPTablesRuleAverage":       m.RuleCountAggregator.Average,
		"IPTablesRuleMinimum":       m.RuleCountAggregator.Minimum,
	})

	m.RuleCountAggregator.Flush()
}
