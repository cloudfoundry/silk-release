package network_stats_fetcher

import (
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lib/rules"
)

//go:generate counterfeiter -o ../fakes/network_stats_fetcher.go --fake-name NetworkStatsFetcher . NetworkStatsFetcher
type NetworkStatsFetcher interface {
	CountIPTablesRules() (int, error)
}

type networkStatsFetcher struct {
	IPTablesAdapter rules.IPTablesAdapter
	Logger          lager.Logger
}

func New(iptablesAdapter rules.IPTablesAdapter, logger lager.Logger) networkStatsFetcher {
	return networkStatsFetcher{
		IPTablesAdapter: iptablesAdapter,
		Logger:          logger,
	}
}

func (stats networkStatsFetcher) CountIPTablesRules() (int, error) {
	filterRules, err := stats.IPTablesAdapter.RuleCount("filter")
	if err != nil {
		stats.Logger.Error("failed-getting-filter-rules", err)
		return 0, err
	}

	natRules, err := stats.IPTablesAdapter.RuleCount("nat")
	if err != nil {
		stats.Logger.Error("failed-getting-nat-rules", err)
		return 0, err
	}

	return filterRules + natRules, nil
}
