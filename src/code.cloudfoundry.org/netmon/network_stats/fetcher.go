package network_stats

import (
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lib/rules"
)

//go:generate counterfeiter -o ../fakes/network_stats_fetcher.go --fake-name NetworkStatsFetcher . Fetcher
type Fetcher interface {
	CountIPTablesRules() (int, error)
}

type fetcher struct {
	IPTablesAdapter rules.IPTablesAdapter
	Logger          lager.Logger
}

func NewFetcher(iptablesAdapter rules.IPTablesAdapter, logger lager.Logger) fetcher {
	return fetcher{
		IPTablesAdapter: iptablesAdapter,
		Logger:          logger,
	}
}

func (stats fetcher) CountIPTablesRules() (int, error) {
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
