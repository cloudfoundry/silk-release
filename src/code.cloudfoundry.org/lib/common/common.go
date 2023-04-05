package common

import (
	"code.cloudfoundry.org/lager/v3/lagerflags"
)

func GetLagerConfig() lagerflags.LagerConfig {
	lagerConfig := lagerflags.DefaultLagerConfig()
	lagerConfig.TimeFormat = lagerflags.FormatRFC3339
	return lagerConfig
}
