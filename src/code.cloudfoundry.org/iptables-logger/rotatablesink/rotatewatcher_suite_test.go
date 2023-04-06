package rotatablesink_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
	"code.cloudfoundry.org/lager/v3"
	"github.com/onsi/gomega/types"
)

func TestRotatewatcher(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Rotatewatcher Suite")
}


var LogsWith = func(level lager.LogLevel, msg string) types.GomegaMatcher {
	return And(
		WithTransform(func(log lager.LogFormat) string {
			return log.Message
		}, Equal(msg)),
		WithTransform(func(log lager.LogFormat) lager.LogLevel {
			return log.LogLevel
		}, Equal(level)),
	)
}

var HaveLogData = func(nextMatcher types.GomegaMatcher) types.GomegaMatcher {
	return WithTransform(func(log lager.LogFormat) lager.Data {
		return log.Data
	}, nextMatcher)
}