// +build modules

package modules

import (
	_ "code.cloudfoundry.org/iptables-logger/cmd/iptables-logger"
	_ "code.cloudfoundry.org/silk/cmd/silk-cni"
	_ "code.cloudfoundry.org/silk/cmd/silk-controller"
	_ "code.cloudfoundry.org/silk/cmd/silk-daemon"
	_ "code.cloudfoundry.org/silk/cmd/silk-teardown"
)

// imporing modules that are needed for building and testing this module
// these modules are not imported in code, but they build binaries
// that are needed at runtime
