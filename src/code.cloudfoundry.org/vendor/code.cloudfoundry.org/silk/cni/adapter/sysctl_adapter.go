package adapter

import (
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
)

type SysctlAdapter struct{}

func (*SysctlAdapter) Sysctl(name string, params ...string) (string, error) {
	return sysctl.Sysctl(name, params...)
}
