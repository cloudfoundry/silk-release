//go:build tools
// +build tools

package tools

import (
	_ "github.com/containernetworking/cni/plugins/test/noop"
	_ "github.com/containernetworking/plugins/plugins/ipam/host-local"
	_ "github.com/containernetworking/plugins/plugins/meta/bandwidth"
)

// This file imports packages that are used when running go generate, or used
// during the development process but not otherwise depended on by built code.
