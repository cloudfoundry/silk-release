// +build externalmods

package externalmods

import (
	_ "github.com/containernetworking/plugins/plugins/ipam/host-local"
	_ "github.com/containernetworking/plugins/plugins/meta/bandwidth"
)

// This file will import mods that can't be imported in main module
// since the version conflicts with another dependency
