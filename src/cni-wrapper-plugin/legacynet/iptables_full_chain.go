package legacynet

import (
	"lib/rules"
)

type IpTablesFullChain struct {
	Table          string
	ParentChain    string
	ChainName      string
	JumpConditions []rules.IPTablesRule
	Rules          []rules.IPTablesRule
}
