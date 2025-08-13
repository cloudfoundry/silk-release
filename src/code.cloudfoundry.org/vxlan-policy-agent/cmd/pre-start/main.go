package main

import (
	"code.cloudfoundry.org/lib/common"
	"code.cloudfoundry.org/lib/rules"
	"flag"
	"log"
	"sync"

	"code.cloudfoundry.org/filelock"
	"github.com/coreos/go-iptables/iptables"
)

const (
	MaxRetries = 15
)

func main() {
	lockFilePath := flag.String("lock-file", "", "path to iptables file")
	flag.Parse()

	ipTablesAdapter, err := createIpTablesAdapter(*lockFilePath, false)
	if err != nil {
		log.Fatalf("Could not initialize ip4tables adapter: %s", err)
	}

	err = PreStart(ipTablesAdapter)
	if err != nil {
		log.Fatalf("pre-start failed after %d attempts - giving up", MaxRetries)
	}

	if common.IsIPv6Enabled() {
		ipTablesAdapter, err = createIpTablesAdapter(*lockFilePath, true)
		if err != nil {
			log.Fatalf("Could not initialize ip6tables adapter: %s", err)
		}

		err = PreStart(ipTablesAdapter)
		if err != nil {
			log.Fatalf("pre-start failed after %d attempts - giving up", MaxRetries)
		}
	}
}

func PreStart(ipTablesAdapter rules.IPTablesAdapter) error {
	var err error
	for i := 0; i < MaxRetries; i++ {
		err = ipTablesAdapter.FlushAndRestore(`*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT
`)
		if err != nil {
			log.Printf("pre-start error: %s", err)
		} else {
			break
		}
	}
	return err
}

func createIpTablesAdapter(iptablesLockFile string, ipv6 bool) (rules.IPTablesAdapter, error) {
	var ipt *iptables.IPTables
	var err error

	if ipv6 {
		ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
	} else {
		ipt, err = iptables.New()
	}

	if err != nil {
		return nil, err
	}

	iptLocker := &filelock.Locker{
		FileLocker: filelock.NewLocker(iptablesLockFile),
		Mutex:      &sync.Mutex{},
	}

	restorer := &rules.Restorer{
		IPv6: ipv6,
	}

	tables := &rules.LockedIPTables{
		IPTables: ipt,
		Locker:   iptLocker,
		Restorer: restorer,
	}

	return tables, nil
}
