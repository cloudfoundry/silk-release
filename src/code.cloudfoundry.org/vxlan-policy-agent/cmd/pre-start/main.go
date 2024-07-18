package main

import (
	"flag"
	"log"
	"sync"
	"time"

	"code.cloudfoundry.org/lib/rules"

	"code.cloudfoundry.org/filelock"
	"github.com/coreos/go-iptables/iptables"
)

const (
	ClientTimeout    = 5 * time.Second
	IngressChainName = "istio-ingress"
	jobPrefix        = "silk-daemon-bootstrap"
	logPrefix        = "cfnetworking"
	MAX_RETRIES      = 15
)

func main() {
	lockFilePath := flag.String("lock-file", "", "path to iptables file")
	flag.Parse()

	ipTablesAdapter, err := createIpTablesAdapter(*lockFilePath)
	if err != nil {
		log.Fatalf("Could not initialize iptables adapter: %s", err)
	}

	err = PreStart(ipTablesAdapter)
	if err != nil {
		log.Fatalf("pre-start failed after %d attempts - giving up", MAX_RETRIES)
	}
}

func PreStart(ipTablesAdapter rules.IPTablesAdapter) error {
	var err error
	for i := 0; i < MAX_RETRIES; i++ {
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

func createIpTablesAdapter(iptablesLockFile string) (rules.IPTablesAdapter, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}

	iptLocker := &filelock.Locker{
		FileLocker: filelock.NewLocker(iptablesLockFile),
		Mutex:      &sync.Mutex{},
	}

	tables := &rules.LockedIPTables{
		IPTables: ipt,
		Locker:   iptLocker,
		Restorer: &rules.Restorer{},
	}

	return tables, nil
}
