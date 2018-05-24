package main

import (
	"code.cloudfoundry.org/filelock"
	"flag"
	"github.com/coreos/go-iptables/iptables"
	"lib/rules"
	"log"
	"strconv"
	"sync"
)

func main() {
	if err := mainWithError(); err != nil {
		log.Fatalf("silk-daemon-bootstrap: %s", err)
	}
}

func mainWithError() error {
	iptablesLockFile := flag.String("iptablesLockFile", "", "path to iptablesLockFile")
	singleIpOnlyFlag := flag.String("singleIpOnly", "false", "single ip mode")
	flag.Parse()

	var singleIpOnly bool

	singleIpOnly, err := strconv.ParseBool(*singleIpOnlyFlag)
	if err != nil {
		return err
	}

	if singleIpOnly {
		ipTablesAdapter, err := createIpTablesAdapter(*iptablesLockFile)
		if err != nil {
			return err
		}

		return addOverlayAccessMarkRule(ipTablesAdapter)
	}

	return nil
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

func addOverlayAccessMarkRule(iptables rules.IPTablesAdapter) error {
	overlayAccessMarkRule := rules.NewOverlayAccessMarkRule()
	exists, err := iptables.Exists("filter", "OUTPUT", overlayAccessMarkRule)
	if err == nil && !exists {
		return iptables.BulkInsert("filter", "OUTPUT", 1, overlayAccessMarkRule)
	}

	return err
}
