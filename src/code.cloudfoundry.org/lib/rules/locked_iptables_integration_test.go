package rules_test

import (
	"fmt"

	"os/exec"
	"runtime"
	"strings"
	"sync"

	"code.cloudfoundry.org/lib/rules"

	"code.cloudfoundry.org/cf-networking-helpers/testsupport"
	"code.cloudfoundry.org/filelock"
	goiptables "github.com/coreos/go-iptables/iptables"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

var _ = Describe("Locked IPTables Integration Test", func() {
	var (
		restorer  *rules.Restorer
		locker    *filelock.Locker
		lockedIPT *rules.LockedIPTables
		ipt       *goiptables.IPTables
	)

	BeforeEach(func() {
		flock := filelock.NewLocker("/tmp/restorer.lock")
		locker = &filelock.Locker{
			FileLocker: flock,
			Mutex:      &sync.Mutex{},
		}
		restorer = &rules.Restorer{}
		var err error
		ipt, err = goiptables.New()
		Expect(err).NotTo(HaveOccurred())
		lockedIPT = &rules.LockedIPTables{
			Locker:   locker,
			Restorer: restorer,
			IPTables: ipt,
		}
	})

	It("bulk inserts iptables rules", func() {
		onlyRunOnLinux()
		err := lockedIPT.BulkInsert("filter", "FORWARD", 1, []rules.IPTablesRule{
			rules.NewMarkSetRule("1.2.3.4", "A", fmt.Sprintf("guid-%d", 1)),
		}...)
		Expect(err).NotTo(HaveOccurred())
		Expect(AllIPTablesRules("filter")).To(ContainElement("-A FORWARD -s 1.2.3.4/32 -m comment --comment \"src:guid-1\" -j MARK --set-xmark 0xa/0xffffffff"))
	})

	It("bulk appends iptables rules", func() {
		onlyRunOnLinux()
		err := lockedIPT.BulkAppend("filter", "FORWARD", []rules.IPTablesRule{
			rules.NewMarkAllowRule("1.2.3.4", "tcp", 1234, 1234, "A", "some-src-app-guid", "some-dst-app-guid"),
		}...)
		Expect(err).NotTo(HaveOccurred())
		Expect(AllIPTablesRules("filter")).To(ContainElement(
			`-A FORWARD -d 1.2.3.4/32 -p tcp -m tcp --dport 1234 -m mark --mark 0xa -m comment --comment "src:some-src-app-guid_dst:some-dst-app-guid" -j ACCEPT`,
		))
	})

	It("supports concurrent bulk inserts", func() {
		onlyRunOnLinux()
		genericRules := []interface{}{}
		numRules := 100
		numWorkers := 10
		for i := 0; i < numRules; i++ {
			genericRules = append(genericRules, []rules.IPTablesRule{rules.NewMarkSetRule("1.2.3.4", "A", fmt.Sprintf("guid-%d", i))})
		}
		runner := testsupport.ParallelRunner{
			NumWorkers: numWorkers,
		}
		restoreWorker := func(item interface{}) {
			ruleItems := item.([]rules.IPTablesRule)
			err := lockedIPT.BulkInsert("filter", "FORWARD", 1, ruleItems...)
			Expect(err).NotTo(HaveOccurred())
		}
		runner.RunOnSlice(genericRules, restoreWorker)
		allRules := AllIPTablesRules("filter")
		for i := 0; i < numRules; i++ {
			Expect(allRules).To(ContainElement(
				fmt.Sprintf("-A FORWARD -s 1.2.3.4/32 -m comment --comment \"src:guid-%d\" -j MARK --set-xmark 0xa/0xffffffff", i)))
		}
	})

	It("writes a single rule to allow all traffic on a given IP range", func() {
		onlyRunOnLinux()
		err := lockedIPT.AllowTrafficForRange([]rules.IPTablesRule{rules.NewAcceptEverythingRule("10.255.0.0/16", "10.255.0.0/16")}...)

		Expect(err).NotTo(HaveOccurred())
		Expect(AllIPTablesRules("filter")).To(ContainElement(`-A FORWARD -s 10.255.0.0/16 -d 10.255.0.0/16 -j ACCEPT`))
	})

	Context("when IPv6 is enabled", func() {
		BeforeEach(func() {
			flock := filelock.NewLocker("/tmp/restorer.lock")
			locker = &filelock.Locker{
				FileLocker: flock,
				Mutex:      &sync.Mutex{},
			}
			restorer = &rules.Restorer{
				IPv6: true,
			}
			var err error
			ipt, err = goiptables.NewWithProtocol(goiptables.ProtocolIPv6)
			Expect(err).NotTo(HaveOccurred())
			lockedIPT = &rules.LockedIPTables{
				Locker:   locker,
				Restorer: restorer,
				IPTables: ipt,
			}
		})

		It("bulk inserts iptables rules", func() {
			onlyRunOnLinux()
			err := lockedIPT.BulkInsert("filter", "FORWARD", 1, []rules.IPTablesRule{
				rules.NewNetOutWithPortsRule("2001::1", "2001::2", 42, 419, "tcp"),
			}...)
			Expect(err).NotTo(HaveOccurred())
			Expect(AllIP6TablesRules("filter")).To(ContainElement(
				"-A FORWARD -p tcp -m iprange --dst-range 2001::1-2001::2 -m tcp --dport 42:419 -j ACCEPT"))
		})
	})
})

func onlyRunOnLinux() {
	if runtime.GOOS != "linux" {
		Skip("OS is not linux. Skipping...")
	}
}

func AllIPTablesRules(tableName string) []string {
	iptablesSession, err := gexec.Start(exec.Command("iptables", "-w", "-S", "-t", tableName), nil, nil)
	Expect(err).NotTo(HaveOccurred())
	Eventually(iptablesSession, "3s").Should(gexec.Exit(0))
	return strings.Split(strings.TrimSpace(string(iptablesSession.Out.Contents())), "\n")
}

func AllIP6TablesRules(tableName string) []string {
	iptablesSession, err := gexec.Start(exec.Command("ip6tables", "-w", "-S", "-t", tableName), nil, nil)
	Expect(err).NotTo(HaveOccurred())
	Eventually(iptablesSession, "3s").Should(gexec.Exit(0))
	return strings.Split(strings.TrimSpace(string(iptablesSession.Out.Contents())), "\n")
}
