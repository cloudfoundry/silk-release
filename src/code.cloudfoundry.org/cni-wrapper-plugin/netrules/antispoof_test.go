package netrules_test

import (
	"errors"
	"fmt"

	"code.cloudfoundry.org/cni-wrapper-plugin/netrules"
	lib_fakes "code.cloudfoundry.org/lib/fakes"
	"code.cloudfoundry.org/lib/rules"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("AntiSpoof", func() {
	var (
		antiSpoof *netrules.AntiSpoof
		iptables  *lib_fakes.IPTablesAdapter
		chain     = "ip6g--container"
		dropRule  = rules.IPTablesRule{"!", "-s", "2001:db8::1/128", "-m", "comment", "--comment", "ip6_anti-spoof", "-j", "DROP"}
		jumpRule  = rules.IPTablesRule{"-i", "veth123", "-m", "comment", "--comment", "ip6_anti-spoof", "-j", "ip6g--container"}
		calls     []string
	)

	BeforeEach(func() {
		iptables = &lib_fakes.IPTablesAdapter{}
		antiSpoof = &netrules.AntiSpoof{ChainNamer: &netrules.ChainNamer{MaxLength: 28}, IPTables: iptables}
		calls = nil
		iptables.ListReturns([]string{"-P PREROUTING ACCEPT"}, nil)
		iptables.ChainExistsReturns(false, nil)
		iptables.NewChainCalls(func(table, name string) error { calls = append(calls, "new"); return nil })
		iptables.BulkAppendCalls(func(table, name string, specs ...rules.IPTablesRule) error {
			calls = append(calls, "append")
			return nil
		})
		iptables.BulkInsertCalls(func(table, name string, pos int, specs ...rules.IPTablesRule) error {
			calls = append(calls, "insert")
			return nil
		})
	})

	Describe("Install", func() {
		It("AC1 Install creates, populates, then inserts jump at 1", func() {
			Expect(antiSpoof.Install("container", "veth123", "2001:db8::1")).To(Succeed())
			Expect(calls).To(Equal([]string{"new", "append", "insert"}))
			table, name := iptables.NewChainArgsForCall(0)
			Expect(table).To(Equal("raw"))
			Expect(name).To(Equal(chain))
			table, name, specs := iptables.BulkAppendArgsForCall(0)
			Expect(table).To(Equal("raw"))
			Expect(name).To(Equal(chain))
			Expect(specs).To(Equal([]rules.IPTablesRule{dropRule}))
			table, name, pos, specs := iptables.BulkInsertArgsForCall(0)
			Expect(table).To(Equal("raw"))
			Expect(name).To(Equal("PREROUTING"))
			Expect(pos).To(Equal(1))
			Expect(specs).To(Equal([]rules.IPTablesRule{jumpRule}))
			for i := 0; i < iptables.BulkAppendCallCount(); i++ {
				_, appendChain, _ := iptables.BulkAppendArgsForCall(i)
				Expect(appendChain).NotTo(Equal("PREROUTING"))
			}
		})
		It("Install rule specs contain no whitespace tokens (restore-safe)", func() {
			Expect(antiSpoof.Install("container", "veth123", "2001:db8::1")).To(Succeed())
			_, _, appendSpecs := iptables.BulkAppendArgsForCall(0)
			_, _, _, insertSpecs := iptables.BulkInsertArgsForCall(0)
			for _, specs := range [][]rules.IPTablesRule{appendSpecs, insertSpecs} {
				for _, spec := range specs {
					for _, token := range spec {
						Expect(token).NotTo(MatchRegexp(`[ \t]`))
					}
				}
			}
		})

		It("AC2 Install rolls back when NewChain fails", func() {
			original := errors.New("new failed")
			iptables.NewChainReturns(original)
			err := antiSpoof.Install("container", "veth123", "2001:db8::1")
			Expect(err).To(MatchError(ContainSubstring(original.Error())))
			Expect(iptables.BulkAppendCallCount()).To(Equal(0))
			Expect(iptables.BulkInsertCallCount()).To(Equal(0))
			Expect(iptables.DeleteChainCallCount()).To(Equal(0))
		})
		It("AC2 Install rolls back when BulkAppend fails", func() {
			original := errors.New("append failed")
			iptables.BulkAppendReturns(original)
			err := antiSpoof.Install("container", "veth123", "2001:db8::1")
			Expect(err).To(MatchError(ContainSubstring(original.Error())))
			Expect(iptables.DeleteChainCallCount()).To(Equal(1))
			table, name := iptables.DeleteChainArgsForCall(0)
			Expect([]string{table, name}).To(Equal([]string{"raw", chain}))
			Expect(iptables.BulkInsertCallCount()).To(Equal(0))
		})
		It("AC2 Install rolls back when BulkInsert fails", func() {
			original := errors.New("insert failed")
			var inserted bool
			var rollbackCalls []string
			iptables.ListCalls(func(table, name string) ([]string, error) {
				if inserted {
					rollbackCalls = append(rollbackCalls, "list")
				}
				return []string{"-P PREROUTING ACCEPT"}, nil
			})
			iptables.ChainExistsCalls(func(table, name string) (bool, error) {
				if inserted {
					rollbackCalls = append(rollbackCalls, "exists")
				}
				return inserted, nil
			})
			iptables.ClearChainCalls(func(table, name string) error { rollbackCalls = append(rollbackCalls, "clear"); return nil })
			iptables.DeleteChainCalls(func(table, name string) error { rollbackCalls = append(rollbackCalls, "delete-chain"); return nil })
			iptables.BulkInsertCalls(func(table, name string, pos int, specs ...rules.IPTablesRule) error {
				inserted = true
				return original
			})
			err := antiSpoof.Install("container", "veth123", "2001:db8::1")
			Expect(err).To(MatchError(ContainSubstring(original.Error())))
			Expect(rollbackCalls).To(Equal([]string{"list", "exists", "clear", "delete-chain"}))
			Expect(iptables.DeleteCallCount()).To(Equal(0))
		})
		It("AC2 Install detaches a committed jump before clearing after BulkInsert fails", func() {
			original := errors.New("insert failed")
			var inserted bool
			var rollbackCalls []string
			jumpLine := "-A PREROUTING -i veth123 -m comment --comment ip6_anti-spoof -j " + chain
			iptables.ListCalls(func(table, name string) ([]string, error) {
				if inserted {
					rollbackCalls = append(rollbackCalls, "list")
					return []string{"-P PREROUTING ACCEPT", jumpLine}, nil
				}
				return []string{"-P PREROUTING ACCEPT"}, nil
			})
			iptables.ChainExistsCalls(func(table, name string) (bool, error) {
				if inserted {
					rollbackCalls = append(rollbackCalls, "exists")
				}
				return inserted, nil
			})
			iptables.DeleteCalls(func(table, parent string, spec rules.IPTablesRule) error {
				rollbackCalls = append(rollbackCalls, "delete-jump")
				return nil
			})
			iptables.ClearChainCalls(func(table, name string) error { rollbackCalls = append(rollbackCalls, "clear"); return nil })
			iptables.DeleteChainCalls(func(table, name string) error { rollbackCalls = append(rollbackCalls, "delete-chain"); return nil })
			iptables.BulkInsertCalls(func(table, name string, pos int, specs ...rules.IPTablesRule) error {
				inserted = true
				return original
			})
			err := antiSpoof.Install("container", "veth123", "2001:db8::1")
			Expect(err).To(MatchError(ContainSubstring(original.Error())))
			Expect(rollbackCalls).To(Equal([]string{"list", "delete-jump", "exists", "clear", "delete-chain"}))
		})

		It("AC7 Install reconciles stale guards on the same veth", func() {
			iptables.ListReturns([]string{"-P PREROUTING ACCEPT", "-A PREROUTING -i veth123 -j ip6g--other", "-A PREROUTING -i other -j ip6g--x", "-A PREROUTING -i veth123 -j ordinary"}, nil)
			iptables.ChainExistsCalls(func(table, name string) (bool, error) { return name == "ip6g--other" || name == chain, nil })
			Expect(antiSpoof.Install("container", "veth123", "2001:db8::1")).To(Succeed())
			Expect(iptables.DeleteCallCount()).To(Equal(1))
			table, parent, spec := iptables.DeleteArgsForCall(0)
			Expect([]string{table, parent}).To(Equal([]string{"raw", "PREROUTING"}))
			Expect(spec).To(Equal(rules.IPTablesRule{"-i", "veth123", "-j", "ip6g--other"}))
			Expect(iptables.ClearChainCallCount()).To(Equal(2))
			Expect(iptables.DeleteChainCallCount()).To(Equal(2))
			_, removed := iptables.DeleteChainArgsForCall(0)
			_, leftover := iptables.DeleteChainArgsForCall(1)
			Expect([]string{removed, leftover}).To(ContainElements("ip6g--other", chain))
		})
		It("AC7 Install stops on reconcile List error", func() {
			iptables.ListReturns(nil, errors.New("list failed"))
			Expect(antiSpoof.Install("container", "veth123", "2001:db8::1")).To(MatchError(ContainSubstring("list failed")))
			Expect(iptables.NewChainCallCount()).To(Equal(0))
		})
		It("AC7 Install stops on reconcile removeGuard/ChainExists error", func() {
			iptables.ListReturns([]string{"-P PREROUTING ACCEPT", "-A PREROUTING -i veth123 -j ip6g--other"}, nil)
			iptables.DeleteReturns(errors.New("delete failed"))
			err := antiSpoof.Install("container", "veth123", "2001:db8::1")
			Expect(err).To(MatchError(ContainSubstring("delete failed")))
			Expect(iptables.NewChainCallCount()).To(Equal(0))

			iptables = &lib_fakes.IPTablesAdapter{}
			antiSpoof.IPTables = iptables
			iptables.ListReturns([]string{"-P PREROUTING ACCEPT"}, nil)
			iptables.ChainExistsReturns(false, errors.New("exists failed"))
			err = antiSpoof.Install("container", "veth123", "2001:db8::1")
			Expect(err).To(MatchError(ContainSubstring("exists failed")))
			Expect(iptables.NewChainCallCount()).To(Equal(0))
		})
	})

	Describe("Cleanup", func() {
		It("AC3 Cleanup does not clear or delete chain when detach fails", func() {
			line := "-A PREROUTING -i veth123 -m comment --comment \"ip6 anti-spoof\" -j " + chain
			iptables.ListReturnsOnCall(0, []string{"-P PREROUTING ACCEPT", line}, nil)
			iptables.ListReturnsOnCall(1, []string{"-P PREROUTING ACCEPT", line}, nil)
			iptables.DeleteReturns(errors.New("delete failed"))
			Expect(antiSpoof.Cleanup("container")).To(MatchError(ContainSubstring("delete failed")))
			Expect(iptables.ClearChainCallCount()).To(Equal(0))
			Expect(iptables.DeleteChainCallCount()).To(Equal(0))
			Expect(iptables.ListCallCount()).To(Equal(2))
		})
		It("AC3 initial List error does not re-list or remove chain", func() {
			iptables.ListReturns(nil, errors.New("list failed"))
			Expect(antiSpoof.Cleanup("container")).To(MatchError(ContainSubstring("list failed")))
			Expect(iptables.ListCallCount()).To(Equal(1))
			Expect(iptables.ClearChainCallCount()).To(Equal(0))
			Expect(iptables.DeleteChainCallCount()).To(Equal(0))
		})
		It("AC4 Cleanup succeeds when jump and chain absent", func() {
			Expect(antiSpoof.Cleanup("container")).To(Succeed())
			Expect(iptables.DeleteCallCount()).To(Equal(0))
			Expect(iptables.ClearChainCallCount()).To(Equal(0))
			Expect(iptables.DeleteChainCallCount()).To(Equal(0))
		})
		It("AC5 Cleanup returns List, ChainExists, ClearChain and DeleteChain errors", func() {
			listError := errors.New("list error")
			iptables.ListReturns(nil, listError)
			Expect(antiSpoof.Cleanup("container")).To(MatchError(ContainSubstring(listError.Error())))
			iptables = &lib_fakes.IPTablesAdapter{}
			antiSpoof.IPTables = iptables
			iptables.ListReturns([]string{"-P PREROUTING ACCEPT"}, nil)
			iptables.ChainExistsReturns(false, errors.New("exists error"))
			Expect(antiSpoof.Cleanup("container")).To(MatchError(ContainSubstring("exists error")))
			iptables = &lib_fakes.IPTablesAdapter{}
			antiSpoof.IPTables = iptables
			iptables.ListReturns([]string{"-P PREROUTING ACCEPT"}, nil)
			iptables.ChainExistsReturns(true, nil)
			iptables.ClearChainReturns(errors.New("clear error"))
			Expect(antiSpoof.Cleanup("container")).To(MatchError(ContainSubstring("clear error")))
			iptables = &lib_fakes.IPTablesAdapter{}
			antiSpoof.IPTables = iptables
			iptables.ListReturns([]string{"-P PREROUTING ACCEPT"}, nil)
			iptables.ChainExistsReturns(true, nil)
			iptables.DeleteChainReturns(errors.New("chain error"))
			Expect(antiSpoof.Cleanup("container")).To(MatchError(ContainSubstring("chain error")))
		})
		It("AC6b Cleanup accepts ClearChain/DeleteChain error only when chain confirmed absent", func() {
			for _, removal := range []string{"clear", "delete"} {
				for _, recheck := range []string{"absent", "present", "error"} {
					iptables = &lib_fakes.IPTablesAdapter{}
					antiSpoof.IPTables = iptables
					iptables.ListReturns([]string{"-P PREROUTING ACCEPT"}, nil)
					iptables.ChainExistsReturnsOnCall(0, true, nil)
					removalError := errors.New(removal + " failed")
					if removal == "clear" {
						iptables.ClearChainReturns(removalError)
					} else {
						iptables.ClearChainReturns(nil)
						iptables.DeleteChainReturns(removalError)
					}
					switch recheck {
					case "absent":
						iptables.ChainExistsReturnsOnCall(1, false, nil)
					case "present":
						iptables.ChainExistsReturnsOnCall(1, true, nil)
					case "error":
						iptables.ChainExistsReturnsOnCall(1, false, errors.New("re-check failed"))
					}

					err := antiSpoof.Cleanup("container")
					if recheck == "absent" {
						Expect(err).NotTo(HaveOccurred(), removal+" / "+recheck)
					} else {
						Expect(err).To(MatchError(ContainSubstring(removalError.Error())), removal+" / "+recheck)
						if recheck == "error" {
							Expect(err).To(MatchError(ContainSubstring("re-check failed")))
						}
					}
					if removal == "clear" {
						Expect(iptables.DeleteChainCallCount()).To(Equal(0))
					}
				}
			}
		})
		It("AC6 Cleanup accepts a Delete error only when re-list confirms the jump is gone", func() {
			iptables.ListReturnsOnCall(0, []string{"-P PREROUTING ACCEPT", "-A PREROUTING -i veth123 -j " + chain}, nil)
			iptables.ListReturnsOnCall(1, []string{"-P PREROUTING ACCEPT"}, nil)
			iptables.DeleteReturns(errors.New("delete failed"))
			iptables.ChainExistsReturns(true, nil)
			Expect(antiSpoof.Cleanup("container")).To(Succeed())
			Expect(iptables.ListCallCount()).To(Equal(2))
			Expect(iptables.ClearChainCallCount()).To(Equal(1))
			Expect(iptables.DeleteChainCallCount()).To(Equal(1))
		})
		It("AC6 Cleanup returns re-list error without clearing or deleting", func() {
			iptables.ListReturnsOnCall(0, []string{"-P PREROUTING ACCEPT", "-A PREROUTING -i veth123 -j " + chain}, nil)
			iptables.ListReturnsOnCall(1, nil, errors.New("re-list error"))
			iptables.DeleteReturns(errors.New("delete error"))
			Expect(antiSpoof.Cleanup("container")).To(MatchError(ContainSubstring("re-list error")))
			Expect(iptables.ClearChainCallCount()).To(Equal(0))
			Expect(iptables.DeleteChainCallCount()).To(Equal(0))
		})
		It("returns a parse error instead of skipping malformed rules", func() {
			iptables.ListReturns([]string{"-A PREROUTING 'unterminated"}, nil)
			Expect(antiSpoof.Cleanup("container")).To(HaveOccurred())
			Expect(iptables.ClearChainCallCount()).To(Equal(0))
			Expect(iptables.DeleteChainCallCount()).To(Equal(0))
		})
		It("includes descriptive context in errors", func() {
			iptables.ListReturns(nil, fmt.Errorf("failure"))
			Expect(antiSpoof.Cleanup("container")).To(MatchError(ContainSubstring("list raw PREROUTING")))
		})
	})
})
