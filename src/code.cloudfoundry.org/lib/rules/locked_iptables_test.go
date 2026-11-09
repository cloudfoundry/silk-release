package rules_test

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"code.cloudfoundry.org/lib/fakes"
	"code.cloudfoundry.org/lib/rules"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("LockedIptables", func() {
	var (
		lockedIPT      *rules.LockedIPTables
		ipt            *fakes.IPTables
		restorer       *fakes.Restorer
		lock           *fakes.Locker
		rulespec       []string
		rule           rules.IPTablesRule
		ipTablesRunner *fakes.CommandRunner
	)
	BeforeEach(func() {
		ipt = &fakes.IPTables{}
		lock = &fakes.Locker{}
		restorer = &fakes.Restorer{}
		ipTablesRunner = &fakes.CommandRunner{}
		lockedIPT = &rules.LockedIPTables{
			IPTables:       ipt,
			Locker:         lock,
			Restorer:       restorer,
			IPTablesRunner: ipTablesRunner,
		}
		rulespec = []string{"some", "args"}
		rule = rules.IPTablesRule{"some", "args"}
	})
	Describe("BulkInsert", func() {
		var ruleSet []rules.IPTablesRule
		BeforeEach(func() {
			ruleSet = []rules.IPTablesRule{
				rules.NewMarkSetRule("1.2.3.4", "A", "a-guid"),
				rules.NewMarkSetRule("2.2.2.2", "B", "b-guid"),
			}
		})

		It("constructs the input and passes it to the restorer", func() {
			err := lockedIPT.BulkInsert("some-table", "some-chain", 1, ruleSet...)
			Expect(err).NotTo(HaveOccurred())

			Expect(lock.LockCallCount()).To(Equal(1))
			Expect(lock.UnlockCallCount()).To(Equal(1))
			Expect(restorer.RestoreCallCount()).To(Equal(1))
			restoreInput := restorer.RestoreArgsForCall(0)
			Expect(restoreInput).To(ContainSubstring("*some-table\n"))
			Expect(restoreInput).To(ContainSubstring("-I some-chain 1 --source 1.2.3.4 --jump MARK --set-xmark 0xA -m comment --comment src:a-guid\n"))
			Expect(restoreInput).To(ContainSubstring("-I some-chain 1 --source 2.2.2.2 --jump MARK --set-xmark 0xB -m comment --comment src:b-guid\n"))
			Expect(restoreInput).To(ContainSubstring("COMMIT\n"))
		})
		Context("when the lock fails", func() {
			BeforeEach(func() {
				lock.LockReturns(errors.New("banana"))
			})
			It("should return an error", func() {
				err := lockedIPT.BulkInsert("some-table", "some-chain", 1, ruleSet...)
				Expect(err).To(MatchError("lock: banana"))
			})
		})

		Context("when the restorer fails", func() {
			BeforeEach(func() {
				restorer.RestoreReturns(fmt.Errorf("banana"))
			})
			It("should return an error", func() {
				err := lockedIPT.BulkInsert("some-table", "some-chain", 1, ruleSet...)
				Expect(err).To(MatchError("iptables call: banana and unlock: <nil>"))
			})
		})

		Context("when the unlock fails", func() {
			BeforeEach(func() {
				lock.UnlockReturns(errors.New("banana"))
			})
			It("should return an error", func() {
				err := lockedIPT.BulkInsert("some-table", "some-chain", 1, ruleSet...)
				Expect(err).To(MatchError("banana"))
			})
		})
		Context("when the restorer fails and then the unlock fails", func() {
			BeforeEach(func() {
				lock.UnlockReturns(errors.New("banana"))
				restorer.RestoreReturns(fmt.Errorf("patato"))
			})
			It("should return an error", func() {
				err := lockedIPT.BulkInsert("some-table", "some-chain", 1, ruleSet...)
				Expect(err).To(MatchError("iptables call: patato and unlock: banana"))
			})
		})
	})

	Describe("BulkAppend", func() {
		var ruleSet []rules.IPTablesRule
		BeforeEach(func() {
			ruleSet = []rules.IPTablesRule{
				rules.NewMarkSetRule("1.2.3.4", "A", "a-guid"),
				rules.NewMarkSetRule("2.2.2.2", "B", "b-guid"),
			}
		})

		It("constructs the input and passes it to the restorer", func() {
			err := lockedIPT.BulkAppend("some-table", "some-chain", ruleSet...)
			Expect(err).NotTo(HaveOccurred())

			Expect(lock.LockCallCount()).To(Equal(1))
			Expect(lock.UnlockCallCount()).To(Equal(1))
			Expect(restorer.RestoreCallCount()).To(Equal(1))
			restoreInput := restorer.RestoreArgsForCall(0)
			Expect(restoreInput).To(ContainSubstring("*some-table\n"))
			Expect(restoreInput).To(ContainSubstring("-A some-chain --source 1.2.3.4 --jump MARK --set-xmark 0xA -m comment --comment src:a-guid\n"))
			Expect(restoreInput).To(ContainSubstring("-A some-chain --source 2.2.2.2 --jump MARK --set-xmark 0xB -m comment --comment src:b-guid\n"))
			Expect(restoreInput).To(ContainSubstring("COMMIT\n"))
		})
		Context("when the lock fails", func() {
			BeforeEach(func() {
				lock.LockReturns(errors.New("banana"))
			})
			It("should return an error", func() {
				err := lockedIPT.BulkAppend("some-table", "some-chain", ruleSet...)
				Expect(err).To(MatchError("lock: banana"))
			})
		})

		Context("when the restorer fails", func() {
			BeforeEach(func() {
				restorer.RestoreReturns(fmt.Errorf("banana"))
			})
			It("should return an error", func() {
				err := lockedIPT.BulkAppend("some-table", "some-chain", ruleSet...)
				Expect(err).To(MatchError("iptables call: banana and unlock: <nil>"))
			})
		})

		Context("when the unlock fails", func() {
			BeforeEach(func() {
				lock.UnlockReturns(errors.New("banana"))
			})
			It("should return an error", func() {
				err := lockedIPT.BulkAppend("some-table", "some-chain", ruleSet...)
				Expect(err).To(MatchError("banana"))
			})
		})
		Context("when the restorer fails and then the unlock fails", func() {
			BeforeEach(func() {
				lock.UnlockReturns(errors.New("banana"))
				restorer.RestoreReturns(fmt.Errorf("patato"))
			})
			It("should return an error", func() {
				err := lockedIPT.BulkAppend("some-table", "some-chain", ruleSet...)
				Expect(err).To(MatchError("iptables call: patato and unlock: banana"))
			})
		})
	})

	Describe("Exists", func() {
		BeforeEach(func() {
			ipt.ExistsReturns(true, nil)
		})
		It("passes the correct parameters to the iptables library", func() {
			exists, err := lockedIPT.Exists("some-table", "some-chain", rule)
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(Equal(true))

			Expect(lock.LockCallCount()).To(Equal(1))
			Expect(lock.UnlockCallCount()).To(Equal(1))
			Expect(ipt.ExistsCallCount()).To(Equal(1))
			table, chain, spec := ipt.ExistsArgsForCall(0)
			Expect(table).To(Equal("some-table"))
			Expect(chain).To(Equal("some-chain"))
			Expect(spec).To(Equal(rulespec))
		})

		Context("when locking fails", func() {
			BeforeEach(func() {
				lock.LockReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				_, err := lockedIPT.Exists("some-table", "some-chain", rule)
				Expect(err).To(MatchError("lock: banana"))
			})
		})

		Context("when iptables call fails and unlock succeeds", func() {
			BeforeEach(func() {
				ipt.ExistsReturns(false, errors.New("banana"))
			})
			It("returns an error", func() {
				_, err := lockedIPT.Exists("some-table", "some-chain", rule)
				Expect(err).To(MatchError("iptables call: banana and unlock: <nil>"))
			})
		})

		Context("when iptables call fails and unlock fails", func() {
			BeforeEach(func() {
				lock.UnlockReturns(errors.New("banana"))
				ipt.ExistsReturns(false, errors.New("patato"))
			})
			It("returns an error", func() {
				_, err := lockedIPT.Exists("some-table", "some-chain", rule)
				Expect(err).To(MatchError("iptables call: patato and unlock: banana"))
			})
		})
	})

	Describe("DeleteAfterRuleNum", func() {
		BeforeEach(func() {
			ipt.ListReturns([]string{"-N some-chain", "-A some-chain rule-1", "-A some-chain rule-2", "-A some-chain rule-3"}, nil)
		})
		DescribeTable("deletes rules after ruleNum only when present",
			func(list []string, expectedDeletes int) {
				ipt.ListReturns(list, nil)

				err := lockedIPT.DeleteAfterRuleNum("some-table", "some-chain", 2)
				Expect(err).NotTo(HaveOccurred())
				Expect(ipt.DeleteCallCount()).To(Equal(expectedDeletes))
				if expectedDeletes == 1 {
					table, chain, ruleNum := ipt.DeleteArgsForCall(0)
					Expect(table).To(Equal("some-table"))
					Expect(chain).To(Equal("some-chain"))
					Expect(ruleNum).To(Equal([]string{"2", "--wait"}))
				}
			},
			Entry("nil list", nil, 0),
			Entry("empty list", []string{}, 0),
			Entry("header-only list", []string{"-N some-chain"}, 0),
			Entry("header and jump", []string{"-N some-chain", "-A some-chain rule-1"}, 0),
			Entry("header, jump and obsolete rule", []string{"-N some-chain", "-A some-chain rule-1", "-A some-chain rule-2"}, 1),
		)

		It("returns an unlock error for a short list", func() {
			ipt.ListReturns([]string{"-N some-chain"}, nil)
			lock.UnlockReturns(errors.New("banana"))

			err := lockedIPT.DeleteAfterRuleNum("some-table", "some-chain", 2)

			Expect(err).To(MatchError("banana"))
			Expect(lock.UnlockCallCount()).To(Equal(1))
			Expect(ipt.DeleteCallCount()).To(Equal(0))
		})

		It("locks and passes the correct parameters to iptables", func() {
			err := lockedIPT.DeleteAfterRuleNum("some-table", "some-chain", 2)
			Expect(err).NotTo(HaveOccurred())

			Expect(lock.LockCallCount()).To(Equal(1))
			Expect(lock.UnlockCallCount()).To(Equal(1))
			Expect(ipt.DeleteCallCount()).To(Equal(2))
			Expect(ipt.ListCallCount()).To(Equal(1))
			table, chain := ipt.ListArgsForCall(0)
			Expect(table).To(Equal("some-table"))
			Expect(chain).To(Equal("some-chain"))
			table, chain, ruleNum := ipt.DeleteArgsForCall(0)
			Expect(table).To(Equal("some-table"))
			Expect(chain).To(Equal("some-chain"))
			Expect(ruleNum).To(Equal([]string{"2", "--wait"}))
			table, chain, ruleNum = ipt.DeleteArgsForCall(1)
			Expect(table).To(Equal("some-table"))
			Expect(chain).To(Equal("some-chain"))
			Expect(ruleNum).To(Equal([]string{"2", "--wait"}))

		})
		Context("when locking fails", func() {
			BeforeEach(func() {
				lock.LockReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				err := lockedIPT.DeleteAfterRuleNum("some-table", "some-chain", 2)
				Expect(err).To(MatchError("lock: banana"))
			})
		})
		Context("when iptables list fails and unlock succeeds", func() {
			BeforeEach(func() {
				ipt.ListReturns([]string{}, errors.New("banana"))
			})
			It("returns an error", func() {
				err := lockedIPT.DeleteAfterRuleNum("some-table", "some-chain", 2)
				Expect(err).To(MatchError("iptables call: banana and unlock: <nil>"))
			})
		})

		Context("when iptables list fails and unlock fails", func() {
			BeforeEach(func() {
				lock.UnlockReturns(errors.New("banana"))
				ipt.ListReturns([]string{}, errors.New("patato"))
			})
			It("returns an error", func() {
				err := lockedIPT.DeleteAfterRuleNum("some-table", "some-chain", 2)
				Expect(err).To(MatchError("iptables call: patato and unlock: banana"))
			})
		})

		Context("when iptables delete fails and unlock succeeds", func() {
			BeforeEach(func() {
				ipt.DeleteReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				err := lockedIPT.DeleteAfterRuleNum("some-table", "some-chain", 2)
				Expect(err).To(MatchError("iptables call: banana and unlock: <nil>"))
			})
		})

		Context("when iptables delete fails and unlock fails", func() {
			BeforeEach(func() {
				lock.UnlockReturns(errors.New("banana"))
				ipt.DeleteReturns(errors.New("patato"))
			})
			It("returns an error", func() {
				err := lockedIPT.DeleteAfterRuleNum("some-table", "some-chain", 2)
				Expect(err).To(MatchError("iptables call: patato and unlock: banana"))
			})
		})

	})

	Describe("DeleteAfterRuleNumKeepReject", func() {
		BeforeEach(func() {
			ipt.ListReturns([]string{
				"-N some-chain",
				"-A some-chain rule-1",
				"-A some-chain rule-2",
				"-A some-chain -j REJECT --reject-with icmp-port-unreachable",
				"-A some-chain rule-3",
			}, nil)
		})
		It("locks, inserts a REJECT at ruleNum, then deletes the rest", func() {
			err := lockedIPT.DeleteAfterRuleNumKeepReject("some-table", "some-chain", 2)
			Expect(err).NotTo(HaveOccurred())

			Expect(lock.LockCallCount()).To(Equal(1))
			Expect(lock.UnlockCallCount()).To(Equal(1))
			Expect(ipt.DeleteCallCount()).To(Equal(3))
			Expect(ipt.ListCallCount()).To(Equal(1))
			Expect(ipt.InsertCallCount()).To(Equal(1))
			Expect(ipt.AppendUniqueCallCount()).To(Equal(0))

			table, chain := ipt.ListArgsForCall(0)
			Expect(table).To(Equal("some-table"))
			Expect(chain).To(Equal("some-chain"))

			table, chain, pos, rulespec := ipt.InsertArgsForCall(0)
			Expect(table).To(Equal("some-table"))
			Expect(chain).To(Equal("some-chain"))
			Expect(pos).To(Equal(2))
			Expect(rulespec).To(Equal([]string{"--jump", "REJECT", "--reject-with", "icmp-port-unreachable"}))

			for i := 0; i < 3; i++ {
				table, chain, ruleNum := ipt.DeleteArgsForCall(i)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("some-chain"))
				Expect(ruleNum).To(Equal([]string{"3", "--wait"}))
			}
		})

		Context("ordering and chain state", func() {
			var (
				callLog               []string
				chainState            []string
				rejectPresentAtDelete []bool
			)

			hasReject := func(chain []string) bool {
				for _, r := range chain {
					if strings.Contains(r, "REJECT") {
						return true
					}
				}
				return false
			}

			// listed includes the "-N chain" header at index 0, as iptables -S does
			setup := func(listed []string) {
				callLog = nil
				rejectPresentAtDelete = nil
				chainState = append([]string{}, listed[1:]...)
				ipt.ListReturns(listed, nil)
				ipt.InsertStub = func(_, _ string, pos int, rulespec ...string) error {
					callLog = append(callLog, fmt.Sprintf("insert:%d", pos))
					idx := pos - 1
					newRule := "-A c " + strings.Join(rulespec, " ")
					chainState = append(chainState[:idx], append([]string{newRule}, chainState[idx:]...)...)
					return nil
				}
				ipt.DeleteStub = func(_, _ string, args ...string) error {
					callLog = append(callLog, "delete:"+strings.Join(args, " "))
					n, err := strconv.Atoi(args[0])
					Expect(err).NotTo(HaveOccurred())
					chainState = append(chainState[:n-1], chainState[n:]...)
					rejectPresentAtDelete = append(rejectPresentAtDelete, hasReject(chainState))
					return nil
				}
			}

			Context("with more rules than ruleNum", func() {
				BeforeEach(func() {
					setup([]string{
						"-N c",
						"-A c A",
						"-A c B",
						"-A c X",
						"-A c Y",
						"-A c -j REJECT --reject-with icmp-port-unreachable",
					})
				})

				It("inserts at ruleNum before any delete", func() {
					Expect(lockedIPT.DeleteAfterRuleNumKeepReject("t", "c", 2)).To(Succeed())
					Expect(callLog).NotTo(BeEmpty())
					Expect(callLog[0]).To(Equal("insert:2"))
					for _, entry := range callLog[1:] {
						Expect(entry).To(HavePrefix("delete:"))
					}
				})

				It("deletes only position ruleNum+1 with --wait", func() {
					Expect(lockedIPT.DeleteAfterRuleNumKeepReject("t", "c", 2)).To(Succeed())
					Expect(callLog).To(Equal([]string{
						"insert:2",
						"delete:3 --wait",
						"delete:3 --wait",
						"delete:3 --wait",
						"delete:3 --wait",
					}))
				})

				It("keeps a REJECT in the chain after every delete", func() {
					Expect(lockedIPT.DeleteAfterRuleNumKeepReject("t", "c", 2)).To(Succeed())
					Expect(rejectPresentAtDelete).To(HaveLen(4))
					Expect(rejectPresentAtDelete).To(Equal([]bool{true, true, true, true}))
				})

				It("ends with the first ruleNum-1 rules followed by the new REJECT", func() {
					Expect(lockedIPT.DeleteAfterRuleNumKeepReject("t", "c", 2)).To(Succeed())
					Expect(chainState).To(Equal([]string{
						"-A c A",
						"-A c --jump REJECT --reject-with icmp-port-unreachable",
					}))
				})
			})

			Context("when the insert fails", func() {
				BeforeEach(func() {
					setup([]string{"-N c", "-A c A", "-A c B", "-A c C"})
					ipt.InsertStub = func(_, _ string, pos int, _ ...string) error {
						callLog = append(callLog, fmt.Sprintf("insert:%d", pos))
						return errors.New("insert-boom")
					}
				})

				It("does not delete anything, returns the error and unlocks", func() {
					err := lockedIPT.DeleteAfterRuleNumKeepReject("t", "c", 2)
					Expect(err).To(MatchError("iptables call: insert-boom and unlock: <nil>"))
					Expect(callLog).To(Equal([]string{"insert:2"}))
					Expect(ipt.DeleteCallCount()).To(Equal(0))
					Expect(lock.UnlockCallCount()).To(Equal(1))
				})
			})

			Context("when the list has no more rules than ruleNum", func() {
				BeforeEach(func() {
					setup([]string{"-N c", "-A c A"})
				})

				It("inserts at len(rules) and does not delete", func() {
					Expect(func() {
						Expect(lockedIPT.DeleteAfterRuleNumKeepReject("t", "c", 5)).To(Succeed())
					}).NotTo(Panic())
					Expect(callLog).To(Equal([]string{"insert:2"}))
					Expect(ipt.DeleteCallCount()).To(Equal(0))
					Expect(lock.UnlockCallCount()).To(Equal(1))
				})
			})
		})

		Context("when locking fails", func() {
			BeforeEach(func() {
				lock.LockReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				err := lockedIPT.DeleteAfterRuleNumKeepReject("some-table", "some-chain", 2)
				Expect(err).To(MatchError("lock: banana"))
			})
		})

		Context("when iptables list fails and unlock succeeds", func() {
			BeforeEach(func() {
				ipt.ListReturns([]string{}, errors.New("banana"))
			})
			It("returns an error", func() {
				err := lockedIPT.DeleteAfterRuleNumKeepReject("some-table", "some-chain", 2)
				Expect(err).To(MatchError("iptables call: banana and unlock: <nil>"))
			})
		})

		Context("when iptables list fails and unlock fails", func() {
			BeforeEach(func() {
				lock.UnlockReturns(errors.New("banana"))
				ipt.ListReturns([]string{}, errors.New("patato"))
			})
			It("returns an error", func() {
				err := lockedIPT.DeleteAfterRuleNumKeepReject("some-table", "some-chain", 2)
				Expect(err).To(MatchError("iptables call: patato and unlock: banana"))
			})
		})

		Context("when iptables delete fails and unlock succeeds", func() {
			BeforeEach(func() {
				ipt.DeleteReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				err := lockedIPT.DeleteAfterRuleNumKeepReject("some-table", "some-chain", 2)
				Expect(err).To(MatchError("iptables call: banana and unlock: <nil>"))
			})
		})

		Context("when iptables delete fails and unlock fails", func() {
			BeforeEach(func() {
				lock.UnlockReturns(errors.New("banana"))
				ipt.DeleteReturns(errors.New("patato"))
			})
			It("returns an error", func() {
				err := lockedIPT.DeleteAfterRuleNumKeepReject("some-table", "some-chain", 2)
				Expect(err).To(MatchError("iptables call: patato and unlock: banana"))
			})
		})

		Context("when IPv6 is enabled", func() {
			BeforeEach(func() {
				ipt.ListReturns([]string{
					"-N some-chain",
					"-A some-chain rule-1",
					"-A some-chain rule-2",
					"-A some-chain -j REJECT --reject-with icmp6-port-unreachable",
					"-A some-chain rule-3",
				}, nil)

				restorer.IsIPv6Returns(true)
			})

			It("inserts an IPv6 REJECT at ruleNum then deletes the rest", func() {
				err := lockedIPT.DeleteAfterRuleNumKeepReject("some-table", "some-chain", 2)
				Expect(err).NotTo(HaveOccurred())

				Expect(lock.UnlockCallCount()).To(Equal(1))
				Expect(ipt.AppendUniqueCallCount()).To(Equal(0))
				Expect(ipt.InsertCallCount()).To(Equal(1))
				table, chain, pos, rulespec := ipt.InsertArgsForCall(0)
				Expect(table).To(Equal("some-table"))
				Expect(chain).To(Equal("some-chain"))
				Expect(pos).To(Equal(2))
				Expect(rulespec).To(Equal([]string{"--jump", "REJECT", "--reject-with", "icmp6-port-unreachable"}))

				Expect(ipt.DeleteCallCount()).To(Equal(3))
				for i := 0; i < 3; i++ {
					_, _, ruleNum := ipt.DeleteArgsForCall(i)
					Expect(ruleNum).To(Equal([]string{"3", "--wait"}))
				}
			})
		})
	})

	Describe("Delete", func() {
		It("locks and passes the correct parameters to the iptables library", func() {
			err := lockedIPT.Delete("some-table", "some-chain", rule)
			Expect(err).NotTo(HaveOccurred())

			Expect(lock.LockCallCount()).To(Equal(1))
			Expect(lock.UnlockCallCount()).To(Equal(1))
			Expect(ipt.DeleteCallCount()).To(Equal(1))
			table, chain, spec := ipt.DeleteArgsForCall(0)
			Expect(table).To(Equal("some-table"))
			Expect(chain).To(Equal("some-chain"))
			Expect(spec).To(Equal(rulespec))
		})

		Context("when locking fails", func() {
			BeforeEach(func() {
				lock.LockReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				err := lockedIPT.Delete("some-table", "some-chain", rule)
				Expect(err).To(MatchError("lock: banana"))
			})
		})

		Context("when iptables call fails and unlock succeeds", func() {
			BeforeEach(func() {
				ipt.DeleteReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				err := lockedIPT.Delete("some-table", "some-chain", rule)
				Expect(err).To(MatchError("iptables call: banana and unlock: <nil>"))
			})
		})

		Context("when iptables call fails and unlock fails", func() {
			BeforeEach(func() {
				lock.UnlockReturns(errors.New("banana"))
				ipt.DeleteReturns(errors.New("patato"))
			})
			It("returns an error", func() {
				err := lockedIPT.Delete("some-table", "some-chain", rule)
				Expect(err).To(MatchError("iptables call: patato and unlock: banana"))
			})
		})
	})

	Describe("ListChains", func() {
		BeforeEach(func() {
			ipt.ListChainsReturns([]string{"some", "list"}, nil)
		})
		It("locks and lists all chains for a given table", func() {
			chains, err := lockedIPT.ListChains("some-table")
			Expect(err).NotTo(HaveOccurred())
			Expect(chains).To(Equal([]string{"some", "list"}))

			Expect(lock.LockCallCount()).To(Equal(1))
			Expect(lock.UnlockCallCount()).To(Equal(1))
			Expect(ipt.ListChainsCallCount()).To(Equal(1))
			table := ipt.ListChainsArgsForCall(0)
			Expect(table).To(Equal("some-table"))
			Expect(err).NotTo(HaveOccurred())
		})
		Context("when locking fails", func() {
			BeforeEach(func() {
				lock.LockReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				_, err := lockedIPT.ListChains("some-table")
				Expect(err).To(MatchError("lock: banana"))
			})
		})

		Context("when iptables call fails and unlock succeeds", func() {
			BeforeEach(func() {
				ipt.ListChainsReturns(nil, errors.New("banana"))
			})
			It("returns an error", func() {
				_, err := lockedIPT.ListChains("some-table")
				Expect(err).To(MatchError("iptables call: banana and unlock: <nil>"))
			})
		})

		Context("when iptables call fails and unlock fails", func() {
			BeforeEach(func() {
				lock.UnlockReturns(errors.New("banana"))
				ipt.ListChainsReturns(nil, errors.New("patato"))
			})
			It("returns an error", func() {
				_, err := lockedIPT.ListChains("some-table")
				Expect(err).To(MatchError("iptables call: patato and unlock: banana"))
			})
		})
	})
	Describe("List", func() {
		BeforeEach(func() {
			ipt.ListReturns([]string{"some", "list"}, nil)
		})
		It("locks and passes the correct parameters to the iptables library", func() {
			list, err := lockedIPT.List("some-table", "some-chain")
			Expect(err).NotTo(HaveOccurred())
			Expect(list).To(Equal([]string{"some", "list"}))

			Expect(lock.LockCallCount()).To(Equal(1))
			Expect(lock.UnlockCallCount()).To(Equal(1))
			Expect(ipt.ListCallCount()).To(Equal(1))
			table, chain := ipt.ListArgsForCall(0)
			Expect(table).To(Equal("some-table"))
			Expect(chain).To(Equal("some-chain"))
		})

		Context("when locking fails", func() {
			BeforeEach(func() {
				lock.LockReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				_, err := lockedIPT.List("some-table", "some-chain")
				Expect(err).To(MatchError("lock: banana"))
			})
		})

		Context("when iptables call fails and unlock succeeds", func() {
			BeforeEach(func() {
				ipt.ListReturns(nil, errors.New("banana"))
			})
			It("returns an error", func() {
				_, err := lockedIPT.List("some-table", "some-chain")
				Expect(err).To(MatchError("iptables call: banana and unlock: <nil>"))
			})
		})

		Context("when iptables call fails and unlock fails", func() {
			BeforeEach(func() {
				lock.UnlockReturns(errors.New("banana"))
				ipt.ListReturns(nil, errors.New("patato"))
			})
			It("returns an error", func() {
				_, err := lockedIPT.List("some-table", "some-chain")
				Expect(err).To(MatchError("iptables call: patato and unlock: banana"))
			})
		})
	})

	Describe("NewChain", func() {
		It("locks and passes the correct parameters to the iptables library", func() {
			err := lockedIPT.NewChain("some-table", "some-chain")
			Expect(err).NotTo(HaveOccurred())

			Expect(lock.LockCallCount()).To(Equal(1))
			Expect(lock.UnlockCallCount()).To(Equal(1))
			Expect(ipt.NewChainCallCount()).To(Equal(1))
			table, chain := ipt.NewChainArgsForCall(0)
			Expect(table).To(Equal("some-table"))
			Expect(chain).To(Equal("some-chain"))
		})

		Context("when locking fails", func() {
			BeforeEach(func() {
				lock.LockReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				err := lockedIPT.NewChain("some-table", "some-chain")
				Expect(err).To(MatchError("lock: banana"))
			})
		})

		Context("when iptables call fails and unlock succeeds", func() {
			BeforeEach(func() {
				ipt.NewChainReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				err := lockedIPT.NewChain("some-table", "some-chain")
				Expect(err).To(MatchError("iptables call: banana and unlock: <nil>"))
			})
		})

		Context("when iptables call fails and unlock fails", func() {
			BeforeEach(func() {
				lock.UnlockReturns(errors.New("banana"))
				ipt.NewChainReturns(errors.New("patato"))
			})
			It("returns an error", func() {
				err := lockedIPT.NewChain("some-table", "some-chain")
				Expect(err).To(MatchError("iptables call: patato and unlock: banana"))
			})
		})
	})

	Describe("DeleteChain", func() {
		It("locks and passes the correct parameters to the iptables library", func() {
			err := lockedIPT.DeleteChain("some-table", "some-chain")
			Expect(err).NotTo(HaveOccurred())

			Expect(lock.LockCallCount()).To(Equal(1))
			Expect(lock.UnlockCallCount()).To(Equal(1))
			Expect(ipt.DeleteChainCallCount()).To(Equal(1))
			table, chain := ipt.DeleteChainArgsForCall(0)
			Expect(table).To(Equal("some-table"))
			Expect(chain).To(Equal("some-chain"))
		})

		Context("when locking fails", func() {
			BeforeEach(func() {
				lock.LockReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				err := lockedIPT.DeleteChain("some-table", "some-chain")
				Expect(err).To(MatchError("lock: banana"))
			})
		})

		Context("when iptables call fails and unlock succeeds", func() {
			BeforeEach(func() {
				ipt.DeleteChainReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				err := lockedIPT.DeleteChain("some-table", "some-chain")
				Expect(err).To(MatchError("iptables call: banana and unlock: <nil>"))
			})
		})

		Context("when iptables call fails and unlock fails", func() {
			BeforeEach(func() {
				lock.UnlockReturns(errors.New("banana"))
				ipt.DeleteChainReturns(errors.New("patato"))
			})
			It("returns an error", func() {
				err := lockedIPT.DeleteChain("some-table", "some-chain")
				Expect(err).To(MatchError("iptables call: patato and unlock: banana"))
			})
		})
	})

	Describe("ClearChain", func() {
		It("locks and passes the correct parameters to the iptables library", func() {
			err := lockedIPT.ClearChain("some-table", "some-chain")
			Expect(err).NotTo(HaveOccurred())

			Expect(lock.LockCallCount()).To(Equal(1))
			Expect(lock.UnlockCallCount()).To(Equal(1))
			Expect(ipt.ClearChainCallCount()).To(Equal(1))
			table, chain := ipt.ClearChainArgsForCall(0)
			Expect(table).To(Equal("some-table"))
			Expect(chain).To(Equal("some-chain"))
		})

		Context("when locking fails", func() {
			BeforeEach(func() {
				lock.LockReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				err := lockedIPT.ClearChain("some-table", "some-chain")
				Expect(err).To(MatchError("lock: banana"))
			})
		})

		Context("when iptables call fails and unlock succeeds", func() {
			BeforeEach(func() {
				ipt.ClearChainReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				err := lockedIPT.ClearChain("some-table", "some-chain")
				Expect(err).To(MatchError("iptables call: banana and unlock: <nil>"))
			})
		})

		Context("when iptables call fails and unlock fails", func() {
			BeforeEach(func() {
				lock.UnlockReturns(errors.New("banana"))
				ipt.ClearChainReturns(errors.New("patato"))
			})
			It("returns an error", func() {
				err := lockedIPT.ClearChain("some-table", "some-chain")
				Expect(err).To(MatchError("iptables call: patato and unlock: banana"))
			})
		})
	})

	Describe("RuleCount", func() {
		It("should return a count of all the rows", func() {
			toReturn := []byte(`a chain
				another chain
				a third chain`)
			ipTablesRunner.CombinedOutputReturns(toReturn, nil)

			rows, err := lockedIPT.RuleCount("table-name")
			Expect(err).NotTo(HaveOccurred())
			Expect(rows).To(Equal(3))

			Expect(lock.LockCallCount()).To(Equal(1))
			Expect(lock.UnlockCallCount()).To(Equal(1))
		})

		Context("when locking fails", func() {
			BeforeEach(func() {
				lock.LockReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				_, err := lockedIPT.RuleCount("table-name")
				Expect(err).To(MatchError("lock: banana"))
			})
		})

		Context("when call fails and unlock succeeds", func() {
			It("returns an error", func() {
				ipTablesRunner.CombinedOutputReturns([]byte{}, errors.New("nope"))

				_, err := lockedIPT.RuleCount("table-name")
				Expect(err).To(MatchError("iptablesCommandRunner: nope and unlock: <nil>"))
			})
		})

		Context("when call fails and unlock fails", func() {
			It("returns an error", func() {
				ipTablesRunner.CombinedOutputReturns([]byte{}, errors.New("nope"))
				lock.UnlockReturns(errors.New("banana"))

				_, err := lockedIPT.RuleCount("table-name")
				Expect(err).To(MatchError("iptablesCommandRunner: nope and unlock: banana"))
			})
		})
	})

	Describe("FlushAndRestore", func() {
		var toRestore string
		BeforeEach(func() {
			toRestore = "rule1\nrule2\n"
		})
		It("executes the command specified with a raw iptables-flush", func() {
			err := lockedIPT.FlushAndRestore(toRestore)
			Expect(err).NotTo(HaveOccurred())

			Expect(lock.LockCallCount()).To(Equal(1))
			Expect(lock.UnlockCallCount()).To(Equal(1))
			Expect(lockedIPT.Restorer.(*fakes.Restorer).RestoreWithFlagsCallCount()).To(Equal(1))
			Expect(lockedIPT.Restorer.(*fakes.Restorer).RestoreWithFlagsArgsForCall(0)).To(Equal("rule1\nrule2\n"))
		})
		Context("when locking fails", func() {
			BeforeEach(func() {
				lock.LockReturns(errors.New("banana"))
			})
			It("returns an error", func() {
				_, err := lockedIPT.RuleCount("table-name")
				Expect(err).To(MatchError("lock: banana"))
			})
		})
		Context("when call fails and unlock succeeds", func() {
			It("returns an error", func() {
				ipTablesRunner.CombinedOutputReturns([]byte{}, errors.New("nope"))

				_, err := lockedIPT.RuleCount("table-name")
				Expect(err).To(MatchError("iptablesCommandRunner: nope and unlock: <nil>"))
			})
		})

		Context("when call fails and unlock fails", func() {
			It("returns an error", func() {
				ipTablesRunner.CombinedOutputReturns([]byte{}, errors.New("nope"))
				lock.UnlockReturns(errors.New("banana"))

				_, err := lockedIPT.RuleCount("table-name")
				Expect(err).To(MatchError("iptablesCommandRunner: nope and unlock: banana"))
			})
		})
	})
})
