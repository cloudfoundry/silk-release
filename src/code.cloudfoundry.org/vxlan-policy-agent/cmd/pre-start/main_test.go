package main_test

import (
	"fmt"

	main "code.cloudfoundry.org/vxlan-policy-agent/cmd/pre-start"

	"code.cloudfoundry.org/lib/fakes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Pre-Start", func() {
	var fakeIpTables *fakes.IPTablesAdapter

	BeforeEach(func() {
		fakeIpTables = &fakes.IPTablesAdapter{}
	})

	It("clears the iptables rules for filter/nat tables", func() {
		err := main.PreStart(fakeIpTables)
		Expect(err).ToNot(HaveOccurred())
		Expect(fakeIpTables.FlushAndRestoreCallCount()).To(Equal(1))
		Expect(fakeIpTables.FlushAndRestoreArgsForCall(0)).To(Equal("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n"))
	})
	Context("when the PreStart() iptables flush and restore fails", func() {
		BeforeEach(func() {
			fakeIpTables.FlushAndRestoreReturns(fmt.Errorf("iptables borked"))
		})

		It("retries up to MAX_RETRIES times", func() {
			err := main.PreStart(fakeIpTables)
			Expect(err).To(HaveOccurred())
			Expect(fakeIpTables.FlushAndRestoreCallCount()).To(Equal(main.MAX_RETRIES))

		})

		It("propagates errors up when encountered", func() {
			err := main.PreStart(fakeIpTables)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("iptables borked"))
		})

		Context("and eventually succeeds", func() {
			BeforeEach(func() {
				fakeIpTables.FlushAndRestoreReturnsOnCall(0, fmt.Errorf("iptables borked"))
				fakeIpTables.FlushAndRestoreReturnsOnCall(1, fmt.Errorf("iptables borked"))
				fakeIpTables.FlushAndRestoreReturnsOnCall(2, fmt.Errorf("iptables borked"))
				fakeIpTables.FlushAndRestoreReturnsOnCall(3, nil)
			})

			It("retries and then clears the iptables rules", func() {
				err := main.PreStart(fakeIpTables)
				Expect(fakeIpTables.FlushAndRestoreCallCount()).To(Equal(4))
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})
})
