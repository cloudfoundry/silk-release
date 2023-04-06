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
	It("propagates errors up when encountered", func() {
		fakeIpTables.FlushAndRestoreReturns(fmt.Errorf("iptables borked"))
		err := main.PreStart(fakeIpTables)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError("iptables borked"))

	})
})
