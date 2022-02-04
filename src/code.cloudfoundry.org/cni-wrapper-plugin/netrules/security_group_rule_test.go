package netrules_test

import (
	"net"

	"code.cloudfoundry.org/cni-wrapper-plugin/netrules"
	"code.cloudfoundry.org/policy_client"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SecurityGroupRule", func() {
	Describe("Networks", func() {
		It("parses an ip address", func() {
			securityGroupRule := policy_client.SecurityGroupRule{
				Destination: "10.0.0.1",
			}
			rule, err := netrules.NewRuleFromSecurityGroupRule(securityGroupRule)
			Expect(err).NotTo(HaveOccurred())
			Expect(rule.Networks()).To(Equal([]netrules.IPRange{{Start: net.IPv4(10, 0, 0, 1), End: net.IPv4(10, 0, 0, 1)}}))
		})

		It("parses a cidr", func() {
			securityGroupRule := policy_client.SecurityGroupRule{
				Destination: "10.0.0.0/24",
			}
			rule, err := netrules.NewRuleFromSecurityGroupRule(securityGroupRule)
			Expect(err).NotTo(HaveOccurred())
			Expect(rule.Networks()).To(Equal([]netrules.IPRange{{Start: net.IPv4(10, 0, 0, 0).To4(), End: net.IPv4(10, 0, 0, 255).To4()}}))
		})

		It("parses an ip range", func() {
			securityGroupRule := policy_client.SecurityGroupRule{
				Destination: "10.0.0.1-10.0.1.10",
			}
			rule, err := netrules.NewRuleFromSecurityGroupRule(securityGroupRule)
			Expect(err).NotTo(HaveOccurred())
			Expect(rule.Networks()).To(Equal([]netrules.IPRange{{Start: net.IPv4(10, 0, 0, 1), End: net.IPv4(10, 0, 1, 10)}}))
		})

		It("raises an error when network is invalid", func() {
			securityGroupRule := policy_client.SecurityGroupRule{
				Destination: "invalid",
			}
			_, err := netrules.NewRuleFromSecurityGroupRule(securityGroupRule)
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(netrules.ErrIPRangeConversionFailed))
		})

		It("raises an error when cidr is invalid", func() {
			securityGroupRule := policy_client.SecurityGroupRule{
				Destination: "10.0.0.1/123",
			}
			_, err := netrules.NewRuleFromSecurityGroupRule(securityGroupRule)
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(netrules.ErrIPRangeConversionFailed))
		})

		It("raises an error when iprange is invalid", func() {
			securityGroupRule := policy_client.SecurityGroupRule{
				Destination: "10.0.0.1-123",
			}
			_, err := netrules.NewRuleFromSecurityGroupRule(securityGroupRule)
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(netrules.ErrIPRangeConversionFailed))
		})
	})

	Describe("Ports", func() {
		It("parses 1 port", func() {
			securityGroupRule := policy_client.SecurityGroupRule{
				Destination: "10.0.0.1",
				Ports:       "8080",
			}
			rule, err := netrules.NewRuleFromSecurityGroupRule(securityGroupRule)
			Expect(err).NotTo(HaveOccurred())
			Expect(rule.Ports()).To(Equal([]netrules.PortRange{{Start: 8080, End: 8080}}))
		})

		It("parses multiple ports", func() {
			securityGroupRule := policy_client.SecurityGroupRule{
				Destination: "10.0.0.1",
				Ports:       "80,443,8080,8443",
			}
			rule, err := netrules.NewRuleFromSecurityGroupRule(securityGroupRule)
			Expect(err).NotTo(HaveOccurred())
			Expect(rule.Ports()).To(Equal([]netrules.PortRange{
				{Start: 80, End: 80},
				{Start: 443, End: 443},
				{Start: 8080, End: 8080},
				{Start: 8443, End: 8443},
			}))
		})

		It("parses 1 range", func() {
			securityGroupRule := policy_client.SecurityGroupRule{
				Destination: "10.0.0.1",
				Ports:       "1000-2000",
			}
			rule, err := netrules.NewRuleFromSecurityGroupRule(securityGroupRule)
			Expect(err).NotTo(HaveOccurred())
			Expect(rule.Ports()).To(Equal([]netrules.PortRange{
				{Start: 1000, End: 2000},
			}))
		})

		It("parses multiple ranges", func() {
			securityGroupRule := policy_client.SecurityGroupRule{
				Destination: "10.0.0.1",
				Ports:       "1000-2000,3000-4000",
			}
			rule, err := netrules.NewRuleFromSecurityGroupRule(securityGroupRule)
			Expect(err).NotTo(HaveOccurred())
			Expect(rule.Ports()).To(ConsistOf(
				netrules.PortRange{Start: 1000, End: 2000},
				netrules.PortRange{Start: 3000, End: 4000},
			))
		})

		It("parses ports and ranges", func() {
			securityGroupRule := policy_client.SecurityGroupRule{
				Destination: "10.0.0.1",
				Ports:       "1000-2000,8080,3000-4000,443",
			}
			rule, err := netrules.NewRuleFromSecurityGroupRule(securityGroupRule)
			Expect(err).NotTo(HaveOccurred())
			Expect(rule.Ports()).To(ConsistOf(
				netrules.PortRange{Start: 1000, End: 2000},
				netrules.PortRange{Start: 8080, End: 8080},
				netrules.PortRange{Start: 3000, End: 4000},
				netrules.PortRange{Start: 443, End: 443},
			))
		})
	})
})
