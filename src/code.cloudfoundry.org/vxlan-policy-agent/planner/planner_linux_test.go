//go:build !windows
// +build !windows

package planner_test

import (
	"errors"
	"fmt"

	"code.cloudfoundry.org/cni-wrapper-plugin/netrules"
	"code.cloudfoundry.org/executor"
	"code.cloudfoundry.org/lib/datastore"
	libfakes "code.cloudfoundry.org/lib/fakes"
	"code.cloudfoundry.org/lib/rules"
	"code.cloudfoundry.org/policy_client"
	"code.cloudfoundry.org/vxlan-policy-agent/enforcer"
	"code.cloudfoundry.org/vxlan-policy-agent/planner"
	"code.cloudfoundry.org/vxlan-policy-agent/planner/fakes"

	"code.cloudfoundry.org/lager/lagertest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/pivotal-cf-experimental/gomegamatchers"
)

var _ = Describe("Planner", func() {
	var (
		policyPlanner              *planner.VxlanPolicyPlanner
		policyClient               *fakes.PolicyClient
		policyServerResponse       []policy_client.Policy
		egressPolicyServerResponse []policy_client.EgressPolicy
		store                      *libfakes.Datastore
		metricsSender              *fakes.MetricsSender
		logger                     *lagertest.TestLogger
		chain                      enforcer.Chain
		data                       map[string]datastore.Container
		loggingStateGetter         *fakes.LoggingStateGetter
		netOutChain                *fakes.NetOutChain
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
		policyClient = &fakes.PolicyClient{}
		metricsSender = &fakes.MetricsSender{}
		loggingStateGetter = &fakes.LoggingStateGetter{}

		netOutChain = &fakes.NetOutChain{}
		netOutChain.NameStub = func(handle string) string {
			return "netout-" + handle
		}
		netOutChain.IPTablesRulesStub = func(containerHandle string, containerWorkload string, ruleSpec []netrules.Rule) ([]rules.IPTablesRule, error) {
			if containerHandle == "container-id-1" {
				return []rules.IPTablesRule{{"rule-1"}, {"rule-2"}}, nil
			} else if containerHandle == "container-id-2" {
				return []rules.IPTablesRule{{"rule-3"}, {"rule-4"}}, nil
			}
			return nil, errors.New("unknown-container-handle")
		}
		store = &libfakes.Datastore{}

		data = make(map[string]datastore.Container)
		data["container-id-1"] = datastore.Container{
			Handle: "container-id-1",
			IP:     "10.255.1.2",
			Metadata: map[string]interface{}{
				"policy_group_id":    "some-app-guid",
				"space_id":           "some-space-guid",
				"ports":              "8080",
				"container_workload": "task",
			},
		}
		data["container-id-2"] = datastore.Container{
			Handle: "container-id-2",
			IP:     "10.255.1.3",
			Metadata: map[string]interface{}{
				"policy_group_id":    "some-other-app-guid",
				"space_id":           "some-other-space-guid",
				"ports":              " 8181 , 9090",
				"container_workload": "staging",
			},
		}
		data["container-id-3"] = datastore.Container{
			Handle: "container-id-3",
			IP:     "10.255.1.4",
		}

		store.ReadAllReturns(data, nil)

		policyServerResponse = []policy_client.Policy{
			{
				Source: policy_client.Source{
					ID:  "some-app-guid",
					Tag: "AA",
				},
				Destination: policy_client.Destination{
					ID: "some-other-app-guid",
					Ports: policy_client.Ports{
						Start: 1234,
						End:   1234,
					},
					Protocol: "tcp",
				},
			},
			{
				Source: policy_client.Source{
					ID:  "another-app-guid",
					Tag: "BB",
				},
				Destination: policy_client.Destination{
					ID: "some-other-app-guid",
					Ports: policy_client.Ports{
						Start: 5555,
						End:   5555,
					},
					Protocol: "udp",
				},
			},
			{
				Source: policy_client.Source{
					ID:  "some-other-app-guid",
					Tag: "CC",
				},
				Destination: policy_client.Destination{
					ID: "yet-another-app-guid",
					Ports: policy_client.Ports{
						Start: 6534,
						End:   6534,
					},
					Protocol: "udp",
				},
			},
			{
				Source: policy_client.Source{
					ID:  "some-app-guid",
					Tag: "AA",
				},
				Destination: policy_client.Destination{
					ID: "some-app-guid",
					Ports: policy_client.Ports{
						Start: 8080,
						End:   8080,
					},
					Protocol: "tcp",
				},
			},
		}

		egressPolicyServerResponse = []policy_client.EgressPolicy{
			{
				Source: &policy_client.EgressSource{
					ID: "some-app-guid",
				},
				Destination: &policy_client.EgressDestination{
					Protocol: "tcp",
					Ports: []policy_client.Ports{
						{Start: 8080, End: 8081},
					},
					IPRanges: []policy_client.IPRange{
						{Start: "1.2.3.4", End: "1.2.3.5"},
					},
				},
				AppLifecycle: "all",
			},
			{
				Source: &policy_client.EgressSource{
					ID: "some-app-guid",
				},
				Destination: &policy_client.EgressDestination{
					Protocol: "udp",
					Ports: []policy_client.Ports{
						{Start: 8080, End: 8081},
					},
					IPRanges: []policy_client.IPRange{
						{Start: "1.2.3.4", End: "1.2.3.5"},
					},
				},
				AppLifecycle: "all",
			},
			{
				Source: &policy_client.EgressSource{
					ID: "some-other-app-guid",
				},
				Destination: &policy_client.EgressDestination{
					Protocol: "icmp",
					ICMPType: 2,
					ICMPCode: 3,
					IPRanges: []policy_client.IPRange{
						{Start: "1.2.3.6", End: "1.2.3.7"},
					},
				},
				AppLifecycle: "all",
			},
			{
				Source: &policy_client.EgressSource{
					ID: "some-other-app-guid",
				},
				Destination: &policy_client.EgressDestination{
					Protocol: "icmp",
					ICMPType: 8,
					ICMPCode: -1,
					IPRanges: []policy_client.IPRange{
						{Start: "1.2.3.6", End: "1.2.3.7"},
					},
				},
				AppLifecycle: "all",
			},
			{
				Source: &policy_client.EgressSource{
					ID: "some-other-app-guid",
				},
				Destination: &policy_client.EgressDestination{
					Protocol: "icmp",
					ICMPType: -1,
					ICMPCode: -1,
					IPRanges: []policy_client.IPRange{
						{Start: "1.2.3.6", End: "1.2.3.7"},
					},
				},
				AppLifecycle: "all",
			},
			{
				Source: &policy_client.EgressSource{
					ID: "some-other-app-guid",
				},
				Destination: &policy_client.EgressDestination{
					Protocol: "tcp",
					IPRanges: []policy_client.IPRange{
						{Start: "1.2.3.6", End: "1.2.3.7"},
					},
				},
				AppLifecycle: "all",
			},
			{
				Source: &policy_client.EgressSource{
					ID:   "some-space-guid",
					Type: "space",
				},
				Destination: &policy_client.EgressDestination{
					Protocol: "udp",
					IPRanges: []policy_client.IPRange{
						{Start: "2.3.4.5", End: "3.3.3.3"},
					},
				},
				AppLifecycle: "all",
			},
			{
				Source: &policy_client.EgressSource{
					ID:   "",
					Type: "default",
				},
				Destination: &policy_client.EgressDestination{
					Protocol: "udp",
					IPRanges: []policy_client.IPRange{
						{Start: "8.7.6.5", End: "4.3.2.1"},
					},
				},
				AppLifecycle: "all",
			},
			{
				Source: &policy_client.EgressSource{
					ID: "some-other-app-guid",
				},
				Destination: &policy_client.EgressDestination{
					Protocol: "all",
					IPRanges: []policy_client.IPRange{
						{Start: "8.8.4.4", End: "8.8.8.8"},
					},
					Ports: []policy_client.Ports{
						{Start: 8080, End: 8081},
					},
				},
				AppLifecycle: "all",
			},
		}

		policyClient.GetPoliciesByIDReturns(policyServerResponse, egressPolicyServerResponse, nil)
		policyClient.CreateOrGetTagReturns("5476", nil)

		chain = enforcer.Chain{
			Table:       "some-table",
			ParentChain: "INPUT",
			Prefix:      "some-prefix",
		}

		policyPlanner = &planner.VxlanPolicyPlanner{
			Logger:                        logger,
			Datastore:                     store,
			PolicyClient:                  policyClient,
			VNI:                           42,
			MetricsSender:                 metricsSender,
			Chain:                         chain,
			LoggingState:                  loggingStateGetter,
			IPTablesAcceptedUDPLogsPerSec: 3,
			EnableOverlayIngressRules:     true,
			HostInterfaceNames:            []string{"eth0"},
			NetOutChain:                   netOutChain,
		}
	})

	Describe("GetPolicyRulesAndChain", func() {
		Context("when multiple underlay interfaces are present", func() {
			BeforeEach(func() {
				policyPlanner.HostInterfaceNames = []string{"eth0", "eth1"}
			})

			It("returns all the rules but no logging rules", func() {
				rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
				Expect(err).NotTo(HaveOccurred())
				Expect(rulesWithChain.Chain).To(Equal(chain))
				Expect(rulesWithChain.Rules).To(ConsistOf([]rules.IPTablesRule{
					{"-s", "10.255.1.2", "-o", "eth0", "-p", "tcp", "-m", "iprange", "--dst-range", "1.2.3.4-1.2.3.5", "-m", "tcp", "--dport", "8080:8081", "-j", "ACCEPT"},
					{"-s", "10.255.1.2", "-o", "eth0", "-p", "udp", "-m", "iprange", "--dst-range", "1.2.3.4-1.2.3.5", "-m", "udp", "--dport", "8080:8081", "-j", "ACCEPT"},
					{"-s", "10.255.1.3", "-o", "eth0", "-p", "icmp", "-m", "iprange", "--dst-range", "1.2.3.6-1.2.3.7", "-m", "icmp", "--icmp-type", "2/3", "-j", "ACCEPT"},
					{"-s", "10.255.1.3", "-o", "eth0", "-p", "icmp", "-m", "iprange", "--dst-range", "1.2.3.6-1.2.3.7", "-m", "icmp", "--icmp-type", "8", "-j", "ACCEPT"},
					{"-s", "10.255.1.3", "-o", "eth0", "-p", "icmp", "-m", "iprange", "--dst-range", "1.2.3.6-1.2.3.7", "-j", "ACCEPT"},
					{"-s", "10.255.1.3", "-o", "eth0", "-p", "tcp", "-m", "iprange", "--dst-range", "1.2.3.6-1.2.3.7", "-j", "ACCEPT"},
					{"-s", "10.255.1.2", "-o", "eth0", "-p", "udp", "-m", "iprange", "--dst-range", "2.3.4.5-3.3.3.3", "-j", "ACCEPT"},
					{"-s", "10.255.1.3", "-o", "eth0", "-p", "all", "-m", "iprange", "--dst-range", "8.8.4.4-8.8.8.8", "-j", "ACCEPT"},
					{"-s", "10.255.1.2", "-o", "eth1", "-p", "tcp", "-m", "iprange", "--dst-range", "1.2.3.4-1.2.3.5", "-m", "tcp", "--dport", "8080:8081", "-j", "ACCEPT"},
					{"-s", "10.255.1.2", "-o", "eth1", "-p", "udp", "-m", "iprange", "--dst-range", "1.2.3.4-1.2.3.5", "-m", "udp", "--dport", "8080:8081", "-j", "ACCEPT"},
					{"-s", "10.255.1.3", "-o", "eth1", "-p", "icmp", "-m", "iprange", "--dst-range", "1.2.3.6-1.2.3.7", "-m", "icmp", "--icmp-type", "2/3", "-j", "ACCEPT"},
					{"-s", "10.255.1.3", "-o", "eth1", "-p", "icmp", "-m", "iprange", "--dst-range", "1.2.3.6-1.2.3.7", "-m", "icmp", "--icmp-type", "8", "-j", "ACCEPT"},
					{"-s", "10.255.1.3", "-o", "eth1", "-p", "icmp", "-m", "iprange", "--dst-range", "1.2.3.6-1.2.3.7", "-j", "ACCEPT"},
					{"-s", "10.255.1.3", "-o", "eth1", "-p", "tcp", "-m", "iprange", "--dst-range", "1.2.3.6-1.2.3.7", "-j", "ACCEPT"},
					{"-s", "10.255.1.2", "-o", "eth1", "-p", "udp", "-m", "iprange", "--dst-range", "2.3.4.5-3.3.3.3", "-j", "ACCEPT"},
					{"-s", "10.255.1.3", "-o", "eth1", "-p", "all", "-m", "iprange", "--dst-range", "8.8.4.4-8.8.8.8", "-j", "ACCEPT"},
					// allow based on mark
					{"-d", "10.255.1.3", "-p", "udp", "--dport", "5555:5555", "-m", "mark", "--mark", "0xBB", "--jump", "ACCEPT", "-m", "comment", "--comment", "src:another-app-guid_dst:some-other-app-guid"},
					{"-d", "10.255.1.3", "-p", "tcp", "--dport", "1234:1234", "-m", "mark", "--mark", "0xAA", "--jump", "ACCEPT", "-m", "comment", "--comment", "src:some-app-guid_dst:some-other-app-guid"},
					{"-d", "10.255.1.2", "-p", "tcp", "--dport", "8080:8080", "-m", "mark", "--mark", "0xAA", "--jump", "ACCEPT", "-m", "comment", "--comment", "src:some-app-guid_dst:some-app-guid"},
					{"-d", "10.255.1.2", "-p", "tcp", "-m", "tcp", "--dport", "8080", "-m", "mark", "--mark", "0x5476", "--jump", "ACCEPT"},
					{"-d", "10.255.1.3", "-p", "tcp", "-m", "tcp", "--dport", "9090", "-m", "mark", "--mark", "0x5476", "--jump", "ACCEPT"},
					{"-d", "10.255.1.3", "-p", "tcp", "-m", "tcp", "--dport", "8181", "-m", "mark", "--mark", "0x5476", "--jump", "ACCEPT"},
					// set tags on all outgoing packets, regardless of local vs remote
					{"--source", "10.255.1.2", "--jump", "MARK", "--set-xmark", "0xAA", "-m", "comment", "--comment", "src:some-app-guid"},
					{"--source", "10.255.1.3", "--jump", "MARK", "--set-xmark", "0xCC", "-m", "comment", "--comment", "src:some-other-app-guid"},
					// default
					{"-s", "10.255.1.3", "-o", "eth0", "-p", "udp", "-m", "iprange", "--dst-range", "8.7.6.5-4.3.2.1", "-j", "ACCEPT"},
					{"-s", "10.255.1.2", "-o", "eth0", "-p", "udp", "-m", "iprange", "--dst-range", "8.7.6.5-4.3.2.1", "-j", "ACCEPT"},
					{"-s", "10.255.1.3", "-o", "eth1", "-p", "udp", "-m", "iprange", "--dst-range", "8.7.6.5-4.3.2.1", "-j", "ACCEPT"},
					{"-s", "10.255.1.2", "-o", "eth1", "-p", "udp", "-m", "iprange", "--dst-range", "8.7.6.5-4.3.2.1", "-j", "ACCEPT"},
				}))
			})
		})
		It("gets every container's properties from the datastore", func() {
			_, err := policyPlanner.GetPolicyRulesAndChain()
			Expect(err).NotTo(HaveOccurred())

			Expect(store.ReadAllCallCount()).To(Equal(1))
		})

		It("gets policies from the policy server", func() {
			_, err := policyPlanner.GetPolicyRulesAndChain()
			Expect(err).NotTo(HaveOccurred())

			By("filtering by ID when calling the internal policy server")
			Expect(policyClient.GetPoliciesByIDCallCount()).To(Equal(1))
			Expect(policyClient.GetPoliciesByIDArgsForCall(0)).To(ConsistOf([]interface{}{"some-app-guid", "some-other-app-guid", "some-space-guid", "some-other-space-guid"}))
		})

		Context("when iptables logging is disabled", func() {
			BeforeEach(func() {
				loggingStateGetter.IsEnabledReturns(false)
			})

			Context("when EnableOverlayIngressRules is enabled", func() {
				BeforeEach(func() {
					policyPlanner.EnableOverlayIngressRules = true
				})

				It("returns all the rules but no logging rules", func() {
					rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
					Expect(err).NotTo(HaveOccurred())
					Expect(rulesWithChain.Chain).To(Equal(chain))
					Expect(rulesWithChain.Rules).To(ConsistOf([]rules.IPTablesRule{
						{
							"-s", "10.255.1.2",
							"-o", "eth0",
							"-p", "tcp",
							"-m", "iprange",
							"--dst-range", "1.2.3.4-1.2.3.5",
							"-m", "tcp",
							"--dport", "8080:8081",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.2",
							"-o", "eth0",
							"-p", "udp",
							"-m", "iprange",
							"--dst-range", "1.2.3.4-1.2.3.5",
							"-m", "udp",
							"--dport", "8080:8081",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.3",
							"-o", "eth0",
							"-p", "icmp",
							"-m", "iprange",
							"--dst-range", "1.2.3.6-1.2.3.7",
							"-m", "icmp",
							"--icmp-type", "2/3",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.3",
							"-o", "eth0",
							"-p", "icmp",
							"-m", "iprange",
							"--dst-range", "1.2.3.6-1.2.3.7",
							"-m", "icmp",
							"--icmp-type", "8",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.3",
							"-o", "eth0",
							"-p", "icmp",
							"-m", "iprange",
							"--dst-range", "1.2.3.6-1.2.3.7",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.3",
							"-o", "eth0",
							"-p", "tcp",
							"-m", "iprange",
							"--dst-range", "1.2.3.6-1.2.3.7",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.2",
							"-o", "eth0",
							"-p", "udp",
							"-m", "iprange",
							"--dst-range", "2.3.4.5-3.3.3.3",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.3",
							"-o", "eth0",
							"-p", "all",
							"-m", "iprange",
							"--dst-range", "8.8.4.4-8.8.8.8",
							"-j", "ACCEPT",
						},
						// allow based on mark
						{
							"-d", "10.255.1.3",
							"-p", "udp",
							"--dport", "5555:5555",
							"-m", "mark", "--mark", "0xBB",
							"--jump", "ACCEPT",
							"-m", "comment", "--comment", "src:another-app-guid_dst:some-other-app-guid",
						},
						{
							"-d", "10.255.1.3",
							"-p", "tcp",
							"--dport", "1234:1234",
							"-m", "mark", "--mark", "0xAA",
							"--jump", "ACCEPT",
							"-m", "comment", "--comment", "src:some-app-guid_dst:some-other-app-guid",
						},
						{
							"-d", "10.255.1.2",
							"-p", "tcp",
							"--dport", "8080:8080",
							"-m", "mark", "--mark", "0xAA",
							"--jump", "ACCEPT",
							"-m", "comment", "--comment", "src:some-app-guid_dst:some-app-guid",
						},
						{
							"-d", "10.255.1.2",
							"-p", "tcp",
							"-m", "tcp", "--dport", "8080",
							"-m", "mark", "--mark", "0x5476",
							"--jump", "ACCEPT",
						},
						{
							"-d", "10.255.1.3",
							"-p", "tcp",
							"-m", "tcp", "--dport", "9090",
							"-m", "mark", "--mark", "0x5476",
							"--jump", "ACCEPT",
						},
						{
							"-d", "10.255.1.3",
							"-p", "tcp",
							"-m", "tcp", "--dport", "8181",
							"-m", "mark", "--mark", "0x5476",
							"--jump", "ACCEPT",
						},
						// set tags on all outgoing packets, regardless of local vs remote
						{
							"--source", "10.255.1.2",
							"--jump", "MARK", "--set-xmark", "0xAA",
							"-m", "comment", "--comment", "src:some-app-guid",
						},
						{
							"--source", "10.255.1.3",
							"--jump", "MARK", "--set-xmark", "0xCC",
							"-m", "comment", "--comment", "src:some-other-app-guid",
						},
						// default
						{
							"-s", "10.255.1.3", "-o", "eth0", "-p", "udp", "-m", "iprange", "--dst-range", "8.7.6.5-4.3.2.1", "-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.2", "-o", "eth0", "-p", "udp", "-m", "iprange", "--dst-range", "8.7.6.5-4.3.2.1", "-j", "ACCEPT",
						},
					}))
				})
			})

			Context("when EnableOverlayIngressRules is disabled", func() {
				BeforeEach(func() {
					policyPlanner.EnableOverlayIngressRules = false
				})

				It("returns the rules without overlay ingress and no logging rules", func() {
					rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
					Expect(err).NotTo(HaveOccurred())
					Expect(rulesWithChain.Chain).To(Equal(chain))

					Expect(rulesWithChain.Rules).To(ConsistOf([]rules.IPTablesRule{
						{
							"-s", "10.255.1.2",
							"-o", "eth0",
							"-p", "udp",
							"-m", "iprange",
							"--dst-range", "1.2.3.4-1.2.3.5",
							"-m", "udp",
							"--dport", "8080:8081",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.2",
							"-o", "eth0",
							"-p", "tcp",
							"-m", "iprange",
							"--dst-range", "1.2.3.4-1.2.3.5",
							"-m", "tcp",
							"--dport", "8080:8081",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.3",
							"-o", "eth0",
							"-p", "tcp",
							"-m", "iprange",
							"--dst-range", "1.2.3.6-1.2.3.7",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.3",
							"-o", "eth0",
							"-p", "icmp",
							"-m", "iprange",
							"--dst-range", "1.2.3.6-1.2.3.7",
							"-m", "icmp",
							"--icmp-type", "2/3",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.3",
							"-o", "eth0",
							"-p", "icmp",
							"-m", "iprange",
							"--dst-range", "1.2.3.6-1.2.3.7",
							"-m", "icmp",
							"--icmp-type", "8",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.3",
							"-o", "eth0",
							"-p", "icmp",
							"-m", "iprange",
							"--dst-range", "1.2.3.6-1.2.3.7",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.2",
							"-o", "eth0",
							"-p", "udp",
							"-m", "iprange",
							"--dst-range", "2.3.4.5-3.3.3.3",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.3",
							"-o", "eth0",
							"-p", "all",
							"-m", "iprange",
							"--dst-range", "8.8.4.4-8.8.8.8",
							"-j", "ACCEPT",
						},
						// allow based on mark
						{
							"-d", "10.255.1.3",
							"-p", "udp",
							"--dport", "5555:5555",
							"-m", "mark", "--mark", "0xBB",
							"--jump", "ACCEPT",
							"-m", "comment", "--comment", "src:another-app-guid_dst:some-other-app-guid",
						},
						{
							"-d", "10.255.1.3",
							"-p", "tcp",
							"--dport", "1234:1234",
							"-m", "mark", "--mark", "0xAA",
							"--jump", "ACCEPT",
							"-m", "comment", "--comment", "src:some-app-guid_dst:some-other-app-guid",
						},
						{
							"-d", "10.255.1.2",
							"-p", "tcp",
							"--dport", "8080:8080",
							"-m", "mark", "--mark", "0xAA",
							"--jump", "ACCEPT",
							"-m", "comment", "--comment", "src:some-app-guid_dst:some-app-guid",
						},
						// set tags on all outgoing packets, regardless of local vs remote
						{
							"--source", "10.255.1.2",
							"--jump", "MARK", "--set-xmark", "0xAA",
							"-m", "comment", "--comment", "src:some-app-guid",
						},
						{
							"--source", "10.255.1.3",
							"--jump", "MARK", "--set-xmark", "0xCC",
							"-m", "comment", "--comment", "src:some-other-app-guid",
						},
						// default policies
						{
							"-s", "10.255.1.3",
							"-o", "eth0",
							"-p", "udp",
							"-m", "iprange",
							"--dst-range", "8.7.6.5-4.3.2.1",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.2",
							"-o", "eth0",
							"-p", "udp",
							"-m", "iprange",
							"--dst-range", "8.7.6.5-4.3.2.1",
							"-j", "ACCEPT",
						},
					}))
				})
			})

		})

		Context("when iptables logging is enabled", func() {
			BeforeEach(func() {
				loggingStateGetter.IsEnabledReturns(true)
			})
			It("returns all the rules including logging rules", func() {
				rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
				Expect(err).NotTo(HaveOccurred())
				Expect(rulesWithChain.Chain).To(Equal(chain))

				Expect(rulesWithChain.Rules).To(gomegamatchers.ContainSequence([]rules.IPTablesRule{
					// LOG bb allow based on mark
					{
						"-d", "10.255.1.3",
						"-p", "udp",
						"--dport", "5555:5555",
						"-m", "mark",
						"--mark", "0xBB",
						"-m", "limit",
						"--limit", "3/s",
						"--limit-burst", "3",
						"--jump", "LOG", "--log-prefix", `"OK_BB_some-other-app-guid "`,
					},
					// allow bb based on mark
					{
						"-d", "10.255.1.3",
						"-p", "udp",
						"--dport", "5555:5555",
						"-m", "mark", "--mark", "0xBB",
						"--jump", "ACCEPT",
						"-m", "comment", "--comment", "src:another-app-guid_dst:some-other-app-guid",
					},
				}))
				Expect(rulesWithChain.Rules).To(gomegamatchers.ContainSequence([]rules.IPTablesRule{
					// LOG aa allow based on mark
					{
						"-d", "10.255.1.3",
						"-p", "tcp",
						"--dport", "1234:1234",
						"-m", "mark", "--mark", "0xAA",
						"-m", "conntrack", "--ctstate", "INVALID,NEW,UNTRACKED",
						"--jump", "LOG", "--log-prefix", `"OK_AA_some-other-app-guid "`,
					},
					// allow aa based on mark
					{
						"-d", "10.255.1.3",
						"-p", "tcp",
						"--dport", "1234:1234",
						"-m", "mark", "--mark", "0xAA",
						"--jump", "ACCEPT",
						"-m", "comment", "--comment", "src:some-app-guid_dst:some-other-app-guid",
					},
				}))
				Expect(rulesWithChain.Rules).To(ContainElement(rules.IPTablesRule{
					// set tags on all outgoing packets, regardless of local vs remote
					"--source", "10.255.1.2",
					"--jump", "MARK", "--set-xmark", "0xAA",
					"-m", "comment", "--comment", "src:some-app-guid",
				}))
				Expect(rulesWithChain.Rules).To(ContainElement(rules.IPTablesRule{
					"--source", "10.255.1.3",
					"--jump", "MARK", "--set-xmark", "0xCC",
					"-m", "comment", "--comment", "src:some-other-app-guid",
				}))
			})
		})

		It("returns all mark set rules before any mark filter rules", func() {
			rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
			Expect(err).NotTo(HaveOccurred())
			Expect(rulesWithChain.Rules[0]).To(ContainElement("--set-xmark"))
			Expect(rulesWithChain.Rules[1]).To(ContainElement("--set-xmark"))
			Expect(rulesWithChain.Rules[2]).To(ContainElement("ACCEPT"))
			Expect(rulesWithChain.Rules[3]).To(ContainElement("ACCEPT"))
		})

		It("emits time metrics", func() {
			_, err := policyPlanner.GetPolicyRulesAndChain()
			Expect(err).NotTo(HaveOccurred())
			Expect(metricsSender.SendDurationCallCount()).To(Equal(2))
			name, _ := metricsSender.SendDurationArgsForCall(0)
			Expect(name).To(Equal("containerMetadataTime"))
			name, _ = metricsSender.SendDurationArgsForCall(1)
			Expect(name).To(Equal("policyServerPollTime"))
		})

		Context("when the policies are returned from the server in a different order", func() {
			var reversed []policy_client.Policy
			var reversedEgress []policy_client.EgressPolicy
			BeforeEach(func() {
				for i := range policyServerResponse {
					reversed = append(reversed, policyServerResponse[len(policyServerResponse)-i-1])
				}
				for i := range egressPolicyServerResponse {
					reversedEgress = append(reversedEgress, egressPolicyServerResponse[len(egressPolicyServerResponse)-i-1])
				}
			})

			It("the order of the rules is not affected", func() {
				rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
				Expect(err).NotTo(HaveOccurred())
				policyClient.GetPoliciesByIDReturns(reversed, reversedEgress, nil)
				rulesWithChain2, err := policyPlanner.GetPolicyRulesAndChain()
				Expect(err).NotTo(HaveOccurred())

				Expect(rulesWithChain).To(Equal(rulesWithChain2))
			})

		})

		Context("when multiple policies are defined for the same source app", func() {
			BeforeEach(func() {
				policyServerResponse = []policy_client.Policy{
					{
						Source: policy_client.Source{
							ID:  "some-app-guid",
							Tag: "AA",
						},
						Destination: policy_client.Destination{
							ID: "some-other-app-guid",
							Ports: policy_client.Ports{
								Start: 1234,
								End:   1234,
							},
							Protocol: "tcp",
						},
					},
					{
						Source: policy_client.Source{
							ID:  "some-app-guid",
							Tag: "AA",
						},
						Destination: policy_client.Destination{
							ID: "some-other-app-guid",
							Ports: policy_client.Ports{
								Start: 1235,
								End:   1235,
							},
							Protocol: "tcp",
						},
					},
				}
				policyClient.GetPoliciesByIDReturns(policyServerResponse, nil, nil)
			})

			It("writes only one set mark rule", func() {
				rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
				Expect(err).NotTo(HaveOccurred())
				Expect(rulesWithChain.Rules).To(HaveLen(6))
				Expect(rulesWithChain.Rules[0]).To(ContainElement("--set-xmark"))
				Expect(rulesWithChain.Rules[1]).To(ContainElement("ACCEPT"))
				Expect(rulesWithChain.Rules[2]).To(ContainElement("ACCEPT"))
			})
		})

		Context("when there are multiple containers for an app on the cell", func() {
			BeforeEach(func() {
				data = make(map[string]datastore.Container)
				data["container-id-1"] = datastore.Container{
					Handle: "container-id-1",
					IP:     "10.255.1.2",
					Metadata: map[string]interface{}{
						"policy_group_id": "some-app-guid",
						"ports":           "8080",
					},
				}
				data["container-id-2"] = datastore.Container{
					Handle: "container-id-2",
					IP:     "10.255.1.3",
					Metadata: map[string]interface{}{
						"policy_group_id": "some-other-app-guid",
						"ports":           "8080",
					},
				}
				data["container-id-3"] = datastore.Container{
					Handle: "container-id-3",
					IP:     "10.255.1.4",
					Metadata: map[string]interface{}{
						"policy_group_id": "some-app-guid",
						"ports":           "8080",
					},
				}
				data["container-id-4"] = datastore.Container{
					Handle: "container-id-4",
					IP:     "10.255.1.5",
					Metadata: map[string]interface{}{
						"policy_group_id": "some-other-app-guid",
						"ports":           "8080",
					},
				}

				store.ReadAllReturns(data, nil)
			})

			It("the order of the rules is not affected", func() {
				rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
				Expect(err).NotTo(HaveOccurred())
				Expect(rulesWithChain.Rules[0]).To(ContainElement("10.255.1.2"))
				Expect(rulesWithChain.Rules[1]).To(ContainElement("10.255.1.3"))
				Expect(rulesWithChain.Rules[2]).To(ContainElement("10.255.1.4"))
				Expect(rulesWithChain.Rules[3]).To(ContainElement("10.255.1.5"))
			})
		})

		Context("when there are app lifecycle limitations", func() {

			BeforeEach(func() {
				egressPolicyServerResponse = []policy_client.EgressPolicy{
					{
						Source: &policy_client.EgressSource{
							ID: "some-app-guid",
						},
						Destination: &policy_client.EgressDestination{
							Protocol: "tcp",
							Ports: []policy_client.Ports{
								{Start: 1234, End: 1234},
							},
							IPRanges: []policy_client.IPRange{
								{Start: "1.2.3.4", End: "1.2.3.5"},
							},
						},
						AppLifecycle: "running",
					},
					{
						Source: &policy_client.EgressSource{
							ID: "some-app-guid",
						},
						Destination: &policy_client.EgressDestination{
							Protocol: "udp",
							Ports: []policy_client.Ports{
								{Start: 5678, End: 5678},
							},
							IPRanges: []policy_client.IPRange{
								{Start: "1.2.3.4", End: "1.2.3.5"},
							},
						},
						AppLifecycle: "staging",
					},
					{
						Source: &policy_client.EgressSource{
							ID: "some-app-guid",
						},
						Destination: &policy_client.EgressDestination{
							Protocol: "udp",
							Ports: []policy_client.Ports{
								{Start: 9999, End: 9999},
							},
							IPRanges: []policy_client.IPRange{
								{Start: "1.2.3.4", End: "1.2.3.5"},
							},
						},
						AppLifecycle: "all",
					},
				}

				policyClient.GetPoliciesByIDReturns(policyServerResponse, egressPolicyServerResponse, nil)
			})

			Context("and the purpose is app", func() {
				BeforeEach(func() {
					data = make(map[string]datastore.Container)
					data["container-id-1"] = datastore.Container{
						Handle: "container-id-1",
						IP:     "10.255.1.2",
						Metadata: map[string]interface{}{
							"policy_group_id":    "some-app-guid",
							"ports":              "8080",
							"container_workload": "app",
						},
					}
					store.ReadAllReturns(data, nil)
				})

				It("assigns the rules correctly", func() {
					rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
					Expect(err).NotTo(HaveOccurred())

					Expect(rulesWithChain.Rules).To(ConsistOf(
						rules.IPTablesRule{"--source", "10.255.1.2", "--jump", "MARK", "--set-xmark", "0xAA", "-m", "comment", "--comment", "src:some-app-guid"},
						rules.IPTablesRule{"-d", "10.255.1.2", "-p", "tcp", "--dport", "8080:8080", "-m", "mark", "--mark", "0xAA", "--jump", "ACCEPT", "-m", "comment", "--comment", "src:some-app-guid_dst:some-app-guid"},
						rules.IPTablesRule{"-s", "10.255.1.2", "-o", "eth0", "-p", "tcp", "-m", "iprange", "--dst-range", "1.2.3.4-1.2.3.5", "-m", "tcp", "--dport", "1234:1234", "-j", "ACCEPT"},
						rules.IPTablesRule{"-s", "10.255.1.2", "-o", "eth0", "-p", "udp", "-m", "iprange", "--dst-range", "1.2.3.4-1.2.3.5", "-m", "udp", "--dport", "9999:9999", "-j", "ACCEPT"},
						rules.IPTablesRule{"-d", "10.255.1.2", "-p", "tcp", "-m", "tcp", "--dport", "8080", "-m", "mark", "--mark", "0x5476", "--jump", "ACCEPT"},
					))
				})
			})

			Context("and the purpose is task", func() {
				BeforeEach(func() {
					data = make(map[string]datastore.Container)
					data["container-id-1"] = datastore.Container{
						Handle: "container-id-1",
						IP:     "10.255.1.2",
						Metadata: map[string]interface{}{
							"policy_group_id":    "some-app-guid",
							"ports":              "8080",
							"container_workload": "task",
						},
					}
					store.ReadAllReturns(data, nil)
				})

				It("assigns the rules correctly", func() {
					rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
					Expect(err).NotTo(HaveOccurred())

					Expect(rulesWithChain.Rules).To(ConsistOf(
						rules.IPTablesRule{"--source", "10.255.1.2", "--jump", "MARK", "--set-xmark", "0xAA", "-m", "comment", "--comment", "src:some-app-guid"},
						rules.IPTablesRule{"-d", "10.255.1.2", "-p", "tcp", "--dport", "8080:8080", "-m", "mark", "--mark", "0xAA", "--jump", "ACCEPT", "-m", "comment", "--comment", "src:some-app-guid_dst:some-app-guid"},
						rules.IPTablesRule{"-s", "10.255.1.2", "-o", "eth0", "-p", "tcp", "-m", "iprange", "--dst-range", "1.2.3.4-1.2.3.5", "-m", "tcp", "--dport", "1234:1234", "-j", "ACCEPT"},
						rules.IPTablesRule{"-s", "10.255.1.2", "-o", "eth0", "-p", "udp", "-m", "iprange", "--dst-range", "1.2.3.4-1.2.3.5", "-m", "udp", "--dport", "9999:9999", "-j", "ACCEPT"},
						rules.IPTablesRule{"-d", "10.255.1.2", "-p", "tcp", "-m", "tcp", "--dport", "8080", "-m", "mark", "--mark", "0x5476", "--jump", "ACCEPT"},
					))
				})
			})

			Context("and the purpose is staging", func() {
				BeforeEach(func() {
					data = make(map[string]datastore.Container)
					data["container-id-1"] = datastore.Container{
						Handle: "container-id-1",
						IP:     "10.255.1.2",
						Metadata: map[string]interface{}{
							"policy_group_id":    "some-app-guid",
							"ports":              "8080",
							"container_workload": "staging",
						},
					}
					store.ReadAllReturns(data, nil)
				})

				It("assigns the rules correctly", func() {
					rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
					Expect(err).NotTo(HaveOccurred())

					Expect(rulesWithChain.Rules).To(ConsistOf(
						rules.IPTablesRule{"--source", "10.255.1.2", "--jump", "MARK", "--set-xmark", "0xAA", "-m", "comment", "--comment", "src:some-app-guid"},
						rules.IPTablesRule{"-d", "10.255.1.2", "-p", "tcp", "--dport", "8080:8080", "-m", "mark", "--mark", "0xAA", "--jump", "ACCEPT", "-m", "comment", "--comment", "src:some-app-guid_dst:some-app-guid"},
						rules.IPTablesRule{"-s", "10.255.1.2", "-o", "eth0", "-p", "udp", "-m", "iprange", "--dst-range", "1.2.3.4-1.2.3.5", "-m", "udp", "--dport", "5678:5678", "-j", "ACCEPT"},
						rules.IPTablesRule{"-s", "10.255.1.2", "-o", "eth0", "-p", "udp", "-m", "iprange", "--dst-range", "1.2.3.4-1.2.3.5", "-m", "udp", "--dport", "9999:9999", "-j", "ACCEPT"},
						rules.IPTablesRule{"-d", "10.255.1.2", "-p", "tcp", "-m", "tcp", "--dport", "8080", "-m", "mark", "--mark", "0x5476", "--jump", "ACCEPT"},
					))
				})
			})

			Context("and the purpose is not present", func() {
				BeforeEach(func() {
					data = make(map[string]datastore.Container)
					data["container-id-1"] = datastore.Container{
						Handle: "container-id-1",
						IP:     "10.255.1.2",
						Metadata: map[string]interface{}{
							"policy_group_id": "some-app-guid",
							"ports":           "8080",
						},
					}
					store.ReadAllReturns(data, nil)
				})

				It("assigns all the policies, in a backwards compatible way", func() {
					rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
					Expect(err).NotTo(HaveOccurred())

					Expect(rulesWithChain.Rules).To(ConsistOf(
						rules.IPTablesRule{"--source", "10.255.1.2", "--jump", "MARK", "--set-xmark", "0xAA", "-m", "comment", "--comment", "src:some-app-guid"},
						rules.IPTablesRule{"-d", "10.255.1.2", "-p", "tcp", "--dport", "8080:8080", "-m", "mark", "--mark", "0xAA", "--jump", "ACCEPT", "-m", "comment", "--comment", "src:some-app-guid_dst:some-app-guid"},
						rules.IPTablesRule{"-s", "10.255.1.2", "-o", "eth0", "-p", "tcp", "-m", "iprange", "--dst-range", "1.2.3.4-1.2.3.5", "-m", "tcp", "--dport", "1234:1234", "-j", "ACCEPT"},
						rules.IPTablesRule{"-s", "10.255.1.2", "-o", "eth0", "-p", "udp", "-m", "iprange", "--dst-range", "1.2.3.4-1.2.3.5", "-m", "udp", "--dport", "5678:5678", "-j", "ACCEPT"},
						rules.IPTablesRule{"-s", "10.255.1.2", "-o", "eth0", "-p", "udp", "-m", "iprange", "--dst-range", "1.2.3.4-1.2.3.5", "-m", "udp", "--dport", "9999:9999", "-j", "ACCEPT"},
						rules.IPTablesRule{"-d", "10.255.1.2", "-p", "tcp", "-m", "tcp", "--dport", "8080", "-m", "mark", "--mark", "0x5476", "--jump", "ACCEPT"},
					))
				})
			})
		})

		Context("when there are no policies", func() {
			BeforeEach(func() {
				policyClient.GetPoliciesByIDReturns([]policy_client.Policy{}, nil, nil)
			})
			It("returns an chain with only the ingress rules", func() {
				rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
				Expect(err).NotTo(HaveOccurred())
				Expect(policyClient.GetPoliciesByIDCallCount()).To(Equal(1))

				Expect(rulesWithChain.Chain).To(Equal(chain))
				Expect(rulesWithChain.Rules).To(ConsistOf([]rules.IPTablesRule{
					{
						"-d", "10.255.1.2",
						"-p", "tcp",
						"-m", "tcp", "--dport", "8080",
						"-m", "mark", "--mark", "0x5476",
						"--jump", "ACCEPT",
					},
					{
						"-d", "10.255.1.3",
						"-p", "tcp",
						"-m", "tcp", "--dport", "8181",
						"-m", "mark", "--mark", "0x5476",
						"--jump", "ACCEPT",
					},
					{
						"-d", "10.255.1.3",
						"-p", "tcp",
						"-m", "tcp", "--dport", "9090",
						"-m", "mark", "--mark", "0x5476",
						"--jump", "ACCEPT",
					},
				}))
			})

			Context("when overlay ingress rules are disabled", func() {
				It("returns a chain with no rules", func() {
					policyPlanner.EnableOverlayIngressRules = false
					rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
					Expect(err).NotTo(HaveOccurred())
					Expect(policyClient.GetPoliciesByIDCallCount()).To(Equal(1))

					Expect(rulesWithChain.Chain).To(Equal(chain))
					Expect(rulesWithChain.Rules).To(BeEmpty())
				})
			})
		})

		Context("when there are no containers in the datastore", func() {
			BeforeEach(func() {
				data = make(map[string]datastore.Container)
				store.ReadAllReturns(data, nil)
			})

			It("does not call the policy client", func() {
				rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
				Expect(err).NotTo(HaveOccurred())
				Expect(policyClient.GetPoliciesByIDCallCount()).To(Equal(0))

				Expect(rulesWithChain.Chain).To(Equal(chain))
				Expect(rulesWithChain.Rules).To(HaveLen(0))
			})
		})

		Context("when a container's metadata is missing required key policy group id", func() {
			BeforeEach(func() {
				data["container-id-fruit"] = datastore.Container{
					Handle: "container-id-fruit",
					IP:     "10.255.1.5",
					Metadata: map[string]interface{}{
						"fruit": "banana",
					},
				}
			})

			It("logs an error for that container and returns rules for other containers", func() {
				rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
				Expect(err).NotTo(HaveOccurred())
				Expect(logger).To(gbytes.Say("container-metadata-policy-group-id.*container-id-fruit.*Container.*metadata.*policy_group_id.*CloudController.*restage"))

				Expect(rulesWithChain.Chain).To(Equal(chain))

				for _, rules := range rulesWithChain.Rules {
					Expect(rules).NotTo(ContainElement("10.255.1.5"))
				}
			})
		})

		Context("when a container's metadata is missing required key ports", func() {
			BeforeEach(func() {
				data["container-id-2"] = datastore.Container{
					Handle: "container-id-2",
					IP:     "10.255.1.3",
					Metadata: map[string]interface{}{
						"policy_group_id": "some-other-app-guid",
					},
				}
			})

			It("logs an error for that container and returns non ingress rules", func() {
				rulesWithChain, err := policyPlanner.GetPolicyRulesAndChain()
				Expect(err).NotTo(HaveOccurred())
				Expect(logger).To(gbytes.Say("container-metadata-policy-group-id.*container-id-2.*Container.*metadata.*ports.*CloudController.*restage"))

				Expect(rulesWithChain.Chain).To(Equal(chain))

				for _, rules := range rulesWithChain.Rules {
					Expect(rules).NotTo(gomegamatchers.ContainSequence([]interface{}{"-d", "10.255.1.3"}))
				}
			})
		})

		Context("when getting containers from datastore fails", func() {
			BeforeEach(func() {
				store.ReadAllReturns(nil, errors.New("banana"))
			})

			It("logs and returns the error", func() {
				_, err := policyPlanner.GetPolicyRulesAndChain()
				Expect(err).To(MatchError("banana"))
				Expect(logger).To(gbytes.Say("datastore.*banana"))
			})
		})

		Context("when getting policies fails", func() {
			BeforeEach(func() {
				policyClient.GetPoliciesByIDReturns(nil, nil, errors.New("kiwi"))
			})

			It("logs and returns the error", func() {
				_, err := policyPlanner.GetPolicyRulesAndChain()
				Expect(err).To(MatchError("failed to get policies: kiwi"))
				Expect(logger).To(gbytes.Say("policy-client-get-container-policies.*kiwi"))
			})
		})

		Context("when getting INGRESS_ROUTER tag fails", func() {
			BeforeEach(func() {
				policyClient.CreateOrGetTagReturns("", errors.New("sad kumquat"))
			})

			It("logs and returns the error", func() {
				_, err := policyPlanner.GetPolicyRulesAndChain()
				Expect(err).To(MatchError("failed to get ingress tags: sad kumquat"))
				Expect(logger).To(gbytes.Say("policy-client-get-container-policies.*sad kumquat"))
			})
		})

		Context("when container metadata port is invalid", func() {
			BeforeEach(func() {
				data["container-id-1"] = datastore.Container{
					Handle: "container-id-1",
					IP:     "10.255.1.2",
					Metadata: map[string]interface{}{
						"policy_group_id": "some-app-guid",
						"ports":           "invalid-port",
					},
				}
			})

			It("logs and returns the error", func() {
				_, err := policyPlanner.GetPolicyRulesAndChain()
				Expect(err).To(MatchError(`converting container metadata port to int: strconv.Atoi: parsing "invalid-port": invalid syntax`))
				Expect(logger).To(gbytes.Say(`policy-client-get-container-policies.*converting container metadata port to int*`))
			})
		})
	})

	Describe("GetASGRulesAndChains", func() {
		It("gets container properties from the datastore", func() {
			_, err := policyPlanner.GetASGRulesAndChains()
			Expect(err).NotTo(HaveOccurred())

			Expect(store.ReadAllCallCount()).To(Equal(1))
		})

		It("emits time metrics", func() {
			_, err := policyPlanner.GetASGRulesAndChains()
			Expect(err).NotTo(HaveOccurred())
			Expect(metricsSender.SendDurationCallCount()).To(Equal(2))
			name, _ := metricsSender.SendDurationArgsForCall(0)
			Expect(name).To(Equal("containerMetadataTime"))
			name, _ = metricsSender.SendDurationArgsForCall(1)
			Expect(name).To(Equal("policyServerASGPollTime"))
		})

		Context("when there are no containers in the datastore", func() {
			BeforeEach(func() {
				data = make(map[string]datastore.Container)
				store.ReadAllReturns(data, nil)
			})

			It("does not call the policy client", func() {
				rulesWithChains, err := policyPlanner.GetASGRulesAndChains()
				Expect(err).NotTo(HaveOccurred())
				Expect(policyClient.GetPoliciesByIDCallCount()).To(Equal(0))

				Expect(rulesWithChains).To(BeEmpty())
			})
		})

		Context("when there are containers in datastore", func() {
			It("gets security groups from the policy server", func() {
				_, err := policyPlanner.GetASGRulesAndChains()
				Expect(err).NotTo(HaveOccurred())

				By("filtering by space guid when calling the internal policy server")
				Expect(policyClient.GetSecurityGroupsForSpaceCallCount()).To(Equal(1))
				Expect(policyClient.GetSecurityGroupsForSpaceArgsForCall(0)).To(ConsistOf("some-space-guid", "some-other-space-guid"))
			})

			Context("when only one container was specified", func() {
				It("only gets security groups for the specified container", func() {
					_, err := policyPlanner.GetASGRulesAndChains("container-id-1")
					Expect(err).ToNot(HaveOccurred())
					Expect(policyClient.GetSecurityGroupsForSpaceCallCount()).To(Equal(1))
					Expect(policyClient.GetSecurityGroupsForSpaceArgsForCall(0)).To(ConsistOf("some-space-guid"))
				})
			})

			Context("when there are security groups for staging and running", func() {
				var (
					expectedRunningRules policy_client.SecurityGroupRules
					expectedStagingRules policy_client.SecurityGroupRules
					securityGroups       []policy_client.SecurityGroup
				)

				BeforeEach(func() {
					expectedRunningRules = policy_client.SecurityGroupRules{{Protocol: "all", Destination: "20.0.0.2"}}
					expectedStagingRules = policy_client.SecurityGroupRules{{Protocol: "icmp", Type: 1, Code: 2, Destination: "10.0.0.1"}}
					securityGroups = []policy_client.SecurityGroup{
						{
							Name:              "staging-security-group",
							StagingSpaceGuids: []string{"some-space-guid"},
							Rules:             policy_client.SecurityGroupRules{{Protocol: "tcp"}},
						},
						{
							Name:              "running-security-group",
							RunningSpaceGuids: []string{"some-space-guid"},
							Rules:             expectedRunningRules,
						},
						{
							Name:              "other-staging-security-group",
							StagingSpaceGuids: []string{"some-other-space-guid"},
							Rules:             expectedStagingRules,
						},
						{
							Name:              "other-running-security-group",
							RunningSpaceGuids: []string{"some-other-space-guid"},
							Rules:             policy_client.SecurityGroupRules{{Protocol: "udp"}},
						},
					}
					policyClient.GetSecurityGroupsForSpaceReturns(securityGroups, nil)
				})

				It("uses security group rules for matching container work load", func() {
					rulesWithChains, err := policyPlanner.GetASGRulesAndChains()
					Expect(err).NotTo(HaveOccurred())
					Expect(rulesWithChains).To(HaveLen(2))
					var containerRules1, containerRules2 enforcer.RulesWithChain
					for _, containerRules := range rulesWithChains {
						if containerRules.Chain.ParentChain == "netout-container-id-1" {
							containerRules1 = containerRules
						} else if containerRules.Chain.ParentChain == "netout-container-id-2" {
							containerRules2 = containerRules
						} else {
							Fail(fmt.Sprintf("contains unexpected Parent Chain name: %s", containerRules.Chain.ParentChain))
						}
					}

					Expect(containerRules1.Rules).To(Equal([]rules.IPTablesRule{{"rule-2"}, {"rule-1"}}))
					Expect(containerRules2.Rules).To(Equal([]rules.IPTablesRule{{"rule-4"}, {"rule-3"}}))

					Expect([]string{containerRules1.Chain.Prefix, containerRules2.Chain.Prefix}).To(ConsistOf("asg-498471", "asg-2a07ad"))
					Expect([]string{containerRules1.Chain.ManagedChainsRegex, containerRules2.Chain.ManagedChainsRegex}).To(ConsistOf(planner.ASGManagedChainsRegex, planner.ASGManagedChainsRegex))
					Expect([]bool{containerRules1.Chain.CleanUpParentChain, containerRules2.Chain.CleanUpParentChain}).To(ConsistOf(true, true))

					Expect(netOutChain.IPTablesRulesCallCount()).To(Equal(2))

					handle1, containerWorkload1, ruleSpec1 := netOutChain.IPTablesRulesArgsForCall(0)
					handle2, containerWorkload2, ruleSpec2 := netOutChain.IPTablesRulesArgsForCall(1)

					Expect([]string{handle1, handle2}).To(ConsistOf("container-id-1", "container-id-2"))

					var receivedRunningRules, receivedStagingRules []netrules.Rule
					var receivedRunningContainerWorkload, receivedStagingContainerWorkload string
					if handle1 == "container-id-1" {
						receivedRunningRules = ruleSpec1
						receivedStagingRules = ruleSpec2
						receivedRunningContainerWorkload = containerWorkload1
						receivedStagingContainerWorkload = containerWorkload2
					} else {
						receivedRunningRules = ruleSpec2
						receivedStagingRules = ruleSpec1
						receivedRunningContainerWorkload = containerWorkload2
						receivedStagingContainerWorkload = containerWorkload1
					}

					By("using running rules for container with running work load")
					expectedRules, err := netrules.NewRulesFromSecurityGroupRules(expectedRunningRules)
					Expect(err).NotTo(HaveOccurred())
					Expect(receivedRunningRules).To(Equal(expectedRules))
					Expect(receivedRunningContainerWorkload).To(Equal("task"))

					By("using staging rules for container with staging work load")
					expectedRules, err = netrules.NewRulesFromSecurityGroupRules(expectedStagingRules)
					Expect(err).NotTo(HaveOccurred())
					Expect(receivedStagingRules).To(Equal(expectedRules))
					Expect(receivedStagingContainerWorkload).To(Equal("staging"))
				})

				Context("and there are also global security groups for staging and running", func() {
					var (
						expectedGlobalRunningRules policy_client.SecurityGroupRules
						expectedGlobalStagingRules policy_client.SecurityGroupRules
					)

					BeforeEach(func() {
						expectedGlobalStagingRules = policy_client.SecurityGroupRules{{Protocol: "tcp", Destination: "30.0.0.3"}}
						expectedGlobalRunningRules = policy_client.SecurityGroupRules{{Protocol: "udp", Destination: "40.0.0.4"}}
						securityGroupsWithGlobal := append(securityGroups, policy_client.SecurityGroup{
							Name:              "global-staging-security-group",
							StagingSpaceGuids: []string{"some-space-guid"},
							Rules:             expectedGlobalStagingRules,
							StagingDefault:    true,
						}, policy_client.SecurityGroup{
							Name:              "global-running-security-group",
							RunningSpaceGuids: []string{"some-space-guid"},
							Rules:             expectedGlobalRunningRules,
							RunningDefault:    true,
						})

						policyClient.GetSecurityGroupsForSpaceReturns(securityGroupsWithGlobal, nil)
					})

					It("appends the global security groups as well", func() {
						rulesWithChains, err := policyPlanner.GetASGRulesAndChains()
						Expect(err).NotTo(HaveOccurred())
						Expect(rulesWithChains).To(HaveLen(2))

						var containerRules1, containerRules2 enforcer.RulesWithChain
						for _, containerRules := range rulesWithChains {
							if containerRules.Chain.ParentChain == "netout-container-id-1" {
								containerRules1 = containerRules
							} else if containerRules.Chain.ParentChain == "netout-container-id-2" {
								containerRules2 = containerRules
							} else {
								Fail(fmt.Sprintf("contains unexpected Parent Chain name: %s", containerRules.Chain.ParentChain))
							}
						}

						By("assiging the correct rules to each container")
						Expect(containerRules1.Rules).To(Equal([]rules.IPTablesRule{{"rule-2"}, {"rule-1"}}))
						Expect(containerRules2.Rules).To(Equal([]rules.IPTablesRule{{"rule-4"}, {"rule-3"}}))

						By("assigning unique prefixes to each container")
						Expect([]string{containerRules1.Chain.Prefix, containerRules2.Chain.Prefix}).To(ConsistOf("asg-498471", "asg-2a07ad"))
						Expect([]string{containerRules1.Chain.ManagedChainsRegex, containerRules2.Chain.ManagedChainsRegex}).To(ConsistOf(planner.ASGManagedChainsRegex, planner.ASGManagedChainsRegex))

						Expect(netOutChain.IPTablesRulesCallCount()).To(Equal(2))

						handle1, containerWorkload1, ruleSpec1 := netOutChain.IPTablesRulesArgsForCall(0)
						handle2, containerWorkload2, ruleSpec2 := netOutChain.IPTablesRulesArgsForCall(1)

						Expect([]string{handle1, handle2}).To(ConsistOf("container-id-1", "container-id-2"))

						var receivedRunningRules, receivedStagingRules []netrules.Rule
						var receivedRunningContainerWorkload, receivedStagingContainerWorkload string
						if handle1 == "container-id-1" {
							receivedRunningRules = ruleSpec1
							receivedStagingRules = ruleSpec2
							receivedRunningContainerWorkload = containerWorkload1
							receivedStagingContainerWorkload = containerWorkload2
						} else {
							receivedRunningRules = ruleSpec2
							receivedStagingRules = ruleSpec1
							receivedRunningContainerWorkload = containerWorkload2
							receivedStagingContainerWorkload = containerWorkload1
						}

						By("using running rules for container with running work load")
						expectedRules, err := netrules.NewRulesFromSecurityGroupRules(append(expectedGlobalRunningRules, expectedRunningRules...))
						Expect(err).NotTo(HaveOccurred())
						Expect(receivedRunningRules).To(Equal(expectedRules))
						Expect(receivedRunningContainerWorkload).To(Equal("task"))

						By("using staging rules for container with staging work load")
						expectedRules, err = netrules.NewRulesFromSecurityGroupRules(append(expectedGlobalStagingRules, expectedStagingRules...))
						Expect(err).NotTo(HaveOccurred())
						Expect(receivedStagingRules).To(Equal(expectedRules))
						Expect(receivedStagingContainerWorkload).To(Equal("staging"))
					})
				})

				Describe("log config", func() {
					Context("when container metadata does not contain log_config", func() {
						It("returns empty log config", func() {
							rulesWithChain, err := policyPlanner.GetASGRulesAndChains("container-id-2")
							Expect(err).NotTo(HaveOccurred())
							Expect(rulesWithChain).To(HaveLen(1))
							Expect(rulesWithChain[0].LogConfig).To(Equal(executor.LogConfig{}))
						})
					})

					Context("when container metadata contains log_config", func() {
						BeforeEach(func() {
							data["container-id-1"].Metadata["log_config"] = "{\"guid\":\"some-app-guid\",\"index\":0,\"source_name\":\"CELL\",\"tags\":{\"app_id\":\"some-app-guid\",\"app_name\":\"dora\"}}"
							store.ReadAllReturns(data, nil)
						})

						It("parses the log config", func() {
							rulesWithChain, err := policyPlanner.GetASGRulesAndChains("container-id-1")
							Expect(err).NotTo(HaveOccurred())
							Expect(rulesWithChain).To(HaveLen(1))
							Expect(rulesWithChain[0].LogConfig.Guid).To(Equal("some-app-guid"))
							Expect(rulesWithChain[0].LogConfig.Index).To(Equal(0))
							Expect(rulesWithChain[0].LogConfig.SourceName).To(Equal("CELL"))
							Expect(rulesWithChain[0].LogConfig.Tags).To(Equal(map[string]string{
								"app_id":   "some-app-guid",
								"app_name": "dora",
							}))
						})
					})
				})
			})

			It("appends default iptables rules to the list", func() {
				netOutChain.DefaultRulesReturns([]rules.IPTablesRule{{"default-rule-1"}, {"default-rule-2"}})

				rulesWithChains, err := policyPlanner.GetASGRulesAndChains()
				Expect(err).NotTo(HaveOccurred())
				Expect(rulesWithChains).To(HaveLen(2))

				var containerRules1, containerRules2 enforcer.RulesWithChain
				for _, containerRules := range rulesWithChains {
					if containerRules.Chain.ParentChain == "netout-container-id-1" {
						containerRules1 = containerRules
					} else if containerRules.Chain.ParentChain == "netout-container-id-2" {
						containerRules2 = containerRules
					} else {
						Fail(fmt.Sprintf("contains unexpected Parent Chain name: %s", containerRules.Chain.ParentChain))
					}
				}

				By("assiging the correct rules to each container")
				Expect(containerRules1.Rules).To(Equal([]rules.IPTablesRule{{"rule-2"}, {"rule-1"}, {"default-rule-1"}, {"default-rule-2"}}))
				Expect(containerRules2.Rules).To(Equal([]rules.IPTablesRule{{"rule-4"}, {"rule-3"}, {"default-rule-1"}, {"default-rule-2"}}))
				Expect(netOutChain.DefaultRulesCallCount()).To(Equal(2))
				Expect(netOutChain.IPTablesRulesCallCount()).To(Equal(2))
			})

		})

		Context("when getting containers from datastore fails", func() {
			BeforeEach(func() {
				store.ReadAllReturns(nil, errors.New("banana"))
			})

			It("logs and returns the error", func() {
				_, err := policyPlanner.GetASGRulesAndChains()
				Expect(err).To(MatchError("banana"))
				Expect(logger).To(gbytes.Say("datastore.*banana"))
			})
		})
	})
})
