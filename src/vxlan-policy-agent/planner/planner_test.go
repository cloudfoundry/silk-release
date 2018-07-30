package planner_test

import (
	"errors"
	"lib/datastore"
	libfakes "lib/fakes"
	"lib/policy_client"
	"lib/rules"
	"vxlan-policy-agent/enforcer"
	"vxlan-policy-agent/planner"
	"vxlan-policy-agent/planner/fakes"

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
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
		policyClient = &fakes.PolicyClient{}
		metricsSender = &fakes.MetricsSender{}
		loggingStateGetter = &fakes.LoggingStateGetter{}

		store = &libfakes.Datastore{}

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
				"ports":           " 8181 , 9090",
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
		}

		egressPolicyServerResponse = []policy_client.EgressPolicy{
			{
				Source: &policy_client.EgressSource{
					ID: "some-app-guid",
				},
				Destination: &policy_client.EgressDestination{
					Protocol: "udp",
					IPRanges: []policy_client.IPRange{
						{Start: "1.2.3.4", End: "1.2.3.5"},
					},
				},
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
		}
	})

	Describe("GetRulesAndChain", func() {
		It("gets every container's properties from the datastore", func() {
			_, err := policyPlanner.GetRulesAndChain()
			Expect(err).NotTo(HaveOccurred())

			Expect(store.ReadAllCallCount()).To(Equal(1))
		})

		It("gets policies from the policy server", func() {
			_, err := policyPlanner.GetRulesAndChain()
			Expect(err).NotTo(HaveOccurred())

			By("filtering by ID when calling the internal policy server")
			Expect(policyClient.GetPoliciesByIDCallCount()).To(Equal(1))
			Expect(policyClient.GetPoliciesByIDArgsForCall(0)).To(ConsistOf([]string{"some-app-guid", "some-other-app-guid"}))
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
					rulesWithChain, err := policyPlanner.GetRulesAndChain()
					Expect(err).NotTo(HaveOccurred())
					Expect(rulesWithChain.Chain).To(Equal(chain))
					Expect(rulesWithChain.Rules).To(ConsistOf([]rules.IPTablesRule{
						{
							"-s", "10.255.1.2",
							"-p", "udp",
							"-m", "iprange",
							"--dst-range", "1.2.3.4-1.2.3.5",
							"-m", "udp",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.3",
							"-p", "tcp",
							"-m", "iprange",
							"--dst-range", "1.2.3.6-1.2.3.7",
							"-m", "tcp",
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
					}))
				})
			})

			Context("when EnableOverlayIngressRules is disabled", func() {
				BeforeEach(func() {
					policyPlanner.EnableOverlayIngressRules = false
				})

				It("returns the rules without overlay ingress and no logging rules", func() {
					rulesWithChain, err := policyPlanner.GetRulesAndChain()
					Expect(err).NotTo(HaveOccurred())
					Expect(rulesWithChain.Chain).To(Equal(chain))

					Expect(rulesWithChain.Rules).To(ConsistOf([]rules.IPTablesRule{
						{
							"-s", "10.255.1.2",
							"-p", "udp",
							"-m", "iprange",
							"--dst-range", "1.2.3.4-1.2.3.5",
							"-m", "udp",
							"-j", "ACCEPT",
						},
						{
							"-s", "10.255.1.3",
							"-p", "tcp",
							"-m", "iprange",
							"--dst-range", "1.2.3.6-1.2.3.7",
							"-m", "tcp",
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
					}))
				})
			})

		})

		Context("when iptables logging is enabled", func() {
			BeforeEach(func() {
				loggingStateGetter.IsEnabledReturns(true)
			})
			It("returns all the rules including logging rules", func() {
				rulesWithChain, err := policyPlanner.GetRulesAndChain()
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
			rulesWithChain, err := policyPlanner.GetRulesAndChain()
			Expect(err).NotTo(HaveOccurred())
			Expect(rulesWithChain.Rules).To(HaveLen(9))
			Expect(rulesWithChain.Rules[0]).To(ContainElement("--set-xmark"))
			Expect(rulesWithChain.Rules[1]).To(ContainElement("--set-xmark"))
			Expect(rulesWithChain.Rules[2]).To(ContainElement("ACCEPT"))
			Expect(rulesWithChain.Rules[3]).To(ContainElement("ACCEPT"))
		})

		It("emits time metrics", func() {
			_, err := policyPlanner.GetRulesAndChain()
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
				rulesWithChain, err := policyPlanner.GetRulesAndChain()
				Expect(err).NotTo(HaveOccurred())
				policyClient.GetPoliciesByIDReturns(reversed, reversedEgress, nil)
				rulesWithChain2, err := policyPlanner.GetRulesAndChain()
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
				rulesWithChain, err := policyPlanner.GetRulesAndChain()
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
				rulesWithChain, err := policyPlanner.GetRulesAndChain()
				Expect(err).NotTo(HaveOccurred())
				Expect(rulesWithChain.Rules).To(HaveLen(16))
				Expect(rulesWithChain.Rules[0]).To(ContainElement("10.255.1.2"))
				Expect(rulesWithChain.Rules[1]).To(ContainElement("10.255.1.4"))
				Expect(rulesWithChain.Rules[2]).To(ContainElement("10.255.1.3"))
				Expect(rulesWithChain.Rules[3]).To(ContainElement("10.255.1.5"))
			})
		})

		Context("when there are no policies", func() {
			BeforeEach(func() {
				policyClient.GetPoliciesByIDReturns([]policy_client.Policy{}, nil, nil)
			})
			It("returns an chain with only the ingress rules", func() {
				rulesWithChain, err := policyPlanner.GetRulesAndChain()
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
					rulesWithChain, err := policyPlanner.GetRulesAndChain()
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
				rulesWithChain, err := policyPlanner.GetRulesAndChain()
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
				rulesWithChain, err := policyPlanner.GetRulesAndChain()
				Expect(err).NotTo(HaveOccurred())
				Expect(logger).To(gbytes.Say("container-metadata-policy-group-id.*container-id-fruit.*Container.*metadata.*policy_group_id.*CloudController.*restage"))

				Expect(rulesWithChain.Chain).To(Equal(chain))
				Expect(rulesWithChain.Rules).To(HaveLen(9))
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
				rulesWithChain, err := policyPlanner.GetRulesAndChain()
				Expect(err).NotTo(HaveOccurred())
				Expect(logger).To(gbytes.Say("container-metadata-policy-group-id.*container-id-2.*Container.*metadata.*ports.*CloudController.*restage"))

				Expect(rulesWithChain.Chain).To(Equal(chain))
				Expect(rulesWithChain.Rules).To(HaveLen(7))
			})
		})

		Context("when getting containers from datastore fails", func() {
			BeforeEach(func() {
				store.ReadAllReturns(nil, errors.New("banana"))
			})

			It("logs and returns the error", func() {
				_, err := policyPlanner.GetRulesAndChain()
				Expect(err).To(MatchError("banana"))
				Expect(logger).To(gbytes.Say("datastore.*banana"))
			})
		})

		Context("when getting policies fails", func() {
			BeforeEach(func() {
				policyClient.GetPoliciesByIDReturns(nil, nil, errors.New("kiwi"))
			})

			It("logs and returns the error", func() {
				_, err := policyPlanner.GetRulesAndChain()
				Expect(err).To(MatchError("kiwi"))
				Expect(logger).To(gbytes.Say("policy-client-get-policies.*kiwi"))
			})
		})

		Context("when getting INGRESS_ROUTER tag fails", func() {
			BeforeEach(func() {
				policyClient.CreateOrGetTagReturns("", errors.New("sad kumquat"))
			})

			It("logs and returns the error", func() {
				_, err := policyPlanner.GetRulesAndChain()
				Expect(err).To(MatchError("sad kumquat"))
				Expect(logger).To(gbytes.Say("policy-client-get-ingress-tags.*sad kumquat"))
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
				_, err := policyPlanner.GetRulesAndChain()
				Expect(err).To(MatchError(`converting container metadata port to int: strconv.Atoi: parsing "invalid-port": invalid syntax`))
				Expect(logger).To(gbytes.Say(`policy-client-get-ingress-tags.*converting container metadata port to int*`))
			})
		})
	})
})
