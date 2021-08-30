// +build windows

package planner_test

import (
	"code.cloudfoundry.org/lib/datastore"
	libfakes "code.cloudfoundry.org/lib/fakes"
	"code.cloudfoundry.org/policy_client"
	"code.cloudfoundry.org/vxlan-policy-agent/enforcer"
	"code.cloudfoundry.org/vxlan-policy-agent/planner/fakes"
	"errors"

	"code.cloudfoundry.org/vxlan-policy-agent/planner"

	"code.cloudfoundry.org/lager/lagertest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
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

		policyPlanner = &planner.VxlanPolicyPlanner{
			Logger:        logger,
			Datastore:     store,
			PolicyClient:  policyClient,
			VNI:           42,
			MetricsSender: metricsSender,
			Chain:         chain, // TODO: consider removing this property
			LoggingState:  loggingStateGetter,
		}
	})

	Describe("GetRules", func() {
		It("gets every container's properties from the datastore", func() {
			_, err := policyPlanner.GetRules()
			Expect(err).NotTo(HaveOccurred())
			Expect(store.ReadAllCallCount()).To(Equal(1))
		})

		It("gets policies from the policy server", func() {
			_, err := policyPlanner.GetRules()
			Expect(err).NotTo(HaveOccurred())

			By("filtering by ID when calling the internal policy server")
			Expect(policyClient.GetPoliciesByIDCallCount()).To(Equal(1))
			Expect(policyClient.GetPoliciesByIDArgsForCall(0)).To(ConsistOf([]interface{}{"some-app-guid", "some-other-app-guid", "some-space-guid"}))
		})

		Context("when the file can't be read", func() {
			BeforeEach(func() {
				store.ReadAllReturns(nil, errors.New("ohno!"))
			})

			It("returns an error", func() {
				_, err := policyPlanner.GetRules()
				Expect(err).To(MatchError("ohno!"))
				Expect(policyClient.GetPoliciesByIDCallCount()).To(Equal(0))
			})
		})

		Context("when the policy server returns an error", func() {
			BeforeEach(func() {
				policyClient.GetPoliciesByIDReturns(nil, nil, errors.New("ohno!"))
			})

			It("returns an error", func() {
				_, err := policyPlanner.GetRules()
				Expect(err).To(MatchError("failed to get policies: ohno!"))
			})
		})
	})
})
