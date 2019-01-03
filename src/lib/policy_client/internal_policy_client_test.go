package policy_client_test

import (
	"encoding/json"
	"errors"
	"lib/policy_client"

	hfakes "code.cloudfoundry.org/cf-networking-helpers/fakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var policyData = `
{
	"policies": [
		{
			"source": { "id": "some-app-guid", "tag": "BEEF" },
			"destination": { "id": "some-other-app-guid", "protocol": "tcp", "port": 8090, "ports": { "start": 8090, "end": 8090 } } 
		}
	],
	"egress_policies": [
		{
			"source": { "id": "some-other-app-guid" },
			"destination": { "protocol": "tcp", "ips": [{ "start": "1.2.3.4", "end": "1.2.3.5" }] }
		},
		{
			"source": { "id": "some-other-app-guid" },
			"destination": { "protocol": "icmp", "icmp_type": 8, "icmp_code": 4, "ips": [{ "start": "1.2.3.4", "end": "1.2.3.5" }] }
		}
	]
}`

var _ = Describe("InternalClient", func() {
	var (
		client     *policy_client.InternalClient
		jsonClient *hfakes.JSONClient
	)

	BeforeEach(func() {
		jsonClient = &hfakes.JSONClient{}
		client = &policy_client.InternalClient{
			JsonClient: jsonClient,
		}
	})

	Describe("GetPolicies", func() {
		BeforeEach(func() {
			jsonClient.DoStub = func(method, route string, reqData, respData interface{}, token string) error {
				respBytes := []byte(policyData)
				json.Unmarshal(respBytes, respData)
				return nil
			}
		})

		It("does the right json http client request", func() {
			policies, egressPolicies, err := client.GetPolicies()
			Expect(err).NotTo(HaveOccurred())

			Expect(jsonClient.DoCallCount()).To(Equal(1))
			method, route, reqData, _, token := jsonClient.DoArgsForCall(0)
			Expect(method).To(Equal("GET"))
			Expect(route).To(Equal("/networking/v1/internal/policies"))
			Expect(reqData).To(BeNil())

			Expect(policies).To(Equal([]policy_client.Policy{
				{
					Source: policy_client.Source{
						ID:  "some-app-guid",
						Tag: "BEEF",
					},
					Destination: policy_client.Destination{
						ID: "some-other-app-guid",
						Ports: policy_client.Ports{
							Start: 8090,
							End:   8090,
						},
						Protocol: "tcp",
					},
				},
			},
			))
			Expect(egressPolicies).To(Equal([]policy_client.EgressPolicy{
				{
					Source: &policy_client.EgressSource{
						ID: "some-other-app-guid",
					},
					Destination: &policy_client.EgressDestination{
						Protocol: "tcp",
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
						Protocol: "icmp",
						ICMPType: 8,
						ICMPCode: 4,
						IPRanges: []policy_client.IPRange{
							{Start: "1.2.3.4", End: "1.2.3.5"},
						},
					},
				},
			}))
			Expect(token).To(BeEmpty())
		})

		Context("when the json client fails", func() {
			BeforeEach(func() {
				jsonClient.DoReturns(errors.New("banana"))
			})
			It("returns the error", func() {
				_, _, err := client.GetPolicies()
				Expect(err).To(MatchError("banana"))
			})
		})
	})

	Describe("GetPoliciesByID", func() {
		BeforeEach(func() {
			jsonClient.DoStub = func(method, route string, reqData, respData interface{}, token string) error {
				respBytes := []byte(policyData)
				json.Unmarshal(respBytes, respData)
				return nil
			}
		})

		It("does the right json http client request", func() {
			policies, egressPolicies, err := client.GetPoliciesByID("some-app-guid", "some-other-app-guid")
			Expect(err).NotTo(HaveOccurred())

			Expect(jsonClient.DoCallCount()).To(Equal(1))
			method, route, reqData, _, token := jsonClient.DoArgsForCall(0)
			Expect(method).To(Equal("GET"))
			Expect(route).To(Equal("/networking/v1/internal/policies?id=some-app-guid,some-other-app-guid"))
			Expect(reqData).To(BeNil())

			Expect(policies).To(Equal([]policy_client.Policy{
				{
					Source: policy_client.Source{
						ID:  "some-app-guid",
						Tag: "BEEF",
					},
					Destination: policy_client.Destination{
						ID: "some-other-app-guid",
						Ports: policy_client.Ports{
							Start: 8090,
							End:   8090,
						},
						Protocol: "tcp",
					},
				},
			},
			))
			Expect(egressPolicies).To(Equal([]policy_client.EgressPolicy{
				{
					Source: &policy_client.EgressSource{
						ID: "some-other-app-guid",
					},
					Destination: &policy_client.EgressDestination{
						Protocol: "tcp",
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
						Protocol: "icmp",
						ICMPType: 8,
						ICMPCode: 4,
						IPRanges: []policy_client.IPRange{
							{Start: "1.2.3.4", End: "1.2.3.5"},
						},
					},
				},
			}))

			Expect(token).To(BeEmpty())
		})

		Context("when the json client fails", func() {
			BeforeEach(func() {
				jsonClient.DoReturns(errors.New("banana"))
			})
			It("returns the error", func() {
				_, _, err := client.GetPoliciesByID("foo")
				Expect(err).To(MatchError("banana"))
			})
		})

		Context("when ids is empty", func() {
			BeforeEach(func() {})
			It("returns an error and does not call the json http client", func() {
				policies, egressPolicies, err := client.GetPoliciesByID()
				Expect(err).To(MatchError("ids cannot be empty"))
				Expect(policies).To(BeNil())
				Expect(egressPolicies).To(BeNil())
				Expect(jsonClient.DoCallCount()).To(Equal(0))
			})
		})
	})

	Describe("CreateOrGetTag", func() {
		BeforeEach(func() {
			jsonClient.DoStub = func(method, route string, reqData, respData interface{}, token string) error {
				respBytes := []byte(`{ "id": "SOME_ID", "type": "some_type", "tag": "1234" }`)
				json.Unmarshal(respBytes, respData)
				return nil
			}
		})
		It("returns a tag", func() {
			tag, err := client.CreateOrGetTag("SOME_ID", "some_type")
			Expect(err).NotTo(HaveOccurred())
			Expect(tag).To(Equal("1234"))

			Expect(jsonClient.DoCallCount()).To(Equal(1))
			method, route, reqData, _, token := jsonClient.DoArgsForCall(0)
			Expect(method).To(Equal("PUT"))
			Expect(route).To(Equal("/networking/v1/internal/tags"))
			Expect(reqData).To(Equal(policy_client.TagRequest{
				ID:   "SOME_ID",
				Type: "some_type",
			}))
			Expect(token).To(BeEmpty())
		})

		Context("when the json client fails", func() {
			BeforeEach(func() {
				jsonClient.DoReturns(errors.New("banana"))
			})
			It("returns the error", func() {
				_, err := client.CreateOrGetTag("", "")
				Expect(err).To(MatchError("banana"))
			})
		})
	})

	Describe("HealthCheck", func() {
		BeforeEach(func() {
			jsonClient.DoStub = func(method, route string, reqData, respData interface{}, token string) error {
				respBytes := []byte(`{ "healthcheck": true }`)
				json.Unmarshal(respBytes, respData)
				return nil
			}
		})

		It("Returns if the server is up", func() {
			health, err := client.HealthCheck()
			Expect(err).NotTo(HaveOccurred())
			Expect(health).To(Equal(true))

			Expect(jsonClient.DoCallCount()).To(Equal(1))
			method, route, reqData, _, token := jsonClient.DoArgsForCall(0)
			Expect(method).To(Equal("GET"))
			Expect(route).To(Equal("/networking/v1/internal/healthcheck"))
			Expect(reqData).To(BeNil())
			Expect(token).To(BeEmpty())
		})

		Context("when the json client fails", func() {
			BeforeEach(func() {
				jsonClient.DoReturns(errors.New("banana"))
			})
			It("returns the error", func() {
				_, err := client.HealthCheck()
				Expect(err).To(MatchError("banana"))
			})
		})
	})
})
