package policy_client_test

import (
	"lib/policy_client"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PolicySlice", func() {
	var (
		policy1  policy_client.Policy
		policy2  policy_client.Policy
		policies []policy_client.Policy
	)
	BeforeEach(func() {
		policy1 = policy_client.Policy{
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
		}
		policy2 = policy_client.Policy{
			Source: policy_client.Source{
				ID:  "some-other-app-guid",
				Tag: "BB",
			},
			Destination: policy_client.Destination{
				ID: "yet-another-app-guid",
				Ports: policy_client.Ports{
					Start: 4567,
					End:   4567,
				},
				Protocol: "tcp",
			},
		}
		policies = []policy_client.Policy{policy1, policy2}
	})

	Describe("Len", func() {
		It("returns the length of the underlying slice", func() {
			slice := policy_client.PolicySlice(policies)
			Expect(slice.Len()).To(Equal(2))
		})
	})

	Describe("Less", func() {
		BeforeEach(func() {
			policies = []policy_client.Policy{
				{
					Source: policy_client.Source{
						ID:  "a",
						Tag: "a",
					},
					Destination: policy_client.Destination{
						ID: "a",
						Ports: policy_client.Ports{
							Start: 1234,
							End:   1234,
						},
						Protocol: "tcp",
					},
				},
				{
					Source: policy_client.Source{
						ID:  "a",
						Tag: "b",
					},
					Destination: policy_client.Destination{
						ID: "a",
						Ports: policy_client.Ports{
							Start: 4321,
							End:   4321,
						},
						Protocol: "tcp",
					},
				},
				{
					Source: policy_client.Source{
						ID:  "b",
						Tag: "a",
					},
					Destination: policy_client.Destination{
						ID: "a",
						Ports: policy_client.Ports{
							Start: 1234,
							End:   1234,
						},
						Protocol: "tcp",
					},
				},
				{
					Source: policy_client.Source{
						ID:  "a",
						Tag: "a",
					},
					Destination: policy_client.Destination{
						ID: "b",
						Ports: policy_client.Ports{
							Start: 1234,
							End:   1234,
						},
						Protocol: "tcp",
					},
				},
				{
					Source: policy_client.Source{
						ID:  "a",
						Tag: "a",
					},
					Destination: policy_client.Destination{
						ID: "a",
						Ports: policy_client.Ports{
							Start: 1235,
							End:   1235,
						},
						Protocol: "tcp",
					},
				},
				{
					Source: policy_client.Source{
						ID:  "a",
						Tag: "a",
					},
					Destination: policy_client.Destination{
						ID: "a",
						Ports: policy_client.Ports{
							Start: 1234,
							End:   1234,
						},
						Protocol: "udp",
					},
				},
			}

		})
		It("Returns true if the string representation sorts first", func() {
			slice := policy_client.PolicySlice(policies)
			Expect(slice.Less(0, 1)).To(Equal(!slice.Less(1, 0)))
			Expect(slice.Less(0, 2)).To(Equal(!slice.Less(2, 0)))
			Expect(slice.Less(0, 3)).To(Equal(!slice.Less(3, 0)))
			Expect(slice.Less(0, 4)).To(Equal(!slice.Less(4, 0)))
			Expect(slice.Less(0, 5)).To(Equal(!slice.Less(5, 0)))
		})

	})

	Describe("Swap", func() {
		It("swaps the elements at the given index", func() {
			slice := policy_client.PolicySlice(policies)
			slice.Swap(0, 1)
			Expect(policies).To(Equal([]policy_client.Policy{policy2, policy1}))
		})
	})
})
