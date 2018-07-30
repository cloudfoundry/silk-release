package handlers_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"net/http/httptest"
	"vxlan-policy-agent/handlers"
	"errors"
	"io/ioutil"
)

var _ = Describe("Force Policy Poll Cycle Handler", func() {
	var (
		response   *httptest.ResponseRecorder
		request    *http.Request
		wasInvoked bool
		handler    *handlers.ForcePolicyPollCycle
	)

	BeforeEach(func() {
		response = httptest.NewRecorder()
		request = httptest.NewRequest("GET", "/force-policy-poll-cycle", nil)

		handler = &handlers.ForcePolicyPollCycle{
			PollCycleFunc: func() error {
				wasInvoked = true
				return nil
			},
		}
	})

	It("should call the function", func() {
		handler.ServeHTTP(response, request)
		Expect(response.Code).To(Equal(200))
		Expect(wasInvoked).To(BeTrue())
	})

	It("returns 500 response when the poll cycle func returns an error", func() {
		handler.PollCycleFunc = func() error {
			return errors.New("couldn't")
		}

		handler.ServeHTTP(response, request)
		Expect(response.Code).To(Equal(500))
		Expect(ioutil.ReadAll(response.Body)).To(Equal([]byte("failed to force policy poll cycle: couldn't")))
	})
})
