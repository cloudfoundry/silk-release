package handlers_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"code.cloudfoundry.org/vxlan-policy-agent/handlers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Force ASGs for Container Handler", func() {
	var (
		response         *httptest.ResponseRecorder
		request          *http.Request
		wasInvoked       bool
		handler          *handlers.ForceASGsForContainer
		updatedContainer string
	)

	BeforeEach(func() {
		response = httptest.NewRecorder()
		request = httptest.NewRequest("GET", "/force-asgs-for-container?container=some-guid", nil)

		wasInvoked = false

		handler = &handlers.ForceASGsForContainer{
			EnableASGSyncing: true,
			ASGUpdateFunc: func(container ...string) error {
				wasInvoked = true
				updatedContainer = container[0]
				return nil
			},
		}
	})

	It("should call the function", func() {
		handler.ServeHTTP(response, request)
		Expect(response.Code).To(Equal(200))
		Expect(wasInvoked).To(BeTrue())
		Expect(updatedContainer).To(Equal("some-guid"))
		Expect(io.ReadAll(response.Body)).To(Equal([]byte(fmt.Sprintf("updated container %s", updatedContainer))))
	})

	It("returns 405 response when enable asg syncing is disabled", func() {
		handler.EnableASGSyncing = false
		handler.ServeHTTP(response, request)
		Expect(response.Code).To(Equal(405))
		Expect(wasInvoked).To(BeFalse())
		Expect(io.ReadAll(response.Body)).To(Equal([]byte("ASG syncing has been disabled administratively")))
	})

	It("returns 400 response when no container guid was provided", func() {
		request = httptest.NewRequest("GET", "/force-asgs-for-container", nil)
		handler.ServeHTTP(response, request)
		Expect(response.Code).To(Equal(400))
		Expect(io.ReadAll(response.Body)).To(Equal([]byte("no container specified")))
	})
	It("returns 500 response when the poll cycle func returns an error", func() {
		handler.ASGUpdateFunc = func(container ...string) error {
			return errors.New("failure")
		}

		handler.ServeHTTP(response, request)
		Expect(response.Code).To(Equal(500))
		Expect(io.ReadAll(response.Body)).To(Equal([]byte("failed to update asgs for container some-guid: failure")))
	})
})
