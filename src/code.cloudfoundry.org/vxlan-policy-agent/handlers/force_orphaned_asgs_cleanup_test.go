package handlers_test

import (
	"errors"
	"github.com/hashicorp/go-multierror"
	"io"
	"net/http"
	"net/http/httptest"

	"code.cloudfoundry.org/vxlan-policy-agent/handlers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Force Orphanded ASGs Cleanup", func() {
	var (
		response         *httptest.ResponseRecorder
		request          *http.Request
		wasInvoked       bool
		cleanupContainer string
		handler          *handlers.ForceOrphanedASGsCleanup
	)

	BeforeEach(func() {
		response = httptest.NewRecorder()
		request = httptest.NewRequest("GET", "/force-orphaned-asgs-cleanup?container=some-guid", nil)

		wasInvoked = false

		handler = &handlers.ForceOrphanedASGsCleanup{
			EnableASGSyncing: true,
			ASGCleanupFunc: func(container string) error {
				wasInvoked = true
				cleanupContainer = container
				return nil
			},
		}
	})

	It("should call the function", func() {
		handler.ServeHTTP(response, request)
		Expect(response.Code).To(Equal(200))
		Expect(wasInvoked).To(BeTrue())
		Expect(cleanupContainer).To(Equal("some-guid"))
		Expect(io.ReadAll(response.Body)).To(Equal([]byte("cleaned up ASGs for container some-guid")))
	})

	It("returns 405 response when enable asg syncing is disabled", func() {
		handler.EnableASGSyncing = false
		handler.ServeHTTP(response, request)
		Expect(response.Code).To(Equal(405))
		Expect(wasInvoked).To(BeFalse())
		Expect(io.ReadAll(response.Body)).To(Equal([]byte("ASG syncing has been disabled administratively")))
	})

	It("returns 400 response when no container guid was provided", func() {
		request = httptest.NewRequest("GET", "/force-orphaned-asgs-cleanup", nil)
		handler.ServeHTTP(response, request)
		Expect(response.Code).To(Equal(400))
		Expect(io.ReadAll(response.Body)).To(Equal([]byte("no container specified")))
	})
	It("returns 500 response when the poll cycle func returns an error", func() {
		handler.ASGCleanupFunc = func(container string) error {
			return errors.New("failure")
		}

		handler.ServeHTTP(response, request)
		Expect(response.Code).To(Equal(500))
		Expect(io.ReadAll(response.Body)).To(Equal([]byte("failed to cleanup ASGs for container some-guid: failure")))
	})

	Context("when the ASGCleanupFunc returns multierror", func() {
		BeforeEach(func() {
			handler.ASGCleanupFunc = func(container string) error {
				err1 := errors.New("failure1")
				err2 := errors.New("failure2")
				multiErr := multierror.Append(err1, err2)
				return multiErr
			}

			handler.ServeHTTP(response, request)
		})

		It("returns 500 response with all errors", func() {
			Expect(response.Code).To(Equal(500))
			Expect(io.ReadAll(response.Body)).To(Equal([]byte("failed to cleanup ASGs for container some-guid: 2 errors occurred:\n\t* failure1\n\t* failure2\n\n")))
		})
	})
})
