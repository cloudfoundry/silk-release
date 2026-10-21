package handlers_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	hfakes "code.cloudfoundry.org/cf-networking-helpers/fakes"
	"code.cloudfoundry.org/cf-networking-helpers/httperror"
	"code.cloudfoundry.org/cf-networking-helpers/testsupport"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/lager/v3/lagertest"
	"code.cloudfoundry.org/silk/controller"
	"code.cloudfoundry.org/silk/controller/handlers"
	"code.cloudfoundry.org/silk/controller/handlers/fakes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RenewLease", func() {
	var (
		logger            *lagertest.TestLogger
		expectedLogger    lager.Logger
		handler           *handlers.RenewLease
		resp              *httptest.ResponseRecorder
		unmarshaler       *hfakes.Unmarshaler
		leaseRenewer      *fakes.LeaseRenewer
		fakeErrorResponse *fakes.ErrorResponse

		expectedLease controller.Lease
		request       *http.Request
	)

	BeforeEach(func() {
		expectedLogger = lager.NewLogger("test").Session("leases-renew")

		testSink := lagertest.NewTestSink()
		expectedLogger.RegisterSink(testSink)
		expectedLogger.RegisterSink(lager.NewWriterSink(GinkgoWriter, lager.DEBUG))

		logger = lagertest.NewTestLogger("test")
		unmarshaler = &hfakes.Unmarshaler{}
		unmarshaler.UnmarshalStub = json.Unmarshal
		leaseRenewer = &fakes.LeaseRenewer{}
		fakeErrorResponse = &fakes.ErrorResponse{}

		handler = &handlers.RenewLease{
			Unmarshaler:   unmarshaler,
			LeaseRenewer:  leaseRenewer,
			ErrorResponse: fakeErrorResponse,
		}
		resp = httptest.NewRecorder()

		expectedLease = controller.Lease{
			UnderlayIP:          "10.244.16.11",
			OverlaySubnet:       "10.255.17.0/24",
			OverlayHardwareAddr: "ee:ee:0a:ff:11:00",
		}
		requestBody := bytes.NewBuffer([]byte(`{ "underlay_ip": "10.244.16.11", "overlay_subnet": "10.255.17.0/24", "overlay_hardware_addr": "ee:ee:0a:ff:11:00" }`))
		var err error
		request, err = http.NewRequest("PUT", "/leases/renew", requestBody)
		Expect(err).NotTo(HaveOccurred())
		request.RemoteAddr = "some-host:some-port"
	})

	Context("when the request body is at the size limit", func() {
		It("accepts a 4096-byte request body", func() {
			validJSON := `{"underlay_ip":"10.244.16.11","overlay_subnet":"10.255.17.0/24","overlay_hardware_addr":"ee:ee:0a:ff:11:00"}`
			body := append([]byte(validJSON), bytes.Repeat([]byte(" "), 4096-len(validJSON))...)
			request := unknownLengthRequest("PUT", "/leases/renew", body)

			handler.ServeHTTP(logger, resp, request)

			Expect(resp.Code).To(Equal(http.StatusOK))
			Expect(unmarshaler.UnmarshalCallCount()).To(Equal(1))
			Expect(leaseRenewer.RenewSubnetLeaseCallCount()).To(Equal(1))
		})
	})

	Context("when the request body exceeds the size limit", func() {
		BeforeEach(func() {
			realErrorResponse := &httperror.ErrorResponse{MetricsSender: &hfakes.MetricsSender{}}
			fakeErrorResponse.BadRequestStub = realErrorResponse.BadRequest
		})

		It("rejects a 4097-byte request body", func() {
			validJSON := `{"underlay_ip":"10.244.16.11","overlay_subnet":"10.255.17.0/24","overlay_hardware_addr":"ee:ee:0a:ff:11:00"}`
			body := append([]byte(validJSON), bytes.Repeat([]byte(" "), 4097-len(validJSON))...)
			request := unknownLengthRequest("PUT", "/leases/renew", body)

			handler.ServeHTTP(logger, resp, request)

			Expect(resp.Code).To(Equal(http.StatusBadRequest))
			Expect(fakeErrorResponse.BadRequestCallCount()).To(Equal(1))
			_, _, _, description := fakeErrorResponse.BadRequestArgsForCall(0)
			Expect(description).To(HavePrefix("read-body:"))
			Expect(unmarshaler.UnmarshalCallCount()).To(Equal(0))
			Expect(leaseRenewer.RenewSubnetLeaseCallCount()).To(Equal(0))
		})

		It("rejects a 1 MiB request body", func() {
			validJSON := `{"underlay_ip":"10.244.16.11","overlay_subnet":"10.255.17.0/24","overlay_hardware_addr":"ee:ee:0a:ff:11:00"}`
			body := append([]byte(validJSON), bytes.Repeat([]byte(" "), 1024*1024-len(validJSON))...)
			request := unknownLengthRequest("PUT", "/leases/renew", body)

			handler.ServeHTTP(logger, resp, request)

			Expect(resp.Code).To(Equal(http.StatusBadRequest))
			Expect(fakeErrorResponse.BadRequestCallCount()).To(Equal(1))
			_, _, _, description := fakeErrorResponse.BadRequestArgsForCall(0)
			Expect(description).To(HavePrefix("read-body:"))
			Expect(unmarshaler.UnmarshalCallCount()).To(Equal(0))
			Expect(leaseRenewer.RenewSubnetLeaseCallCount()).To(Equal(0))
		})
	})

	It("renews a lease for subnet", func() {
		handler.ServeHTTP(logger, resp, request)
		Expect(leaseRenewer.RenewSubnetLeaseCallCount()).To(Equal(1))
		Expect(leaseRenewer.RenewSubnetLeaseArgsForCall(0)).To(Equal(expectedLease))

		Expect(resp.Code).To(Equal(http.StatusOK))
		Expect(resp.Body.String()).To(Equal("{}"))
	})

	Context("when there are errors reading the body bytes", func() {
		BeforeEach(func() {
			request.Body = io.NopCloser(&testsupport.BadReader{})
		})

		It("logs the error and returns a 400", func() {
			handler.ServeHTTP(logger, resp, request)

			Expect(fakeErrorResponse.BadRequestCallCount()).To(Equal(1))
			l, w, err, description := fakeErrorResponse.BadRequestArgsForCall(0)
			Expect(l).To(Equal(expectedLogger))
			Expect(w).To(Equal(resp))
			Expect(err).To(MatchError("banana"))
			Expect(description).To(Equal("read-body: banana"))
		})
	})

	Context("when the request cannot be unmarshaled", func() {
		BeforeEach(func() {
			unmarshaler.UnmarshalReturns(errors.New("fig"))
		})

		It("returns a BadRequest error", func() {
			handler.ServeHTTP(logger, resp, request)

			Expect(fakeErrorResponse.BadRequestCallCount()).To(Equal(1))
			l, w, err, description := fakeErrorResponse.BadRequestArgsForCall(0)
			Expect(l).To(Equal(expectedLogger))
			Expect(w).To(Equal(resp))
			Expect(err).To(MatchError("fig"))
			Expect(description).To(Equal("unmarshal-request: fig"))
		})
	})

	Context("when renewing a lease fails due to a non-retriable error", func() {
		var terr controller.NonRetriableError
		BeforeEach(func() {
			terr = controller.NonRetriableError("kiwi")
			leaseRenewer.RenewSubnetLeaseReturns(terr)
		})

		It("calls the Error Response Conflict() handler", func() {
			handler.ServeHTTP(logger, resp, request)

			Expect(fakeErrorResponse.ConflictCallCount()).To(Equal(1))
			l, w, err, description := fakeErrorResponse.ConflictArgsForCall(0)
			Expect(l).To(Equal(expectedLogger))
			Expect(w).To(Equal(resp))
			Expect(err).To(Equal(terr))
			Expect(description).To(Equal(fmt.Sprintf("renew-subnet-lease: %s", terr.Error())))
		})
	})

	Context("when renewing a lease fails due to some other error", func() {
		BeforeEach(func() {
			leaseRenewer.RenewSubnetLeaseReturns(errors.New("kiwi"))
		})

		It("calls the Error Response InternalServerError() handler", func() {
			handler.ServeHTTP(logger, resp, request)

			Expect(fakeErrorResponse.InternalServerErrorCallCount()).To(Equal(1))
			l, w, err, description := fakeErrorResponse.InternalServerErrorArgsForCall(0)
			Expect(l).To(Equal(expectedLogger))
			Expect(w).To(Equal(resp))
			Expect(err).To(MatchError("kiwi"))
			Expect(description).To(Equal("renew-subnet-lease: kiwi"))
		})
	})
})
