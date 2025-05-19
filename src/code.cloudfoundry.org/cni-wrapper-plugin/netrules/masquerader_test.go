package netrules_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"code.cloudfoundry.org/cni-wrapper-plugin/fakes"
	"code.cloudfoundry.org/cni-wrapper-plugin/lib"
	"code.cloudfoundry.org/cni-wrapper-plugin/netrules"
	lib_fakes "code.cloudfoundry.org/lib/fakes"
	"code.cloudfoundry.org/lib/rules"
	"code.cloudfoundry.org/silk/daemon"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("Masquerader", func() {

	var (
		fakeIPTables     *lib_fakes.IPTablesAdapter
		masquerader      *netrules.Masquerader
		pluginController *lib.PluginController

		containerIP string
		daemonPort  string
		leaseCIDR   string
		vtepName    string
	)

	BeforeEach(func() {
		containerIP = "10.255.11.11"
		daemonPort = "8787"
		leaseCIDR = "10.255.11.0/24"
		vtepName = "meow-vtep"

		fakeDelegator := &fakes.Delegator{}
		fakeIPTables = &lib_fakes.IPTablesAdapter{}
		pluginController = &lib.PluginController{
			Delegator: fakeDelegator,
			IPTables:  fakeIPTables,
		}
		masquerader = &netrules.Masquerader{
			PluginController: pluginController,
			VTEPName:         vtepName,
			DaemonPort:       daemonPort,
			ContainerIP:      containerIP,
		}
	})

	Describe("AddIPMasq", func() {
		Context("when customNoMasqueradeCIDRRange is NOT set", func() {
			var (
				fakeSilkDaemonServer    *ghttp.Server
				silkDaemonResponseBytes []byte
			)

			BeforeEach(func() {
				fakeSilkDaemonServer = ghttp.NewServer()

				daemonPort := strings.Split(fakeSilkDaemonServer.Addr(), ":")[1]
				masquerader.DaemonPort = daemonPort

				silkDaemonResponse := daemon.NetworkInfo{
					OverlaySubnet: leaseCIDR,
				}

				var err error
				silkDaemonResponseBytes, err = json.Marshal(silkDaemonResponse)
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				fakeSilkDaemonServer.Close()
			})

			Context("when the silk daemon is available", func() {
				BeforeEach(func() {
					fakeSilkDaemonServer.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("GET", "/"),
							ghttp.RespondWith(http.StatusOK, silkDaemonResponseBytes),
						),
					)
				})

				It("calls silk daemon to get the lease and uses that instead", func() {
					expectedRule := rules.IPTablesRule{"--source", containerIP, "!", "-o", vtepName, "!", "--destination", leaseCIDR, "--jump", "MASQUERADE"}
					err := masquerader.AddIPMasq()
					Expect(err).NotTo(HaveOccurred())
					Expect(fakeIPTables.BulkAppendCallCount()).To(Equal(1))
					table, chain, rules := fakeIPTables.BulkAppendArgsForCall(0)
					Expect(table).To(Equal("nat"))
					Expect(chain).To(Equal("POSTROUTING"))
					Expect(rules).To(HaveLen(1))
					Expect(rules[0]).To(Equal(expectedRule))
				})

				Context("when IPtables errors", func() {
					BeforeEach(func() {
						fakeIPTables.BulkAppendReturns(errors.New("meow-bad"))
					})

					It("returns an error and doesn't call the silk-daemon twice", func() {
						err := masquerader.AddIPMasq()
						Expect(err).To(MatchError("meow-bad"))

						// Only one handler is set on the daemon server, so if
						// it was called again it would have failed above with a
						// different error. The test below validates that there
						// is only one handler.
						thisShouldNotPanic := func() {
							fakeSilkDaemonServer.GetHandler(0)
						}
						thisShouldPanic := func() {
							fakeSilkDaemonServer.GetHandler(1)
						}
						Expect(thisShouldNotPanic).ToNot(Panic())
						Expect(thisShouldPanic).To(Panic())
					})
				})
			})

			Context("when the silk-daemon is not available", func() {
				BeforeEach(func() {
					fakeSilkDaemonServer.Close()
				})

				It("returns an error and logs", func() {
					err := masquerader.AddIPMasq()
					Expect(err).To(MatchError(ContainSubstring("failed to get lease from silk daemon")))
				})
			})

			Context("when it fails initially but eventually becomes available within 5 attempts", func() {
				BeforeEach(func() {
					fakeSilkDaemonServer.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("GET", "/"),
							ghttp.RespondWith(http.StatusInternalServerError, []byte{}),
						),
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("GET", "/"),
							ghttp.RespondWith(http.StatusInternalServerError, []byte{}),
						),
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("GET", "/"),
							ghttp.RespondWith(http.StatusInternalServerError, []byte{}),
						),
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("GET", "/"),
							ghttp.RespondWith(http.StatusOK, silkDaemonResponseBytes),
						),
					)
				})

				It("eventually succeeds", func() {
					expectedRule := rules.IPTablesRule{"--source", containerIP, "!", "-o", vtepName, "!", "--destination", leaseCIDR, "--jump", "MASQUERADE"}
					err := masquerader.AddIPMasq()
					Expect(err).NotTo(HaveOccurred())
					Expect(fakeIPTables.BulkAppendCallCount()).To(Equal(1))
					table, chain, rules := fakeIPTables.BulkAppendArgsForCall(0)
					Expect(table).To(Equal("nat"))
					Expect(chain).To(Equal("POSTROUTING"))
					Expect(rules).To(HaveLen(1))
					Expect(rules[0]).To(Equal(expectedRule))
				})
			})
		})

		Context("when customNoMasqueradeCIDRRange is set", func() {
			var customNoMasqueradeCIDRRange string

			BeforeEach(func() {
				customNoMasqueradeCIDRRange = "10.33.0.0/16"
				masquerader.CustomNoMasqueradeCIDRRange = customNoMasqueradeCIDRRange
			})

			It("makes a masq rule with the customNoMasqueradeCIDRRange", func() {
				expectedRule := rules.IPTablesRule{"--source", containerIP, "!", "-o", vtepName, "!", "--destination", customNoMasqueradeCIDRRange, "--jump", "MASQUERADE"}
				err := masquerader.AddIPMasq()
				Expect(err).ToNot(HaveOccurred())
				Expect(fakeIPTables.BulkAppendCallCount()).To(Equal(1))
				table, chain, rules := fakeIPTables.BulkAppendArgsForCall(0)
				Expect(table).To(Equal("nat"))
				Expect(chain).To(Equal("POSTROUTING"))
				Expect(rules).To(HaveLen(1))
				Expect(rules[0]).To(Equal(expectedRule))
			})

			Context("when IPtables errors", func() {
				BeforeEach(func() {
					fakeIPTables.BulkAppendReturns(errors.New("meow-bad"))
				})

				It("returns an error", func() {
					err := masquerader.AddIPMasq()
					Expect(err).To(MatchError("meow-bad"))
				})
			})
		})
	})

	Describe("DelIPMasq", func() {
		Context("when customNoMasqueradeCIDRRange is NOT set", func() {
			var fakeSilkDaemonServer *ghttp.Server
			var silkDaemonResponseBytes []byte

			BeforeEach(func() {
				fakeSilkDaemonServer = ghttp.NewServer()
				daemonPort := strings.Split(fakeSilkDaemonServer.Addr(), ":")[1]
				masquerader.DaemonPort = daemonPort

				silkDaemonResponse := daemon.NetworkInfo{
					OverlaySubnet: leaseCIDR,
				}

				var err error
				silkDaemonResponseBytes, err = json.Marshal(silkDaemonResponse)
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				fakeSilkDaemonServer.Close()
			})

			Context("when the silk daemon responds with the lease", func() {
				BeforeEach(func() {
					fakeSilkDaemonServer.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("GET", "/"),
							ghttp.RespondWith(http.StatusOK, silkDaemonResponseBytes),
						),
					)
				})

				It("calls silk daemon to get the lease and uses that instead", func() {
					expectedRule := rules.IPTablesRule{"--source", containerIP, "!", "-o", vtepName, "!", "--destination", leaseCIDR, "--jump", "MASQUERADE"}
					err := masquerader.DelIPMasq()
					Expect(err).NotTo(HaveOccurred())
					Expect(fakeIPTables.DeleteCallCount()).To(Equal(1))
					table, chain, rule := fakeIPTables.DeleteArgsForCall(0)
					Expect(table).To(Equal("nat"))
					Expect(chain).To(Equal("POSTROUTING"))
					Expect(rule).To(Equal(expectedRule))
				})
			})

			Context("when the silk-daemon is not available", func() {
				BeforeEach(func() {
					fakeSilkDaemonServer.Close()
				})

				It("returns an error and logs", func() {
					err := masquerader.DelIPMasq()
					Expect(err).To(MatchError(ContainSubstring("failed to get lease from silk daemon")))
				})
			})

			Context("when it fails initially but eventually becomes available within 5 attempts", func() {
				BeforeEach(func() {
					fakeSilkDaemonServer.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("GET", "/"),
							ghttp.RespondWith(http.StatusInternalServerError, []byte{}),
						),
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("GET", "/"),
							ghttp.RespondWith(http.StatusInternalServerError, []byte{}),
						),
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("GET", "/"),
							ghttp.RespondWith(http.StatusInternalServerError, []byte{}),
						),
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("GET", "/"),
							ghttp.RespondWith(http.StatusOK, silkDaemonResponseBytes),
						),
					)
				})

				It("eventually succeeds", func() {
					expectedRule := rules.IPTablesRule{"--source", containerIP, "!", "-o", vtepName, "!", "--destination", leaseCIDR, "--jump", "MASQUERADE"}
					err := masquerader.DelIPMasq()
					Expect(err).NotTo(HaveOccurred())
					Expect(fakeIPTables.DeleteCallCount()).To(Equal(1))
					table, chain, rule := fakeIPTables.DeleteArgsForCall(0)
					Expect(table).To(Equal("nat"))
					Expect(chain).To(Equal("POSTROUTING"))
					Expect(rule).To(Equal(expectedRule))
				})
			})
		})

		Context("when customNoMasqueradeCIDRRange is set", func() {
			var customNoMasqueradeCIDRRange string

			BeforeEach(func() {
				customNoMasqueradeCIDRRange = "10.33.0.0/16"
				masquerader.CustomNoMasqueradeCIDRRange = customNoMasqueradeCIDRRange
			})

			It("makes a masq rule with the customNoMasqueradeCIDRRange", func() {
				expectedRule := rules.IPTablesRule{"--source", containerIP, "!", "-o", vtepName, "!", "--destination", customNoMasqueradeCIDRRange, "--jump", "MASQUERADE"}
				err := masquerader.DelIPMasq()
				Expect(err).ToNot(HaveOccurred())
				Expect(fakeIPTables.DeleteCallCount()).To(Equal(1))
				table, chain, rule := fakeIPTables.DeleteArgsForCall(0)
				Expect(table).To(Equal("nat"))
				Expect(chain).To(Equal("POSTROUTING"))
				Expect(rule).To(Equal(expectedRule))
			})

			Context("when IPtables errors", func() {
				BeforeEach(func() {
					fakeIPTables.DeleteReturns(errors.New("meow-bad"))
				})

				It("returns an error", func() {
					err := masquerader.DelIPMasq()
					Expect(err).To(MatchError("meow-bad"))
				})
			})
		})
	})
})
