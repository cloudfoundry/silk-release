package integration_test

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"code.cloudfoundry.org/cf-networking-helpers/db"
	"code.cloudfoundry.org/cf-networking-helpers/testsupport"
	"code.cloudfoundry.org/cf-networking-helpers/testsupport/metrics"
	"code.cloudfoundry.org/cf-networking-helpers/testsupport/ports"
	mcn "code.cloudfoundry.org/lib/multiple-cidr-network"
	"code.cloudfoundry.org/silk/controller"
	"code.cloudfoundry.org/silk/controller/config"
	"code.cloudfoundry.org/silk/controller/integration/helpers"
	"code.cloudfoundry.org/silk/controller/leaser"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/onsi/gomega/types"
)

var (
	dbConfig   db.Config
	session    *gexec.Session
	conf       config.Config
	testClient *controller.Client
	fakeMetron metrics.FakeMetron
)

var _ = BeforeEach(func() {
	fakeMetron = metrics.NewFakeMetron()
	dbConfig = testsupport.GetDBConfig()
	dbConfig.DatabaseName = fmt.Sprintf("test_%d", ports.PickAPort())
	testsupport.CreateDatabase(dbConfig)

	conf = helpers.DefaultTestConfig(dbConfig, "fixtures")
	conf.MetronPort = fakeMetron.Port()
	testClient = helpers.TestClient(conf, "fixtures")
})

var _ = Describe("Silk Controller", func() {
	BeforeEach(func() {
		session = helpers.StartAndWaitForServer(controllerBinaryPath, conf, testClient)
	})

	AfterEach(func() {
		testClient.JsonClient.CloseIdleConnections()
		helpers.StopServer(session)
		testsupport.RemoveDatabase(dbConfig)
	})

	It("gracefully terminates when sent an interrupt signal", func() {
		Consistently(session).ShouldNot(gexec.Exit())
		Expect(session.Out).To(gbytes.Say(`potato-prefix\.silk-controller\.starting-servers`))
		Expect(session.Out).To(gbytes.Say(`potato-prefix\.silk-controller\.running`))

		session.Interrupt()

		Eventually(session, "5s").Should(gexec.Exit(0))
		Expect(session.Out).To(gbytes.Say(`potato-prefix\.silk-controller\.exited`))
	})

	It("runs the cf debug server on the configured port", func() {
		resp, err := http.Get(
			fmt.Sprintf("http://127.0.0.1:%d/debug/pprof", conf.DebugServerPort),
		)
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})

	It("runs the health check server on the configured port", func() {
		resp, err := http.Get(
			fmt.Sprintf("http://127.0.0.1:%d/health", conf.HealthCheckPort),
		)
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})

	Describe("acquiring", func() {
		It("provides an endpoint to acquire a subnet leases", func() {
			By("acquiring a lease")
			lease, err := testClient.AcquireSubnetLease("10.244.4.5")
			Expect(err).NotTo(HaveOccurred())
			Expect(lease.UnderlayIP).To(Equal("10.244.4.5"))

			By("checking that the lease subnet is valid")
			_, subnet, err := net.ParseCIDR(lease.OverlaySubnet)
			Expect(err).NotTo(HaveOccurred())

			By("checking that the lease is contained in the overlay network")
			overlayNetwork, err := mcn.NewMultipleCIDRNetwork(conf.Network)
			Expect(err).NotTo(HaveOccurred())
			Expect(overlayNetwork.Contains(subnet.IP)).To(BeTrue())

			By("checking the hardware addr")
			expectedHardwareAddr, err := (&leaser.HardwareAddressGenerator{}).GenerateForVTEP(subnet.IP)
			Expect(err).NotTo(HaveOccurred())
			Expect(lease.OverlayHardwareAddr).To(Equal(expectedHardwareAddr.String()))

			Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(
				HaveName("LeasesAcquireRequestTime"),
			))
		})

		Context("when there is an existing lease for the underlay IP", func() {
			var existingLease controller.Lease
			BeforeEach(func() {
				var err error
				existingLease, err = testClient.AcquireSubnetLease("10.244.4.5")
				Expect(err).NotTo(HaveOccurred())
			})
			It("returns the same lease", func() {
				lease, err := testClient.AcquireSubnetLease("10.244.4.5")
				Expect(err).NotTo(HaveOccurred())

				Expect(lease).To(Equal(existingLease))
			})

			Context("when the existing lease is in a different overlay network", func() {
				BeforeEach(func() {
					helpers.StopServer(session)
					conf.Network = []string{"10.254.0.0/16", "10.253.0.0/16"}
					session = helpers.StartAndWaitForServer(controllerBinaryPath, conf, testClient)
				})

				It("returns a new lease in the new network", func() {
					By("validating that the old lease is not in the new network")
					overlayNetwork, err := mcn.NewMultipleCIDRNetwork(conf.Network)
					Expect(err).NotTo(HaveOccurred())
					ip, _, err := net.ParseCIDR(existingLease.OverlaySubnet)
					Expect(err).NotTo(HaveOccurred())
					Expect(overlayNetwork.Contains(ip)).To(BeFalse())

					By("acquiring a new lease after the overlay network has changed")
					lease, err := testClient.AcquireSubnetLease("10.244.4.5")
					Expect(err).NotTo(HaveOccurred())
					Expect(lease).NotTo(Equal(existingLease))

					By("checking that the new lease is a valid subnet")
					_, subnet, err := net.ParseCIDR(lease.OverlaySubnet)
					Expect(err).NotTo(HaveOccurred())

					By("checking that the new lease is in the new overlay network")
					Expect(overlayNetwork.Contains(subnet.IP)).To(BeTrue())
				})
			})
		})
	})

	Describe("releasing", func() {
		It("releases a subnet lease", func() {
			By("getting a valid lease")
			lease, err := testClient.AcquireSubnetLease("10.244.4.5")
			Expect(err).NotTo(HaveOccurred())

			By("checking that the lease is present in the list of routable leases")
			leases, err := testClient.GetActiveLeases()
			Expect(err).NotTo(HaveOccurred())
			Expect(len(leases)).To(Equal(1))
			Expect(leases[0]).To(Equal(lease))

			By("attempting to release it")
			err = testClient.ReleaseSubnetLease("10.244.4.5")
			Expect(err).NotTo(HaveOccurred())

			By("checking that the lease is not present in the list of routable leases")
			leases, err = testClient.GetActiveLeases()
			Expect(err).NotTo(HaveOccurred())
			Expect(len(leases)).To(Equal(0))

			Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(
				HaveName("LeasesReleaseRequestTime"),
			))
		})

		Context("when trying to release a single ip", func() {
			It("releases a subnet lease", func() {
				By("getting a valid lease")
				lease, err := testClient.AcquireSingleOverlayIPLease("10.244.4.5")
				Expect(err).NotTo(HaveOccurred())

				By("checking that the lease is present in the list of routable leases")
				leases, err := testClient.GetActiveLeases()
				Expect(err).NotTo(HaveOccurred())
				Expect(len(leases)).To(Equal(1))
				Expect(leases[0]).To(Equal(lease))

				By("attempting to release it")
				err = testClient.ReleaseSubnetLease("10.244.4.5")
				Expect(err).NotTo(HaveOccurred())

				By("checking that the lease is not present in the list of routable leases")
				leases, err = testClient.GetActiveLeases()
				Expect(err).NotTo(HaveOccurred())
				Expect(len(leases)).To(Equal(0))

				Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(
					HaveName("LeasesReleaseRequestTime"),
				))
			})
		})

		Context("when lease is not present in database", func() {
			It("does not error", func() {
				err := testClient.ReleaseSubnetLease("9.9.9.9")
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Describe("lease expiration", func() {
		BeforeEach(func() {
			helpers.StopServer(session)
			conf.Network = []string{"10.255.0.0/29"}
			conf.SubnetPrefixLength = 30
			conf.LeaseExpirationSeconds = 3
			session = helpers.StartAndWaitForServer(controllerBinaryPath, conf, testClient)
		})

		It("reclaims expired leases", func() {
			oldLease, err := testClient.AcquireSubnetLease("10.244.4.5")
			Expect(err).NotTo(HaveOccurred())

			_, err = testClient.AcquireSubnetLease("10.244.4.15")
			Expect(err).To(MatchError(ContainSubstring("no lease available")))

			// wait for lease to expire
			time.Sleep(time.Duration(conf.LeaseExpirationSeconds+1) * time.Second)

			newLease, err := testClient.AcquireSubnetLease("10.244.4.15")
			Expect(err).NotTo(HaveOccurred())
			Expect(newLease.OverlaySubnet).To(Equal(oldLease.OverlaySubnet))
		})
	})

	Describe("renewal", func() {
		It("successfully renews", func() {
			By("getting a valid lease")
			lease, err := testClient.AcquireSubnetLease("10.244.4.5")
			Expect(err).NotTo(HaveOccurred())

			By("attempting to renew it")
			err = testClient.RenewSubnetLease(lease)
			Expect(err).NotTo(HaveOccurred())

			By("checking that the lease is present in the list of routable leases")
			leases, err := testClient.GetActiveLeases()
			Expect(err).NotTo(HaveOccurred())
			Expect(len(leases)).To(Equal(1))
			Expect(leases[0]).To(Equal(lease))

			Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(
				HaveName("LeasesRenewRequestTime"),
			))
		})

		Context("when trying to renew a single ip", func() {
			It("successfully renews", func() {
				By("getting a valid lease")
				lease, err := testClient.AcquireSingleOverlayIPLease("10.244.4.5")
				Expect(err).NotTo(HaveOccurred())

				By("attempting to renew it")
				err = testClient.RenewSubnetLease(lease)
				Expect(err).NotTo(HaveOccurred())

				By("checking that the lease is present in the list of routable leases")
				leases, err := testClient.GetActiveLeases()
				Expect(err).NotTo(HaveOccurred())
				Expect(len(leases)).To(Equal(1))
				Expect(leases[0]).To(Equal(lease))

				Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(
					HaveName("LeasesRenewRequestTime"),
				))
			})
		})

		Context("when the lease is not valid for some reason", func() {
			It("returns a non-retriable error", func() {
				By("getting a valid lease")
				validLease, err := testClient.AcquireSubnetLease("10.244.4.5")
				Expect(err).NotTo(HaveOccurred())

				By("corrupting it somehow")
				invalidLease := controller.Lease{
					UnderlayIP:          validLease.UnderlayIP,
					OverlaySubnet:       "10.9.9.9/24",
					OverlayHardwareAddr: validLease.OverlayHardwareAddr,
				}

				By("attempting to renew it")
				err = testClient.RenewSubnetLease(invalidLease)
				Expect(err).To(BeAssignableToTypeOf(controller.NonRetriableError("")))
				typedError := err.(controller.NonRetriableError)
				Expect(typedError.Error()).To(Equal("non-retriable: renew-subnet-lease: lease mismatch"))

				By("checking that the corrupted lease is not present in the list of routable leases")
				leases, err := testClient.GetActiveLeases()
				Expect(err).NotTo(HaveOccurred())
				Expect(len(leases)).To(Equal(1))
				Expect(leases[0]).To(Equal(validLease))
			})
		})

		Context("when there is an existing lease for the underlay IP", func() {
			var existingLease controller.Lease
			BeforeEach(func() {
				var err error
				existingLease, err = testClient.AcquireSubnetLease("10.244.4.5")
				Expect(err).NotTo(HaveOccurred())
			})

			// This test simulates what happens during a deployment when the
			// operator changes the overlay network from ON-1 to ON-2.

			// 1. Before the deploy, there is a Diego Cell with apps on it. The
			//	  lease for that Diego Cell is a subnet of ON-1.
			// 2. The deploy starts.
			// 3. Silk-controller rolls first. It updates the cidr-pool to
			//    calculate leases for the new overlay network: ON-2.
			// 4. The Diego Cell has not rolled yet. The apps are still using
			//    overlay IPs from ON-1.
			// 5. The Diego Cell renews its lease from ON-1. This renewal
			//    attempt succeeds, despite the fact that the lease is not in
			//    ON-2. A Diego Cell's lease should never change while apps are
			//    running on the cell.
			// 6. During the deploy the Diego Cell drains the apps.
			// 7. When the Diego Cell starts up again it will claim a lease in
			//    the new overlay network ON-2.
			Context("when the overylay network has changed", func() {
				var oldOverlayNetwork []string
				BeforeEach(func() {
					oldOverlayNetwork = conf.Network
					helpers.StopServer(session)
					conf.Network = []string{"10.254.0.0/16"}
					session = helpers.StartAndWaitForServer(controllerBinaryPath, conf, testClient)
				})

				It("renews the same lease in the old network", func() {
					By("validating that the old lease is in the old network")
					overlayNetwork, err := mcn.NewMultipleCIDRNetwork(oldOverlayNetwork)
					Expect(err).NotTo(HaveOccurred())

					ip, _, err := net.ParseCIDR(existingLease.OverlaySubnet)
					Expect(err).NotTo(HaveOccurred())
					Expect(overlayNetwork.Contains(ip)).To(BeTrue())

					By("renewing the lease")
					err = testClient.RenewSubnetLease(existingLease)
					Expect(err).NotTo(HaveOccurred())

					By("checking that the lease is present in the list of routable leases")
					leases, err := testClient.GetActiveLeases()
					Expect(err).NotTo(HaveOccurred())
					Expect(len(leases)).To(Equal(1))
					Expect(leases[0]).To(Equal(existingLease))
				})
			})
		})

		Context("when the local lease is not present in the database", func() {
			It("the renew succeeds (even though its really more of an acquire)", func() {
				lease := controller.Lease{
					UnderlayIP:          "10.244.9.9",
					OverlaySubnet:       "10.255.9.0/24",
					OverlayHardwareAddr: "ee:ee:0a:ff:09:00",
				}

				By("attempting to renew something new but ok")
				err := testClient.RenewSubnetLease(lease)
				Expect(err).NotTo(HaveOccurred())

				By("checking that the lease is present in the list of routable leases")
				leases, err := testClient.GetActiveLeases()
				Expect(err).NotTo(HaveOccurred())
				Expect(len(leases)).To(Equal(1))
				Expect(leases[0]).To(Equal(lease))
			})
		})
	})

	Describe("listing leases", func() {
		It("list the current routable leases", func() {
			lease, err := testClient.AcquireSubnetLease("10.244.4.5")
			Expect(err).NotTo(HaveOccurred())

			singleIPLease, err := testClient.AcquireSingleOverlayIPLease("10.244.4.6")
			Expect(err).NotTo(HaveOccurred())

			leases, err := testClient.GetActiveLeases()
			Expect(err).NotTo(HaveOccurred())
			Expect(len(leases)).To(Equal(2))
			Expect(leases).To(ConsistOf([]controller.Lease{
				lease,
				singleIPLease,
			}))

			Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(
				HaveName("LeasesIndexRequestTime"),
			))
		})

		Context("when a lease expires", func() {
			BeforeEach(func() {
				helpers.StopServer(session)
				conf.LeaseExpirationSeconds = 2
				session = helpers.StartAndWaitForServer(controllerBinaryPath, conf, testClient)
			})

			It("does not return expired leases", func() {
				lease1, err := testClient.AcquireSubnetLease("10.244.4.5")
				Expect(err).NotTo(HaveOccurred())
				lease2, err := testClient.AcquireSubnetLease("10.244.4.6")
				Expect(err).NotTo(HaveOccurred())

				leases, err := testClient.GetActiveLeases()
				Expect(err).NotTo(HaveOccurred())

				Expect(leases).To(ConsistOf(lease1, lease2))

				renewAndCheck := func() []controller.Lease {
					Expect(testClient.RenewSubnetLease(lease2)).To(Succeed())
					leases, err := testClient.GetActiveLeases()
					Expect(err).NotTo(HaveOccurred())
					return leases
				}

				Eventually(renewAndCheck, 4).Should(ConsistOf(lease2))
				Consistently(renewAndCheck).Should(ConsistOf(lease2))
			})
		})

		Context("when there are leases from different networks", func() {
			var oldNetworkLease controller.Lease
			var newNetworkLease controller.Lease
			BeforeEach(func() {
				var err error
				oldNetworkLease, err = testClient.AcquireSubnetLease("10.244.4.5")
				Expect(err).NotTo(HaveOccurred())

				helpers.StopServer(session)
				conf.Network = []string{"10.254.0.0/16"}
				session = helpers.StartAndWaitForServer(controllerBinaryPath, conf, testClient)

				newNetworkLease, err = testClient.AcquireSubnetLease("10.244.4.6")
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns all the leases", func() {
				leases, err := testClient.GetActiveLeases()
				Expect(err).NotTo(HaveOccurred())

				Expect(leases).To(ConsistOf(oldNetworkLease, newNetworkLease))
			})
		})
	})

	It("assigns unique leases from the whole network to multiple clients acquiring subnets concurrently", func() {
		parallelRunner := &testsupport.ParallelRunner{
			NumWorkers: 4,
		}
		nHosts := 255
		underlayIPs := []string{}
		for i := 0; i < nHosts; i++ {
			underlayIPs = append(underlayIPs, fmt.Sprintf("10.244.42.%d", i))
		}

		leases := make(chan (controller.Lease), nHosts)
		go func() {
			parallelRunner.RunOnSliceStrings(underlayIPs, func(underlayIP string) {
				lease, err := testClient.AcquireSubnetLease(underlayIP)
				Expect(err).NotTo(HaveOccurred())
				leases <- lease
			})
			close(leases)
		}()

		leaseIPs := make(map[string]struct{})
		leaseSubnets := make(map[string]struct{})
		overlayNetwork, err := mcn.NewMultipleCIDRNetwork(conf.Network)
		Expect(err).NotTo(HaveOccurred())

		for lease := range leases {
			_, subnet, err := net.ParseCIDR(lease.OverlaySubnet)
			Expect(err).NotTo(HaveOccurred())
			Expect(overlayNetwork.Contains(subnet.IP)).To(BeTrue())

			leaseIPs[lease.UnderlayIP] = struct{}{}
			leaseSubnets[lease.OverlaySubnet] = struct{}{}
		}
		Expect(len(leaseIPs)).To(Equal(nHosts))
		Expect(len(leaseSubnets)).To(Equal(nHosts))
	})

	It("assigns unique leases to multiple clients acquiring single ips concurrently", func() {
		parallelRunner := &testsupport.ParallelRunner{
			NumWorkers: 4,
		}
		nHosts := 255
		var underlayIPs []string
		for i := 0; i < nHosts; i++ {
			underlayIPs = append(underlayIPs, fmt.Sprintf("10.244.0.%d", i))
		}

		leases := make(chan controller.Lease, nHosts)
		go func() {
			parallelRunner.RunOnSliceStrings(underlayIPs, func(underlayIP string) {
				lease, err := testClient.AcquireSingleOverlayIPLease(underlayIP)
				Expect(err).NotTo(HaveOccurred())
				leases <- lease
			})
			close(leases)
		}()

		leaseUnderlays := make(map[string]struct{})
		leaseIPs := make(map[string]struct{})
		overlayNetwork, err := mcn.NewMultipleCIDRNetwork(conf.Network)
		Expect(err).NotTo(HaveOccurred())

		for lease := range leases {
			_, subnet, err := net.ParseCIDR(lease.OverlaySubnet)
			Expect(err).NotTo(HaveOccurred())
			Expect(overlayNetwork.Contains(subnet.IP)).To(BeTrue())
			Expect(lease.OverlaySubnet).To(ContainSubstring("/32"))

			leaseUnderlays[lease.UnderlayIP] = struct{}{}
			leaseIPs[lease.OverlaySubnet] = struct{}{}
		}
		Expect(len(leaseUnderlays)).To(Equal(nHosts))
		Expect(len(leaseIPs)).To(Equal(nHosts))
	})

	withName := func(name string) types.GomegaMatcher {
		return WithTransform(func(ev metrics.Event) string {
			return ev.Name
		}, Equal(name))
	}

	withValue := func(value interface{}) types.GomegaMatcher {
		return WithTransform(func(ev metrics.Event) float64 {
			return ev.Value
		}, BeEquivalentTo(value))
	}

	hasMetricWithValue := func(name string, value interface{}) types.GomegaMatcher {
		return SatisfyAll(withName(name), withValue(value))
	}

	Describe("metrics", func() {
		It("emits an uptime metric", func() {
			Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(withName("uptime")))
		})

		It("emits database metric", func() {
			Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(withName("DBOpenConnections")))
			Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(withName("DBQueriesTotal")))
			Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(withName("DBQueriesSucceeded")))
			Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(withName("DBQueriesFailed")))
			Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(withName("DBQueriesInFlight")))
			Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(withName("DBQueryDurationMax")))
		})

		Context("when some leases have been claimed", func() {
			BeforeEach(func() {
				_, err := testClient.AcquireSubnetLease("10.244.4.5")
				Expect(err).NotTo(HaveOccurred())
				_, err = testClient.AcquireSubnetLease("10.244.4.6")
				Expect(err).NotTo(HaveOccurred())
			})
			It("emits number of total leases", func() {
				Eventually(fakeMetron.AllEvents, "10s").Should(ContainElement(hasMetricWithValue("totalLeases", 2)))
			})
			It("emits number of free leases", func() {
				// 256 per /16
				// 2 * /16 cidrs = 512
				// 512 - 2 (for the reserved subnet for each network cidr) = 511
				// 511 - 2 (for the two leases acquired in this test) = 209
				Eventually(fakeMetron.AllEvents, "10s").Should(ContainElement(hasMetricWithValue("freeLeases", 508)))
			})
			It("emits number of stale leases", func() {
				Eventually(fakeMetron.AllEvents, "2s").Should(ContainElement(hasMetricWithValue("staleLeases", 0)))
				Consistently(fakeMetron.AllEvents, "2s").Should(ContainElement(hasMetricWithValue("staleLeases", 0)))
				Eventually(fakeMetron.AllEvents, "10s").Should(ContainElement(hasMetricWithValue("staleLeases", 2)))
			})
		})
	})
})
