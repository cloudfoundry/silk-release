package integration_test

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"code.cloudfoundry.org/cf-networking-helpers/mutualtls"
	"code.cloudfoundry.org/cf-networking-helpers/testsupport/metrics"
	"code.cloudfoundry.org/cf-networking-helpers/testsupport/ports"
	"code.cloudfoundry.org/lager/v3/lagertest"
	mcn "code.cloudfoundry.org/lib/multiple-cidr-network"
	"code.cloudfoundry.org/silk/client/config"
	"code.cloudfoundry.org/silk/controller"
	"code.cloudfoundry.org/silk/daemon"
	"code.cloudfoundry.org/silk/daemon/vtep"
	"code.cloudfoundry.org/silk/lib/adapter"
	"code.cloudfoundry.org/silk/testsupport"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/onsi/gomega/types"
	matchers "github.com/pivotal-cf-experimental/gomegamatchers"
	"github.com/vishvananda/netlink"
)

const (
	DEFAULT_TIMEOUT = "5s"
	localIP         = "127.0.0.1"
)

var (
	externalMTU                        int
	daemonConf                         config.Config
	daemonLease                        controller.Lease
	fakeServer                         *testsupport.FakeController
	serverListenPort                   int
	serverListenAddr                   string
	serverTLSConfig                    *tls.Config
	session                            *gexec.Session
	daemonHealthCheckURL               string
	daemonDebugServerPort              int
	datastorePath                      string
	vtepFactory                        *vtep.Factory
	vtepName                           string
	vtepPort                           int
	vni                                int
	fakeMetron                         metrics.FakeMetron
	localOverlayLeaseSubnet            string
	localOverlayLeaseIP                net.IP
	overlayNetworks                    mcn.MultipleCIDRNetwork
	remoteOverlaySubnet                string
	remoteOverlayVtepIP                net.IP
	remoteSingleIPSubnet               string
	remoteSingleIP                     net.IP
	remoteOverlaySubnetOnSecondNetwork string
	remoteOverlayVtepIPOnSecondNetwork net.IP
	leases                             []controller.Lease
)

var _ = BeforeEach(func() {
	fakeMetron = metrics.NewFakeMetron()

	externalIface, err := locateInterface(net.ParseIP(localIP))
	Expect(err).NotTo(HaveOccurred())
	externalMTU = externalIface.MTU

	localOverlayLeaseSubnet = fmt.Sprintf("10.255.%d.0/24", GinkgoParallelProcess()+100)
	localOverlayLeaseIP, _, _ = net.ParseCIDR(localOverlayLeaseSubnet)

	remoteOverlaySubnet = fmt.Sprintf("10.255.%d.0/24", GinkgoParallelProcess()+2)
	remoteOverlayVtepIP, _, _ = net.ParseCIDR(remoteOverlaySubnet)

	remoteOverlaySubnetOnSecondNetwork = fmt.Sprintf("10.250.%d.0/24", GinkgoParallelProcess()+2)
	remoteOverlayVtepIPOnSecondNetwork, _, _ = net.ParseCIDR(remoteOverlaySubnetOnSecondNetwork)

	remoteSingleIPSubnet = fmt.Sprintf("10.255.0.%d/32", GinkgoParallelProcess()+20)
	remoteSingleIP, _, _ = net.ParseCIDR(remoteSingleIPSubnet)

	daemonLease = controller.Lease{
		UnderlayIP:          localIP,
		OverlaySubnet:       localOverlayLeaseSubnet,
		OverlayHardwareAddr: "ee:ee:0a:ff:1e:00",
	}
	vni = GinkgoParallelProcess()
	vtepName = fmt.Sprintf("silk-vtep-%d", GinkgoParallelProcess())
	daemonHealthCheckPort := ports.PickAPort()
	daemonHealthCheckURL = fmt.Sprintf("http://127.0.0.1:%d/health", daemonHealthCheckPort)
	daemonDebugServerPort = ports.PickAPort()
	serverListenPort = ports.PickAPort()
	vtepPort = ports.PickAPort()
	serverListenAddr = fmt.Sprintf("127.0.0.1:%d", serverListenPort)
	datastoreDir, err := os.MkdirTemp("", "")
	Expect(err).NotTo(HaveOccurred())
	datastorePath = filepath.Join(datastoreDir, "container-metadata.json")

	overlayNetworksString := []string{"10.255.0.0/16", "10.250.0.0/16"}
	overlayNetworks, err = mcn.NewMultipleCIDRNetwork(overlayNetworksString)
	Expect(err).NotTo(HaveOccurred())

	daemonConf = config.Config{
		UnderlayIP:                localIP,
		SubnetPrefixLength:        24,
		OverlayNetworks:           overlayNetworksString,
		HealthCheckPort:           uint16(daemonHealthCheckPort),
		VTEPName:                  vtepName,
		ConnectivityServerURL:     fmt.Sprintf("https://%s", serverListenAddr),
		ServerCACertFile:          paths.ServerCACertFile,
		ClientCertFile:            paths.ClientCertFile,
		ClientKeyFile:             paths.ClientKeyFile,
		VNI:                       vni,
		PollInterval:              1,
		DebugServerPort:           daemonDebugServerPort,
		Datastore:                 datastorePath,
		PartitionToleranceSeconds: 10,
		ClientTimeoutSeconds:      10,
		MetronPort:                fakeMetron.Port(),
		VTEPPort:                  vtepPort,
		LogPrefix:                 "potato-prefix",
	}

	vtepFactory = &vtep.Factory{NetlinkAdapter: &adapter.NetlinkAdapter{}, Logger: lagertest.NewTestLogger("test")}

	serverTLSConfig, err = mutualtls.NewServerTLSConfig(paths.ServerCertFile, paths.ServerKeyFile, paths.ClientCACertFile)
	Expect(err).NotTo(HaveOccurred())
	fakeServer = testsupport.StartServer(serverListenAddr, serverTLSConfig)

	acquireHandler := &testsupport.FakeHandler{
		ResponseCode: 200,
		ResponseBody: &controller.Lease{
			UnderlayIP:          localIP,
			OverlaySubnet:       localOverlayLeaseSubnet,
			OverlayHardwareAddr: "ee:ee:0a:ff:1e:00",
		},
	}

	leases = []controller.Lease{
		{
			UnderlayIP:          localIP,
			OverlaySubnet:       localOverlayLeaseSubnet,
			OverlayHardwareAddr: "ee:ee:0a:ff:1e:00",
		}, {
			UnderlayIP:          "172.17.0.5",
			OverlaySubnet:       remoteOverlaySubnet,
			OverlayHardwareAddr: "ee:ee:0a:ff:28:00",
		}, {
			UnderlayIP:          "172.17.0.6",
			OverlaySubnet:       remoteSingleIPSubnet,
			OverlayHardwareAddr: "ee:ee:0a:ff:28:ff",
		}, {
			UnderlayIP:          "172.17.0.9",
			OverlaySubnet:       remoteOverlaySubnetOnSecondNetwork,
			OverlayHardwareAddr: "cc:cc:cc:cc:cc:cc",
		},
	}
	leasesResponse := map[string][]controller.Lease{"leases": leases}
	indexHandler := &testsupport.FakeHandler{
		ResponseCode: 200,
		ResponseBody: leasesResponse,
	}

	fakeServer.SetHandler("/leases/acquire", acquireHandler)
	fakeServer.SetHandler("/leases", indexHandler)
})

var _ = AfterEach(func() {
	fakeServer.Stop()
	vtepFactory.DeleteVTEP(vtepName)
})

var _ = Describe("Daemon Integration", func() {
	BeforeEach(func() {
		startAndWaitForDaemon()
	})

	AfterEach(func() {
		stopDaemon()
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

	It("syncs with the controller and updates the local networking stack", func() {
		By("getting the device")
		link, err := netlink.LinkByName(vtepName)
		Expect(err).NotTo(HaveOccurred())
		vtep := link.(*netlink.Vxlan)

		By("asserting on the device properties")
		Expect(vtep.Attrs().Flags & net.FlagUp).To(Equal(net.FlagUp))
		Expect(vtep.HardwareAddr.String()).To(Equal("ee:ee:0a:ff:1e:00"))
		Expect(vtep.SrcAddr.String()).To(Equal(localIP))
		defaultDevice, err := locateInterface(net.ParseIP(localIP))
		Expect(err).NotTo(HaveOccurred())
		Expect(vtep.VtepDevIndex).To(Equal(defaultDevice.Index))
		Expect(vtep.VxlanId).To(Equal(vni))
		Expect(vtep.Port).To(Equal(vtepPort))
		Expect(vtep.Learning).To(Equal(false))
		Expect(vtep.GBP).To(BeTrue())

		By("getting the addresses on the device")
		addresses, err := netlink.AddrList(vtep, netlink.FAMILY_V4)
		Expect(err).NotTo(HaveOccurred())
		Expect(addresses).To(HaveLen(len(daemonConf.OverlayNetworks)))
		Expect(addresses[0].IP.String()).To(Equal(localOverlayLeaseIP.String()))
		Expect(addresses[1].IP.String()).To(Equal("10.250.0.0"))
		By("checking the daemon's healthcheck")
		doHealthCheck()

		By("inspecting the daemon's log to see that it acquired a new lease")
		Expect(session.Out).To(gbytes.Say(`potato-prefix\.silk-daemon.*acquired-lease.*overlay_subnet.*` + localOverlayLeaseSubnet + `.*overlay_hardware_addr.*ee:ee:0a:ff:1e:00`))

		By("stopping the daemon")
		stopDaemon()

		By("setting up renew handler")
		renewHandler := &testsupport.FakeHandler{
			ResponseCode: 200,
			ResponseBody: struct{}{},
		}
		fakeServer.SetHandler("/leases/renew", renewHandler)

		By("restarting the daemon")
		startAndWaitForDaemon()

		By("renewing its lease")
		var renewRequest controller.Lease
		Expect(json.Unmarshal(renewHandler.LastRequestBody, &renewRequest)).To(Succeed())
		Expect(renewRequest).To(Equal(daemonLease))

		By("checking the daemon's healthcheck")
		doHealthCheck()

		By("inspecting the daemon's log to see that it renewed a new lease")
		Expect(session.Out).To(gbytes.Say(`renewed-lease.*overlay_subnet.*` + localOverlayLeaseSubnet + `.*overlay_hardware_addr.*ee:ee:0a:ff:1e:00`))

		By("checking that a renew-success metric was emitted")
		Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(withName("renewSuccess")))

		By("modifying the renewHandler to respond with 404")
		renewHandler = &testsupport.FakeHandler{
			ResponseCode: 404,
			ResponseBody: struct{}{},
		}
		fakeServer.SetHandler("/leases/renew", renewHandler)

		By("checking that a renew-failed metric was emitted")
		Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(withName("renewFailure")))
	})

	Context("when single ip only is true", func() {
		var (
			localSingleIPLease     controller.Lease
			localSingleIPOverlayIP string
		)

		JustBeforeEach(func() {
			By("defining a local singleIP lease")
			localSingleIPOverlayIP = "10.255.0.32"
			localSingleIPLease = controller.Lease{
				UnderlayIP:          "10.244.64.65",
				OverlaySubnet:       fmt.Sprintf("%s/32", localSingleIPOverlayIP),
				OverlayHardwareAddr: "ee:ee:0a:ff:00:20",
			}

			By("setting the acquire endpoint to return the singleIP lease")
			fakeServer.SetHandlerFunc("/leases/acquire", func(w http.ResponseWriter, req *http.Request) {
				contents, err := io.ReadAll(req.Body)
				Expect(err).NotTo(HaveOccurred())

				var acquireRequest controller.AcquireLeaseRequest
				err = json.Unmarshal(contents, &acquireRequest)
				Expect(err).NotTo(HaveOccurred())
				if acquireRequest.SingleOverlayIP {
					contents, err := json.Marshal(localSingleIPLease)
					Expect(err).NotTo(HaveOccurred())
					w.WriteHeader(http.StatusOK)
					w.Write(contents)
					return
				}

				By("failing if the daemon ever tries to claim a non-SingleIP lease")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("{}"))
			})

			fakeServer.SetHandlerFunc("/leases/renew", func(w http.ResponseWriter, req *http.Request) {
				var renewLease controller.Lease
				err := json.NewDecoder(req.Body).Decode(&renewLease)
				Expect(err).NotTo(HaveOccurred())

				if strings.Contains(renewLease.OverlaySubnet, "/32") {
					By("Making the renew handler return a 200 only if the lease is a singleIP")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("{}"))
				} else {
					By("Making the renew handler return a 500 initially so it will re-request a lease")
					w.WriteHeader(http.StatusInternalServerError)
				}
			})

			By("adding the new localSingleIPLease to the list of all other leases used in other tests")
			leases = append(leases, localSingleIPLease)
			leasesResponse := map[string][]controller.Lease{"leases": leases}
			indexHandler := &testsupport.FakeHandler{
				ResponseCode: 200,
				ResponseBody: leasesResponse,
			}
			fakeServer.SetHandler("/leases", indexHandler)

			By("restarting the daemon so it becomes SingleIP")
			daemonConf.SingleIPOnly = true
			stopDaemon()
			startAndWaitForDaemon()
			By("checking that the lease renewal is logged")
			Eventually(session.Out, 2).Should(gbytes.Say(`silk-daemon.renewed-lease.*"lease".*overlay_subnet.*` + "10.255.0.32/32" + `.*overlay_hardware_addr.*ee:ee:0a:ff:00:20`))
		})

		It("updates the local networking stack", func() {
			link, err := netlink.LinkByName(vtepName)
			Expect(err).NotTo(HaveOccurred())
			vtep := link.(*netlink.Vxlan)
			Expect(vtep.HardwareAddr.String()).To(Equal("ee:ee:0a:ff:00:20"))
			Expect(vtep.SrcAddr.String()).To(Equal(localIP))

			addresses, err := netlink.AddrList(vtep, netlink.FAMILY_V4)
			Expect(err).NotTo(HaveOccurred())
			Expect(addresses).To(HaveLen(len(daemonConf.OverlayNetworks)))
			Expect(addresses[0].IP.String()).To(Equal("10.255.0.32"))
			Expect(addresses[1].IP.String()).To(Equal("10.250.0.0"))
		})

		It("updates the local routing stack", func() {
			By("checking that it emits a metric for the number of leases it sees")
			Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(hasMetricWithValue("numberLeases", 5)))

			By("turning on debug logging")
			setLogLevel("DEBUG", daemonDebugServerPort)

			By("checking that the correct leases are logged")
			Eventually(session.Out, 2).Should(gbytes.Say(`level.*debug.*silk-daemon.converge-leases`))
			Eventually(session.Out, 2).Should(gbytes.Say(fmt.Sprintf(`underlay_ip.*%s.*overlay_subnet.*`+localOverlayLeaseSubnet+`.*overlay_hardware_addr.*ee:ee:0a:ff:1e:00`, localIP)))
			Eventually(session.Out, 2).Should(gbytes.Say(`underlay_ip.*172.17.0.5.*overlay_subnet.*` + remoteOverlaySubnet + `.*overlay_hardware_addr.*ee:ee:0a:ff:28:00`))
			Eventually(session.Out, 2).Should(gbytes.Say(`underlay_ip.*172.17.0.9.*overlay_subnet.*` + remoteOverlaySubnetOnSecondNetwork + `.*overlay_hardware_addr.*cc:cc:cc:cc:cc:cc`))
			Eventually(session.Out, 2).Should(gbytes.Say(`underlay_ip.*172.17.0.6.*overlay_subnet.*` + remoteSingleIPSubnet + `.*overlay_hardware_addr.*ee:ee:0a:ff:28:ff`))
			Eventually(session.Out, 2).Should(gbytes.Say(`underlay_ip.*10.244.64.65.*overlay_subnet.*` + "10.255.0.32/32" + `.*overlay_hardware_addr.*ee:ee:0a:ff:00:20`))

			By("checking the routing is correct")
			routes := mustSucceed("ip", "route", "list", "dev", vtepName)
			routeFields := strings.Fields(routes)
			Expect(routeFields).To(matchers.ContainSequence([]string{"10.255.0.0/16", "proto", "kernel", "scope", "link", "src", localSingleIPOverlayIP}))
			Expect(routeFields).To(matchers.ContainSequence([]string{"10.250.0.0/16", "proto", "kernel", "scope", "link", "src", "10.250.0.0"}))

			By("checking that leases in the same overlay CIDR as this lease include a src with my lease IP")
			Expect(routeFields).To(matchers.ContainSequence([]string{localOverlayLeaseSubnet, "via", localOverlayLeaseIP.String(), "src", localSingleIPOverlayIP}))
			Expect(routeFields).To(matchers.ContainSequence([]string{remoteOverlaySubnet, "via", remoteOverlayVtepIP.String(), "src", localSingleIPOverlayIP}))

			By("checking that leases in a different overlay CIDR as the local lease include a src with the overlay CIDR IP")
			Expect(routeFields).To(matchers.ContainSequence([]string{remoteOverlaySubnetOnSecondNetwork, "via", remoteOverlayVtepIPOnSecondNetwork.String(), "src", "10.250.0.0"}))

			By("checking that singleIP VMs are not given a route")
			Expect(routeFields).NotTo(matchers.ContainSequence([]string{remoteSingleIP.String(), "via", remoteSingleIP.String()}))
		})
	})

	Context("when custom_underlay_interface_name is specified", func() {
		var (
			dummyName      string
			dummyInterface *net.Interface
		)
		BeforeEach(func() {
			var err error

			dummyName = "eth1"
			daemonConf.VxlanInterfaceName = dummyName
			mustSucceed("ip", "link", "add", dummyName, "type", "dummy")

			dummyInterface, err = net.InterfaceByName("eth1")
			Expect(err).NotTo(HaveOccurred())

			stopDaemon()
		})
		AfterEach(func() {
			mustSucceed("ip", "link", "delete", dummyName)
		})
		It("attaches the vtep device to the interface specified", func() {
			startAndWaitForDaemon()
			link, err := netlink.LinkByName(vtepName)
			Expect(err).NotTo(HaveOccurred())

			vtep := link.(*netlink.Vxlan)
			Expect(vtep.VtepDevIndex).To(Equal(dummyInterface.Index))
		})
	})

	It("emits an uptime metric", func() {
		Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(withName("uptime")))
	})

	Describe("polling", func() {
		BeforeEach(func() {
			By("set up renew handler")
			handler := &testsupport.FakeHandler{
				ResponseCode: 200,
				ResponseBody: struct{}{},
			}
			fakeServer.SetHandler("/leases/renew", handler)

			By("turning on debug logging")
			setLogLevel("DEBUG", daemonDebugServerPort)
		})

		It("polls to renew the lease and logs at debug level", func() {
			By("checking that the lease renewal is logged")
			Eventually(session.Out, 2).Should(gbytes.Say(fmt.Sprintf(`silk-daemon.renew-lease.*"lease".*overlay_subnet.*` + localOverlayLeaseSubnet + `.*overlay_hardware_addr.*ee:ee:0a:ff:1e:00`)))

			By("stopping the controller")
			handler := &testsupport.FakeHandler{
				ResponseCode: 500,
				ResponseBody: struct{}{},
			}
			fakeServer.SetHandler("/leases/renew", handler)

			By("checking that the lease renewal failure is logged")
			Eventually(session.Out, 2).Should(gbytes.Say(`silk-daemon.poll-cycle.*renew lease: http status 500`))

		})

		It("polls for other leases and logs at debug level", func() {
			By("checking that the correct leases are logged")
			Eventually(session.Out, 2).Should(gbytes.Say(`level.*debug.*silk-daemon.converge-leases`))
			Eventually(session.Out, 2).Should(gbytes.Say(fmt.Sprintf(`underlay_ip.*%s.*overlay_subnet.*`+localOverlayLeaseSubnet+`.*overlay_hardware_addr.*ee:ee:0a:ff:1e:00`, localIP)))
			Eventually(session.Out, 2).Should(gbytes.Say(`underlay_ip.*172.17.0.5.*overlay_subnet.*` + remoteOverlaySubnet + `.*overlay_hardware_addr.*ee:ee:0a:ff:28:00`))
			Eventually(session.Out, 2).Should(gbytes.Say(`underlay_ip.*172.17.0.9.*overlay_subnet.*` + remoteOverlaySubnetOnSecondNetwork + `.*overlay_hardware_addr.*cc:cc:cc:cc:cc:cc`))
			Eventually(session.Out, 2).Should(gbytes.Say(`underlay_ip.*172.17.0.6.*overlay_subnet.*` + remoteSingleIPSubnet + `.*overlay_hardware_addr.*ee:ee:0a:ff:28:ff`))

			By("checking the arp fdb and routing are correct")
			routes := mustSucceed("ip", "route", "list", "dev", vtepName)
			routeFields := strings.Fields(routes)
			Expect(routeFields).To(matchers.ContainSequence([]string{"10.255.0.0/16", "proto", "kernel", "scope", "link", "src", localOverlayLeaseIP.String()}))
			Expect(routeFields).To(matchers.ContainSequence([]string{remoteOverlaySubnet, "via", remoteOverlayVtepIP.String(), "src", localOverlayLeaseIP.String()}))
			Expect(routeFields).To(matchers.ContainSequence([]string{remoteOverlaySubnetOnSecondNetwork, "via", remoteOverlayVtepIPOnSecondNetwork.String(), "src", overlayNetworks.Networks[1].IP.String()}))
			Expect(routeFields).NotTo(matchers.ContainSequence([]string{remoteSingleIP.String(), "via", remoteSingleIP.String()}))

			arpEntries := mustSucceed("ip", "neigh", "list", "dev", vtepName)
			Expect(arpEntries).To(ContainSubstring(remoteOverlayVtepIP.String() + " lladdr ee:ee:0a:ff:28:00 PERMANENT"))
			Expect(arpEntries).To(ContainSubstring(remoteOverlayVtepIPOnSecondNetwork.String() + " lladdr cc:cc:cc:cc:cc:cc PERMANENT"))
			Expect(arpEntries).To(ContainSubstring(remoteSingleIP.String() + " lladdr ee:ee:0a:ff:28:ff PERMANENT"))

			fdbEntries := mustSucceed("bridge", "fdb", "list", "dev", vtepName)
			Expect(fdbEntries).To(ContainSubstring("ee:ee:0a:ff:28:00 dst 172.17.0.5 self permanent"))
			Expect(fdbEntries).To(ContainSubstring("cc:cc:cc:cc:cc:cc dst 172.17.0.9 self permanent"))
			Expect(fdbEntries).To(ContainSubstring("ee:ee:0a:ff:28:ff dst 172.17.0.6 self permanent"))

			By("checking that it emits a metric for the number of leases it sees")
			Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(hasMetricWithValue("numberLeases", 4)))

			By("removing the leases from the controller")
			fakeServer.SetHandler("/leases", &testsupport.FakeHandler{
				ResponseCode: 200,
				ResponseBody: map[string][]controller.Lease{"leases": []controller.Lease{}}},
			)

			By("checking that the emitted number of leases has updated to zero")
			Eventually(fakeMetron.AllEvents, "5s").Should(ContainElement(hasMetricWithValue("numberLeases", 0)))

			By("checking that no leases are logged")
			Eventually(session.Out, 2).Should(gbytes.Say(`silk-daemon.converge-leases.*"leases":\[]`))
		})

		Context("when cells with overlay subnets are brought down", func() {
			It("polls and updates the leases accordingly", func() {
				By("checking that the correct leases are logged")
				Eventually(session.Out, 2).Should(gbytes.Say(`level.*debug.*silk-daemon.converge-leases`))
				Eventually(session.Out, 2).Should(gbytes.Say(fmt.Sprintf(`underlay_ip.*%s.*overlay_subnet.*`+localOverlayLeaseSubnet+`.*overlay_hardware_addr.*ee:ee:0a:ff:1e:00`, localIP)))
				Eventually(session.Out, 2).Should(gbytes.Say(`underlay_ip.*172.17.0.5.*overlay_subnet.*` + remoteOverlaySubnet + `.*overlay_hardware_addr.*ee:ee:0a:ff:28:00`))
				Eventually(session.Out, 2).Should(gbytes.Say(`underlay_ip.*172.17.0.9.*overlay_subnet.*` + remoteOverlaySubnetOnSecondNetwork + `.*overlay_hardware_addr.*cc:cc:cc:cc:cc:cc`))
				Eventually(session.Out, 2).Should(gbytes.Say(`underlay_ip.*172.17.0.6.*overlay_subnet.*` + remoteSingleIPSubnet + `.*overlay_hardware_addr.*ee:ee:0a:ff:28:ff`))

				By("checking the arp fdb and routing are correct")

				part1 := `"level":"debug","source":"potato-prefix.silk-daemon","message":"potato-prefix.silk-daemon.converge-leases","data":{`
				part2 := `"leases":[{"underlay_ip":"127.0.0.1","overlay_subnet":"` + localOverlayLeaseSubnet + `","overlay_hardware_addr":"ee:ee:0a:ff:1e:00"},`
				part3 := `{"underlay_ip":"172.17.0.5","overlay_subnet":"` + remoteOverlaySubnet + `","overlay_hardware_addr":"ee:ee:0a:ff:28:00"},`
				part4 := `{"underlay_ip":"172.17.0.6","overlay_subnet":"` + remoteSingleIPSubnet + `","overlay_hardware_addr":"ee:ee:0a:ff:28:ff"},`
				part5 := `{"underlay_ip":"172.17.0.9","overlay_subnet":"` + remoteOverlaySubnetOnSecondNetwork + `","overlay_hardware_addr":"cc:cc:cc:cc:cc:cc"}]}}`

				expectedConvergeLeaseLog := fmt.Sprintf("%s%s%s%s%s", part1, part2, part3, part4, part5)

				Eventually(string(session.Out.Contents()), "5s").Should(ContainSubstring(expectedConvergeLeaseLog))

				routes := mustSucceed("ip", "route", "list", "dev", vtepName)
				routeFields := strings.Fields(routes)
				Expect(routeFields).To(matchers.ContainSequence([]string{"10.255.0.0/16", "proto", "kernel", "scope", "link", "src", localOverlayLeaseIP.String()}))
				Expect(routeFields).To(matchers.ContainSequence([]string{remoteOverlaySubnet, "via", remoteOverlayVtepIP.String()}))
				Expect(routeFields).To(matchers.ContainSequence([]string{remoteOverlaySubnet, "via", remoteOverlayVtepIP.String()}))
				Expect(routeFields).NotTo(matchers.ContainSequence([]string{remoteSingleIPSubnet, "via", remoteSingleIP.String()}))
				Expect(routeFields).NotTo(matchers.ContainSequence([]string{remoteOverlaySubnetOnSecondNetwork, "via", remoteOverlayVtepIPOnSecondNetwork.String(), "src", localOverlayLeaseIP.String()}))
				Expect(routeFields).NotTo(matchers.ContainSequence([]string{remoteOverlaySubnetOnSecondNetwork, "via", remoteOverlayVtepIPOnSecondNetwork.String(), "src", localOverlayLeaseIP.String()}))

				arpEntries := mustSucceed("ip", "neigh", "list", "dev", vtepName)
				Expect(arpEntries).To(ContainSubstring(remoteOverlayVtepIP.String() + " lladdr ee:ee:0a:ff:28:00 PERMANENT"))
				Expect(arpEntries).To(ContainSubstring(remoteOverlayVtepIPOnSecondNetwork.String() + " lladdr cc:cc:cc:cc:cc:cc PERMANENT"))
				Expect(arpEntries).To(ContainSubstring(remoteSingleIP.String() + " lladdr ee:ee:0a:ff:28:ff PERMANENT"))

				fdbEntries := mustSucceed("bridge", "fdb", "list", "dev", vtepName)
				Expect(fdbEntries).To(ContainSubstring("ee:ee:0a:ff:28:00 dst 172.17.0.5 self permanent"))
				Expect(fdbEntries).To(ContainSubstring("cc:cc:cc:cc:cc:cc dst 172.17.0.9 self permanent"))
				Expect(fdbEntries).To(ContainSubstring("ee:ee:0a:ff:28:ff dst 172.17.0.6 self permanent"))

				By("simulating a cell shutdown by removing leases from the controller")
				fakeServer.SetHandler("/leases", &testsupport.FakeHandler{
					ResponseCode: 200,
					ResponseBody: map[string][]controller.Lease{"leases": []controller.Lease{
						{
							UnderlayIP:          localIP,
							OverlaySubnet:       localOverlayLeaseSubnet,
							OverlayHardwareAddr: "ee:ee:0a:ff:1e:00",
						},
					}}},
				)

				By("checking that updated leases are logged")
				Eventually(session.Out, 2).Should(gbytes.Say(`level.*debug.*silk-daemon.converge-leases`))
				Eventually(session.Out, 2).Should(gbytes.Say(fmt.Sprintf(`underlay_ip.*%s.*overlay_subnet.*`+localOverlayLeaseSubnet+`.*overlay_hardware_addr.*ee:ee:0a:ff:1e:00`, localIP)))
				Eventually(session.Out, 2).ShouldNot(gbytes.Say(`underlay_ip.*172.17.0.5.*overlay_subnet.*` + remoteOverlaySubnet + `.*overlay_hardware_addr.*ee:ee:0a:ff:28:00`))
				Eventually(session.Out, 2).ShouldNot(gbytes.Say(`underlay_ip.*172.17.0.9.*overlay_subnet.*` + remoteOverlaySubnetOnSecondNetwork + `.*overlay_hardware_addr.*cc:cc:cc:cc:cc:cc`))

				By("checking the arp fdb and routing are updated correctly")
				getRouteFields := func() []string {
					routes = mustSucceed("ip", "route", "list", "dev", vtepName)
					return strings.Fields(routes)
				}
				Eventually(getRouteFields).Should(matchers.ContainSequence([]string{"10.255.0.0/16", "proto", "kernel", "scope", "link", "src", localOverlayLeaseIP.String()}))
				Eventually(getRouteFields).ShouldNot(matchers.ContainSequence([]string{remoteOverlaySubnet, "via", remoteOverlayVtepIP.String()}))
				Expect(getRouteFields()).NotTo(matchers.ContainSequence([]string{remoteOverlaySubnetOnSecondNetwork, "via", remoteOverlayVtepIPOnSecondNetwork.String()}))

				arpEntries = mustSucceed("ip", "neigh", "list", "dev", vtepName)
				Expect(arpEntries).NotTo(ContainSubstring(remoteOverlayVtepIP.String() + " lladdr ee:ee:0a:ff:28:00 PERMANENT"))
				Expect(arpEntries).NotTo(ContainSubstring(remoteOverlayVtepIPOnSecondNetwork.String() + " lladdr cc:cc:cc:cc:cc:cc PERMANENT"))
				Expect(arpEntries).NotTo(ContainSubstring(remoteSingleIP.String() + " lladdr ee:ee:0a:ff:28:ff PERMANENT"))

				fdbEntries = mustSucceed("bridge", "fdb", "list", "dev", vtepName)
				Expect(fdbEntries).NotTo(ContainSubstring("ee:ee:0a:ff:28:00 dst 172.17.0.5 self permanent"))
				Expect(fdbEntries).NotTo(ContainSubstring("cc:cc:cc:cc:cc:cc dst 172.17.0.9 self permanent"))
				Expect(fdbEntries).NotTo(ContainSubstring("ee:ee:0a:ff:28:ff dst 172.17.0.6 self permanent"))
			})
		})

		Context("when the controller returns leases outside of my overlay network", func() {
			BeforeEach(func() {
				indexHandler := &testsupport.FakeHandler{
					ResponseCode: 200,
					ResponseBody: map[string][]controller.Lease{
						"leases": []controller.Lease{
							{ // in our overlay
								UnderlayIP:          localIP,
								OverlaySubnet:       localOverlayLeaseSubnet,
								OverlayHardwareAddr: "ee:ee:0a:ff:1e:00",
							},
							{ // not in our overlay
								UnderlayIP:          "172.17.0.4",
								OverlaySubnet:       "10.123.40.0/24",
								OverlayHardwareAddr: "ee:ee:0a:fe:28:00",
							},
							{ // in our overlay
								UnderlayIP:          "172.17.0.5",
								OverlaySubnet:       remoteOverlaySubnet,
								OverlayHardwareAddr: "ee:ee:0a:ff:28:00",
							},
							{ // in our overlay
								UnderlayIP:          "172.17.0.9",
								OverlaySubnet:       remoteOverlaySubnetOnSecondNetwork,
								OverlayHardwareAddr: "cc:cc:cc:cc:cc:cc",
							},
						},
					},
				}
				fakeServer.SetHandler("/leases", indexHandler)
			})

			It("only updates the leases inside the overlay network", func() {
				By("logging the number of leases we skipped")
				Eventually(session.Out, 2).Should(gbytes.Say(`level.*info.*silk-daemon.converger.*non-routable-lease-count.*1`))

				By("checking that the correct leases are logged")
				Eventually(session.Out, 2).Should(gbytes.Say(`level.*debug.*silk-daemon.converge-leases`))
				Eventually(session.Out, 2).Should(gbytes.Say(fmt.Sprintf(`underlay_ip.*%s.*overlay_subnet.*`+localOverlayLeaseSubnet+`.*overlay_hardware_addr.*ee:ee:0a:ff:1e:00`, localIP)))
				Eventually(session.Out, 2).Should(gbytes.Say(`underlay_ip.*172.17.0.5.*overlay_subnet.*` + remoteOverlaySubnet + `.*overlay_hardware_addr.*ee:ee:0a:ff:28:00`))
				Eventually(session.Out, 2).Should(gbytes.Say(`underlay_ip.*172.17.0.9.*overlay_subnet.*` + remoteOverlaySubnetOnSecondNetwork + `.*overlay_hardware_addr.*cc:cc:cc:cc:cc:cc`))

				part1 := `"level":"debug","source":"potato-prefix.silk-daemon","message":"potato-prefix.silk-daemon.converge-leases","data":{`
				part2 := `"leases":[{"underlay_ip":"127.0.0.1","overlay_subnet":"` + localOverlayLeaseSubnet + `","overlay_hardware_addr":"ee:ee:0a:ff:1e:00"},`
				part3 := `{"underlay_ip":"172.17.0.4","overlay_subnet":"10.123.40.0/24","overlay_hardware_addr":"ee:ee:0a:fe:28:00"},`
				part4 := `{"underlay_ip":"172.17.0.5","overlay_subnet":"` + remoteOverlaySubnet + `","overlay_hardware_addr":"ee:ee:0a:ff:28:00"},`
				part5 := `{"underlay_ip":"172.17.0.9","overlay_subnet":"` + remoteOverlaySubnetOnSecondNetwork + `","overlay_hardware_addr":"cc:cc:cc:cc:cc:cc"}]}}`
				expectedConvergeLeaseLog := fmt.Sprintf("%s%s%s%s%s", part1, part2, part3, part4, part5)

				Eventually(string(session.Out.Contents()), "5s").Should(ContainSubstring(expectedConvergeLeaseLog))

				By("checking the arp fdb and routing are correct")
				routes := mustSucceed("ip", "route", "list", "dev", vtepName)
				routeFields := strings.Fields(routes)
				Expect(routeFields).To(matchers.ContainSequence([]string{"10.255.0.0/16", "proto", "kernel", "scope", "link", "src", localOverlayLeaseIP.String()}))

				Expect(routeFields).To(matchers.ContainSequence([]string{remoteOverlaySubnet, "via", remoteOverlayVtepIP.String(), "src", localOverlayLeaseIP.String()}))
				Expect(routeFields).To(matchers.ContainSequence([]string{remoteOverlaySubnetOnSecondNetwork, "via", remoteOverlayVtepIPOnSecondNetwork.String(), "src", overlayNetworks.Networks[1].IP.String()}))

				arpEntries := mustSucceed("ip", "neigh", "list", "dev", vtepName)
				Expect(arpEntries).To(ContainSubstring(remoteOverlayVtepIP.String() + " lladdr ee:ee:0a:ff:28:00 PERMANENT"))
				Expect(arpEntries).To(ContainSubstring(remoteOverlayVtepIPOnSecondNetwork.String() + " lladdr cc:cc:cc:cc:cc:cc PERMANENT"))

				fdbEntries := mustSucceed("bridge", "fdb", "list", "dev", vtepName)
				Expect(fdbEntries).To(ContainSubstring("ee:ee:0a:ff:28:00 dst 172.17.0.5 self permanent"))
				Expect(fdbEntries).To(ContainSubstring("cc:cc:cc:cc:cc:cc dst 172.17.0.9 self permanent"))

				By("checking that routes do not exist for the nonroutable lease")
				Expect(routeFields).NotTo(matchers.ContainSequence([]string{"10.123.40.0/24", "via", "10.123.40.0"}))
				Expect(arpEntries).NotTo(ContainSubstring("10.123.40.0 lladdr ee:ee:0a:fe:28:00 PERMANENT"))
				Expect(fdbEntries).NotTo(ContainSubstring("ee:ee:0a:fe:28:00 dst 172.17.0.4 self permanent"))
			})
		})
	})

	Context("when a local lease is discovered but it cannot be renewed", func() {
		BeforeEach(func() {
			stopDaemon()

			fakeServer.SetHandler("/leases/renew", &testsupport.FakeHandler{
				ResponseCode: 404,
				ResponseBody: map[string]interface{}{},
			})
		})

		Context("when no containers are running", func() {
			It("logs an error message, acquires a new lease and stays alive", func() {
				startAndWaitForDaemon()
				Expect(session.Out).To(gbytes.Say(`renew-lease.*"error":"http status 404: "`))
				Expect(session.Out).To(gbytes.Say(`acquired-lease.*`))
				Consistently(session, "4s").ShouldNot(gexec.Exit())
			})

			Context("when renew returns a 500", func() {
				BeforeEach(func() {
					fakeServer.SetHandler("/leases/renew", &testsupport.FakeHandler{
						ResponseCode: 500,
						ResponseBody: struct{}{},
					})
				})

				It("logs the error message and stays alive", func() {
					startAndWaitForDaemon()
					Expect(session.Out).To(gbytes.Say(`renew-lease.*"error":"http status 500: "`))
					Consistently(session, "4s").ShouldNot(gexec.Exit())
				})
			})

			Context("when renew returns a 409 Conflict", func() {
				BeforeEach(func() {
					fakeServer.SetHandler("/leases/renew", &testsupport.FakeHandler{
						ResponseCode: 409,
						ResponseBody: map[string]string{"error": "lease mismatch"},
					})
				})

				It("logs the error and dies", func() {
					session = startDaemon(writeConfigFile(daemonConf))
					// startAndWaitForDaemon()
					Eventually(session.Out).Should(gbytes.Say(`renew-lease.*"error":"non-retriable: lease mismatch"`))

					Eventually(session, "10s").Should(gexec.Exit(1))
				})
			})
		})
	})

	Context("when the discovered lease is not in the overlay network", func() {
		BeforeEach(func() {
			stopDaemon()
			daemonConf.OverlayNetworks = []string{"10.254.0.0/16"}
		})

		Context("when no containers are running", func() {
			It("logs an error message and acquires a new lease", func() {
				acquireHandler := &testsupport.FakeHandler{
					ResponseCode: 200,
					ResponseBody: &controller.Lease{
						UnderlayIP:          localIP,
						OverlaySubnet:       "10.254.10.0/24",
						OverlayHardwareAddr: "ee:ee:0a:ff:1e:00",
					},
				}
				fakeServer.SetHandler("/leases/acquire", acquireHandler)
				startAndWaitForDaemon()
				Expect(session.Out).To(gbytes.Say(`network-contains-lease.*"error":"discovered lease is not in overlay network"`))
				Expect(session.Out).To(gbytes.Say(`acquired-lease.*`))
			})
		})
	})
})

func startAndWaitForDaemon() {
	session = startDaemon(writeConfigFile(daemonConf))

	By("waiting until the daemon is healthy before tests")
	callHealthcheck := func() (int, error) {
		resp, err := http.Get(daemonHealthCheckURL)
		if resp == nil {
			return -1, err
		}
		return resp.StatusCode, nil
	}
	Eventually(callHealthcheck, time.Minute, time.Second).Should(Equal(http.StatusOK))
}

func doHealthCheck() {
	Expect(doHealthCheckWithErr()).To(Succeed())
}

func doHealthCheckWithErr() error {
	resp, err := http.Get(daemonHealthCheckURL)
	if err != nil {
		return err
	}
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var response daemon.NetworkInfo
	err = json.Unmarshal(responseBytes, &response)
	if err != nil {
		return err
	}
	if response.OverlaySubnet != daemonLease.OverlaySubnet {
		return fmt.Errorf("mismatched overlay subnet: %s vs %s", response.OverlaySubnet, daemonLease.OverlaySubnet)
	}
	const vxlanEncapOverhead = 50 // bytes
	Expect(response.MTU).To(Equal(externalMTU - vxlanEncapOverhead))
	if response.MTU != externalMTU-vxlanEncapOverhead {
		return fmt.Errorf("mismatched mtu: %d vs %d", response.MTU, externalMTU-vxlanEncapOverhead)
	}
	return nil
}

func writeConfigFile(config config.Config) string {
	configFile, err := os.CreateTemp("", "test-config")
	Expect(err).NotTo(HaveOccurred())

	configBytes, err := json.Marshal(config)
	Expect(err).NotTo(HaveOccurred())

	err = os.WriteFile(configFile.Name(), configBytes, os.ModePerm)
	Expect(err).NotTo(HaveOccurred())

	return configFile.Name()
}

func startDaemon(configFilePath string) *gexec.Session {
	startCmd := exec.Command(paths.DaemonBin, "--config", configFilePath)
	s, err := gexec.Start(startCmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	session = s
	return s
}

func stopDaemon() {
	session.Interrupt()
	Eventually(session, DEFAULT_TIMEOUT).Should(gexec.Exit())
}

func locateInterface(toFind net.IP) (net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return net.Interface{}, err
		}

		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				return net.Interface{}, err
			}
			if ip.String() == toFind.String() {
				return iface, nil
			}
		}
	}

	return net.Interface{}, fmt.Errorf("no interface with address %s", toFind.String())
}

func mustSucceed(binary string, args ...string) string {
	cmd := exec.Command(binary, args...)
	sess, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, "10s").Should(gexec.Exit(0))
	return string(sess.Out.Contents())
}

func setLogLevel(level string, port int) {
	serverAddress := fmt.Sprintf("localhost:%d/log-level", port)
	curlCmd := exec.Command("curl", serverAddress, "-X", "POST", "-d", level)
	Expect(curlCmd.Start()).To(Succeed())
	Expect(curlCmd.Wait()).To(Succeed())
}
