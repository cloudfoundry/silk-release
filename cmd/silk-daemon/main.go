package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"code.cloudfoundry.org/debugserver"
	"code.cloudfoundry.org/go-db-helpers/mutualtls"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/silk/client/config"
	"code.cloudfoundry.org/silk/controller"
	"code.cloudfoundry.org/silk/daemon/planner"
	"code.cloudfoundry.org/silk/daemon/poller"
	"code.cloudfoundry.org/silk/daemon/vtep"
	"code.cloudfoundry.org/silk/lib/adapter"
	"code.cloudfoundry.org/silk/lib/datastore"
	"code.cloudfoundry.org/silk/lib/filelock"
	"code.cloudfoundry.org/silk/lib/serial"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/grouper"
	"github.com/tedsuo/ifrit/http_server"
	"github.com/tedsuo/ifrit/sigmon"
)

func main() {
	if err := mainWithError(); err != nil {
		log.Fatalf("silk-daemon error: %s", err)
	}
}

func mainWithError() error {
	logger := lager.NewLogger("silk-daemon")
	reconfigurableSink := lager.NewReconfigurableSink(
		lager.NewWriterSink(os.Stdout, lager.DEBUG),
		lager.INFO)
	logger.RegisterSink(reconfigurableSink)
	logger.Info("starting")

	configFilePath := flag.String("config", "", "path to config file")
	flag.Parse()

	cfg, err := config.LoadConfig(*configFilePath)
	if err != nil {
		return fmt.Errorf("load config file: %s", err)
	}

	tlsConfig, err := mutualtls.NewClientTLSConfig(cfg.ClientCertFile, cfg.ClientKeyFile, cfg.ServerCACertFile)
	if err != nil {
		return fmt.Errorf("create tls config: %s", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	vtepFactory := &vtep.Factory{
		NetlinkAdapter: &adapter.NetlinkAdapter{},
	}
	vtepConfigCreator := &vtep.ConfigCreator{
		NetAdapter: &adapter.NetAdapter{},
	}

	client := controller.NewClient(logger, httpClient, cfg.ConnectivityServerURL)

	store := &datastore.Store{
		Serializer: &serial.Serial{},
		Locker:     &filelock.Locker{},
	}

	lease, err := discoverLocalLease(cfg)
	if err != nil {
		lease, err = acquireLease(logger, client, vtepConfigCreator, vtepFactory, cfg)
		if err != nil {
			return err
		}
	} else {
		err = client.RenewSubnetLease(lease)
		if err != nil {
			logger.Error("renew-lease", err, lager.Data{"lease": lease})

			metadata, err := store.ReadAll(cfg.Datastore)
			if err != nil {
				return fmt.Errorf("read datastore: %s", err)
			}

			if len(metadata) != 0 {
				return fmt.Errorf("renew subnet lease with containers: %d", len(metadata))
			} else {
				err := vtepFactory.DeleteVTEP(cfg.VTEPName)
				if err != nil {
					return fmt.Errorf("delete vtep: %s", err) // not tested, should be impossible
				}
				lease, err = acquireLease(logger, client, vtepConfigCreator, vtepFactory, cfg)
				if err != nil {
					return err
				}
			}
		}
		logger.Info("renewed-lease", lager.Data{"lease": lease})
	}

	debugServerAddress := fmt.Sprintf("127.0.0.1:%d", cfg.DebugServerPort)
	healthCheckServer, err := buildHealthCheckServer(cfg.HealthCheckPort, lease)
	if err != nil {
		return fmt.Errorf("create health check server: %s", err) // not tested
	}

	_, localSubnet, err := net.ParseCIDR(lease.OverlaySubnet)
	if err != nil {
		log.Fatalf("parse local subnet CIDR") //TODO add test coverage
	}

	vxlanIface, err := net.InterfaceByName(cfg.VTEPName)
	if err != nil || vxlanIface == nil {
		log.Fatalf("find local VTEP") //TODO add test coverage
	}

	vxlanPoller := &poller.Poller{
		Logger:       logger,
		PollInterval: time.Duration(cfg.PollInterval) * time.Second,
		SingleCycleFunc: (&planner.VXLANPlanner{
			Logger:           logger,
			ControllerClient: client,
			Converger: &vtep.Converger{
				LocalSubnet:    localSubnet,
				LocalVTEP:      *vxlanIface,
				NetlinkAdapter: &adapter.NetlinkAdapter{},
			},
		}).DoCycle,
	}

	members := grouper.Members{
		{"server", healthCheckServer},
		{"vxlan_poller", vxlanPoller},
		{"debug-server", debugserver.Runner(debugServerAddress, reconfigurableSink)},
	}
	group := grouper.NewOrdered(os.Interrupt, members)
	monitor := ifrit.Invoke(sigmon.New(group))

	err = <-monitor.Wait()
	return err
}

func acquireLease(logger lager.Logger, client *controller.Client, vtepConfigCreator *vtep.ConfigCreator, vtepFactory *vtep.Factory, cfg config.Config) (controller.Lease, error) {
	lease, err := client.AcquireSubnetLease(cfg.UnderlayIP)
	if err != nil {
		return controller.Lease{}, fmt.Errorf("acquire subnet lease: %s", err)
	}
	logger.Info("acquired-lease", lager.Data{"lease": lease})

	if cfg.HealthCheckPort == 0 {
		return controller.Lease{}, fmt.Errorf("invalid health check port: %d", cfg.HealthCheckPort)
	}

	vtepConf, err := vtepConfigCreator.Create(cfg, lease)
	if err != nil {
		return controller.Lease{}, fmt.Errorf("create vtep config: %s", err) // not tested
	}

	err = vtepFactory.CreateVTEP(vtepConf)
	if err != nil {
		return controller.Lease{}, fmt.Errorf("create vtep: %s", err) // not tested
	}

	return lease, nil
}

func buildHealthCheckServer(healthCheckPort uint16, lease controller.Lease) (ifrit.Runner, error) {
	leaseBytes, err := json.Marshal(lease)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling lease: %s", err) // not possible
	}

	return http_server.New(
		fmt.Sprintf("127.0.0.1:%d", healthCheckPort),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(leaseBytes)
		}),
	), nil
}

func discoverLocalLease(clientConfig config.Config) (controller.Lease, error) {
	vtepFactory := &vtep.Factory{
		NetlinkAdapter: &adapter.NetlinkAdapter{},
	}
	overlayHwAddr, overlayIP, err := vtepFactory.GetVTEPState(clientConfig.VTEPName)
	if err != nil {
		return controller.Lease{}, fmt.Errorf("get vtep overlay ip: %s", err)
	}
	overlaySubnet := &net.IPNet{
		IP:   overlayIP,
		Mask: net.CIDRMask(clientConfig.SubnetPrefixLength, 32),
	}
	return controller.Lease{
		UnderlayIP:          clientConfig.UnderlayIP,
		OverlaySubnet:       overlaySubnet.String(),
		OverlayHardwareAddr: overlayHwAddr.String(),
	}, nil
}