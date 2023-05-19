package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"

	"code.cloudfoundry.org/cni-wrapper-plugin/adapter"
	"code.cloudfoundry.org/cni-wrapper-plugin/lib"
	"code.cloudfoundry.org/cni-wrapper-plugin/netrules"
	"code.cloudfoundry.org/lib/datastore"
	"code.cloudfoundry.org/lib/interfacelookup"
	"code.cloudfoundry.org/lib/rules"
	"code.cloudfoundry.org/lib/serial"

	"io/ioutil"
	"net/http"

	"os/user"
	"strconv"

	"code.cloudfoundry.org/filelock"
	"github.com/containernetworking/cni/pkg/skel"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/coreos/go-iptables/iptables"
)

func cmdAdd(args *skel.CmdArgs) error {
	cfg, err := lib.LoadWrapperConfig(args.StdinData)
	if err != nil {
		return err
	}

	pluginController, err := newPluginController(cfg)
	if err != nil {
		return err
	}

	result, err := pluginController.DelegateAdd(cfg.Delegate)
	if err != nil {
		return fmt.Errorf("delegate call: %s", err)
	}

	resultActual, err := current.GetResult(result)
	if err != nil {
		return fmt.Errorf("converting result from delegate plugin: %s", err) // not tested
	}

	containerIP := resultActual.IPs[0].Address.IP
	var containerWorkload string

	// Add container metadata info
	store := &datastore.Store{
		Serializer: &serial.Serial{},
		Locker: &filelock.Locker{
			FileLocker: filelock.NewLocker(cfg.Datastore + "_lock"),
			Mutex:      new(sync.Mutex),
		},
		DataFilePath:    cfg.Datastore,
		VersionFilePath: cfg.Datastore + "_version",
		LockedFilePath:  cfg.Datastore + "_lock",
		FileOwner:       cfg.DatastoreFileOwner,
		FileGroup:       cfg.DatastoreFileGroup,
		CacheMutex:      new(sync.RWMutex),
	}

	var cniAddData struct {
		Metadata map[string]interface{}
	}
	if err := json.Unmarshal(args.StdinData, &cniAddData); err != nil {
		return err // not tested, this should be impossible
	}
	if workload, present := cniAddData.Metadata["container_workload"]; present {
		containerWorkload, _ = workload.(string)
	}

	if err := store.Add(args.ContainerID, containerIP.String(), cniAddData.Metadata); err != nil {
		storeErr := fmt.Errorf("store add: %s", err)
		fmt.Fprintf(os.Stderr, "%s", storeErr)
		fmt.Fprint(os.Stderr, "cleaning up from error")
		err = pluginController.DelIPMasq(containerIP.String(), cfg.NoMasqueradeCIDRRange, cfg.VTEPName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "during cleanup: removing IP masq: %s", err)
		}

		return storeErr
	}

	resp, err := http.DefaultClient.Get(fmt.Sprintf("http://%s/force-policy-poll-cycle", cfg.PolicyAgentForcePollAddress))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		return fmt.Errorf("vpa response code: %v with message: %s", resp.StatusCode, body)
	}

	localDNSServers, err := getLocalDNSServers(cfg.DNSServers)
	if err != nil {
		return err
	}

	interfaceNameLookup := interfacelookup.InterfaceNameLookup{
		NetlinkAdapter: &adapter.NetlinkAdapter{},
	}

	var interfaceNames []string
	if len(cfg.TemporaryUnderlayInterfaceNames) > 0 {
		interfaceNames = cfg.TemporaryUnderlayInterfaceNames
	} else {
		interfaceNames, err = interfaceNameLookup.GetNamesFromIPs(cfg.UnderlayIPs)
		if err != nil {
			return fmt.Errorf("looking up interface names: %s", err) // not tested
		}
	}

	if args.ContainerID == "" {
		return fmt.Errorf("invalid Container ID")
	}

	chainNamer := &netrules.ChainNamer{
		MaxLength: 28,
	}
	outConn := netrules.OutConn{
		Limit:      cfg.OutConn.Limit,
		Logging:    cfg.OutConn.Logging,
		Burst:      cfg.OutConn.Burst,
		RatePerSec: cfg.OutConn.RatePerSec,
		DryRun:     cfg.OutConn.DryRun,
	}

	netOutChain := &netrules.NetOutChain{
		ChainNamer:       chainNamer,
		Converter:        &netrules.RuleConverter{LogWriter: os.Stderr},
		ASGLogging:       cfg.IPTablesASGLogging,
		DeniedLogsPerSec: cfg.IPTablesDeniedLogsPerSec,
		DenyNetworks: netrules.DenyNetworks{
			Always:  cfg.DenyNetworks.Always,
			Running: cfg.DenyNetworks.Running,
			Staging: cfg.DenyNetworks.Staging,
		},
		Conn: outConn,
	}

	netOutProvider := netrules.NetOut{
		ChainNamer:            chainNamer,
		IPTables:              pluginController.IPTables,
		NetOutChain:           netOutChain,
		C2CLogging:            cfg.IPTablesC2CLogging,
		DeniedLogsPerSec:      cfg.IPTablesDeniedLogsPerSec,
		AcceptedUDPLogsPerSec: cfg.IPTablesAcceptedUDPLogsPerSec,
		IngressTag:            cfg.IngressTag,
		VTEPName:              cfg.VTEPName,
		HostInterfaceNames:    interfaceNames,
		ContainerHandle:       args.ContainerID,
		ContainerWorkload:     containerWorkload,
		ContainerIP:           containerIP.String(),
		HostTCPServices:       cfg.HostTCPServices,
		HostUDPServices:       cfg.HostUDPServices,
		DNSServers:            localDNSServers,
		Conn:                  outConn,
	}
	if err := netOutProvider.Initialize(); err != nil {
		return fmt.Errorf("initialize net out: %s", err)
	}

	netinProvider := netrules.NetIn{
		ChainNamer: &netrules.ChainNamer{
			MaxLength: 28,
		},
		IPTables:           pluginController.IPTables,
		IngressTag:         cfg.IngressTag,
		HostInterfaceNames: interfaceNames,
	}
	err = netinProvider.Initialize(args.ContainerID)
	if err != nil {
		return fmt.Errorf("initializing net in: %s", err)
	}

	portMappings := cfg.RuntimeConfig.PortMappings
	for _, netIn := range portMappings {
		if netIn.HostPort <= 0 {
			return fmt.Errorf("cannot allocate port %d", netIn.HostPort)
		}
		if err := netinProvider.AddRule(args.ContainerID, int(netIn.HostPort), int(netIn.ContainerPort), cfg.InstanceAddress, containerIP.String()); err != nil {
			return fmt.Errorf("adding netin rule: %s", err)
		}
	}

	resp, err = http.DefaultClient.Get(fmt.Sprintf("http://%s/force-asgs-for-container?container=%s", cfg.PolicyAgentForcePollAddress, args.ContainerID))
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusMethodNotAllowed {
		netOutRules := cfg.RuntimeConfig.NetOutRules
		if err := netOutProvider.BulkInsertRules(netrules.NewRulesFromGardenNetOutRules(netOutRules)); err != nil {
			return fmt.Errorf("bulk insert: %s", err) // not tested
		}
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusMethodNotAllowed {
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		return fmt.Errorf("asg sync returned %v with message: %s", resp.StatusCode, body)
	}

	err = pluginController.AddIPMasq(containerIP.String(), cfg.NoMasqueradeCIDRRange, cfg.VTEPName)
	if err != nil {
		return fmt.Errorf("error setting up default ip masq rule: %s", err)
	}

	resultActual.DNS.Nameservers = cfg.DNSServers

	resultVersioned, err := resultActual.GetAsVersion(cfg.CNIVersion)
	if err != nil {
		return fmt.Errorf("converting to CNI version %s: %s", cfg.CNIVersion, err)
	}
	return resultVersioned.Print()
}

func cmdCheck(args *skel.CmdArgs) error {
	return fmt.Errorf("Meow this isn't implemented yet")
}

func getLocalDNSServers(allDNSServers []string) ([]string, error) {
	var localDNSServers []string
	for _, entry := range allDNSServers {
		dnsIP := net.ParseIP(entry)
		if dnsIP == nil {
			return nil, fmt.Errorf(`invalid DNS server "%s", must be valid IP address`, entry)
		} else if dnsIP.IsLinkLocalUnicast() {
			localDNSServers = append(localDNSServers, entry)
		}
	}
	return localDNSServers, nil
}

func cmdDel(args *skel.CmdArgs) error {
	cfg, err := lib.LoadWrapperConfig(args.StdinData)
	if err != nil {
		return err
	}

	store := &datastore.Store{
		Serializer: &serial.Serial{},
		Locker: &filelock.Locker{
			FileLocker: filelock.NewLocker(cfg.Datastore + "_lock"),
			Mutex:      new(sync.Mutex),
		},
		DataFilePath:    cfg.Datastore,
		VersionFilePath: cfg.Datastore + "_version",
		CacheMutex:      new(sync.RWMutex),
	}

	container, err := store.Delete(args.ContainerID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store delete: %s", err)
	}

	pluginController, err := newPluginController(cfg)
	if err != nil {
		return err
	}

	if err := pluginController.DelegateDel(cfg.Delegate); err != nil {
		fmt.Fprintf(os.Stderr, "delegate delete: %s", err)
	}

	netInProvider := netrules.NetIn{
		ChainNamer: &netrules.ChainNamer{
			MaxLength: 28,
		},
		IPTables:   pluginController.IPTables,
		IngressTag: cfg.IngressTag,
	}

	if err = netInProvider.Cleanup(args.ContainerID); err != nil {
		fmt.Fprintf(os.Stderr, "net in cleanup: %s", err)
	}

	interfaceNameLookup := interfacelookup.InterfaceNameLookup{
		NetlinkAdapter: &adapter.NetlinkAdapter{},
	}

	var interfaceNames []string
	if len(cfg.TemporaryUnderlayInterfaceNames) > 0 {
		interfaceNames = cfg.TemporaryUnderlayInterfaceNames
	} else {
		interfaceNames, err = interfaceNameLookup.GetNamesFromIPs(cfg.UnderlayIPs)
		if err != nil {
			return fmt.Errorf("looking up interface names: %s", err) // not tested
		}
	}

	chainNamer := &netrules.ChainNamer{
		MaxLength: 28,
	}
	outConn := netrules.OutConn{
		Limit:   cfg.OutConn.Limit,
		Logging: cfg.OutConn.Logging,
		DryRun:  cfg.OutConn.DryRun,
	}

	netOutChain := &netrules.NetOutChain{
		ChainNamer: chainNamer,
		Converter:  &netrules.RuleConverter{LogWriter: os.Stderr},
		Conn:       outConn,
	}

	netOutProvider := netrules.NetOut{
		ChainNamer:         chainNamer,
		NetOutChain:        netOutChain,
		IPTables:           pluginController.IPTables,
		ContainerHandle:    args.ContainerID,
		ContainerIP:        container.IP,
		HostInterfaceNames: interfaceNames,
		Conn:               outConn,
	}

	if err = netOutProvider.Cleanup(); err != nil {
		fmt.Fprintf(os.Stderr, "net out cleanup: %s", err)
	}

	err = pluginController.DelIPMasq(container.IP, cfg.NoMasqueradeCIDRRange, cfg.VTEPName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "removing IP masq: %s", err)
	}

	resp, err := http.DefaultClient.Get(fmt.Sprintf("http://%s/force-orphaned-asgs-cleanup?container=%s", cfg.PolicyAgentForcePollAddress, args.ContainerID))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusMethodNotAllowed {
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		return fmt.Errorf("asg cleanup returned %v with message: %s", resp.StatusCode, body)
	}

	return nil
}

func ensureIptablesFileOwnership(filePath, fileOwner, fileGroup string) error {
	err := ioutil.WriteFile(filePath, make([]byte, 0), 0600)
	if err != nil {
		return err
	}

	if fileOwner == "" || fileGroup == "" {
		return nil
	}
	uid, gid, err := lookupFileOwnerUIDandGID(fileOwner, fileGroup)
	if err != nil {
		return err
	}

	err = os.Chown(filePath, uid, gid)
	if err != nil {
		return err
	}

	return nil
}

func lookupFileOwnerUIDandGID(fileOwner, fileGroup string) (int, int, error) {
	fileOwnerUser, err := user.Lookup(fileOwner)
	if err != nil {
		return 0, 0, err
	}

	fileOwnerGroup, err := user.LookupGroup(fileGroup)
	if err != nil {
		return 0, 0, err
	}

	uid, err := strconv.Atoi(fileOwnerUser.Uid)
	if err != nil {
		return 0, 0, err
	}

	gid, err := strconv.Atoi(fileOwnerGroup.Gid)
	if err != nil {
		return 0, 0, err
	}

	return uid, gid, nil
}

func newPluginController(config *lib.WrapperConfig) (*lib.PluginController, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}

	err = ensureIptablesFileOwnership(config.IPTablesLockFile, config.DatastoreFileOwner, config.DatastoreFileGroup)
	if err != nil {
		return nil, err
	}

	iptLocker := &filelock.Locker{
		FileLocker: filelock.NewLocker(config.IPTablesLockFile),
		Mutex:      &sync.Mutex{},
	}
	restorer := &rules.Restorer{}
	lockedIPTables := &rules.LockedIPTables{
		IPTables: ipt,
		Locker:   iptLocker,
		Restorer: restorer,
	}

	pluginController := &lib.PluginController{
		Delegator: lib.NewDelegator(),
		IPTables:  lockedIPTables,
	}
	return pluginController, nil
}

func main() {
	supportedVersions := []string{"1.0.0"}

	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.PluginSupports(supportedVersions...), "CNI Plugin silk-cni-wrapper-plugin")
}
