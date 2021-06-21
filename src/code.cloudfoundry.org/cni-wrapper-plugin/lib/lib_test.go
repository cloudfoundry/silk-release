package lib_test

import (
	"encoding/json"
	"fmt"
	"net"

	"code.cloudfoundry.org/cni-wrapper-plugin/fakes"
	"code.cloudfoundry.org/cni-wrapper-plugin/lib"
	lib_fakes "code.cloudfoundry.org/lib/fakes"
	"code.cloudfoundry.org/lib/rules"

	"github.com/containernetworking/cni/pkg/types"
	types020 "github.com/containernetworking/cni/pkg/types/020"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("LoadWrapperConfig", func() {
	var input []byte
	BeforeEach(func() {
		input = []byte(`{
			"datastore": "/some/path",
			"datastore_file_owner": "vcap",
			"datastore_file_group": "vcap",
			"iptables_lock_file": "/some/other/path",
			"health_check_url": "http://127.0.0.1:10007",
			"instance_address": "10.244.20.1",
			"no_masquerade_cidr_range": "10.255.0.0/16",
			"underlay_ips": ["10.244.20.1", "10.244.20.2"],
			"temporary_underlay_interface_names": ["some-temporary-underlay-interface-name"],
			"iptables_asg_logging": true,
			"ingress_tag": "ffaa0000",
			"vtep_name": "some-device",
			"delegate": {
				"some": "info"
			},
			"iptables_denied_logs_per_sec": 2,
			"iptables_accepted_udp_logs_per_sec": 4,
			"outbound_connections": {
				"limit": true,
				"logging": true,
				"burst": 900,
				"rate_per_sec": 100
			}
		}`)
	})

	It("should parse it", func() {
		result, err := lib.LoadWrapperConfig(input)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(&lib.WrapperConfig{
			Datastore:                       "/some/path",
			DatastoreFileOwner:              "vcap",
			DatastoreFileGroup:              "vcap",
			IPTablesLockFile:                "/some/other/path",
			InstanceAddress:                 "10.244.20.1",
			NoMasqueradeCIDRRange:           "10.255.0.0/16",
			UnderlayIPs:                     []string{"10.244.20.1", "10.244.20.2"},
			TemporaryUnderlayInterfaceNames: []string{"some-temporary-underlay-interface-name"},
			IPTablesASGLogging:              true,
			Delegate: map[string]interface{}{
				"cniVersion": "0.3.1",
				"some":       "info",
			},
			IngressTag:                    "ffaa0000",
			VTEPName:                      "some-device",
			IPTablesDeniedLogsPerSec:      2,
			IPTablesAcceptedUDPLogsPerSec: 4,
			OutConn: lib.OutConnConfig{
				Limit:      true,
				Logging:    true,
				Burst:      900,
				RatePerSec: 100,
			},
		}))
	})

	Context("When the stdin is not a valid json", func() {
		BeforeEach(func() {
			input = []byte("}{")
		})

		It("should return a useful error", func() {
			_, err := lib.LoadWrapperConfig(input)
			Expect(err).To(MatchError(HavePrefix("loading wrapper config: ")))
		})
	})

	Describe("delegate cniVersion", func() {
		Context("when the input JSON doesn't have an explicit version on the delgate", func() {
			BeforeEach(func() {
				var inputData map[string]interface{}
				Expect(json.Unmarshal(input, &inputData)).To(Succeed())
				inputData["delegate"] = map[string]string{"some": "info"}
				input, _ = json.Marshal(inputData)
			})
			It("should set the version", func() {
				conf, err := lib.LoadWrapperConfig(input)
				Expect(err).NotTo(HaveOccurred())
				Expect(conf.Delegate).To(HaveKeyWithValue("cniVersion", "0.3.1"))
			})
		})

		Context("when the input JSON does set an explicit version on the delegate", func() {
			BeforeEach(func() {
				var inputData map[string]interface{}
				Expect(json.Unmarshal(input, &inputData)).To(Succeed())
				inputData["delegate"] = map[string]string{
					"cniVersion": "0.99.1",
					"some":       "info",
				}
				input, _ = json.Marshal(inputData)
			})
			It("should set the version", func() {
				conf, err := lib.LoadWrapperConfig(input)
				Expect(err).NotTo(HaveOccurred())
				Expect(conf.Delegate).To(HaveKeyWithValue("cniVersion", "0.99.1"))
			})
		})
	})

	DescribeTable("missing required field", func(field, errMessage string) {
		var config map[string]interface{}
		Expect(json.Unmarshal(input, &config)).To(Succeed())
		delete(config, field)

		var err error
		input, err = json.Marshal(config)
		Expect(err).NotTo(HaveOccurred())
		_, err = lib.LoadWrapperConfig(input)
		Expect(err).To(MatchError(errMessage))
	},
		Entry("datastore", "datastore", "missing datastore path"),
		Entry("ip tables lock file", "iptables_lock_file", "missing iptables lock file path"),
		Entry("underlay ips", "underlay_ips", "missing underlay ips"),
		Entry("instance address", "instance_address", "missing instance address"),
		Entry("ingress tag", "ingress_tag", "missing ingress tag"),
		Entry("vtep device name", "vtep_name", "missing vtep device name"),
		Entry("denied logs per sec", "iptables_denied_logs_per_sec", "invalid denied logs per sec"),
		Entry("accepted udp logs per sec", "iptables_accepted_udp_logs_per_sec", "invalid accepted udp logs per sec"),
	)

	DescribeTable("invalid value for field", func(field string, value interface{}, errMessage string) {
		var config map[string]interface{}
		Expect(json.Unmarshal(input, &config)).To(Succeed())
		config[field] = value

		var err error
		input, err = json.Marshal(config)
		Expect(err).NotTo(HaveOccurred())
		_, err = lib.LoadWrapperConfig(input)
		Expect(err).To(MatchError(errMessage))
	},
		Entry("denied logs per sec", "iptables_denied_logs_per_sec", -1, "invalid denied logs per sec"),
		Entry("accepted udp logs per sec", "iptables_accepted_udp_logs_per_sec", -1, "invalid accepted udp logs per sec"),
		Entry("out conn burst", "outbound_connections", map[string]interface{}{"burst": -1}, "invalid outbound connection burst"),
		Entry("out conn rate", "outbound_connections", map[string]interface{}{"burst": 1, "rate_per_sec": -1}, "invalid outbound connection rate"),
	)
})

var _ = Describe("DelegateAdd", func() {
	var (
		input            map[string]interface{}
		pluginController *lib.PluginController
		fakeDelegator    *fakes.Delegator
		expectedResult   types.Result
	)

	BeforeEach(func() {
		_, expectedIPNet, _ := net.ParseCIDR("1.2.3.4/32")
		expectedResult = &types020.Result{
			IP4: &types020.IPConfig{
				IP: *expectedIPNet,
			},
		}
		fakeDelegator = &fakes.Delegator{}
		fakeDelegator.DelegateAddReturns(expectedResult, nil)
		pluginController = &lib.PluginController{
			Delegator: fakeDelegator,
		}

		input = map[string]interface{}{
			"type": "something",
		}
	})

	It("should call the plugin specified by the type", func() {
		result, err := pluginController.DelegateAdd(input)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(expectedResult))
	})

	Context("when the input cannot be serialized into json", func() {
		BeforeEach(func() {
			input = map[string]interface{}{
				"bad-data": make(chan bool),
			}
		})

		It("should return a useful error", func() {
			_, err := pluginController.DelegateAdd(input)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(HavePrefix("serializing delegate netconf:")))
		})
	})

	Context("when the delegator returns an error", func() {
		BeforeEach(func() {
			fakeDelegator.DelegateAddReturns(nil, fmt.Errorf("patato"))
		})

		It("should return a useful error", func() {
			_, err := pluginController.DelegateAdd(input)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("patato"))
		})
	})

	Context("when the input type is missing", func() {
		BeforeEach(func() {
			input = map[string]interface{}{
				"notype": "shoudbemissing",
			}

		})

		It("should return a useful error", func() {
			_, err := pluginController.DelegateAdd(input)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("delegate config is missing type"))
		})
	})
})

var _ = Describe("DelegateDel", func() {
	var (
		input            map[string]interface{}
		pluginController *lib.PluginController
		fakeDelegator    *fakes.Delegator
	)

	BeforeEach(func() {
		fakeDelegator = &fakes.Delegator{}
		fakeDelegator.DelegateDelReturns(nil)
		pluginController = &lib.PluginController{
			Delegator: fakeDelegator,
		}

		input = map[string]interface{}{
			"type": "something",
		}
	})

	It("should call the plugin specified by the type", func() {
		err := pluginController.DelegateDel(input)
		Expect(err).NotTo(HaveOccurred())
	})

	Context("when the input cannot be serialized into json", func() {
		BeforeEach(func() {
			input = map[string]interface{}{
				"bad-data": make(chan bool),
			}
		})

		It("should return a useful error", func() {
			err := pluginController.DelegateDel(input)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(HavePrefix("serializing delegate netconf:")))
		})
	})

	Context("when the delegator returns an error", func() {
		BeforeEach(func() {
			fakeDelegator.DelegateDelReturns(fmt.Errorf("patato"))
		})

		It("should return a useful error", func() {
			err := pluginController.DelegateDel(input)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("patato"))
		})
	})

	Context("when the input type is missing", func() {
		BeforeEach(func() {
			input = map[string]interface{}{
				"notype": "shoudbemissing",
			}
		})

		It("should return a useful error", func() {
			err := pluginController.DelegateDel(input)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("delegate config is missing type"))
		})
	})
})

var _ = Describe("AddIPMasq", func() {
	var (
		pluginController *lib.PluginController

		fakeIPTablesAdapter *lib_fakes.IPTablesAdapter
	)

	BeforeEach(func() {
		fakeIPTablesAdapter = &lib_fakes.IPTablesAdapter{}
		pluginController = &lib.PluginController{
			IPTables: fakeIPTablesAdapter,
		}
	})

	It("should add the ip masquerade rules for egress traffic", func() {
		err := pluginController.AddIPMasq("10.255.5.5/32", "10.255.0.0/16", "silk-vtep")
		Expect(err).NotTo(HaveOccurred())

		tableName, chainName, iptablesRule := fakeIPTablesAdapter.BulkAppendArgsForCall(0)
		Expect(tableName).To(Equal("nat"))
		Expect(chainName).To(Equal("POSTROUTING"))
		Expect(iptablesRule).To(ContainElement(rules.NewDefaultEgressRule("10.255.5.5/32", "10.255.0.0/16", "silk-vtep")))
	})
})

var _ = Describe("DelIPMasq", func() {
	var (
		pluginController *lib.PluginController

		fakeIPTablesAdapter *lib_fakes.IPTablesAdapter
	)

	BeforeEach(func() {
		fakeIPTablesAdapter = &lib_fakes.IPTablesAdapter{}
		pluginController = &lib.PluginController{
			IPTables: fakeIPTablesAdapter,
		}
	})

	It("should delete the ip masquerade rules for egress traffic", func() {
		err := pluginController.DelIPMasq("10.255.5.5/32", "10.255.0.0/16", "silk-vtep")
		Expect(err).NotTo(HaveOccurred())

		tableName, chainName, iptablesRule := fakeIPTablesAdapter.DeleteArgsForCall(0)
		Expect(tableName).To(Equal("nat"))
		Expect(chainName).To(Equal("POSTROUTING"))
		Expect(iptablesRule).To(Equal(rules.NewDefaultEgressRule("10.255.5.5/32", "10.255.0.0/16", "silk-vtep")))
	})
})
