module code.cloudfoundry.org

go 1.16

replace code.cloudfoundry.org/runtimeschema => code.cloudfoundry.org/runtimeschema v0.0.0-20180622181441-7dcd19348be6

replace code.cloudfoundry.org/lager => code.cloudfoundry.org/lager v1.1.1-0.20210513163233-569157d2803b

replace github.com/vishvananda/netlink => github.com/vishvananda/netlink v0.0.0-20180201184657-c27b7f7359fa

replace github.com/vishvananda/netns => github.com/vishvananda/netns v0.0.0-20171111001504-be1fbeda1936

replace github.com/containernetworking/plugins => github.com/containernetworking/plugins v0.6.1-0.20171122160932-92c634042c38

replace github.com/containernetworking/cni => github.com/containernetworking/cni v0.6.0

replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.0.0

replace github.com/square/certstrap => github.com/square/certstrap v1.1.1

require (
	code.cloudfoundry.org/cf-networking-helpers v0.0.0-20210929193536-efcc04207348
	code.cloudfoundry.org/debugserver v0.0.0-20210608171006-d7658ce493f4
	code.cloudfoundry.org/filelock v0.0.0-20180314203404-13cd41364639
	code.cloudfoundry.org/garden v0.0.0-20210608104724-fa3a10d59c82
	code.cloudfoundry.org/lager v2.0.0+incompatible
	code.cloudfoundry.org/policy_client v0.0.0-20190731000202-6324003c2bfd
	code.cloudfoundry.org/runtimeschema v0.0.0-00010101000000-000000000000
	code.cloudfoundry.org/silk v0.0.0-20211004235850-da152076940f
	github.com/cloudfoundry/dropsonde v1.0.0
	github.com/containernetworking/cni v0.6.0
	github.com/coreos/go-iptables v0.6.0
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hpcloud/tail v1.0.0
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.16.0
	github.com/pivotal-cf-experimental/gomegamatchers v0.0.0-20180326192815-e36bfcc98c3a
	github.com/tedsuo/ifrit v0.0.0-20191009134036-9a97d0632f00
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f // indirect
	gopkg.in/validator.v2 v2.0.0-20210331031555-b37d688a7fb0
)
