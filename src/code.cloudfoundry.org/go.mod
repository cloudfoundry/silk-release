module code.cloudfoundry.org

go 1.17

replace code.cloudfoundry.org/runtimeschema => code.cloudfoundry.org/runtimeschema v0.0.0-20180622181441-7dcd19348be6

replace code.cloudfoundry.org/lager => code.cloudfoundry.org/lager v1.1.1-0.20210513163233-569157d2803b

replace github.com/vishvananda/netlink => github.com/vishvananda/netlink v0.0.0-20180201184657-c27b7f7359fa

replace github.com/vishvananda/netns => github.com/vishvananda/netns v0.0.0-20171111001504-be1fbeda1936

replace github.com/containernetworking/plugins => github.com/containernetworking/plugins v0.6.1-0.20171122160932-92c634042c38

replace github.com/containernetworking/cni => github.com/containernetworking/cni v0.8.1

replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.0.0

require (
	code.cloudfoundry.org/cf-networking-helpers v0.0.0-20211111210832-d3a705b8ebff
	code.cloudfoundry.org/debugserver v0.0.0-20210608171006-d7658ce493f4
	code.cloudfoundry.org/filelock v0.0.0-20180314203404-13cd41364639
	code.cloudfoundry.org/garden v0.0.0-20210608104724-fa3a10d59c82
	code.cloudfoundry.org/lager v2.0.0+incompatible
	code.cloudfoundry.org/policy_client v0.0.0-20220203234022-670e720134e3
	code.cloudfoundry.org/runtimeschema v0.0.0-00010101000000-000000000000
	code.cloudfoundry.org/silk v0.0.0-20211004235850-da152076940f
	github.com/cloudfoundry/dropsonde v1.0.0
	github.com/containernetworking/cni v0.8.1
	github.com/coreos/go-iptables v0.6.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hpcloud/tail v1.0.0
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.18.1
	github.com/pivotal-cf-experimental/gomegamatchers v0.0.0-20180326192815-e36bfcc98c3a
	github.com/tedsuo/ifrit v0.0.0-20191009134036-9a97d0632f00
	github.com/vishvananda/netlink v1.1.0
	gopkg.in/validator.v2 v2.0.0-20210331031555-b37d688a7fb0
)

require (
	code.cloudfoundry.org/bbs v0.0.0-20210727125654-2ad50317f7ed // indirect
	github.com/bmizerany/pat v0.0.0-20210406213842-e4b6760bdd6f // indirect
	github.com/cloudfoundry/gosteno v0.0.0-20150423193413-0c8581caea35 // indirect
	github.com/cloudfoundry/sonde-go v0.0.0-20200416163440-a42463ba266b // indirect
	github.com/containernetworking/plugins v0.0.0-00010101000000-000000000000 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/go-sql-driver/mysql v1.6.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/jmoiron/sqlx v1.3.4 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/lib/pq v1.10.3 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/rubenv/sql-migrate v0.0.0-20210614095031-55d5740dbbcc // indirect
	github.com/square/certstrap v1.2.0 // indirect
	github.com/tedsuo/rata v1.0.0 // indirect
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f // indirect
	github.com/ziutek/utils v0.0.0-20190626152656-eb2a3b364d6c // indirect
	golang.org/x/net v0.0.0-20210525063256-abc453219eb5 // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
	golang.org/x/text v0.3.6 // indirect
	google.golang.org/protobuf v1.26.0 // indirect
	gopkg.in/fsnotify.v1 v1.4.7 // indirect
	gopkg.in/gorp.v1 v1.7.2 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
