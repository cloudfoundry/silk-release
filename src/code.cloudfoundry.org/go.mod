module code.cloudfoundry.org

go 1.19

replace code.cloudfoundry.org/runtimeschema => code.cloudfoundry.org/runtimeschema v0.0.0-20180622181441-7dcd19348be6

replace code.cloudfoundry.org/lager => code.cloudfoundry.org/lager v1.1.1-0.20210513163233-569157d2803b

replace github.com/containernetworking/plugins => github.com/containernetworking/plugins v0.6.1-0.20171122160932-92c634042c38

replace github.com/containernetworking/cni => github.com/containernetworking/cni v0.6.0

replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2

replace github.com/hashicorp/consul => github.com/hashicorp/consul v0.7.0

require (
	code.cloudfoundry.org/cf-networking-helpers v0.0.0-20221205130414-742bd12bf674
	code.cloudfoundry.org/debugserver v0.0.0-20210608171006-d7658ce493f4
	code.cloudfoundry.org/diego-logging-client v0.0.0-20220314190632-277a9c460661
	code.cloudfoundry.org/executor v0.0.0-20220401134035-4e7113938d00
	code.cloudfoundry.org/filelock v0.0.0-20230302172038-1783f8b1c987
	code.cloudfoundry.org/garden v0.0.0-20210608104724-fa3a10d59c82
	code.cloudfoundry.org/go-loggregator/v8 v8.0.5
	code.cloudfoundry.org/lager v2.0.0+incompatible
	code.cloudfoundry.org/policy_client v0.0.0-20220420200808-7feb15de93f1
	code.cloudfoundry.org/runtimeschema v0.0.0-00010101000000-000000000000
	code.cloudfoundry.org/silk v0.0.0-20230302180659-dae4c798146c
	github.com/cloudfoundry/dropsonde v1.0.0
	github.com/containernetworking/cni v0.8.1
	github.com/coreos/go-iptables v0.6.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hpcloud/tail v1.0.0
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.27.2
	github.com/pivotal-cf-experimental/gomegamatchers v0.0.0-20180326192815-e36bfcc98c3a
	github.com/tedsuo/ifrit v0.0.0-20191009134036-9a97d0632f00
	github.com/vishvananda/netlink v1.1.0
	gopkg.in/validator.v2 v2.0.0-20210331031555-b37d688a7fb0
)

require (
	code.cloudfoundry.org/bbs v0.0.0-20210727125654-2ad50317f7ed // indirect
	code.cloudfoundry.org/clock v1.0.0 // indirect
	code.cloudfoundry.org/consuladapter v0.0.0-20211122211027-9dbbfa656ee0 // indirect
	code.cloudfoundry.org/go-diodes v0.0.0-20190809170250-f77fb823c7ee // indirect
	code.cloudfoundry.org/locket v0.0.0-20220325152040-ad30c800960d // indirect
	code.cloudfoundry.org/rep v0.1441.2 // indirect
	code.cloudfoundry.org/routing-info v0.0.0-20220215234142-7d023ecb0fad // indirect
	code.cloudfoundry.org/tlsconfig v0.0.0-20200131000646-bbe0f8da39b3 // indirect
	github.com/armon/go-metrics v0.3.11 // indirect
	github.com/bmizerany/pat v0.0.0-20210406213842-e4b6760bdd6f // indirect
	github.com/cloudfoundry-incubator/bbs v0.0.0-20220325145300-b2855629fde1 // indirect
	github.com/cloudfoundry-incubator/executor v0.0.0-20220414185128-2d32ceb4f663 // indirect
	github.com/cloudfoundry/gosteno v0.0.0-20150423193413-0c8581caea35 // indirect
	github.com/cloudfoundry/sonde-go v0.0.0-20200416163440-a42463ba266b // indirect
	github.com/containernetworking/plugins v0.0.0-00010101000000-000000000000 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/go-sql-driver/mysql v1.7.0 // indirect
	github.com/go-test/deep v1.0.8 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/hashicorp/consul v1.12.0 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/serf v0.9.8 // indirect
	github.com/jackc/pgx v3.6.2+incompatible // indirect
	github.com/jmoiron/sqlx v1.3.5 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/lib/pq v1.10.7 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/pivotal-golang/clock v1.0.0 // indirect
	github.com/pivotal-golang/lager v2.0.0+incompatible // indirect
	github.com/rubenv/sql-migrate v0.0.0-20210614095031-55d5740dbbcc // indirect
	github.com/square/certstrap v1.2.0 // indirect
	github.com/tedsuo/rata v1.0.0 // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	github.com/vito/go-sse v1.0.0 // indirect
	github.com/ziutek/utils v0.0.0-20190626152656-eb2a3b364d6c // indirect
	golang.org/x/crypto v0.1.0 // indirect
	golang.org/x/net v0.7.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013 // indirect
	google.golang.org/grpc v1.45.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
	gopkg.in/fsnotify.v1 v1.4.7 // indirect
	gopkg.in/gorp.v1 v1.7.2 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
