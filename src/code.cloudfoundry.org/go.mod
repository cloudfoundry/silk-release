module code.cloudfoundry.org

go 1.19

replace code.cloudfoundry.org/runtimeschema => code.cloudfoundry.org/runtimeschema v0.0.0-20180622181441-7dcd19348be6

replace github.com/containernetworking/plugins => github.com/containernetworking/plugins v0.6.1-0.20171122160932-92c634042c38

replace github.com/containernetworking/cni => github.com/containernetworking/cni v0.6.0

replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2

replace github.com/hashicorp/consul => github.com/hashicorp/consul v0.7.0

require (
	code.cloudfoundry.org/cf-networking-helpers v0.0.0-20230510133512-ebb4c931f5d5
	code.cloudfoundry.org/debugserver v0.0.0-20230508035730-c4fc5f67e21e
	code.cloudfoundry.org/diego-logging-client v0.0.0-20230508200927-824f04190d59
	code.cloudfoundry.org/executor v0.0.0-20230406153242-208a08c51850
	code.cloudfoundry.org/filelock v0.0.0-20230410204127-470838d066c5
	code.cloudfoundry.org/garden v0.0.0-20230509175005-ab96b4719f65
	code.cloudfoundry.org/go-loggregator/v8 v8.0.5
	code.cloudfoundry.org/lager/v3 v3.0.1
	code.cloudfoundry.org/policy_client v0.0.0-20230405194717-ac8a054e5f69
	code.cloudfoundry.org/runtimeschema v0.0.0-20230323223330-5366865eed76
	code.cloudfoundry.org/silk v0.0.0-20230508155759-ca6518c29f9c
	github.com/cloudfoundry/dropsonde v1.0.1-0.20230324134055-c6dd7c5e990e
	github.com/containernetworking/cni v1.1.2
	github.com/coreos/go-iptables v0.6.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hpcloud/tail v1.0.0
	github.com/onsi/ginkgo/v2 v2.9.4
	github.com/onsi/gomega v1.27.6
	github.com/pivotal-cf-experimental/gomegamatchers v0.0.0-20180326192815-e36bfcc98c3a
	github.com/tedsuo/ifrit v0.0.0-20230330192023-5cba443a66c4
	github.com/vishvananda/netlink v1.1.0
	gopkg.in/validator.v2 v2.0.1
)

require (
	code.cloudfoundry.org/bbs v0.0.0-20230419194333-54391379d38f // indirect
	code.cloudfoundry.org/clock v1.1.0 // indirect
	code.cloudfoundry.org/go-diodes v0.0.0-20230508203442-8ce2048f62dc // indirect
	code.cloudfoundry.org/locket v0.0.0-20230406154009-5e8522d975d2 // indirect
	code.cloudfoundry.org/routing-info v0.0.0-20230405185804-c6998d604bb2 // indirect
	code.cloudfoundry.org/tlsconfig v0.0.0-20230320190829-8f91c367795b // indirect
	filippo.io/edwards25519 v1.0.0 // indirect
	github.com/bmizerany/pat v0.0.0-20210406213842-e4b6760bdd6f // indirect
	github.com/cloudfoundry/sonde-go v0.0.0-20230412182205-eaf74d09b55a // indirect
	github.com/containernetworking/plugins v0.0.0-00010101000000-000000000000 // indirect
	github.com/go-gorp/gorp/v3 v3.1.0 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-sql-driver/mysql v1.7.1 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/go-test/deep v1.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/pprof v0.0.0-20230510103437-eeec1cb781c3 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/jackc/pgx v3.6.2+incompatible // indirect
	github.com/jmoiron/sqlx v1.3.5 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/openzipkin/zipkin-go v0.4.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rubenv/sql-migrate v1.4.0 // indirect
	github.com/square/certstrap v1.3.0 // indirect
	github.com/tedsuo/rata v1.0.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	github.com/ziutek/utils v0.0.0-20190626152656-eb2a3b364d6c // indirect
	go.step.sm/crypto v0.28.0 // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	golang.org/x/tools v0.9.1 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	google.golang.org/grpc v1.55.0 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/fsnotify.v1 v1.4.7 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
