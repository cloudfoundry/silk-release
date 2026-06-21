module code.cloudfoundry.org

go 1.26.0

replace code.cloudfoundry.org/runtimeschema => code.cloudfoundry.org/runtimeschema v0.0.0-20180622181441-7dcd19348be6

replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2

require (
	code.cloudfoundry.org/bbs/models v1.3.0
	code.cloudfoundry.org/cf-networking-helpers v0.90.0
	code.cloudfoundry.org/debugserver v0.102.0
	code.cloudfoundry.org/diego-logging-client v0.112.0
	code.cloudfoundry.org/filelock v0.69.0
	code.cloudfoundry.org/garden v0.0.0-20260617020226-a9e754564bb5
	code.cloudfoundry.org/go-loggregator/v9 v9.2.1
	code.cloudfoundry.org/lager/v3 v3.74.0
	code.cloudfoundry.org/policy_client v0.108.0
	code.cloudfoundry.org/runtimeschema v0.0.0-20240514235758-31be7684c5bf
	github.com/cloudfoundry/dropsonde v1.1.0
	github.com/containernetworking/cni v1.3.0
	github.com/containernetworking/plugins v1.9.1
	github.com/coreos/go-iptables v0.8.0
	github.com/go-sql-driver/mysql v1.10.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/google/uuid v1.6.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hpcloud/tail v1.0.0
	github.com/jmoiron/sqlx v1.4.0
	github.com/lib/pq v1.12.3
	github.com/onsi/ginkgo/v2 v2.31.0
	github.com/onsi/gomega v1.42.0
	github.com/pivotal-cf-experimental/gomegamatchers v0.0.0-20180326192815-e36bfcc98c3a
	github.com/pkg/errors v0.9.1
	github.com/rubenv/sql-migrate v1.8.1
	github.com/tedsuo/ifrit v0.0.0-20260418191334-846868129986
	github.com/tedsuo/rata v1.0.0
	github.com/vishvananda/netlink v1.3.1
	github.com/ziutek/utils v0.0.0-20190626152656-eb2a3b364d6c
	golang.org/x/sys v0.46.0
	gopkg.in/validator.v2 v2.0.1
)

require (
	code.cloudfoundry.org/bbs v1.3.0 // indirect
	code.cloudfoundry.org/go-diodes v0.0.0-20260615142411-472d6bcdb3c6 // indirect
	code.cloudfoundry.org/tlsconfig v0.60.0 // indirect
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/Masterminds/semver/v3 v3.5.0 // indirect
	github.com/alexflint/go-filemutex v1.3.0 // indirect
	github.com/bmizerany/pat v0.0.0-20210406213842-e4b6760bdd6f // indirect
	github.com/cloudfoundry/sonde-go v0.0.0-20260526083715-66f310f13c26 // indirect
	github.com/go-gorp/gorp/v3 v3.1.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20260604005048-7023385849c0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/openzipkin/zipkin-go v0.4.3 // indirect
	github.com/safchain/ethtool v0.7.0 // indirect
	github.com/square/certstrap v1.3.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	go.step.sm/crypto v0.83.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	golang.org/x/tools v0.46.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260618152121-87f3d3e198d3 // indirect
	google.golang.org/grpc v1.81.1 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/fsnotify.v1 v1.4.7 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	sigs.k8s.io/knftables v0.0.21 // indirect
)
