module code.cloudfoundry.org

go 1.21

toolchain go1.21.5

replace code.cloudfoundry.org/runtimeschema => code.cloudfoundry.org/runtimeschema v0.0.0-20180622181441-7dcd19348be6

replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2

// Prevents `go get -u ./...` from trying to get a branch of executor that we
// tried to make an independent module (adding it's own go mod)`
//   Generated from story https://www.pivotaltracker.com/story/show/184869807
// i.e. we need executor to float on main (v0.0.0-...)
exclude code.cloudfoundry.org/executor v0.1442.0

require (
	code.cloudfoundry.org/cf-networking-helpers v0.0.0-20240507174452-9ffc46cf328c
	code.cloudfoundry.org/debugserver v0.0.0-20240507165104-fb56dd559b10
	code.cloudfoundry.org/diego-logging-client v0.0.0-20240507165108-8f850b7f6df6
	code.cloudfoundry.org/executor v0.0.0-20230406153242-208a08c51850
	code.cloudfoundry.org/filelock v0.0.0-20240508145508-413890995ac0
	code.cloudfoundry.org/garden v0.0.0-20240507191029-a5d2960a4fb1
	code.cloudfoundry.org/go-loggregator/v8 v8.0.5
	code.cloudfoundry.org/lager/v3 v3.0.3
	code.cloudfoundry.org/policy_client v0.0.0-20240507165300-cde941a94707
	code.cloudfoundry.org/runtimeschema v0.0.0-20240111181315-c828d462f664
	github.com/cloudfoundry/dropsonde v1.1.0
	github.com/containernetworking/cni v1.2.0
	github.com/containernetworking/plugins v1.4.1
	github.com/coreos/go-iptables v0.7.0
	github.com/go-sql-driver/mysql v1.8.1
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/google/uuid v1.6.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hpcloud/tail v1.0.0
	github.com/jmoiron/sqlx v1.4.0
	github.com/lib/pq v1.10.9
	github.com/onsi/ginkgo/v2 v2.17.3
	github.com/onsi/gomega v1.33.1
	github.com/pivotal-cf-experimental/gomegamatchers v0.0.0-20180326192815-e36bfcc98c3a
	github.com/rubenv/sql-migrate v1.6.1
	github.com/tedsuo/ifrit v0.0.0-20230516164442-7862c310ad26
	github.com/tedsuo/rata v1.0.0
	github.com/vishvananda/netlink v1.2.1-beta.2
	github.com/ziutek/utils v0.0.0-20190626152656-eb2a3b364d6c
	gopkg.in/validator.v2 v2.0.1
)

require (
	code.cloudfoundry.org/bbs v0.0.0-20240418184526-a7ed0dccd9f7 // indirect
	code.cloudfoundry.org/clock v1.1.0 // indirect
	code.cloudfoundry.org/go-diodes v0.0.0-20240507202434-96dd3c119b5c // indirect
	code.cloudfoundry.org/locket v0.0.0-20230406154009-5e8522d975d2 // indirect
	code.cloudfoundry.org/routing-info v0.0.0-20240405184658-449674f046fa // indirect
	code.cloudfoundry.org/tlsconfig v0.0.0-20240506165053-ee50c1ee9388 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/alexflint/go-filemutex v1.3.0 // indirect
	github.com/bmizerany/pat v0.0.0-20210406213842-e4b6760bdd6f // indirect
	github.com/cloudfoundry/sonde-go v0.0.0-20240507181428-8b8ae008ea35 // indirect
	github.com/go-gorp/gorp/v3 v3.1.0 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/go-test/deep v1.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/pprof v0.0.0-20240508145209-1db217f89380 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/jackc/pgx/v5 v5.5.5 // indirect
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/openzipkin/zipkin-go v0.4.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/safchain/ethtool v0.3.0 // indirect
	github.com/square/certstrap v1.3.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.step.sm/crypto v0.44.8 // indirect
	golang.org/x/crypto v0.23.0 // indirect
	golang.org/x/net v0.25.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	golang.org/x/text v0.15.0 // indirect
	golang.org/x/tools v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240506185236-b8a5c65736ae // indirect
	google.golang.org/grpc v1.63.2 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
	gopkg.in/fsnotify.v1 v1.4.7 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
