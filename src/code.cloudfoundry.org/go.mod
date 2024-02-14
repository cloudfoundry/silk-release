module code.cloudfoundry.org

go 1.21

toolchain go1.21.5

replace code.cloudfoundry.org/runtimeschema => code.cloudfoundry.org/runtimeschema v0.0.0-20180622181441-7dcd19348be6

replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2

require (
	code.cloudfoundry.org/cf-networking-helpers v0.0.0-20240209161148-7a6d04db6b8c
	code.cloudfoundry.org/debugserver v0.0.0-20240209143423-2b9fa99122f1
	code.cloudfoundry.org/diego-logging-client v0.0.0-20240209143437-cd540f1e347d
	code.cloudfoundry.org/executor v0.0.0-20230406153242-208a08c51850
	code.cloudfoundry.org/filelock v0.0.0-20240209144509-13bda475cb97
	code.cloudfoundry.org/garden v0.0.0-20240214130550-8a0cb81e0f4f
	code.cloudfoundry.org/go-loggregator/v8 v8.0.5
	code.cloudfoundry.org/lager/v3 v3.0.3
	code.cloudfoundry.org/policy_client v0.0.0-20240209144915-fbaaddbe3acf
	code.cloudfoundry.org/runtimeschema v0.0.0-20240111181315-c828d462f664
	github.com/cloudfoundry/dropsonde v1.1.0
	github.com/containernetworking/cni v1.1.2
	github.com/containernetworking/plugins v1.4.0
	github.com/coreos/go-iptables v0.7.0
	github.com/go-sql-driver/mysql v1.7.1
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/google/uuid v1.6.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hpcloud/tail v1.0.0
	github.com/jmoiron/sqlx v1.3.5
	github.com/lib/pq v1.10.9
	github.com/onsi/ginkgo/v2 v2.15.0
	github.com/onsi/gomega v1.31.1
	github.com/pivotal-cf-experimental/gomegamatchers v0.0.0-20180326192815-e36bfcc98c3a
	github.com/rubenv/sql-migrate v1.6.1
	github.com/tedsuo/ifrit v0.0.0-20230516164442-7862c310ad26
	github.com/tedsuo/rata v1.0.0
	github.com/vishvananda/netlink v1.2.1-beta.2
	github.com/ziutek/utils v0.0.0-20190626152656-eb2a3b364d6c
	gopkg.in/validator.v2 v2.0.1
)

require (
	code.cloudfoundry.org/bbs v0.0.0-20240208160729-6d10e764fb3e // indirect
	code.cloudfoundry.org/clock v1.1.0 // indirect
	code.cloudfoundry.org/go-diodes v0.0.0-20240124183017-31ac915ce912 // indirect
	code.cloudfoundry.org/locket v0.0.0-20230406154009-5e8522d975d2 // indirect
	code.cloudfoundry.org/routing-info v0.0.0-20230911184850-3a6d4ccb3cfc // indirect
	code.cloudfoundry.org/tlsconfig v0.0.0-20240213144909-765c8d6ec2ff // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/alexflint/go-filemutex v1.3.0 // indirect
	github.com/bmizerany/pat v0.0.0-20210406213842-e4b6760bdd6f // indirect
	github.com/cloudfoundry/sonde-go v0.0.0-20231227232801-b682ba3cb37d // indirect
	github.com/go-gorp/gorp/v3 v3.1.0 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/go-test/deep v1.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/pprof v0.0.0-20240207164012-fb44976bdcd5 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/jackc/pgx v3.6.2+incompatible // indirect
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/openzipkin/zipkin-go v0.4.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/safchain/ethtool v0.3.0 // indirect
	github.com/square/certstrap v1.3.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.step.sm/crypto v0.43.0 // indirect
	golang.org/x/crypto v0.19.0 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.18.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240213162025-012b6fc9bca9 // indirect
	google.golang.org/grpc v1.61.1 // indirect
	google.golang.org/protobuf v1.32.0 // indirect
	gopkg.in/fsnotify.v1 v1.4.7 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
