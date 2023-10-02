# silk-release

Silk Release is the Cloud Foundry pluggable container networking solution that
is used in conjunction with [CF Networking
Release](https://code.cloudfoundry.org/cf-networking-release). It provides
networking via the Silk CNI plugin and enforces policy that is stored in the
Policy Server.

The components in this release used to be a part of CF Networking Release.
However, it is the default container networking plugin for CF Deployment. To use
it, simply deploy [CF
Deployment](https://github.com/cloudfoundry/cf-deployment).

This release contains the following jobs:
- `silk-controller`
- `silk-daemon`
- `silk-cni`
- `silk-datastore-syncer`
- `netmon`
- `vxlan-policy-agent`
- `iptables-logger`

For more information about what these jobs do, we recommend looking at the [silk
repo](https://code.cloudfoundry.org/silk) and the [CF Networking Release
repo](https://code.cloudfoundry.org/cf-networking-release).

### <a name="developer-workflow"></a> Developer Workflow

- Clone [CI repository](https://github.com/cloudfoundry/wg-app-platform-runtime-ci) (next to where this code is cloned), and make sure latest
is pulled by running `git pull`

  ```bash
  mkdir -p ~/workspace
  cd ~/workspace
  git clone https://github.com/cloudfoundry/wg-app-platform-runtime-ci.git
  ```
- [Git](https://git-scm.com/) - Distributed version control system
- [Go](https://golang.org/doc/install#install) - The Go programming
  language

### <a name="running-tests"></a>Running Tests

##### With Docker

Running tests for this release requires a `DB` flavor. The following scripts with default to `mysql` DB. Set `DB` environment variable for alternate DBs e.g. <mysql-8.0(or mysql),mysql-5.7,postgres>

- `./scripts/create-docker-container.bash`: This will create a docker container with appropriate mounts.
- `./scripts/test-in-docker-locally.bash`: Create docker container and run all tests and setup in a single script.
  - `./scripts/test-in-docker-locally.bash <package> <sub-package>`: For running tests under a specific package and/or sub-package: e.g. `./scripts/test-in-docker-locally.bash iptables-logger config`

When inside docker container: 
- `/repo/scripts/docker/test.bash`: This will run all tests in this release
- `/repo/scripts/docker/test.bash iptables-logger`: This will only run `iptables-logger` tests
- `/repo/scripts/docker/test.bash iptables-logger config`: This will only run `iptables-logger` sub-package tests for `config` package
- `/repo/scripts/docker/tests-templates.bash`: This will run all of tests for bosh tempalates
- `/repo/scripts/docker/lint.bash`: This will run all of linting defined for this repo.

## Getting Help

For help or questions with this release or any of its submodules, you can reach
the maintainers on Slack at
[cloudfoundry.slack.com](https://cloudfoundry.slack.com) in the `#cf-for-vms-networking`
channel.

## Known Issues
For known issues related to both `silk-release` and `cf-networking-release` you can find them here:
[cf-networking-release/docs/known-issues](https://github.com/cloudfoundry/cf-networking-release/blob/develop/docs/known-issues.md).
