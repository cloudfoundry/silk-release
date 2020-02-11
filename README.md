# silk-release

Silk Release is the Cloud Foundry pluggable container networking solution that is used in conjunction
with [CF Networking Release](https://code.cloudfoundry.org/cf-networking-release). It provides networking via the Silk CNI plugin
and enforces policy that is stored in the Policy Server.

The components in this release used to be a part of CF Networking Release. To use this release, you may deploy
[CF Deployment](https://github.com/cloudfoundry/cf-deployment) with the [provided ops-file](https://github.com/cloudfoundry/cf-deployment/tree/master/operations/experimental/use-silk-release.yml).

This release contains the following jobs:
- `silk-controller`
- `silk-daemon`
- `silk-cni`
- `netmon`
- `vxlan-policy-agent`
- `iptables-logger`

For more information about what these jobs do, we recommend looking at the [silk repo](https://code.cloudfoundry.org/silk)
and the [CF Networking Release repo](https://code.cloudfoundry.org/cf-networking-release).

## Getting Help

For help or questions with this release or any of its submodules, you can reach the maintainers on Slack at [cloudfoundry.slack.com](https://cloudfoundry.slack.com) in the `#networking` channel.

## Project links
- [Engineering backlog](https://www.pivotaltracker.com/n/projects/2245594)
- [CI dashboard](https://networking.ci.cf-app.com/teams/ga/pipelines/cf-networking) and [config](https://github.com/cloudfoundry/cf-networking-release/blob/develop/ci/pipelines/cf-networking.yml)

## Known Issues
For known issues related to both `silk-release` and `cf-networking-release` you can find them here:
[cf-networking-release/docs/known-issues](https://github.com/cloudfoundry/cf-networking-release/blob/develop/docs/known-issues.md).
