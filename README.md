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

## Project links
- [Engineering backlog](https://www.pivotaltracker.com/n/projects/1498342)
- Chat with us at the `#container-networking` channel on [Cloud Foundry Slack](http://slack.cloudfoundry.org/)
- [CI dashboard](http://dashboard.c2c.cf-app.com) and [config](https://github.com/cloudfoundry-incubator/cf-networking-ci)

## Known Issues
For known issues related to both `silk-release` and `cf-networking-release` you can find them here:
[cf-networking-release/docs/known-issues](https://github.com/cloudfoundry/cf-networking-release/blob/develop/docs/known-issues.md).
