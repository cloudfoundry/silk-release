# silk-release

Silk Release is the Cloud Foundry pluggable container networking solution that is used in conjunction
with [CF Networking Release](https://code.cloudfoundry.org/cf-networking-release). It provides networking via the Silk CNI plugin
and enforces policy that is stored in the Policy Server.

The components in this release used to be a part of CF Networking Release. To use this release, you may deploy
[CF Deployment](https://github.com/cloudfoundry/cf-deployment) with the [provided ops-file](opsfiles/use-silk-release.yml).

This release contains the following jobs:
- `silk-controller`
- `silk-daemon`
- `cni`
- `netmon`
- `vxlan-policy-agent`
- `iptables-logger`

For more information about what these jobs do, we recommend looking at the [silk repo](https://code.cloudfoundry.org/silk)
and the [CF Networking Release repo](https://code.cloudfoundry.org/cf-networking-release).
