---
title: Sub Projects
expires_at: never
tags: [silk-release]
---

# Sub Projects

- `cni-teardown`: Standalone binary used within silk-cni
- `cni-wrapper-plugin`: Provision the network namespace and configure the network interface and routing rules for a container.
- `iptables-logger`: Enables iptables kernel logs and emits logs augmented with additonal metadata.
- `netmon`: Emits metrics every 30 seconds about network interface count, overlay RX/TX bytes sent and dropped, and iptables rules count. This component Uses iptables mutex lock.
- `silk-daemon-bootstrap` and `silk-daemon-shutdown`: Daemon that polls the silk-controller API to acquire and renew the overlay subnet lease for the Diego cell. Polling frequency can be configured and is 5s by default. It also serves an API that the silk-cni calls to retrieve information about the overlay subnet lease.
- `silk-datastore-syncer`: Sync silk datastore for running containers from Garden
- `silk`: Silk is an open-source, [CNI](https://github.com/containernetworking/cni/)-compatible container networking fabric. It was inspired by the [flannel](https://github.com/coreos/flannel) VXLAN backend and designed to meet the strict operational requirements of [Cloud Foundry](https://cloudfoundry.org/platform/).
- `vxlan-policy-agent`: Polls the the [Policy Server Internal API](https://github.com/cloudfoundry/cf-networking-release/tree/develop/jobs) for desired network policies (container networking and dynamic application security groups) and writes IPTables rules on the Diego cell to enforce those policies for network traffic between applications. For container networking policies, the IPtables rules tag traffic from applications with network policies on egress, and separate rules at the destination allow traffic with tags whitelisted by policies to applications on ingress. This component Uses iptables mutex lock.



