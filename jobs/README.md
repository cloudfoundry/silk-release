# Silk Release Jobs

This is the README for Silk-release jobs. To learn more about `silk-release`, go to the main [README](../README.md).

| Job Name | Purpose | Additional Notes |
| --- | --- | --- |
| `iptables-logger` | Enables iptables kernel logs and emits logs augmented with additonal metadata. | [Additional details](../docs/traffic_logging.md) |
| `netmon` | Emits metrics every 30 seconds about network interface count, overlay RX/TX bytes sent and dropped, and iptables rules count. | Uses iptables mutex lock. |
| `silk-cni` | Short-lived [CNI](https://github.com/containernetworking/cni) job, executed along with the [`cni-wrapper-plugin`](https://github.com/cloudfoundry/silk-release/tree/master/src/cni-wrapper-plugin) to provision the network namespace and configure the network interface and routing rules for a container. | When executed, it obtains an overlay subnet and MTU from the `silk-daemon` for the container. Optionally limits bandwidth in and out of each container with the [`bandwidth` plugin](https://github.com/containernetworking/plugins/tree/master/plugins/meta/bandwidth). Uses iptables mutex lock.|
| `silk-controller` | Manages IP subnet lease allocation for the Diego cell. State that maps the Diego cell to the leased overlay subnet is stored in a SQL database. |  |
| `silk-daemon` | Daemon that polls the `silk-controller` API to acquire and renew the overlay subnet lease for the Diego cell. Polling frequency can be configured and is 5s by default. It also serves an API that the `silk-cni` calls to retrieve information about the overlay subnet lease. |  |
| `vxlan-policy-agent` | Polls the the [Policy Server Internal API](https://github.com/cloudfoundry/cf-networking-release/tree/develop/jobs) for desired network policies (container networking and dynamic application security groups) and writes IPTables rules on the Diego cell to enforce those policies for network traffic between applications. For container networking policies, the IPtables rules tag traffic from applications with network policies on egress, and separate rules at the destination allow traffic with tags whitelisted by policies to applications on ingress. | Uses iptables mutex lock. |
