# Silk Release Jobs

This is the README for Silk-release jobs. To learn more about `silk-release`, go to the main [README](../README.md).

| Job Name | Purpose | Additional Notes |
| --- | --- | --- |
| `iptables-logger` | Logs iptables kernel logs every 30 seconds. | |
| `netmon` | Emits metrics every 30 seconds about network interface count, overlay RX/TX bytes sent and dropped, and iptables rules count. | Uses iptables mutex lock. |
| `silk-cni` | Short-lived job, ran by the container runner, that double-checks `silk-daemon` health before provisioning the network stack for an application container. | |
| `silk-controller` | Manages IP subnet lease allocation for the Container Orchestrator (e.g. Diego).|  |
| `silk-daemon` | Background daemon that acquires and renews the subnet lease for the host by calling the `silk-controller` API every 5s by default. It also serves an API endpoint about the subnet lease information. |  |
| `vxlan-policy-agent` | Enforces network policy for network traffic between applications: discovers new desired network policies from the Policy Server Internal API, updates Diego cell to allow white-listed ingress traffic, tags egress traffic with a unique identifier per source application using the VXLAN GBP header and optionally limit bandwidth in and out of each container. | Uses iptables mutex lock. |
| `vxlan-policy-agent-windows` | Accomplishes the same purpose of `vxlan-policy-agent`, but on Windows based VMs. Also bootstraps `sshd` daemon. |  |
