---
title: Configuring bandwidth for containers
expires_at: never
tags: [silk-release]
---

<!-- vim-markdown-toc GFM -->

* [Configuring bandwidth for containers](#configuring-bandwidth-for-containers)
  * [How bandwidth limiting is implemented in Silk](#how-bandwidth-limiting-is-implemented-in-silk)
    * [Ingress traffic into containers](#ingress-traffic-into-containers)
    * [Egress traffic from containers](#egress-traffic-from-containers)
  * [Further reading](#further-reading)

<!-- vim-markdown-toc -->
# Configuring bandwidth for containers

Optional parameters have been added to limit the bandwidth in and out of
containers:

  - `rate` on the `cni` job is the rate in Kbps at which traffic can leave and
    enter a container.
  - `burst` on the `cni` job is the burst in Kb at which traffic can leave and
    enter a container.

Both of these parameters must be set in order to limit bandwidth. If neither one
is set, then bandwidth is not limited.

The burst must high enough to support the given rate. If burst is not high
enough, then creating containers will fail.

## How bandwidth limiting is implemented in Silk

When the bandwidth limiting properties are set, they are rendered into the
config file for the Silk CNI plugin. When Silk CNI is configured to limit
bandwidth for containers, it does the following in additon to it's normal
network device set up for connectivity.

Bandwidth limits are implemented using a token bucket filter (tbf) queing
discipline (qdisc).

### Ingress traffic into containers

Ingress traffic into the container is limited by adding an *egress* filter to
the host-side of the veth device that connects to the host to the container.
This is roughly equivalent to the following command using traffic control (tc):

```bash
tc qdisc add dev ${host_veth_device} root tbf rate ${RATE}bit burst ${BURST} latency 100ms
```

### Egress traffic from containers

Egress traffic from the container is little more complicated. Setting the filter
inside the container is not desirable because that could be potentially abused
by anyone who is able to get inside the container (for example, an app developer
could potentially subvert the bandwidth limits that are being imposed by the
platform).

Additionally, setting the limit as an ingress filter on the host-side of the
veth device could lead to dropping packets.

So instead, when bandwidth limits are in place, an additional dummy device (IFB)
is created per container. A [mirred
filter](http://man7.org/linux/man-pages/man8/tc-mirred.8.html) redirects ingress
packets on the host side of the veth device to the IFB device on the host, and a
separate egress filter is added to the IFB device to limit traffic leaving the
host for that container.

This is roughly equivalent to these commands in traffic control:

```bash
ip link add ${ifb_device} type ifb
tc qdisc add dev ${host_veth_device} ingress handle ffff:
tc filter add dev ${host_veth_device} parent ffff: protocol all u32 match ip src 0.0.0.0/0 action mirred egress redirect dev ${ifb_device}
tc qdisc add dev ${ifb_device} root tbf rate ${RATE}bit burst ${BURST} latency 100ms
```

In the end, when bandwidth limits are configured, the data plane looks something like this:

![](bandwidth-limit-dataplane.png)

## Further reading

- [Token bucket filter man page](http://lartc.org/manpages/tc-tbf.html)
- [TLDP: Components of Linux Traffic Control](http://tldp.org/HOWTO/Traffic-Control-HOWTO/components.html)
- [Server Fault: Tc: ingress policing and ifb mirroring](https://serverfault.com/questions/350023/tc-ingress-policing-and-ifb-mirroring)
- [Stack Exchange: Bucket size in tbf](https://unix.stackexchange.com/questions/100785/bucket-size-in-tbf)
