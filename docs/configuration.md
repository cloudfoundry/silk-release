# Configuration Information for Operators

## Table of Contents
1. [Silk Network Configuration](#silk-network-configuration)
1. [Database Configuration](#database-configuration)
1. [MTU](#mtu)
1. [Mutual TLS](#mutual-tls)
1. [Max Open/Idle Connections](#max-openidle-connections)

## Silk Network Configuration
The IP address allocation scheme is simple:

- The operator chooses a large contiguous address block for the entire VXLAN
  network (`network`).
- The operator also chooses a uniform
  [subnet](https://en.wikipedia.org/wiki/Subnetwork) size
  (`subnet_prefix_length`).
- Silk ensures that each Diego Cell (container host) is allocated a dedicated a
  single subnet of that size from within that large block.
- The Silk CNI plugin ensures that every container receives a unique IP within
  the subnet assigned to its host Cell.

In this way, every container in the installation receives a unique IP address.

> **Note**: by default, the `cf-deployment` will enable garden to use the Silk CNI plugin.

If you are not using `cf-deployment`, please add the following two properties to the `garden` job:
```yaml
garden:
  network_plugin: /var/vcap/packages/runc-cni/bin/garden-external-networker
  network_plugin_extra_args:
  - --configFile=/var/vcap/jobs/garden-cni/config/adapter.json
```

#### BOSH properties
To configure the global network block and the size of the per-cell subnets, two
BOSH properties are used:

- `network`: The address block for the entire VXLAN network.  Defaults to
  `10.255.0.0/16`

- `subnet_prefix_length`: The length, in bits, of the mask for the per-cell
  subnets.  Must be less than 31 but larger than the prefix length for
  `network`.  Defaults to `24`.

> **Note**: The `network` option should be configured to not overlap with
> anything on the infrastructure network used by BOSH, CF or services.
> If the overlay network overlaps with anything on the underlay, traffic from the
> cell will not be able to reach that entity on the underlay.  To repair a
> deployment that has been misconfigured, follow our [recovery
> steps](https://github.com/cloudfoundry/cf-networking-release/blob/develop/docs/troubleshooting.md#diagnosing-and-recovering-from-subnet-overlap).

> **Note**: the `network` property is consumed by two BOSH jobs: `silk-daemon`
> and `silk-controller`.

> **Note:** On BOSH-lite, avoid using or overlapping with the `10.244.0.0/16` or
> `10.254.0.0/16` ranges. Those are both in use by BOSH-lite components and
> unpredictable behavior may result.

#### Network size limitations
The size of a given CF Networking w/ Silk installation is limited by the values
of these two BOSH properties.

- let `s` be the value of `subnet_prefix_length`, e.g. `24` in the default case.
- let `n` be the prefix length in `network`, e.g. `16` in the default case.

Then:
- the number of containers on a given Diego cell cannot exceed `2^(32-s) - 2`
- the number of Diego cells in the installation cannot exceed `2^(s-n) - 1`
- the total number of containers running on the installation cannot exceed the
  product of the previous two numbers.

For example, using the default values, the maximum number of containers per cell
is `2^(32-24) - 2 = 254`, the maximum number of cells in the installation is
`2^(24-16) - 1 = 255`, and thus no more than `254 * 255 = 64770` containers
total may be running at a time on the installation.

Alternately, if `network` = `10.32.0.0/11` and `subnet_prefix_length` = `22`
then the maximum number of containers per cell would be `2^(32-22) - 2 = 1022`,
the maximum number of cells in the installation would be `2^(22-11) - 1 = 2047`,
and no more than `1022 * 2047 = 2092034` containers total may be running at a
time on the installation.

> **Note**: these upper bounds are for the network only.  Other limitations may
> also apply to your installation, e.g.
> [`garden.max_containers`](https://github.com/cloudfoundry/garden-runc-release/blob/master/jobs/garden/spec).

#### Changing the network
It is safe to expand `network` on an existing deployment. However it is not safe
to modify `subnet_prefix_length`.  Unpredictable behavior may result.

Any changes which result in an IP range that does not completely contain the old
network address block must be done using
```bash
bosh deploy --recreate
```
and may cause the container network to become temporarily unavailable during the
deploy.

## Database Configuration
A SQL database is required to store Subnet Leases. MySQL and PostgreSQL
databases are currently supported.

### Hosting options
The database may be hosted anywhere that the silk-controller can reach it,
including on another BOSH-deployed VM or on a cloud-provided service.  Here are
some options:

#### MySQL

- Add a logical database to the CF-MySQL cluster that ships with
  [CF-Deployment](https://github.com/cloudfoundry/cf-deployment).

- BOSH-deploy the [CF-MySQL
  release](https://github.com/cloudfoundry/cf-mysql-release) to dedicated VM(s).
  CF-MySQL may be deployed either as a single-node or as a highly available (HA)
  cluster.

- Use a database service provided by your cloud infrastructure provider.  For
  example, in some of our automated tests we use an AWS RDS MySQL instance
  configured as follows:
    - MySQL 5.7.16
    - db.t2.medium (4 Gib)
    - 20 GB storage


#### PostgreSQL

- Use a database service provided by your cloud infrastructure provider.  For
  example, in some of our automated tests we use an AWS RDS PostgreSQL instance
  configured as follows:
  - PostgreSQL 9.5.4
  - db.m3.medium (3.75 GiB)
  - 20 GB storage

- BOSH-deploy the [Postgres
  release](https://github.com/cloudfoundry/postgres-release/) to a dedicated VM.

## MTU
Operators not using any additional encapsulation should not need to do any
special configuration for MTUs.  The CNI plugins should automatically detect the
host MTU and set the container MTU appropriately, accounting for any overhead.

However, operators should understand that:
 - All Diego cells should be on the same network, and should have the same MTU
 - A change the Diego cell MTU will likely require the VMs to be recreated in
   order for the container network to function properly.

Operators using some additional encapsulation (e.g. ipsec) can manually
configure the MTU for containers.  The configuration can be specified in the
manifest under `mtu`.  The operator should set the MTU low enough to account for
the overhead of their own encapsulation plus the overhead from VXLAN.  As an
example, if you are using ipsec with a recommended overhead of 100 bytes, and
your VMs have MTU 1500, you should set the MTU to 1350 (1500 - 100 for ipsec -
50 for VXLAN).


## Mutual TLS
In the batteries-included networking stack, there are two different
control-plane connections between system components:

- The Silk Daemon is a client of the Silk Controller
- The VXLAN Policy Agent is a client of the internal Policy Server API

Both of these connections require Mutual TLS.

If you want to generate them yourself, ensure that all certificates support the
cipher suite `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.  The Silk Controller will
reject connections using any other cipher suite.

## Max Open/Idle Connections

In order to limit the number of open or idle connections between the silk daemon
and silk controller, the following properties can be set.
- `max_open_connections`
- `max_idle_connections`

By default there is no limit to the number of open or idle connections.
