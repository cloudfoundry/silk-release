---
title: Troubleshooting
expires_at: never
tags: [silk-release]
---

<!-- vim-markdown-toc GFM -->

* [Troubleshooting](#troubleshooting)
    * [Enabling Debug Logging](#enabling-debug-logging)
    * [Enabling IPTables Logging for Container to Container Traffic](#enabling-iptables-logging-for-container-to-container-traffic)
    * [Enabling IPTables Logging for ASG Traffic](#enabling-iptables-logging-for-asg-traffic)
    * [Metrics](#metrics)
    * [Diagnosing and Recovering from Subnet Overlap](#diagnosing-and-recovering-from-subnet-overlap)

<!-- vim-markdown-toc -->
# Troubleshooting

### Enabling Debug Logging

  The VXLAN policy agent log at the `info` level by default. The log level can
  be adjusted at runtime by making a request to the debug server running on the
  VM.  To enable debug logging ssh to the VM and make this request to the debug
  server:
  ```bash
  curl -X POST -d 'DEBUG' localhost:8721/log-level
  ```
  To switch back to info logging make this request:
  ```bash
  curl -X POST -d 'INFO' localhost:8721/log-level
  ```
  For the vxlan policy agent, the debug server listens on port 8721 by default,
  and can be overridden by `debug_server_port`.


### Enabling IPTables Logging for Container to Container Traffic

Logging for policy iptables rules can be enabled through the VXLAN policy agent
debug server. SSH to a cell VM and make this request to enable logging on the
VM:
```bash
curl -X PUT -d '{"enabled": true}' localhost:8721/iptables-c2c-logging
```
To disable:
```bash
curl -X PUT -d '{"enabled": false}' localhost:8721/iptables-c2c-logging
```

This can be configured at startup via the `iptables_logging` property. It
defaults to `false`. This property is used by the `vxlan-policy-agent` and the
`silk-cni` jobs.

Logs from iptables end up in `/var/log/kern.log`.

Example of a rejected connection:
```
May  3 23:34:07 localhost kernel: [87921.493829] DENY_C2C_cb40f81e-52ce-41c5- IN=s-010255015007 OUT=s-010255015013 MAC=aa:aa:0a:ff:0f:07:ee:ee:0a:ff:0f:07:08:00 SRC=10.255.15.7 DST=10.255.15.13 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=35889 DF PROTO=TCP SPT=36004 DPT=723 WINDOW=29200 RES=0x00 SYN URGP=0 MARK=0x2
```

Example of an accepted connection, note that the prefix `OK_0003` indicates the
packet with tag 3 was accepted:
```
May  3 23:35:07 localhost kernel: [87981.320056] OK_0002_e9e8959f-3828-4136-8 IN=s-010255015007 OUT=s-010255015013 MAC=aa:aa:0a:ff:0f:07:ee:ee:0a:ff:0f:07:08:00 SRC=10.255.15.7 DST=10.255.15.13 LEN=52 TOS=0x00 PREC=0x00 TTL=63 ID=43997 DF PROTO=TCP SPT=60012 DPT=8080 WINDOW=237 RES=0x00 ACK URGP=0 MARK=0x2
```

### Enabling IPTables Logging for ASG Traffic

Logging for ASG iptables rules can be configured at startup via the
`iptables_logging` property. It defaults to `false`.

Logs from iptables end up in `/var/log/kern.log`.

Example of a rejected connection, note that the prefix
`DENY_b6de7d0c-4792-4614-5e51-` indicates that an app instance with instance
guid starting with `b6de7d0c-4792-4614-5e51-` was not able to connect to
`10.0.16.8`:

```
May  3 23:35:58 localhost kernel: [88032.025828] DENY_d538d169-f2f6-4587-77b1 IN=s-010255015007 OUT=eth0 MAC=aa:aa:0a:ff:0f:07:ee:ee:0a:ff:0f:07:08:00 SRC=10.255.15.7 DST=10.10.10.1 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=61375 DF PROTO=TCP SPT=49466 DPT=80 WINDOW=29200 RES=0x00 SYN URGP=0 MARK=0x2
```

Example of an accepted connection, note that the prefix
`OK_b6de7d0c-4792-4614-5e51-4c` indicates that an app instance with an instance
guid starting with `b6de7d0c-4792-4614-5e51-4c` was able to connect to
`93.184.216.34`:
```
May  3 23:35:35 localhost kernel: [88008.920287] OK_d538d169-f2f6-4587-77b1-f IN=s-010255015007 OUT=eth0 MAC=aa:aa:0a:ff:0f:07:ee:ee:0a:ff:0f:07:08:00 SRC=10.255.15.7 DST=173.194.210.139 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=45400 DF PROTO=TCP SPT=35236 DPT=80 WINDOW=29200 RES=0x00 SYN URGP=0 MARK=0x2
```

### Metrics

  CF networking components emit metrics which can be consumed from the firehose,
  e.g. with the datadog firehose nozzle. Relevant metrics have theses prefixes:
  -   `netmon`
  -   `vxlan_policy_agent`

### Diagnosing and Recovering from Subnet Overlap

See [cf-networking-release](https://code.cloudfoundry.org/cf-networking-release) for
information on how to recover from a deploy of CF Networking with Silk which has
an overlay network configured which conflicts with the entire CF subnet.
