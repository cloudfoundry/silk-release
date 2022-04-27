# rule-converter

Converts garden.NetOutRule definitions into ASG-compatible rules.

This utility is handy for troubleshooting IPTables issues when garden spits out errors for external-cni-up failures, as those
contain json-encoded rulesets that are passed into the CNI.

# Usage

1. Take the rulesets from the garden logs.
  1. `grep 'cfnetworking: cni up failed:' /var/vcap/sys/log/garden.stdout.log`
  1. Select the log message for the CNI error you're interested in, and , and pipe them into rule-converter, redirecting its output to a file:

```
message='{"timestamp":"2022-04-26T19:32:52.646992461Z","level":"error","source":"guardian","message":"guardian.create.external-networker-result","data":{"action":"up","error":"exit status 1","handle":"6de68121-5eb5-47f6-4c1e-6884","session":"592","stderr":"cfnetworking: cni up failed: add network list failed: asg sync returned 500 with message: failed to update asgs for container 6de68121-5eb5-47f6-4c1e-6884: 1 error occurred:\n\t* enforce-asg: cleaning up: clean up parent chain: iptables call: running [/var/vcap/packages/iptables/sbin/iptables -t filter -D netout--6de68121-5eb5-47f6-4 -p icmp -m iprange --dst-range 0.0.0.0-255.255.255.255 -m icmp --icmp-type any -j ACCEPT --wait]: exit status 1: iptables: Bad rule (does a matching rule exist in that chain?).\n and unlock: \u003cnil\u003e\n\n\n","stdin":"{\"Pid\":428166,\"Properties\":{\"app_id\":\"5355a9d8-00a9-43f5-af13-d3f83c4a39d1\",\"container_workload\":\"app\",\"org_id\":\"f2c2cf77-71b2-4a11-830f-f51758d6fc85\",\"policy_group_id\":\"5355a9d8-00a9-43f5-af13-d3f83c4a39d1\",\"ports\":\"8080\",\"space_id\":\"d47b339b-c948-4ca5-8720-e94a00a6d2ff\"},\"netout_rules\":[{\"protocol\":3,\"networks\":[{\"start\":\"0.0.0.0\",\"end\":\"255.255.255.255\"}],\"icmps\":{\"type\":255,\"code\":1}}],\"netin\":[{\"host_port\":0,\"container_port\":8080},{\"host_port\":0,\"container_port\":2222},{\"host_port\":0,\"container_port\":61001},{\"host_port\":0,\"container_port\":61443},{\"host_port\":0,\"container_port\":61002}]}","stdout":""}}'
echo "${message}" | jq -r .data.stdin | jq -c .netout_rules  | ./rule-converter > sg.json
```
