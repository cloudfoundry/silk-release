package rules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/shlex"
)

type IPTablesRule []string

func NewIPTablesRuleFromIPTablesLine(line string) (IPTablesRule, error) {
	args, err := shlex.Split(line)
	return IPTablesRule(args), err
}

func AppendComment(rule IPTablesRule, comment string) IPTablesRule {
	comment = strings.Replace(comment, " ", "_", -1)
	return IPTablesRule(
		append(rule, "-m", "comment", "--comment", comment),
	)
}

func NewPortForwardingRule(hostPort, containerPort int, hostIP, containerIP string) IPTablesRule {
	return IPTablesRule{
		"-d", hostIP, "-p", "tcp",
		"-m", "tcp", "--dport", fmt.Sprintf("%d", hostPort),
		"--jump", "DNAT",
		"--to-destination", fmt.Sprintf("%s:%d", containerIP, containerPort),
	}
}

func NewIngressMarkRules(hostInterfaceNames []string, hostPort int, hostIP, tag string) []IPTablesRule {
	jumpConditions := make([]IPTablesRule, len(hostInterfaceNames))

	for i, hostInterfaceName := range hostInterfaceNames {
		jumpConditions[i] = IPTablesRule{
			"-i", hostInterfaceName, "-d", hostIP, "-p", "tcp",
			"-m", "tcp", "--dport", fmt.Sprintf("%d", hostPort),
			"--jump", "MARK",
			"--set-mark", fmt.Sprintf("0x%s", tag),
		}
	}

	return jumpConditions
}

func NewNetOutJumpConditions(hostInterfaceNames []string, hostIP, forwardChainName string) []IPTablesRule {
	jumpConditions := make([]IPTablesRule, len(hostInterfaceNames))

	for i, hostInterfaceName := range hostInterfaceNames {
		jumpConditions[i] = IPTablesRule{
			"-s", hostIP,
			"-o", hostInterfaceName,
			"--jump", forwardChainName,
		}
	}

	return jumpConditions
}

func NewMarkAllowRuleNoComment(destinationIP, protocol string, port int, tag string) IPTablesRule {
	return IPTablesRule{
		"-d", destinationIP,
		"-p", protocol,
		"-m", protocol, "--dport", fmt.Sprintf("%d", port),
		"-m", "mark", "--mark", fmt.Sprintf("0x%s", tag),
		"--jump", "ACCEPT",
	}
}

func NewMarkAllowRule(destinationIP, protocol string, startPort, endPort int, tag string, sourceAppGUID, destinationAppGUID string) IPTablesRule {
	return AppendComment(IPTablesRule{
		"-d", destinationIP,
		"-p", protocol,
		"--dport", fmt.Sprintf("%d:%d", startPort, endPort),
		"-m", "mark", "--mark", fmt.Sprintf("0x%s", tag),
		"--jump", "ACCEPT",
	}, fmt.Sprintf("src:%s_dst:%s", sourceAppGUID, destinationAppGUID))
}

func NewMarkAllowLogRule(destinationIP, protocol string, startPort, endPort int, tag string, destinationAppGUID string, acceptedUDPLogsPerSec int) IPTablesRule {
	if protocol != "udp" {
		return IPTablesRule{
			"-d", destinationIP,
			"-p", protocol,
			"--dport", fmt.Sprintf("%d:%d", startPort, endPort),
			"-m", "mark", "--mark", fmt.Sprintf("0x%s", tag),
			"-m", "conntrack", "--ctstate", "INVALID,NEW,UNTRACKED",
			"--jump", "LOG", "--log-prefix",
			trimAndPad(fmt.Sprintf("OK_%s_%s", tag, destinationAppGUID))}
	} else {
		return IPTablesRule{
			"-d", destinationIP,
			"-p", protocol,
			"--dport", fmt.Sprintf("%d:%d", startPort, endPort),
			"-m", "mark", "--mark", fmt.Sprintf("0x%s", tag),
			"-m", "limit",
			"--limit", fmt.Sprintf("%d/s", acceptedUDPLogsPerSec),
			"--limit-burst", strconv.Itoa(acceptedUDPLogsPerSec),
			"--jump", "LOG", "--log-prefix",
			trimAndPad(fmt.Sprintf("OK_%s_%s", tag, destinationAppGUID))}
	}
}

func NewMarkSetRule(sourceIP, tag, appGUID string) IPTablesRule {
	return AppendComment(IPTablesRule{
		"--source", sourceIP,
		"--jump", "MARK", "--set-xmark", fmt.Sprintf("0x%s", tag),
	}, fmt.Sprintf("src:%s", appGUID))
}

func NewDefaultEgressRule(localSubnet, noMasqueradeCIDRRange, deviceName string) IPTablesRule {
	ipTablesRule := IPTablesRule{
		"--source", localSubnet,
		"!", "-o", deviceName,
	}
	if noMasqueradeCIDRRange != "" {
		ipTablesRule = append(ipTablesRule, "!", "--destination", noMasqueradeCIDRRange)
	}
	ipTablesRule = append(ipTablesRule, "--jump", "MASQUERADE")
	return ipTablesRule
}

func NewLogRule(rule IPTablesRule, name string) IPTablesRule {
	return IPTablesRule(append(
		rule, "-m", "limit", "--limit", "2/min",
		"--jump", "LOG",
		"--log-prefix", trimAndPad(name),
	))
}

func NewAcceptExistingLocalRule() IPTablesRule {
	return IPTablesRule{
		"-m", "state", "--state", "ESTABLISHED,RELATED",
		"--jump", "ACCEPT",
	}
}

func NewLogLocalRejectRule(localSubnet string) IPTablesRule {
	return NewLogRule(
		IPTablesRule{
			"-s", localSubnet,
			"-d", localSubnet,
		},
		"REJECT_LOCAL: ",
	)
}

func NewDefaultDenyLocalRule(localSubnet string) IPTablesRule {
	return IPTablesRule{
		"--source", localSubnet,
		"-d", localSubnet,
		"--jump", "REJECT",
	}
}

func NewNetOutRule(startIP, endIP string) IPTablesRule {
	return IPTablesRule{
		"-m", "iprange",
		"--dst-range", fmt.Sprintf("%s-%s", startIP, endIP),
		"--jump", "ACCEPT",
	}
}

func NewNetOutWithPortsRule(startIP, endIP string, startPort, endPort int, protocol string) IPTablesRule {
	return IPTablesRule{
		"-m", "iprange",
		"-p", protocol,
		"--dst-range", fmt.Sprintf("%s-%s", startIP, endIP),
		"-m", protocol,
		"--destination-port", fmt.Sprintf("%d:%d", startPort, endPort),
		"--jump", "ACCEPT",
	}
}

func NewNetOutICMPRule(startIP, endIP string, icmpType, icmpCode int) IPTablesRule {
	return IPTablesRule{
		"-m", "iprange",
		"-p", "icmp",
		"--dst-range", fmt.Sprintf("%s-%s", startIP, endIP),
		"-m", "icmp",
		"--icmp-type", fmt.Sprintf("%d/%d", icmpType, icmpCode),
		"--jump", "ACCEPT",
	}
}

func NewNetOutICMPLogRule(startIP, endIP string, icmpType, icmpCode int, chain string) IPTablesRule {
	return IPTablesRule{
		"-m", "iprange",
		"-p", "icmp",
		"--dst-range", fmt.Sprintf("%s-%s", startIP, endIP),
		"-m", "icmp",
		"--icmp-type", fmt.Sprintf("%d/%d", icmpType, icmpCode),
		"-g", chain,
	}
}

func NewNetOutLogRule(startIP, endIP, chain string) IPTablesRule {
	return IPTablesRule{
		"-m", "iprange",
		"--dst-range", fmt.Sprintf("%s-%s", startIP, endIP),
		"-g", chain,
	}
}

func NewNetOutWithPortsLogRule(startIP, endIP string, startPort, endPort int, protocol, chain string) IPTablesRule {
	return IPTablesRule{
		"-m", "iprange",
		"-p", protocol,
		"--dst-range", fmt.Sprintf("%s-%s", startIP, endIP),
		"-m", protocol,
		"--destination-port", fmt.Sprintf("%d:%d", startPort, endPort),
		"-g", chain,
	}
}

func NewNetOutDefaultNonUDPLogRule(prefix string) IPTablesRule {
	return IPTablesRule{
		"!", "-p", "udp",
		"-m", "conntrack", "--ctstate", "INVALID,NEW,UNTRACKED",
		"-j", "LOG", "--log-prefix", trimAndPad(fmt.Sprintf("OK_%s", prefix)),
	}
}

func NewNetOutDefaultUDPLogRule(prefix string, acceptedUDPLogsPerSec int) IPTablesRule {
	return IPTablesRule{
		"-p", "udp",
		"-m", "limit", "--limit", fmt.Sprintf("%d/s", acceptedUDPLogsPerSec),
		"--limit-burst", strconv.Itoa(acceptedUDPLogsPerSec),
		"-j", "LOG", "--log-prefix", trimAndPad(fmt.Sprintf("OK_%s", prefix)),
	}
}

func NewAcceptRule() IPTablesRule {
	return IPTablesRule{
		"--jump", "ACCEPT",
	}
}

func NewAcceptEverythingRule(ipRange string) IPTablesRule {
	return IPTablesRule{
		"-s", ipRange, "-d", ipRange, "-j", "ACCEPT",
	}
}

func NewInputRelatedEstablishedRule() IPTablesRule {
	return IPTablesRule{
		"-m", "state", "--state", "RELATED,ESTABLISHED",
		"--jump", "ACCEPT",
	}
}

func NewInputAllowRule(protocol, destination string, destPort int) IPTablesRule {
	return IPTablesRule{
		"-p", protocol,
		"-d", destination, "--destination-port", strconv.Itoa(destPort),
		"--jump", "ACCEPT",
	}
}

func NewInputRejectRule(destinationIP string) IPTablesRule {
	return IPTablesRule{
		"-d", destinationIP,
		"--jump", "REJECT",
		"--reject-with", "icmp-port-unreachable",
	}
}

func NewInputDefaultRejectRule() IPTablesRule {
	return IPTablesRule{
		"--jump", "REJECT",
		"--reject-with", "icmp-port-unreachable",
	}
}

func NewNetOutInvalidRule() IPTablesRule {
	return IPTablesRule{
		"-p", "tcp", "-m", "state", "--state", "INVALID",
		"--jump", "DROP",
	}
}

func NewNetOutRelatedEstablishedRule() IPTablesRule {
	return IPTablesRule{
		"-m", "state", "--state", "RELATED,ESTABLISHED",
		"--jump", "ACCEPT",
	}
}

func NewNetOutConnRateLimitRule(rate, burst, containerHandle, expiryPeriod, rateLimitLogChainName string) IPTablesRule {
	return IPTablesRule{
		"-p", "tcp",
		"-m", "conntrack", "--ctstate", "NEW",
		"-m", "hashlimit", "--hashlimit-above", rate, "--hashlimit-burst", burst,
		"--hashlimit-mode", "dstip,dstport", "--hashlimit-name", containerHandle,
		"--hashlimit-htable-expire", expiryPeriod, "-j", rateLimitLogChainName,
	}
}

func NewOverlayTagAcceptRule(containerIP, tag string) IPTablesRule {
	return IPTablesRule{
		"-d", containerIP,
		"-m", "mark", "--mark", fmt.Sprintf("0x%s", tag),
		"--jump", "ACCEPT",
	}
}

func NewOverlayDefaultRejectRule(containerIP string) IPTablesRule {
	return IPTablesRule{
		"-d", containerIP,
		"--jump", "REJECT",
		"--reject-with", "icmp-port-unreachable",
	}
}

func NewOverlayDefaultRejectLogRule(containerHandle, containerIP string, deniedLogsPerSec int) IPTablesRule {
	return IPTablesRule{
		"-d", containerIP,
		"-m", "limit", "--limit", fmt.Sprintf("%d/s", deniedLogsPerSec),
		"--limit-burst", strconv.Itoa(deniedLogsPerSec),
		"--jump", "LOG",
		"--log-prefix", trimAndPad(fmt.Sprintf("DENY_C2C_%s", containerHandle)),
	}
}

func NewOverlayAllowEgress(deviceName, containerIP string) IPTablesRule {
	return IPTablesRule{
		"-s", containerIP,
		"-o", deviceName,
		"-m", "mark", "!", "--mark", "0x0",
		"--jump", "ACCEPT",
	}
}

func NewOverlayRelatedEstablishedRule(containerIP string) IPTablesRule {
	return IPTablesRule{
		"-d", containerIP,
		"-m", "state", "--state", "RELATED,ESTABLISHED",
		"--jump", "ACCEPT",
	}
}

func NewNetOutDefaultRejectLogRule(containerHandle string, deniedLogsPerSec int) IPTablesRule {
	return newNetOutRejectLogRule(containerHandle, "DENY", deniedLogsPerSec)
}

func NewNetOutConnRateLimitRejectLogRule(containerHandle string, deniedLogsPerSec int) IPTablesRule {
	return newNetOutRejectLogRule(containerHandle, "DENY_ORL", deniedLogsPerSec)
}

func NewNetOutDefaultRejectRule() IPTablesRule {
	return IPTablesRule{
		"--jump", "REJECT",
		"--reject-with", "icmp-port-unreachable",
	}
}

func NewOverlayAccessMarkRule(tag string) IPTablesRule {
	return IPTablesRule{
		"-o", "silk-vtep",
		"-j", "MARK",
		"--set-mark", fmt.Sprintf("0x%s", tag),
	}
}

func NewEgress(interfaceName, ip, protocol, ipStart, ipEnd string, icmpType, icmpCode, portStart, portEnd int) IPTablesRule {
	egressRule := IPTablesRule{
		"-s", ip,
		"-o", interfaceName,
		"-p", protocol,
		"-m", "iprange",
		"--dst-range", fmt.Sprintf("%s-%s", ipStart, ipEnd),
	}

	if protocol == "icmp" {
		if icmpType != -1 {
			icmpType := strconv.Itoa(icmpType)
			if icmpCode != -1 {
				icmpType += "/" + strconv.Itoa(icmpCode)
			}
			egressRule = append(egressRule, "-m", "icmp", "--icmp-type", icmpType)
		}
	}

	if (portStart != 0 && portEnd != 0) && (protocol == "tcp" || protocol == "udp") {
		egressRule = append(egressRule,
			"-m", protocol,
			"--dport", fmt.Sprintf("%d:%d", portStart, portEnd))
	}

	egressRule = append(egressRule, "-j", "ACCEPT")

	return egressRule
}

func trimAndPad(name string) string {
	if len(name) > 28 {
		name = name[:28]
	}
	return fmt.Sprintf(`"%s "`, name)
}

func newNetOutRejectLogRule(containerHandle, prefix string, deniedLogsPerSec int) IPTablesRule {
	return IPTablesRule{
		"-m", "limit", "--limit", fmt.Sprintf("%d/s", deniedLogsPerSec),
		"--limit-burst", strconv.Itoa(deniedLogsPerSec),
		"--jump", "LOG",
		"--log-prefix", trimAndPad(fmt.Sprintf("%s_%s", prefix, containerHandle)),
	}
}
