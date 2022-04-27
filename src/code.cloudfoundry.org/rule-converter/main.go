package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"code.cloudfoundry.org/cni-wrapper-plugin/netrules"
	"code.cloudfoundry.org/garden"
)

func main() {
	asgs := []SecurityGroupRule{}
	// read rules from stdin
	scanner := bufio.NewScanner(os.Stdin)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		line := scanner.Text()
		rule := garden.NetOutRule{}
		err := json.Unmarshal([]byte(line), &rule)
		if err != nil {
			log.Fatalf("Error unmarshalling '%s' to a garden.NetOutRule: %s", line, err)
		}

		asgRule := netoutToASGRule(rule)

		asgs = append(asgs, asgRule)
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading from stdin: %s", err)
	}

	data, err := json.Marshal(asgs)
	if err != nil {
		log.Fatalf("Couldn't json encode ASG rules: %s", err)
	}
	fmt.Printf("%s\n", data)
}

type SecurityGroupRule struct {
	Protocol    string           `json:"protocol"`
	Destination string           `json:"destination"`
	Ports       string           `json:"ports,omitempty"`
	Type        *garden.ICMPType `json:"type,omitempty"`
	Code        *garden.ICMPCode `json:"code,omitempty"`
	Description string           `json:"description,omitempty"`
	Log         bool             `json:"log"`
}

type intptr *int

func netoutToASGRule(rule garden.NetOutRule) SecurityGroupRule {

	sg := SecurityGroupRule{}

	switch rule.Protocol {
	case garden.ProtocolTCP:
		sg.Protocol = string(netrules.ProtocolTCP)
	case garden.ProtocolUDP:
		sg.Protocol = string(netrules.ProtocolUDP)
	case garden.ProtocolICMP:
		sg.Protocol = string(netrules.ProtocolICMP)
		sg.Type = &rule.ICMPs.Type
		sg.Code = rule.ICMPs.Code
	case garden.ProtocolAll:
		sg.Protocol = string(netrules.ProtocolAll)
	}
	sg.Destination = fmt.Sprintf("%s-%s", rule.Networks[0].Start.String(), rule.Networks[0].End.String())
	if len(rule.Ports) > 0 {
		if rule.Ports[0].Start != rule.Ports[0].End {
			sg.Ports = fmt.Sprintf("%d-%d", rule.Ports[0].Start, rule.Ports[0].End)
		} else {
			sg.Ports = fmt.Sprintf("%d", rule.Ports[0].Start)
		}
	}
	sg.Log = rule.Log

	return sg
}
