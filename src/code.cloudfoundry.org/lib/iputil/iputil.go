package iputil

import (
	"fmt"
	"net"
)

type IPVersion int

const (
	InvalidIPVersion IPVersion = iota
	IPVersion4       IPVersion = 4
	IPVersion6       IPVersion = 6
)

func GetFamily(ip net.IP) IPVersion {
	if len(ip) == 0 {
		return InvalidIPVersion
	}
	if ip.To4() != nil {
		return IPVersion4
	}
	if ip.To16() != nil {
		return IPVersion6
	}
	return InvalidIPVersion
}

func FilterIPsByVersion(ipStrs []string, version IPVersion) ([]string, error) {
	filtered := make([]string, 0, len(ipStrs))

	for _, str := range ipStrs {
		ip := net.ParseIP(str)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP string: %s", str)
		}

		family := GetFamily(ip)

		if family == version {
			filtered = append(filtered, str)
		}
	}

	return filtered, nil
}
