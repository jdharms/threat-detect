package dnsbl

import (
	"fmt"
	"net"
	"strings"
)

type SpamhausClient struct{}

func (sc SpamhausClient) Query(ip string) (string, error) {
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("%s is not a valid IPv4 address", ip)
	}

	// reverse ip octets
	octets := strings.Split(ip, ".")
	octets[0], octets[1], octets[2], octets[3] = octets[3], octets[2], octets[1], octets[0]
	reversed := strings.Join(octets, ".")

	queryAddress := reversed + ".zen.spamhaus.org"

	results, err := net.LookupHost(queryAddress)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return "", nil
		}

		return "", err
	}

	var builder strings.Builder
	for i, code := range results {
		if i == 0 {
			builder.WriteString(code)
		} else {
			builder.WriteString(fmt.Sprintf(",%s", code))
		}
	}

	return builder.String(), nil
}
