package dnsbl

import (
	"fmt"
	"net"
	"strings"
)

// Assigning net.LookupHost to a package internal variable lets us patch it away for tests without
// disrupting users of this package.
var netLookupHost = net.LookupHost

type SpamhausClient struct{}

func NewSpamhausClient() SpamhausClient {
	return SpamhausClient{}
}

func (sc SpamhausClient) Query(ip string) (string, error) {
	if net.ParseIP(ip) == nil {
		return "", newInvalidIPv4AddrError(ip)
	}

	reversed, err := reverseOctets(ip)
	if err != nil {
		return "", err
	}

	queryAddress := reversed + ".zen.spamhaus.org"

	results, err := netLookupHost(queryAddress)
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

// Caller may want to know if failure is due to an invalid IP, so we'll make this a separate type.
type InvalidIPv4AddrError struct {
	ip string
}

func newInvalidIPv4AddrError(ip string) InvalidIPv4AddrError {
	return InvalidIPv4AddrError{ip: ip}
}

func (i InvalidIPv4AddrError) Error() string {
	return fmt.Sprintf("%s is not a valid IPv4 address", i.ip)
}

func reverseOctets(addr string) (string, error) {
	octets := strings.Split(addr, ".")
	if len(octets) != 4 {
		return "", newInvalidIPv4AddrError(addr)
	}
	octets[0], octets[1], octets[2], octets[3] = octets[3], octets[2], octets[1], octets[0]
	reversed := strings.Join(octets, ".")
	return reversed, nil
}
