package dnsbl

import (
	"fmt"
	"strings"
	"testing"
)

type lookupMock struct {
	ReceivedIP    string
	ResultStrings []string
	ResultError   error
}

func netLookupPatch(mock *lookupMock) func(string) ([]string, error) {
	return func(s string) ([]string, error) {
		mock.ReceivedIP = s
		return mock.ResultStrings, mock.ResultError
	}
}

func TestSpamhausQuery(t *testing.T) {
	testCases := []struct {
		name            string
		ip              string
		lookupHostRecvd string
		mock            lookupMock
		expectedRes     string
		errKey          string
	}{
		{
			"test invalid ip",
			"foobar",
			"",
			lookupMock{ResultStrings: nil, ResultError: newInvalidIPv4AddrError("foobar")},
			"",
			"valid",
		},
		{
			"test octets reversed",
			"1.2.3.4",
			"4.3.2.1.zen.spamhaus.org",
			lookupMock{ResultStrings: []string{"a", "b"}, ResultError: nil},
			"a,b",
			"",
		},
		{
			"not found in spamhaus blocklist",
			"1.2.3.4",
			"4.3.2.1.zen.spamhaus.org",
			lookupMock{ResultStrings: nil, ResultError: fmt.Errorf("no such host")},
			"",
			"",
		},
		{
			"test one result",
			"1.2.3.4",
			"4.3.2.1.zen.spamhaus.org",
			lookupMock{ResultStrings: []string{"a"}, ResultError: nil},
			"a",
			"",
		},
		{
			"test error on lookup",
			"1.2.3.4",
			"4.3.2.1.zen.spamhaus.org",
			lookupMock{ResultStrings: nil, ResultError: fmt.Errorf("some unknown error")},
			"",
			"error",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			netLookupHost = netLookupPatch(&test.mock)
			c := NewSpamhausClient()
			res, err := c.Query(test.ip)
			if !errorContains(err, test.errKey) {
				t.Errorf("Expected error '%s' but found '%s'", test.errKey, err.Error())
			}
			if res != test.expectedRes {
				t.Errorf("Expected result '%s' but got '%s'", test.expectedRes, res)
			}
			if test.mock.ReceivedIP != test.lookupHostRecvd {
				t.Errorf("Call to net.LookupHost expected for '%s' but got '%s'", test.lookupHostRecvd, test.mock.ReceivedIP)
			}
		})

	}
}

func errorContains(e error, want string) bool {
	if e == nil {
		return want == ""
	}
	if want == "" {
		return false
	}
	return strings.Contains(e.Error(), want)
}
