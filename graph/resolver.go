package graph

import (
	"github.com/jdharms/threat-detect/graph/model"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type IPDetailsAdder interface {
	AddIPDetails(details model.IPDetails) error
}

type IPDetailsGetter interface {
	GetIPDetails(addr string) (model.IPDetails, error)
}

type DNSBLClient interface {
	Query(ip string) (string, error)
}

type Resolver struct {
	Adder  IPDetailsAdder
	Getter IPDetailsGetter
	DNSBL  DNSBLClient
}
