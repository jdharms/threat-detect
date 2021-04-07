package db

import (
	"fmt"
	"time"

	"github.com/jdharms/threat-detect/graph/model"
)

type IPDetails struct {
	UUID         string    `db:"id"`
	CreatedAt    time.Time `db:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"`
	ResponseCode string    `db:"response_code"`
	IPAddress    string    `db:"ip_address"`
}

func dbModelToGraphQL(d IPDetails) model.IPDetails {
	res := model.IPDetails{
		UUID:         d.UUID,
		CreatedAt:    d.CreatedAt,
		UpdatedAt:    d.UpdatedAt,
		ResponseCode: d.ResponseCode,
		IPAddress:    d.IPAddress, //
	}

	return res
}

type ErrNotFound struct {
	ipAddr   string
	innerErr error
}

func (e ErrNotFound) Error() string {
	return fmt.Sprintf("details for ip address %s not found", e.ipAddr)
}

func (e ErrNotFound) Unwrap() error {
	return e.innerErr
}

func newErrNotFound(ipAddr string, innerErr error) ErrNotFound {
	return ErrNotFound{
		ipAddr:   ipAddr,
		innerErr: innerErr,
	}
}
