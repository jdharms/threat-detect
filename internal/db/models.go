package db

import (
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
		IPAddress:    d.IPAddress,
	}

	return res
}
