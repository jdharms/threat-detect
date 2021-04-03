package db

import (
	"fmt"

	"github.com/jdharms/threat-detect/graph/model"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

type Client struct {
	db *sqlx.DB
}

func NewClient(path string) (*Client, error) {
	sqliteDb, err := sqlx.Open("sqlite3", fmt.Sprintf("file:%s", path))
	if err != nil {
		return nil, err
	}

	err = sqliteDb.Ping()
	if err != nil {
		return nil, err
	}

	return &Client{db: sqliteDb}, nil
}

func (c *Client) Close() error {
	return c.db.Close()
}

func (c *Client) AddIPDetails(details model.IPDetails) error {
	_, err := c.db.Exec(
		"INSERT INTO detail(id, created_at, updated_at, response_code, ip_address) VALUES ($1, $2, $3, $4, $5)",
		details.UUID,
		details.CreatedAt,
		details.UpdatedAt,
		details.ResponseCode,
		details.IPAddress,
	)

	return err
}

func (c *Client) GetIPDetails(addr string) (model.IPDetails, error) {
	var details IPDetails
	var res model.IPDetails
	if err := c.db.Get(&details, "SELECT * FROM detail WHERE ip_address = ?", addr); err != nil {
		return res, err
	}

	res = dbModelToGraphQL(details)
	return res, nil
}
