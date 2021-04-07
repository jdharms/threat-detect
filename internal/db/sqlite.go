package db

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jdharms/threat-detect/graph/model"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

type Client struct {
	db *sqlx.DB
}

var sqliteDbOpener = func(path string) (*sqlx.DB, error) {
	return sqlx.Open("sqlite3", path)
}

var initStmt = `CREATE TABLE IF NOT EXISTS detail
(
	id TEXT PRIMARY KEY,
	created_at DATETIME,
	updated_at DATETIME,
	response_code TEXT,
	ip_address TEXT
);`

func NewClient(path string) (*Client, error) {
	sqliteDb, err := sqliteDbOpener(fmt.Sprintf("file:%s?_journal_mode=WAL&_txlock=immediate", path))
	if err != nil {
		return nil, err
	}

	err = sqliteDb.Ping()
	if err != nil {
		sqliteDb.Close()
		return nil, err
	}

	_, err = sqliteDb.Exec(initStmt)
	if err != nil {
		sqliteDb.Close()
		return nil, err
	}

	return &Client{db: sqliteDb}, nil
}

func (c *Client) Close() error {
	return c.db.Close()
}

// AddIPDetails takes a partially filled in IPDetails structure
// and either adds it to the database or updates an existing record
// if it exists.  This process is transparent to the caller.
func (c *Client) AddIPDetails(details model.IPDetails) error {
	id := uuid.New().String()
	createdAt := time.Now()
	updatedAt := createdAt

	var existingDetails IPDetails

	// We open an "immediate" transaction here to ensure nobody adds
	// a record for the same IP address before we do.
	tx, err := c.db.Begin()
	if err != nil {
		return fmt.Errorf("error starting transaction: %w", err)
	}
	rows, err := tx.Query("SELECT * FROM detail WHERE ip_address = ?", details.IPAddress)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("error checking for existing details: %w", err)
	}
	if rows.Next() {
		err = rows.Scan(&existingDetails.UUID, &existingDetails.CreatedAt, &existingDetails.UpdatedAt, &existingDetails.ResponseCode, &existingDetails.IPAddress)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("error scanning db result: %w", err)
		}
		id = existingDetails.UUID
		createdAt = existingDetails.CreatedAt
	}

	_, err = tx.Exec(
		"INSERT OR REPLACE INTO detail(id, created_at, updated_at, response_code, ip_address) VALUES ($1, $2, $3, $4, $5)",
		id,
		createdAt,
		updatedAt,
		details.ResponseCode,
		details.IPAddress,
	)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("error inserting row")
	}
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("error commiting tx: %w", err)
	}

	return err
}

func (c *Client) GetIPDetails(addr string) (model.IPDetails, error) {
	var details IPDetails
	var res model.IPDetails
	if err := c.db.Get(&details, "SELECT * FROM detail WHERE ip_address = ?", addr); err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return res, newErrNotFound(addr, err)
		}
		return res, err
	}

	res = dbModelToGraphQL(details)
	return res, nil
}
