package db

import (
	"fmt"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jdharms/threat-detect/graph/model"
	"github.com/jmoiron/sqlx"
)

func TestSqliteNewClient(t *testing.T) {
	mockDb, myMock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Errorf("unexpected error creating mock db: %s", err.Error())
	}

	// insert mock db into package
	sqliteDbOpener = func(dataSource string) (*sqlx.DB, error) {
		return sqlx.NewDb(mockDb, "sqlmock"), nil
	}

	myMock.ExpectPing()
	myMock.ExpectExec("CREATE TABLE IF NOT EXISTS detail").WillReturnResult(sqlmock.NewResult(1, 1))
	myMock.ExpectClose()

	db, err := NewClient("somefile.db")
	if err != nil {
		t.Errorf("unexpected error creating sqlite client: %s", err.Error())
	}

	err = db.Close()
	if err != nil {
		t.Error(err.Error())
	}

	err = myMock.ExpectationsWereMet()
	if err != nil {
		t.Error(err.Error())
	}
}

func TestSqliteNewClientReturnsErrorOnBadOpen(t *testing.T) {
	// insert mock db into package
	sqliteDbOpener = func(dataSource string) (*sqlx.DB, error) {
		return nil, fmt.Errorf("some error")
	}

	_, err := NewClient("somefile.db")
	if err == nil {
		t.Errorf("expected error creating sqlite client but didn't receive one")
	}
}

func TestSqliteNewClientErrOnBadPing(t *testing.T) {
	mockDb, myMock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Errorf("unexpected error creating mock db: %s", err.Error())
	}

	// insert mock db into package
	sqliteDbOpener = func(dataSource string) (*sqlx.DB, error) {
		return sqlx.NewDb(mockDb, "sqlmock"), nil
	}

	myMock.ExpectPing().WillReturnError(fmt.Errorf("some error"))
	myMock.ExpectClose()

	_, err = NewClient("somefile.db")
	if err == nil {
		t.Errorf("expected error creating sqlite client but didn't receive one")
	}

	err = myMock.ExpectationsWereMet()
	if err != nil {
		t.Error(err.Error())
	}
}

func TestSqliteNewClientErrOnBadInit(t *testing.T) {
	mockDb, myMock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Errorf("unexpected error creating mock db: %s", err.Error())
	}

	// insert mock db into package
	sqliteDbOpener = func(dataSource string) (*sqlx.DB, error) {
		return sqlx.NewDb(mockDb, "sqlmock"), nil
	}

	myMock.ExpectPing()
	myMock.ExpectExec("CREATE TABLE IF NOT EXISTS detail").WillReturnError(fmt.Errorf("some error"))
	myMock.ExpectClose()

	_, err = NewClient("somefile.db")
	if err == nil {
		t.Errorf("error expected creating sqlite client but didn't receive one")
	}

	err = myMock.ExpectationsWereMet()
	if err != nil {
		t.Error(err.Error())
	}
}

func TestSqliteAddIPDetails(t *testing.T) {
	mockDb, myMock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Errorf("unexpected error creating mock db: %s", err.Error())
	}

	// insert mock db into package
	sqliteDbOpener = func(dataSource string) (*sqlx.DB, error) {
		return sqlx.NewDb(mockDb, "sqlmock"), nil
	}

	testDetails := model.IPDetails{
		UUID:         "61996e6d-bffd-42eb-9641-7567e709f6a7",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		ResponseCode: "123456",
		IPAddress:    "127.0.0.1",
	}

	myMock.ExpectPing()
	myMock.ExpectExec("CREATE TABLE IF NOT EXISTS detail").WillReturnResult(sqlmock.NewResult(1, 1))
	myMock.ExpectBegin()
	myMock.ExpectQuery("SELECT \\* FROM detail").WithArgs("127.0.0.1").WillReturnRows(&sqlmock.Rows{})
	myMock.ExpectExec("INSERT OR REPLACE INTO detail").WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), testDetails.ResponseCode, testDetails.IPAddress).WillReturnResult(sqlmock.NewResult(1, 1))
	myMock.ExpectCommit()
	myMock.ExpectClose()

	db, err := NewClient("somefile.db")
	if err != nil {
		t.Errorf("unexpected error creating sqlite client: %s", err.Error())
	}

	err = db.AddIPDetails(testDetails)
	if err != nil {
		t.Error(err.Error())
	}

	err = db.Close()
	if err != nil {
		t.Error(err.Error())
	}

	err = myMock.ExpectationsWereMet()
	if err != nil {
		t.Error(err.Error())
	}
}

func TestSqliteUpdateIPDetails(t *testing.T) {
	mockDb, myMock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Errorf("unexpected error creating mock db: %s", err.Error())
	}

	// insert mock db into package
	sqliteDbOpener = func(dataSource string) (*sqlx.DB, error) {
		return sqlx.NewDb(mockDb, "sqlmock"), nil
	}

	testDetails := model.IPDetails{
		UUID:         "61996e6d-bffd-42eb-9641-7567e709f6a7",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		ResponseCode: "123456",
		IPAddress:    "127.0.0.1",
	}

	rows := sqlmock.NewRows([]string{"id", "created_at", "updated_at", "response_code", "ip_address"}).AddRow(
		testDetails.UUID,
		testDetails.CreatedAt,
		testDetails.UpdatedAt,
		testDetails.ResponseCode,
		testDetails.IPAddress,
	)

	myMock.ExpectPing()
	myMock.ExpectExec("CREATE TABLE IF NOT EXISTS detail").WillReturnResult(sqlmock.NewResult(1, 1))
	myMock.ExpectBegin()
	myMock.ExpectQuery("SELECT \\* FROM detail").WithArgs("127.0.0.1").WillReturnRows(rows)
	myMock.ExpectExec("INSERT OR REPLACE INTO detail").WithArgs(testDetails.UUID, testDetails.CreatedAt, sqlmock.AnyArg(), sqlmock.AnyArg(), testDetails.IPAddress).WillReturnResult(sqlmock.NewResult(1, 1))
	myMock.ExpectCommit()
	myMock.ExpectClose()

	db, err := NewClient("somefile.db")
	if err != nil {
		t.Errorf("unexpected error creating sqlite client: %s", err.Error())
	}

	err = db.AddIPDetails(testDetails)
	if err != nil {
		t.Error(err.Error())
	}

	err = db.Close()
	if err != nil {
		t.Error(err.Error())
	}

	err = myMock.ExpectationsWereMet()
	if err != nil {
		t.Error(err.Error())
	}
}

func TestSqliteAddIPDetailsTxErr(t *testing.T) {
	mockDb, myMock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Errorf("unexpected error creating mock db: %s", err.Error())
	}

	// insert mock db into package
	sqliteDbOpener = func(dataSource string) (*sqlx.DB, error) {
		return sqlx.NewDb(mockDb, "sqlmock"), nil
	}

	testDetails := model.IPDetails{
		UUID:         "61996e6d-bffd-42eb-9641-7567e709f6a7",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		ResponseCode: "123456",
		IPAddress:    "127.0.0.1",
	}

	myMock.ExpectPing()
	myMock.ExpectExec("CREATE TABLE IF NOT EXISTS detail").WillReturnResult(sqlmock.NewResult(1, 1))
	myMock.ExpectBegin().WillReturnError(fmt.Errorf("some error"))
	myMock.ExpectClose()

	db, err := NewClient("somefile.db")
	if err != nil {
		t.Errorf("unexpected error creating sqlite client: %s", err.Error())
	}

	err = db.AddIPDetails(testDetails)
	if err == nil {
		t.Error("expected error from AddIPDetails when Begin() fails")
	}

	err = db.Close()
	if err != nil {
		t.Error(err.Error())
	}

	err = myMock.ExpectationsWereMet()
	if err != nil {
		t.Error(err.Error())
	}
}

func TestSqliteAddIPDetailsQueryErr(t *testing.T) {
	mockDb, myMock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Errorf("unexpected error creating mock db: %s", err.Error())
	}

	// insert mock db into package
	sqliteDbOpener = func(dataSource string) (*sqlx.DB, error) {
		return sqlx.NewDb(mockDb, "sqlmock"), nil
	}

	testDetails := model.IPDetails{
		UUID:         "61996e6d-bffd-42eb-9641-7567e709f6a7",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		ResponseCode: "123456",
		IPAddress:    "127.0.0.1",
	}

	myMock.ExpectPing()
	myMock.ExpectExec("CREATE TABLE IF NOT EXISTS detail").WillReturnResult(sqlmock.NewResult(1, 1))
	myMock.ExpectBegin()
	myMock.ExpectQuery("SELECT \\* FROM detail").WithArgs("127.0.0.1").WillReturnError(fmt.Errorf("some error"))
	myMock.ExpectRollback()
	myMock.ExpectClose()

	db, err := NewClient("somefile.db")
	if err != nil {
		t.Errorf("unexpected error creating sqlite client: %s", err.Error())
	}

	err = db.AddIPDetails(testDetails)
	if err == nil {
		t.Error("expected error from AddIPDetail")
	}

	err = db.Close()
	if err != nil {
		t.Error(err.Error())
	}

	err = myMock.ExpectationsWereMet()
	if err != nil {
		t.Error(err.Error())
	}
}

func TestSqliteAddIPDetailsInsertErr(t *testing.T) {
	mockDb, myMock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Errorf("unexpected error creating mock db: %s", err.Error())
	}

	// insert mock db into package
	sqliteDbOpener = func(dataSource string) (*sqlx.DB, error) {
		return sqlx.NewDb(mockDb, "sqlmock"), nil
	}

	testDetails := model.IPDetails{
		UUID:         "61996e6d-bffd-42eb-9641-7567e709f6a7",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		ResponseCode: "123456",
		IPAddress:    "127.0.0.1",
	}

	myMock.ExpectPing()
	myMock.ExpectExec("CREATE TABLE IF NOT EXISTS detail").WillReturnResult(sqlmock.NewResult(1, 1))
	myMock.ExpectBegin()
	myMock.ExpectQuery("SELECT \\* FROM detail").WithArgs("127.0.0.1").WillReturnRows(&sqlmock.Rows{})
	myMock.ExpectExec("INSERT OR REPLACE INTO detail").WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), testDetails.ResponseCode, testDetails.IPAddress).WillReturnError(fmt.Errorf("some error"))
	myMock.ExpectRollback()
	myMock.ExpectClose()

	db, err := NewClient("somefile.db")
	if err != nil {
		t.Errorf("unexpected error creating sqlite client: %s", err.Error())
	}

	err = db.AddIPDetails(testDetails)
	if err == nil {
		t.Error("expected error from AddIPDetail")
	}

	err = db.Close()
	if err != nil {
		t.Error(err.Error())
	}

	err = myMock.ExpectationsWereMet()
	if err != nil {
		t.Error(err.Error())
	}
}

func TestSqliteAddIPDetailsCommitErr(t *testing.T) {
	mockDb, myMock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Errorf("unexpected error creating mock db: %s", err.Error())
	}

	// insert mock db into package
	sqliteDbOpener = func(dataSource string) (*sqlx.DB, error) {
		return sqlx.NewDb(mockDb, "sqlmock"), nil
	}

	testDetails := model.IPDetails{
		UUID:         "61996e6d-bffd-42eb-9641-7567e709f6a7",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		ResponseCode: "123456",
		IPAddress:    "127.0.0.1",
	}

	myMock.ExpectPing()
	myMock.ExpectExec("CREATE TABLE IF NOT EXISTS detail").WillReturnResult(sqlmock.NewResult(1, 1))
	myMock.ExpectBegin()
	myMock.ExpectQuery("SELECT \\* FROM detail").WithArgs("127.0.0.1").WillReturnRows(&sqlmock.Rows{})
	myMock.ExpectExec("INSERT OR REPLACE INTO detail").WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), testDetails.ResponseCode, testDetails.IPAddress).WillReturnResult(sqlmock.NewResult(1, 1))
	myMock.ExpectCommit().WillReturnError(fmt.Errorf("some error"))
	myMock.ExpectClose()

	db, err := NewClient("somefile.db")
	if err != nil {
		t.Errorf("unexpected error creating sqlite client: %s", err.Error())
	}

	err = db.AddIPDetails(testDetails)
	if err == nil {
		t.Error("expected error from AddIPDetail when commit fails")
	}

	err = db.Close()
	if err != nil {
		t.Error(err.Error())
	}

	err = myMock.ExpectationsWereMet()
	if err != nil {
		t.Error(err.Error())
	}
}

func TestSqliteGetIPDetails(t *testing.T) {
	mockDb, myMock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Errorf("unexpected error creating mock db: %s", err.Error())
	}

	testDetails := model.IPDetails{
		UUID:         "61996e6d-bffd-42eb-9641-7567e709f6a7",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		ResponseCode: "123456",
		IPAddress:    "127.0.0.1",
	}

	// insert mock db into package
	sqliteDbOpener = func(dataSource string) (*sqlx.DB, error) {
		return sqlx.NewDb(mockDb, "sqlmock"), nil
	}

	myMock.ExpectPing()
	myMock.ExpectExec("CREATE TABLE IF NOT EXISTS detail").WillReturnResult(sqlmock.NewResult(1, 1))
	myMock.ExpectQuery("SELECT \\* FROM detail").WithArgs("127.0.0.1").WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at", "response_code", "ip_address"}).AddRow(testDetails.UUID, testDetails.CreatedAt, testDetails.UpdatedAt, testDetails.ResponseCode, testDetails.IPAddress))
	myMock.ExpectClose()

	db, err := NewClient("somefile.db")
	if err != nil {
		t.Errorf("unexpected error creating sqlite client: %s", err.Error())
	}

	d, err := db.GetIPDetails("127.0.0.1")
	if err != nil {
		t.Error(err.Error())
	}

	if d != testDetails {
		t.Error("details don't match expectation")
	}

	err = db.Close()
	if err != nil {
		t.Error(err.Error())
	}

	err = myMock.ExpectationsWereMet()
	if err != nil {
		t.Error(err.Error())
	}
}

func TestSqliteGetIPDetailsNotFound(t *testing.T) {
	mockDb, myMock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Errorf("unexpected error creating mock db: %s", err.Error())
	}

	// insert mock db into package
	sqliteDbOpener = func(dataSource string) (*sqlx.DB, error) {
		return sqlx.NewDb(mockDb, "sqlmock"), nil
	}

	myMock.ExpectPing()
	myMock.ExpectExec("CREATE TABLE IF NOT EXISTS detail").WillReturnResult(sqlmock.NewResult(1, 1))
	myMock.ExpectQuery("SELECT \\* FROM detail").WithArgs("127.0.0.1").WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at", "response_code", "ip_address"}))
	myMock.ExpectClose()

	db, err := NewClient("somefile.db")
	if err != nil {
		t.Errorf("unexpected error creating sqlite client: %s", err.Error())
	}

	_, err = db.GetIPDetails("127.0.0.1")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Error("expected an 'error not found'")
	}

	err = db.Close()
	if err != nil {
		t.Error(err.Error())
	}

	err = myMock.ExpectationsWereMet()
	if err != nil {
		t.Error(err.Error())
	}
}
