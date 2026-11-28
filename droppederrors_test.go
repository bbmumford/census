/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"
	"time"
)

// A stored key whose capabilities column is not a JSON string array is an error on every read, never a
// key that holds no capabilities.
func TestAStoredAPIKeyWhoseCapabilitiesDoNotParseIsAnError(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	store := NewSQLVaultStore(db)
	if err := store.InitSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.PutAPIKey(ctx, &APIKey{Partition: "p1", Subject: "s1", KeyHash: "h1", Capabilities: []string{"orbtr:read"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE censusApiKeys SET capabilities = 'not json'`); err != nil {
		t.Fatal(err)
	}
	if k, err := store.GetAPIKeyByHash(ctx, "h1"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAPIKeyByHash over unparseable capabilities = %+v, %v; want a read error", k, err)
	}
	if ks, err := store.ListAPIKeysBySubject(ctx, "p1", "s1"); err == nil {
		t.Fatalf("ListAPIKeysBySubject over unparseable capabilities = %+v, nil; want a read error", ks)
	}
}

// failingTouch is a VaultStore whose record of a key's use fails.
type failingTouch struct{ VaultStore }

var errTouch = errors.New("use record unavailable")

func (failingTouch) TouchAPIKeyUsed(context.Context, string, int64) error { return errTouch }

// VerifyAPIKey answers the store's error when the key's use cannot be recorded, and no key.
func TestVerifyAPIKeyRefusesAKeyWhoseUseCannotBeRecorded(t *testing.T) {
	ctx := context.Background()
	mem := NewMemStore()
	raw, _, err := newServiceWith(t, mem).MintAPIKey(ctx, "p1", "s1", "key", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if k, err := newServiceWith(t, failingTouch{mem}).VerifyAPIKey(ctx, raw); !errors.Is(err, errTouch) || k != nil {
		t.Fatalf("VerifyAPIKey with the use record failing = %+v, %v; want no key and the store's error", k, err)
	}
}

// A delete or revoke whose driver cannot report the rows it changed answers the driver's error, not
// ErrNotFound.
func TestADeleteWhoseRowCountFailsAnswersTheDriverError(t *testing.T) {
	ctx := context.Background()
	db := sql.OpenDB(rowCountFails{})
	t.Cleanup(func() { _ = db.Close() })
	store := NewSQLVaultStore(db)
	if err := store.DeleteCredential(ctx, "p1", "c1"); !errors.Is(err, errRowCount) {
		t.Fatalf("DeleteCredential = %v, want the driver's row-count error", err)
	}
	if err := store.RevokeAPIKey(ctx, "p1", "k1", 1); !errors.Is(err, errRowCount) {
		t.Fatalf("RevokeAPIKey = %v, want the driver's row-count error", err)
	}
}

var errRowCount = errors.New("rows affected unsupported")

// rowCountFails is a database/sql driver whose every statement executes and cannot report how many
// rows it changed.
type rowCountFails struct{}

func (rowCountFails) Connect(context.Context) (driver.Conn, error) { return rowCountConn{}, nil }
func (rowCountFails) Driver() driver.Driver                        { return nil }

type rowCountConn struct{}

func (rowCountConn) Prepare(string) (driver.Stmt, error) { return rowCountStmt{}, nil }
func (rowCountConn) Close() error                        { return nil }
func (rowCountConn) Begin() (driver.Tx, error)           { return nil, errors.New("no transactions") }

type rowCountStmt struct{}

func (rowCountStmt) Close() error                               { return nil }
func (rowCountStmt) NumInput() int                              { return -1 }
func (rowCountStmt) Exec([]driver.Value) (driver.Result, error) { return rowCountResult{}, nil }
func (rowCountStmt) Query([]driver.Value) (driver.Rows, error)  { return nil, errors.New("no queries") }

type rowCountResult struct{}

func (rowCountResult) LastInsertId() (int64, error) { return 0, errRowCount }
func (rowCountResult) RowsAffected() (int64, error) { return 0, errRowCount }
