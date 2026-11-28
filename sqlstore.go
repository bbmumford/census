/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// SQLVaultStore is the durable default VaultStore over any database/sql driver — the shipped standalone
// store. The package imports only database/sql (stdlib); the APP supplies the opened *sql.DB and
// registers the driver (go-libsql/Turso, modernc, Postgres), so census pulls no driver dependency yet
// works out of the box. Partition is an opaque column the store filters on but never interprets; an empty
// partition on a partition-scoped read matches nothing, because every partition-scoped predicate rejects
// an empty parameter before comparing — an unscoped read returns no rows, never every partition's. Times persist as INTEGER Unix nanoseconds with
// NULL for an unset *time.Time. Only sealed material is stored (encrypted emails, deterministic hashes,
// Hasher digests). The VaultStore interface stays the escape-hatch for a mesh gateway or MemStore.
type SQLVaultStore struct{ db *sql.DB }

// NewSQLVaultStore builds a store over an opened *sql.DB. Call InitSchema once before use.
func NewSQLVaultStore(db *sql.DB) *SQLVaultStore { return &SQLVaultStore{db: db} }

var _ VaultStore = (*SQLVaultStore)(nil)

// InitSchema creates the vault tables + indexes (idempotent); run once at boot.
func (s *SQLVaultStore) InitSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS censusCredentials (
			id TEXT PRIMARY KEY, partitionId TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL DEFAULT '',
			kind TEXT NOT NULL DEFAULT '', identifierHash TEXT NOT NULL DEFAULT '',
			secret TEXT NOT NULL DEFAULT '', createdAt INTEGER NOT NULL DEFAULT 0,
			updatedAt INTEGER NOT NULL DEFAULT 0
		)`,
		// The login identifier is unique per credential kind — a second subject cannot claim it.
		`CREATE UNIQUE INDEX IF NOT EXISTS idxCensusCredIdentity ON censusCredentials(kind, identifierHash)`,
		`CREATE INDEX IF NOT EXISTS idxCensusCredSubject ON censusCredentials(partitionId, subject)`,
		// A single-use token (an email code, a login handoff, a native sign-in code) is signed, not
		// stored; only the id of one already used is kept, until the token's expiry, so SpendID
		// refuses it a second time.
		`CREATE TABLE IF NOT EXISTS censusSpentIds (
			id TEXT PRIMARY KEY, expiresAt INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idxCensusSpentIdExpiry ON censusSpentIds(expiresAt)`,
		// A step is spent once per subject, whatever partition's request presents the code, so the key
		// is (subject, step) and partition is carried for the scoped clear DeleteSpentSteps performs.
		`CREATE TABLE IF NOT EXISTS censusSpentSteps (
			subject TEXT NOT NULL DEFAULT '', step INTEGER NOT NULL DEFAULT 0,
			partitionId TEXT NOT NULL DEFAULT '', spentAt INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (subject, step)
		)`,
		`CREATE INDEX IF NOT EXISTS idxCensusSpentSubject ON censusSpentSteps(partitionId, subject)`,
		`CREATE INDEX IF NOT EXISTS idxCensusSpentStepAt ON censusSpentSteps(spentAt)`,
		`CREATE TABLE IF NOT EXISTS censusApiKeys (
			id TEXT PRIMARY KEY, partitionId TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL DEFAULT '',
			label TEXT NOT NULL DEFAULT '', keyHash TEXT NOT NULL DEFAULT '',
			capabilities TEXT NOT NULL DEFAULT '[]', createdAt INTEGER NOT NULL DEFAULT 0,
			expiresAt INTEGER, revokedAt INTEGER, lastUsedAt INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idxCensusApikeyHash ON censusApiKeys(keyHash)`,
		`CREATE INDEX IF NOT EXISTS idxCensusApikeySubject ON censusApiKeys(partitionId, subject)`,
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// ── time / json codecs ──

func tnanos(t time.Time) int64 { return t.UnixNano() }

func fromNanos(n int64) time.Time { return time.Unix(0, n).UTC() }

func ptrNanos(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UnixNano()
}

func fromNullNanos(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := fromNanos(n.Int64)
	return &t
}

func jsonSlice(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func readSliceJSON(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var v []string
	_ = json.Unmarshal([]byte(s), &v)
	return v
}

// ── Credentials ──

func (s *SQLVaultStore) PutCredential(ctx context.Context, c *Credential) error {
	if c.Partition == "" {
		return ErrUnscoped
	}
	if c.ID == "" {
		c.ID = randomID()
	}
	// A login identifier is unique per kind: a DIFFERENT credential claiming the same (kind,
	// identifierHash) is ErrConflict. The same id re-puts (a password change) within its own partition
	// and subject only: a re-put naming a known id under another partition or subject is ErrConflict,
	// since rewriting them would move the credential out of reach of the partition that wrote it,
	// whose list and delete select by partition. The check + upsert run in one transaction so the
	// mapping is driver-agnostic (no reliance on parsing a driver's unique-violation error). The
	// UNIQUE index backstops a concurrent race for integrity.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM censusCredentials
		WHERE kind = ? AND identifierHash = ? AND id != ?`, c.Kind, c.IdentifierHash, c.ID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrConflict
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM censusCredentials
		WHERE id = ? AND (partitionId != ? OR subject != ?)`, c.ID, c.Partition, c.Subject).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO censusCredentials
		(id, partitionId, subject, kind, identifierHash, secret, createdAt, updatedAt)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET kind=excluded.kind, identifierHash=excluded.identifierHash,
			secret=excluded.secret, updatedAt=excluded.updatedAt`,
		c.ID, c.Partition, c.Subject, c.Kind, c.IdentifierHash, c.Secret, tnanos(c.CreatedAt), tnanos(c.UpdatedAt)); err != nil {
		return err
	}
	return tx.Commit()
}

func scanCredential(sc interface{ Scan(...any) error }) (*Credential, error) {
	var c Credential
	var created, updated int64
	if err := sc.Scan(&c.ID, &c.Partition, &c.Subject, &c.Kind, &c.IdentifierHash, &c.Secret, &created, &updated); err != nil {
		return nil, err
	}
	c.CreatedAt = fromNanos(created)
	c.UpdatedAt = fromNanos(updated)
	return &c, nil
}

const credentialCols = `id, partitionId, subject, kind, identifierHash, secret, createdAt, updatedAt`

func (s *SQLVaultStore) GetCredentialByIdentifier(ctx context.Context, kind, identifierHash string) (*Credential, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+credentialCols+` FROM censusCredentials
		WHERE kind = ? AND identifierHash = ? LIMIT 1`, kind, identifierHash)
	c, err := scanCredential(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return c, err
}

func (s *SQLVaultStore) ListCredentialsBySubject(ctx context.Context, partition, subject string) ([]*Credential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+credentialCols+` FROM censusCredentials
		WHERE (? <> '' AND partitionId = ?) AND subject = ? ORDER BY createdAt ASC`, partition, partition, subject)
	if err != nil {
		return nil, err
	}
	defer closeRows(rows)
	var out []*Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLVaultStore) DeleteCredential(ctx context.Context, partition, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM censusCredentials WHERE id = ? AND (? <> '' AND partitionId = ?)`,
		id, partition, partition)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ── API keys ──

func (s *SQLVaultStore) PutAPIKey(ctx context.Context, k *APIKey) error {
	if k.Partition == "" {
		return ErrUnscoped
	}
	if k.ID == "" {
		k.ID = randomID()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO censusApiKeys
		(id, partitionId, subject, label, keyHash, capabilities, createdAt, expiresAt, revokedAt, lastUsedAt)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		k.ID, k.Partition, k.Subject, k.Label, k.KeyHash, jsonSlice(k.Capabilities), tnanos(k.CreatedAt),
		ptrNanos(k.ExpiresAt), ptrNanos(k.RevokedAt), ptrNanos(k.LastUsedAt))
	return err
}

const apiKeyCols = `id, partitionId, subject, label, keyHash, capabilities, createdAt, expiresAt, revokedAt, lastUsedAt`

func scanAPIKey(sc interface{ Scan(...any) error }) (*APIKey, error) {
	var k APIKey
	var caps string
	var created int64
	var expires, revoked, lastUsed sql.NullInt64
	if err := sc.Scan(&k.ID, &k.Partition, &k.Subject, &k.Label, &k.KeyHash, &caps, &created,
		&expires, &revoked, &lastUsed); err != nil {
		return nil, err
	}
	k.Capabilities = readSliceJSON(caps)
	k.CreatedAt = fromNanos(created)
	k.ExpiresAt = fromNullNanos(expires)
	k.RevokedAt = fromNullNanos(revoked)
	k.LastUsedAt = fromNullNanos(lastUsed)
	return &k, nil
}

func (s *SQLVaultStore) GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+apiKeyCols+` FROM censusApiKeys WHERE keyHash = ? LIMIT 1`, keyHash)
	k, err := scanAPIKey(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return k, err
}

func (s *SQLVaultStore) ListAPIKeysBySubject(ctx context.Context, partition, subject string) ([]*APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+apiKeyCols+` FROM censusApiKeys
		WHERE (? <> '' AND partitionId = ?) AND subject = ? ORDER BY createdAt ASC`, partition, partition, subject)
	if err != nil {
		return nil, err
	}
	defer closeRows(rows)
	var out []*APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *SQLVaultStore) RevokeAPIKey(ctx context.Context, partition, id string, revokedAt int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE censusApiKeys SET revokedAt = COALESCE(revokedAt, ?)
		WHERE id = ? AND (? <> '' AND partitionId = ?)`, revokedAt, id, partition, partition)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLVaultStore) TouchAPIKeyUsed(ctx context.Context, id string, usedAt int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE censusApiKeys SET lastUsedAt = ? WHERE id = ?`, usedAt, id)
	return err
}

// rollbackUnlessCommitted is the deferred Rollback of every transaction in this
// package. After Commit it returns sql.ErrTxDone, and an early return already
// carries the error that stopped the transaction; its result is dropped.
func rollbackUnlessCommitted(tx *sql.Tx) { _ = tx.Rollback() }

// closeRows is the deferred Close of every query's rows in this package.
// database/sql closes rows itself once Next reports the end, so a normal return
// leaves nothing to close, and an early return already carries the error that
// stopped the read; its result is dropped.
func closeRows(rows *sql.Rows) { _ = rows.Close() }
