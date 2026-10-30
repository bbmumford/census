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
// partition ("") on a partition-scoped read matches nothing, because the predicates read
// (? <> '' AND partition = ?) — an unscoped read returns no rows, never every partition's. Times persist as INTEGER Unix nanoseconds with
// NULL for an unset *time.Time. Only sealed material is stored (encrypted emails, deterministic hashes,
// Hasher digests). The VaultStore interface stays the escape-hatch for a mesh gateway or MemStore.
type SQLVaultStore struct{ db *sql.DB }

// NewSQLVaultStore builds a store over an opened *sql.DB. Call InitSchema once before use.
func NewSQLVaultStore(db *sql.DB) *SQLVaultStore { return &SQLVaultStore{db: db} }

var _ VaultStore = (*SQLVaultStore)(nil)

// InitSchema creates the vault tables + indexes (idempotent); run once at boot.
func (s *SQLVaultStore) InitSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS census_credentials (
			id TEXT PRIMARY KEY, partition TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL DEFAULT '',
			kind TEXT NOT NULL DEFAULT '', identifier_hash TEXT NOT NULL DEFAULT '',
			secret TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL DEFAULT 0
		)`,
		// The login identifier is unique per credential kind — a second subject cannot claim it.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_census_cred_identity ON census_credentials(kind, identifier_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_census_cred_subject ON census_credentials(partition, subject)`,
		`CREATE TABLE IF NOT EXISTS census_email_verifications (
			id TEXT PRIMARY KEY, partition TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL DEFAULT '',
			identifier_enc TEXT NOT NULL DEFAULT '', identifier TEXT NOT NULL DEFAULT '',
			token_hash TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL DEFAULT 0,
			expires_at INTEGER, consumed_at INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_census_verify_token ON census_email_verifications(token_hash)`,
		// A step is spent once per subject, whatever partition's request presents the code, so the key
		// is (subject, step) and partition is carried for the scoped clear DeleteSpentSteps performs.
		`CREATE TABLE IF NOT EXISTS census_spent_steps (
			subject TEXT NOT NULL DEFAULT '', step INTEGER NOT NULL DEFAULT 0,
			partition TEXT NOT NULL DEFAULT '', spent_at INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (subject, step)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_census_spent_subject ON census_spent_steps(partition, subject)`,
		`CREATE TABLE IF NOT EXISTS census_api_keys (
			id TEXT PRIMARY KEY, partition TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL DEFAULT '',
			label TEXT NOT NULL DEFAULT '', key_hash TEXT NOT NULL DEFAULT '',
			capabilities TEXT NOT NULL DEFAULT '[]', created_at INTEGER NOT NULL DEFAULT 0,
			expires_at INTEGER, revoked_at INTEGER, last_used_at INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_census_apikey_hash ON census_api_keys(key_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_census_apikey_subject ON census_api_keys(partition, subject)`,
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

func jsonStrMap(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func readStrMapJSON(s string) map[string]string {
	if s == "" || s == "{}" {
		return nil
	}
	var m map[string]string
	_ = json.Unmarshal([]byte(s), &m)
	return m
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
	if c.ID == "" {
		c.ID = randomID()
	}
	// A login identifier is unique per kind: a DIFFERENT credential claiming the same (kind,
	// identifier_hash) is ErrConflict. The same id re-puts (a password change). The check + upsert run
	// in one transaction so the mapping is driver-agnostic (no reliance on parsing a driver's unique-
	// violation error). The UNIQUE index backstops a concurrent race for integrity.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM census_credentials
		WHERE kind = ? AND identifier_hash = ? AND id != ?`, c.Kind, c.IdentifierHash, c.ID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO census_credentials
		(id, partition, subject, kind, identifier_hash, secret, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET partition=excluded.partition, subject=excluded.subject,
			kind=excluded.kind, identifier_hash=excluded.identifier_hash, secret=excluded.secret,
			updated_at=excluded.updated_at`,
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

const credentialCols = `id, partition, subject, kind, identifier_hash, secret, created_at, updated_at`

func (s *SQLVaultStore) GetCredentialByIdentifier(ctx context.Context, kind, identifierHash string) (*Credential, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+credentialCols+` FROM census_credentials
		WHERE kind = ? AND identifier_hash = ? LIMIT 1`, kind, identifierHash)
	c, err := scanCredential(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return c, err
}

func (s *SQLVaultStore) ListCredentialsBySubject(ctx context.Context, partition, subject string) ([]*Credential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+credentialCols+` FROM census_credentials
		WHERE (? <> '' AND partition = ?) AND subject = ? ORDER BY created_at ASC`, partition, partition, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
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
	res, err := s.db.ExecContext(ctx, `DELETE FROM census_credentials WHERE id = ? AND (? <> '' AND partition = ?)`,
		id, partition, partition)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Email verifications ──

func (s *SQLVaultStore) PutEmailVerification(ctx context.Context, v *EmailVerification) error {
	if v.ID == "" {
		v.ID = randomID()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO census_email_verifications
		(id, partition, subject, identifier_enc, identifier, token_hash, created_at, expires_at, consumed_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		v.ID, v.Partition, v.Subject, v.IdentifierEnc, v.Identifier, v.TokenHash, tnanos(v.CreatedAt),
		ptrNanos(v.ExpiresAt), ptrNanos(v.ConsumedAt))
	return err
}

func (s *SQLVaultStore) GetEmailVerificationByToken(ctx context.Context, tokenHash string) (*EmailVerification, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, partition, subject, identifier_enc, identifier, token_hash,
		created_at, expires_at, consumed_at FROM census_email_verifications WHERE token_hash = ? LIMIT 1`, tokenHash)
	var v EmailVerification
	var created int64
	var expires, consumed sql.NullInt64
	if err := row.Scan(&v.ID, &v.Partition, &v.Subject, &v.IdentifierEnc, &v.Identifier, &v.TokenHash,
		&created, &expires, &consumed); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	v.CreatedAt = fromNanos(created)
	v.ExpiresAt = fromNullNanos(expires)
	v.ConsumedAt = fromNullNanos(consumed)
	return &v, nil
}

func (s *SQLVaultStore) MarkEmailVerificationConsumed(ctx context.Context, id string, consumedAt int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE census_email_verifications
		SET consumed_at = COALESCE(consumed_at, ?) WHERE id = ?`, consumedAt, id)
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
	if k.ID == "" {
		k.ID = randomID()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO census_api_keys
		(id, partition, subject, label, key_hash, capabilities, created_at, expires_at, revoked_at, last_used_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		k.ID, k.Partition, k.Subject, k.Label, k.KeyHash, jsonSlice(k.Capabilities), tnanos(k.CreatedAt),
		ptrNanos(k.ExpiresAt), ptrNanos(k.RevokedAt), ptrNanos(k.LastUsedAt))
	return err
}

const apiKeyCols = `id, partition, subject, label, key_hash, capabilities, created_at, expires_at, revoked_at, last_used_at`

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
	row := s.db.QueryRowContext(ctx, `SELECT `+apiKeyCols+` FROM census_api_keys WHERE key_hash = ? LIMIT 1`, keyHash)
	k, err := scanAPIKey(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return k, err
}

func (s *SQLVaultStore) ListAPIKeysBySubject(ctx context.Context, partition, subject string) ([]*APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+apiKeyCols+` FROM census_api_keys
		WHERE (? <> '' AND partition = ?) AND subject = ? ORDER BY created_at ASC`, partition, partition, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
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
	res, err := s.db.ExecContext(ctx, `UPDATE census_api_keys SET revoked_at = COALESCE(revoked_at, ?)
		WHERE id = ? AND (? <> '' AND partition = ?)`, revokedAt, id, partition, partition)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLVaultStore) TouchAPIKeyUsed(ctx context.Context, id string, usedAt int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE census_api_keys SET last_used_at = ? WHERE id = ?`, usedAt, id)
	return err
}
