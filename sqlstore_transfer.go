package census

import (
	"context"
	"database/sql"
)

// SQLTransferLog is the durable default TransferLog over any database/sql driver — the shipped
// append-only sink for relationship-change provenance. Like SQLVaultStore it imports only stdlib
// database/sql; the app supplies the driver + *sql.DB. Partition is opaque; "" on List matches nothing.
type SQLTransferLog struct{ db *sql.DB }

// NewSQLTransferLog builds a log over an opened *sql.DB. Call InitSchema once before use.
func NewSQLTransferLog(db *sql.DB) *SQLTransferLog { return &SQLTransferLog{db: db} }

var _ TransferLog = (*SQLTransferLog)(nil)

// InitSchema creates the transfer table + indexes (idempotent); run once at boot.
func (l *SQLTransferLog) InitSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS census_transfers (
			id TEXT PRIMARY KEY, partition TEXT NOT NULL DEFAULT '', from_id TEXT NOT NULL DEFAULT '',
			to_id TEXT NOT NULL DEFAULT '', type TEXT NOT NULL DEFAULT '', change TEXT NOT NULL DEFAULT '',
			trigger TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '', auto INTEGER NOT NULL DEFAULT 0,
			at INTEGER NOT NULL DEFAULT 0, seq INTEGER
		)`,
		// A monotonic sequence preserves record order for List even when two events share a timestamp.
		`CREATE INDEX IF NOT EXISTS idx_census_transfers_from ON census_transfers(from_id, seq)`,
		`CREATE INDEX IF NOT EXISTS idx_census_transfers_to ON census_transfers(to_id, seq)`,
	}
	for _, q := range stmts {
		if _, err := l.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func (l *SQLTransferLog) Record(ctx context.Context, e *TransferEvent) error {
	if e.ID == "" {
		e.ID = randomID()
	}
	auto := 0
	if e.Auto {
		auto = 1
	}
	// seq is the next monotonic ordinal so List returns events in the order recorded, tie-breaking a
	// shared `at`. COALESCE(MAX,0)+1 is evaluated in the same statement.
	_, err := l.db.ExecContext(ctx, `INSERT INTO census_transfers
		(id, partition, from_id, to_id, type, change, trigger, source, auto, at, seq)
		VALUES (?,?,?,?,?,?,?,?,?,?, (SELECT COALESCE(MAX(seq),0)+1 FROM census_transfers))`,
		e.ID, e.Partition, e.From, e.To, e.Type, e.Change, e.Trigger, e.Source, auto, tnanos(e.At))
	return err
}

// List returns every recorded event where the entity is the edge source or target, scoped to one
// partition, in the order recorded. An empty partition matches nothing: the predicate reads
// (? <> '' AND partition = ?), so an unscoped call returns no events rather than every partition's
// provenance — an audit read that names no partition comes back empty, it does not come back complete.
func (l *SQLTransferLog) List(ctx context.Context, partition, entity string) ([]*TransferEvent, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT id, partition, from_id, to_id, type, change, trigger, source,
		auto, at FROM census_transfers WHERE (? <> '' AND partition = ?) AND (from_id = ? OR to_id = ?)
		ORDER BY seq ASC`, partition, partition, entity, entity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*TransferEvent
	for rows.Next() {
		var e TransferEvent
		var auto int
		var at int64
		if err := rows.Scan(&e.ID, &e.Partition, &e.From, &e.To, &e.Type, &e.Change, &e.Trigger, &e.Source,
			&auto, &at); err != nil {
			return nil, err
		}
		e.Auto = auto != 0
		e.At = fromNanos(at)
		out = append(out, &e)
	}
	return out, rows.Err()
}
