package census

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
		// Since reads the log by seq alone, from a cursor, across every partition.
		`CREATE INDEX IF NOT EXISTS idx_census_transfers_seq ON census_transfers(seq)`,
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
	rows, err := l.db.QueryContext(ctx, `SELECT `+transferColumns+` FROM census_transfers
		WHERE (? <> '' AND partition = ?) AND (from_id = ? OR to_id = ?)
		ORDER BY seq ASC`, partition, partition, entity, entity)
	if err != nil {
		return nil, err
	}
	return scanTransfers(rows)
}

// transferColumns are the columns scanTransfers reads, in its order.
const transferColumns = `id, partition, from_id, to_id, type, change, trigger, source, auto, at, COALESCE(seq, 0)`

func scanTransfers(rows *sql.Rows) ([]*TransferEvent, error) {
	defer rows.Close()
	var out []*TransferEvent
	for rows.Next() {
		var e TransferEvent
		var auto int
		var at int64
		if err := rows.Scan(&e.ID, &e.Partition, &e.From, &e.To, &e.Type, &e.Change, &e.Trigger, &e.Source,
			&auto, &at, &e.Seq); err != nil {
			return nil, err
		}
		e.Auto = auto != 0
		e.At = fromNanos(at)
		out = append(out, &e)
	}
	return out, rows.Err()
}

// errSinceLimit refuses a Since that names no page size: the log grows without
// bound, so a reader always takes it a page at a time.
var errSinceLimit = errors.New("census: Since needs a positive limit")

// Since returns up to limit events recorded after seq, across every partition, in
// seq order, each with its Seq set. Its consumer is a change-feed reader: it keeps
// the last Seq it handled as its cursor and passes it back, and because seq
// increases in commit order (RecordTx), a cursor never skips an event committed
// before the events it has read.
func (l *SQLTransferLog) Since(ctx context.Context, seq int64, limit int) ([]*TransferEvent, error) {
	if limit <= 0 {
		return nil, errSinceLimit
	}
	rows, err := l.db.QueryContext(ctx, `SELECT `+transferColumns+` FROM census_transfers
		WHERE seq > ? ORDER BY seq ASC LIMIT ?`, seq, limit)
	if err != nil {
		return nil, err
	}
	return scanTransfers(rows)
}

// transferRow is one event as RecordTx passes it to json_each.
type transferRow struct {
	ID        string `json:"id"`
	Partition string `json:"partition"`
	From      string `json:"from"`
	To        string `json:"to"`
	Type      string `json:"type"`
	Change    string `json:"change"`
	Trigger   string `json:"trigger"`
	Source    string `json:"source"`
	Auto      int    `json:"auto"`
	At        int64  `json:"at"`
}

// RecordTx records events inside tx, the transaction the graph change they
// describe runs in, so the change and its record commit or roll back together.
// census's Atomic is its caller, passing the transaction nexus's Update opened.
//
// Every event goes in with one INSERT … SELECT over a JSON array, whatever the
// count, so a set revoke of thousands of edges is one statement and no bound on
// bound parameters applies. seq continues from the log's highest, in the events'
// order: tx is serializable, so no other writer records between the read of that
// highest and the insert, and seq order is commit order.
func (l *SQLTransferLog) RecordTx(ctx context.Context, tx *sql.Tx, events ...*TransferEvent) error {
	if len(events) == 0 {
		return nil
	}
	rows := make([]transferRow, len(events))
	for i, e := range events {
		if e.ID == "" {
			e.ID = randomID()
		}
		auto := 0
		if e.Auto {
			auto = 1
		}
		rows[i] = transferRow{e.ID, e.Partition, e.From, e.To, e.Type, e.Change, e.Trigger, e.Source, auto, tnanos(e.At)}
	}
	payload, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	var base int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM census_transfers`).Scan(&base); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO census_transfers
		(id, partition, from_id, to_id, type, change, trigger, source, auto, at, seq)
		SELECT json_extract(j.value, '$.id'), json_extract(j.value, '$.partition'),
			json_extract(j.value, '$.from'), json_extract(j.value, '$.to'), json_extract(j.value, '$.type'),
			json_extract(j.value, '$.change'), json_extract(j.value, '$.trigger'),
			json_extract(j.value, '$.source'), json_extract(j.value, '$.auto'), json_extract(j.value, '$.at'),
			? + 1 + j.key
		FROM json_each(?) AS j ORDER BY j.key`, base, string(payload))
	return err
}
