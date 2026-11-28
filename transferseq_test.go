/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"testing"
)

// The transfer log refuses a second event at a seq one already holds, so Since's seq > cursor paging
// can never skip an event, including over a database whose seq index was built plain.
func TestTheTransferLogRefusesTwoEventsAtOneSeq(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	if _, err := db.ExecContext(ctx, `CREATE TABLE censusTransfers (
			id TEXT PRIMARY KEY, partitionId TEXT NOT NULL DEFAULT '', fromId TEXT NOT NULL DEFAULT '',
			toId TEXT NOT NULL DEFAULT '', type TEXT NOT NULL DEFAULT '', change TEXT NOT NULL DEFAULT '',
			trigger TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '', auto INTEGER NOT NULL DEFAULT 0,
			at INTEGER NOT NULL DEFAULT 0, seq INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE INDEX idxCensusTransfersSeq ON censusTransfers(seq)`); err != nil {
		t.Fatal(err)
	}
	l := NewSQLTransferLog(db)
	if err := l.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema over a plain seq index: %v", err)
	}
	if err := l.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema run again: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO censusTransfers (id, partitionId, seq) VALUES ('e1', 'p1', 7)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO censusTransfers (id, partitionId, seq) VALUES ('e2', 'p1', 7)`); err == nil {
		t.Fatal("a second event committed at seq 7")
	}
}
