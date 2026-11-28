/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/bbmumford/nexus"
)

// TestGraphTxSQLTx_ARowOnTheGraphDatabaseCommitsAndRollsBackWithTheGraph holds
// SQLTx over the SQL pairing: a row written through it commits with the graph's
// edge, and a function returning an error leaves neither the row nor the edge.
// The in-memory pairing answers false.
func TestGraphTxSQLTx_ARowOnTheGraphDatabaseCommitsAndRollsBackWithTheGraph(t *testing.T) {
	db := fileDB(t)
	s, g, _ := sqlGraph(t, db)
	if _, err := db.ExecContext(ctx, `CREATE TABLE side (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	write := func(id string, fail error) error {
		return s.Atomic(ctx, func(tx *GraphTx) error {
			if err := tx.Grant(ctx, id, "P", "member", nil, txMeta); err != nil {
				return err
			}
			sqlTx, ok := tx.SQLTx()
			if !ok {
				t.Fatal("POSITIVE CONTROL: the SQL pairing answers its transaction")
			}
			if _, err := sqlTx.ExecContext(ctx, `INSERT INTO side (id) VALUES (?)`, id); err != nil {
				return err
			}
			return fail
		})
	}
	sideHas := func(id string) bool {
		var got string
		err := db.QueryRowContext(ctx, `SELECT id FROM side WHERE id = ?`, id).Scan(&got)
		if errors.Is(err, sql.ErrNoRows) {
			return false
		}
		if err != nil {
			t.Fatal(err)
		}
		return true
	}
	if err := write("kept", nil); err != nil {
		t.Fatal(err)
	}
	if ok, _ := g.HasRelationship(ctx, "kept", "P", "member"); !ok || !sideHas("kept") {
		t.Fatalf("a committed Atomic left edge=%v row=%v", ok, sideHas("kept"))
	}
	if err := write("dropped", errAbort); !errors.Is(err, errAbort) {
		t.Fatalf("Atomic returned %v, want the function's error", err)
	}
	if ok, _ := g.HasRelationship(ctx, "dropped", "P", "member"); ok || sideHas("dropped") {
		t.Fatalf("a rolled-back Atomic left edge=%v row=%v", ok, sideHas("dropped"))
	}

	mem, err := NewGraphService(GraphConfig{Graph: nexus.NewMemStore(), Log: NewMemTransferLog()})
	if err != nil {
		t.Fatal(err)
	}
	if err := mem.Atomic(ctx, func(tx *GraphTx) error {
		if _, ok := tx.SQLTx(); ok {
			t.Error("the in-memory pairing answered a SQL transaction")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
