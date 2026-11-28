/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"testing"

	"github.com/bbmumford/nexus"
)

// TestViewSQLTx_ARowOnTheGraphDatabaseIsReadAtTheViewsSnapshot holds ViewSQLTx over
// the SQL pairing: inside a View, a row on the graph's database read through the
// answered transaction keeps the value it had when the View's reads began while a
// grant and a row update commit beside it, and the edge read in the same View does
// not see the grant either. The in-memory pairing answers false.
func TestViewSQLTx_ARowOnTheGraphDatabaseIsReadAtTheViewsSnapshot(t *testing.T) {
	db := fileDB(t)
	s, g, _ := sqlGraph(t, db)
	if _, err := db.ExecContext(ctx, `CREATE TABLE side (id TEXT PRIMARY KEY, v TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO side (id, v) VALUES ('a', 'before')`); err != nil {
		t.Fatal(err)
	}
	err := s.View(ctx, func(r nexus.GraphReader) error {
		sqlTx, ok := ViewSQLTx(r)
		if !ok {
			t.Fatal("POSITIVE CONTROL: the SQL pairing's View answers its transaction")
		}
		read := func() (string, bool) {
			var v string
			if err := sqlTx.QueryRowContext(ctx, `SELECT v FROM side WHERE id = 'a'`).Scan(&v); err != nil {
				t.Fatal(err)
			}
			has, err := r.HasRelationship(ctx, "S", "P", "member")
			if err != nil {
				t.Fatal(err)
			}
			return v, has
		}
		if v, has := read(); v != "before" || has {
			t.Fatalf("first reads: row %q, edge %v; want before and no edge", v, has)
		}
		if err := s.Grant(ctx, "S", "P", "member", nil, txMeta); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE side SET v = 'after' WHERE id = 'a'`); err != nil {
			t.Fatal(err)
		}
		if v, has := read(); v != "before" || has {
			t.Fatalf("reads after a concurrent commit: row %q, edge %v; the snapshot held before and no edge", v, has)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := g.HasRelationship(ctx, "S", "P", "member"); !ok {
		t.Fatal("the grant made during the View did not commit")
	}

	mem, err := NewGraphService(GraphConfig{Graph: nexus.NewMemStore(), Log: NewMemTransferLog()})
	if err != nil {
		t.Fatal(err)
	}
	if err := mem.View(ctx, func(r nexus.GraphReader) error {
		if _, ok := ViewSQLTx(r); ok {
			t.Error("the in-memory pairing answered a SQL transaction")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
