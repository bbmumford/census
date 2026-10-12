package census

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/bbmumford/nexus"
	_ "modernc.org/sqlite"
)

// sinceLog is the cursor read both shipped logs answer.
type sinceLog interface {
	TransferLog
	Since(ctx context.Context, seq int64, limit int) ([]*TransferEvent, error)
}

// fileDB opens a file database in WAL mode with every writing transaction opened
// BEGIN IMMEDIATE, as the libSQL replicas the graph runs on open theirs. A file,
// because these tests hold a reader and a writer on two connections at once.
func fileDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "graph.db")+
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(20000)&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// sqlGraph is the production pairing: the nexus store and the transfer log on one
// *sql.DB.
func sqlGraph(t *testing.T, db *sql.DB) (*GraphService, nexus.GraphStore, *SQLTransferLog) {
	t.Helper()
	g := nexus.NewSQLStore(db)
	if err := g.InitSchema(ctx); err != nil {
		t.Fatal(err)
	}
	log := NewSQLTransferLog(db)
	if err := log.InitSchema(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := NewGraphService(GraphConfig{Graph: g, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return s, g, log
}

// eachAtomic runs one contract over the in-memory pairing and the SQL pairing.
func eachAtomic(t *testing.T, run func(t *testing.T, s *GraphService, g nexus.GraphStore, log sinceLog)) {
	t.Run("mem", func(t *testing.T) {
		g, log := nexus.NewMemStore(), NewMemTransferLog()
		s, err := NewGraphService(GraphConfig{Graph: g, Log: log})
		if err != nil {
			t.Fatal(err)
		}
		run(t, s, g, log)
	})
	t.Run("sql", func(t *testing.T) {
		s, g, log := sqlGraph(t, fileDB(t))
		run(t, s, g, log)
	})
}

func since(t *testing.T, log sinceLog, seq int64) []*TransferEvent {
	t.Helper()
	ev, err := log.Since(ctx, seq, 100000)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func describe(ev []*TransferEvent) []string {
	out := make([]string, len(ev))
	for i, e := range ev {
		out[i] = e.Change + " " + e.From + ">" + e.To + ":" + e.Type
	}
	return out
}

var (
	errAbort = errors.New("abort")
	txMeta   = ChangeMeta{Partition: "P", Trigger: "editor", Source: "test"}
)

func TestAtomic_CommitsEachChangeWithItsEvent(t *testing.T) {
	eachAtomic(t, func(t *testing.T, s *GraphService, g nexus.GraphStore, log sinceLog) {
		err := s.Atomic(ctx, func(tx *GraphTx) error {
			if err := tx.PutEntity(ctx, &nexus.Entity{ID: "role", Type: "role"}); err != nil {
				return err
			}
			if err := tx.Grant(ctx, "s1", "role", "assigned", map[string]string{"partition": "P"}, txMeta); err != nil {
				return err
			}
			if err := tx.Grant(ctx, "s2", "role", "assigned", nil, txMeta); err != nil {
				return err
			}
			if ok, err := tx.HasRelationship(ctx, "s1", "role", "assigned"); err != nil || !ok {
				return fmt.Errorf("a read inside Atomic does not see its own grant: %v %v", ok, err)
			}
			return tx.Revoke(ctx, "s2", "role", "assigned", txMeta)
		})
		if err != nil {
			t.Fatal(err)
		}
		if ok, _ := g.HasRelationship(ctx, "s1", "role", "assigned"); !ok {
			t.Fatal("the committed grant is not stored")
		}
		got := describe(since(t, log, 0))
		want := []string{"grant s1>role:assigned", "grant s2>role:assigned", "revoke s2>role:assigned"}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("events %v, want %v", got, want)
		}
		if hist, _ := s.History(ctx, "P", "role"); len(hist) != 3 || hist[0].Trigger != "editor" {
			t.Fatalf("History reads the Atomic's events with their provenance: %+v", hist)
		}
	})
}

func TestAtomic_ARollbackLeavesNoEdgeAndNoEvent(t *testing.T) {
	eachAtomic(t, func(t *testing.T, s *GraphService, g nexus.GraphStore, log sinceLog) {
		if err := s.Grant(ctx, "s1", "P", "member", nil, txMeta); err != nil {
			t.Fatal(err)
		}
		_ = g.PutEntity(ctx, &nexus.Entity{ID: "role", Type: "role"})
		before := len(since(t, log, 0))
		// Each change must succeed inside the transaction, so a change or an event
		// that cannot be written there fails the test instead of leaving nothing to
		// roll back; only the final errAbort is the rollback this test is about.
		err := s.Atomic(ctx, func(tx *GraphTx) error {
			steps := []func() error{
				func() error { return tx.Grant(ctx, "s1", "role", "assigned", nil, txMeta) },
				func() error { return tx.Revoke(ctx, "s1", "P", "member", txMeta) },
				func() error {
					_, err := tx.RevokeWhere(ctx, nexus.EdgeSelector{From: "s1", Type: "member"}, txMeta)
					return err
				},
				func() error { return tx.DeleteEntity(ctx, "role", txMeta) },
			}
			for _, step := range steps {
				if err := step(); err != nil {
					return err
				}
			}
			return errAbort
		})
		if !errors.Is(err, errAbort) {
			t.Fatalf("Atomic returned %v, want the function's error", err)
		}
		if ok, _ := g.HasRelationship(ctx, "s1", "role", "assigned"); ok {
			t.Fatal("a rolled-back grant is stored")
		}
		if ok, _ := g.HasRelationship(ctx, "s1", "P", "member"); !ok {
			t.Fatal("a rolled-back revoke removed the edge")
		}
		if _, err := g.GetEntity(ctx, "role"); err != nil {
			t.Fatalf("a rolled-back DeleteEntity removed the entity: %v", err)
		}
		if after := since(t, log, 0); len(after) != before {
			t.Fatalf("a rolled-back Atomic left %d events: %v", len(after)-before, describe(after[before:]))
		}
	})
}

func TestView_DoesNotSeeAnAtomicCommittedDuringIt(t *testing.T) {
	eachAtomic(t, func(t *testing.T, s *GraphService, g nexus.GraphStore, log sinceLog) {
		_ = s.Grant(ctx, "s1", "P", "member", nil, txMeta)
		err := s.View(ctx, func(r nexus.GraphReader) error {
			if e, _ := r.OutEdges(ctx, "s1"); len(e) != 1 {
				return fmt.Errorf("first read: %d edges", len(e))
			}
			if err := s.Atomic(ctx, func(tx *GraphTx) error {
				return tx.Grant(ctx, "s1", "role", "assigned", nil, txMeta)
			}); err != nil {
				return err
			}
			if e, _ := r.OutEdges(ctx, "s1"); len(e) != 1 {
				return fmt.Errorf("a read after a concurrent Atomic sees %d edges; the snapshot held 1", len(e))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

// nonTxStore hides View and Update: a store a consumer wrapped, or a gateway that
// cannot transact.
type nonTxStore struct{ nexus.GraphStore }

// otherLog is a TransferLog census cannot write inside a store transaction.
type otherLog struct{ TransferLog }

func TestAtomic_RefusesWhenTheChangeAndItsEventCannotShareATransaction(t *testing.T) {
	db := fileDB(t)
	sqlStore := nexus.NewSQLStore(db)
	if err := sqlStore.InitSchema(ctx); err != nil {
		t.Fatal(err)
	}
	sameLog := NewSQLTransferLog(db)
	otherDB := NewSQLTransferLog(fileDB(t))
	for _, l := range []*SQLTransferLog{sameLog, otherDB} {
		if err := l.InitSchema(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for name, cfg := range map[string]GraphConfig{
		"store not a TxStore":        {Graph: nonTxStore{nexus.NewMemStore()}, Log: NewMemTransferLog()},
		"SQL log on another *sql.DB": {Graph: sqlStore, Log: otherDB},
		"SQL store, in-memory log":   {Graph: sqlStore, Log: NewMemTransferLog()},
		"in-memory store, SQL log":   {Graph: nexus.NewMemStore(), Log: sameLog},
		"a log census cannot enlist": {Graph: nexus.NewMemStore(), Log: otherLog{NewMemTransferLog()}},
	} {
		s, err := NewGraphService(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ran := false
		err = s.Atomic(ctx, func(tx *GraphTx) error {
			ran = true
			return tx.Grant(ctx, "s1", "P", "member", nil, txMeta)
		})
		if !errors.Is(err, ErrNoTransaction) || ran {
			t.Errorf("%s: Atomic err %v ran %v, want ErrNoTransaction before the function runs", name, err, ran)
		}
		if ok, _ := cfg.Graph.HasRelationship(ctx, "s1", "P", "member"); ok {
			t.Errorf("%s: a refused Atomic wrote the edge", name)
		}
	}
	s, _ := NewGraphService(GraphConfig{Graph: nonTxStore{nexus.NewMemStore()}, Log: NewMemTransferLog()})
	if err := s.View(ctx, func(nexus.GraphReader) error { return nil }); !errors.Is(err, ErrNoTransaction) {
		t.Errorf("View over a store that is not a TxStore: %v, want ErrNoTransaction", err)
	}
	// The pairing that can transact is admitted.
	s, _ = NewGraphService(GraphConfig{Graph: sqlStore, Log: sameLog})
	if err := s.Atomic(ctx, func(tx *GraphTx) error { return tx.Grant(ctx, "s1", "P", "member", nil, txMeta) }); err != nil {
		t.Fatalf("the store and the log on one *sql.DB: %v", err)
	}
}

// Atomics run at once each read a count and grant the edge it names, so the
// edge names give the order they committed in. Since must return their events in
// that order, with seq increasing, and page through it from a cursor.
func TestSince_ReturnsCommitOrder(t *testing.T) {
	const n = 24
	eachAtomic(t, func(t *testing.T, s *GraphService, g nexus.GraphStore, log sinceLog) {
		var wg sync.WaitGroup
		errs := make(chan error, n)
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs <- s.Atomic(ctx, func(tx *GraphTx) error {
					in, err := tx.InEdges(ctx, "ctr", "tick")
					if err != nil {
						return err
					}
					return tx.Grant(ctx, fmt.Sprintf("t%03d", len(in)), "ctr", "tick", nil, txMeta)
				})
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("an Atomic failed: %v", err)
			}
		}
		var paged []*TransferEvent
		var cursor int64
		for {
			page, err := log.Since(ctx, cursor, 5)
			if err != nil {
				t.Fatal(err)
			}
			if len(page) == 0 {
				break
			}
			paged = append(paged, page...)
			cursor = page[len(page)-1].Seq
		}
		if len(paged) != n {
			t.Fatalf("Since paged %d events, want %d", len(paged), n)
		}
		for i, e := range paged {
			if want := fmt.Sprintf("t%03d", i); e.From != want {
				t.Fatalf("event %d is %s, want %s: the log is not in commit order", i, e.From, want)
			}
			if i > 0 && e.Seq <= paged[i-1].Seq {
				t.Fatalf("seq does not increase at %d: %d after %d", i, e.Seq, paged[i-1].Seq)
			}
		}
		if _, err := log.Since(ctx, 0, 0); err == nil {
			t.Fatal("Since with no page size must be refused")
		}
	})
}

func TestRevokeWhere_RecordsOneEventPerRemovedEdgeInKeyOrder(t *testing.T) {
	eachAtomic(t, func(t *testing.T, s *GraphService, g nexus.GraphStore, log sinceLog) {
		inst := map[string]string{"partition": "P", "membership_id": "m1"}
		for _, to := range []string{"rc", "ra", "rb"} {
			_ = s.Grant(ctx, "s1", to, "assigned", inst, txMeta)
		}
		_ = s.Grant(ctx, "s1", "rd", "assigned", map[string]string{"partition": "P", "membership_id": "m0"}, txMeta)
		cursor := int64(len(since(t, log, 0)))
		var keys []nexus.EdgeKey
		err := s.Atomic(ctx, func(tx *GraphTx) error {
			var err error
			keys, err = tx.RevokeWhere(ctx, nexus.EdgeSelector{From: "s1", Type: "assigned", Attrs: inst}, txMeta)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) != 3 {
			t.Fatalf("removed %v, want the three edges of instance m1", keys)
		}
		got := describe(since(t, log, cursor))
		want := []string{"revoke s1>ra:assigned", "revoke s1>rb:assigned", "revoke s1>rc:assigned"}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("events %v, want %v", got, want)
		}
		if ok, _ := g.HasRelationship(ctx, "s1", "rd", "assigned"); !ok {
			t.Fatal("the other instance's edge was removed")
		}
	})
}

// A set revoke of thousands of edges is one statement and one event per edge,
// consecutive in seq.
func TestRevokeWhere_ThousandsOfEdgesInOneAtomic(t *testing.T) {
	const n = 3000
	s, g, log := sqlGraph(t, fileDB(t))
	err := g.(nexus.TxStore).Update(ctx, func(w nexus.TxWriter) error {
		for i := 0; i < n; i++ {
			if err := w.PutRelationship(ctx, &nexus.Relationship{From: fmt.Sprintf("s%05d", i), To: "role", Type: "assigned"}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var keys []nexus.EdgeKey
	if err := s.Atomic(ctx, func(tx *GraphTx) error {
		var err error
		keys, err = tx.RevokeWhere(ctx, nexus.EdgeSelector{To: "role", Type: "assigned"}, txMeta)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ev := since(t, log, 0)
	if len(keys) != n || len(ev) != n {
		t.Fatalf("removed %d, recorded %d, want %d each", len(keys), len(ev), n)
	}
	for i, e := range ev {
		if e.Seq != int64(i+1) || e.From != keys[i].From {
			t.Fatalf("event %d: seq %d from %s, want seq %d from %s", i, e.Seq, e.From, i+1, keys[i].From)
		}
	}
}

func TestGraphTx_RecordsOnlyRemovalsThatHappened(t *testing.T) {
	eachAtomic(t, func(t *testing.T, s *GraphService, g nexus.GraphStore, log sinceLog) {
		_ = s.Grant(ctx, "a", "P", "member", nil, txMeta)
		cursor := int64(len(since(t, log, 0)))
		err := s.Atomic(ctx, func(tx *GraphTx) error {
			if err := tx.Revoke(ctx, "ghost", "P", "member", txMeta); err != nil {
				return err
			}
			if err := tx.RevokeKeepingMin(ctx, "a", "P", "member", 1, txMeta); !errors.Is(err, ErrCardinalityFloor) {
				return fmt.Errorf("revoking the last member under a floor of 1: %v", err)
			}
			_ = tx.Grant(ctx, "b", "P", "member", nil, txMeta)
			return tx.RevokeKeepingMin(ctx, "a", "P", "member", 1, txMeta)
		})
		if err != nil {
			t.Fatal(err)
		}
		got := describe(since(t, log, cursor))
		want := []string{"grant b>P:member", "revoke a>P:member"}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("events %v, want %v: an absent edge or a refused floor recorded a revoke", got, want)
		}
	})
}

func TestGraphTx_DeleteEntityRecordsEveryIncidentEdge(t *testing.T) {
	eachAtomic(t, func(t *testing.T, s *GraphService, g nexus.GraphStore, log sinceLog) {
		_ = g.PutEntity(ctx, &nexus.Entity{ID: "role", Type: "role"})
		_ = s.Grant(ctx, "s1", "role", "assigned", nil, txMeta)
		_ = s.Grant(ctx, "P", "role", "role_def", nil, txMeta)
		_ = s.Grant(ctx, "role", "P", "in", nil, txMeta)
		cursor := int64(len(since(t, log, 0)))
		if err := s.Atomic(ctx, func(tx *GraphTx) error { return tx.DeleteEntity(ctx, "role", txMeta) }); err != nil {
			t.Fatal(err)
		}
		got := describe(since(t, log, cursor))
		want := []string{"revoke P>role:role_def", "revoke role>P:in", "revoke s1>role:assigned"}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("events %v, want %v", got, want)
		}
		err := s.Atomic(ctx, func(tx *GraphTx) error { return tx.DeleteEntity(ctx, "role", txMeta) })
		if !errors.Is(err, nexus.ErrNotFound) {
			t.Fatalf("deleting an unknown entity: %v, want nexus.ErrNotFound", err)
		}
	})
}

func TestSQLTransferLog_SinceHasItsIndex(t *testing.T) {
	db := fileDB(t)
	if err := NewSQLTransferLog(db).InitSchema(ctx); err != nil {
		t.Fatal(err)
	}
	var sqlText string
	err := db.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_census_transfers_seq'`).Scan(&sqlText)
	if err != nil {
		t.Fatalf("idx_census_transfers_seq: %v", err)
	}
	var plan string
	rows, err := db.QueryContext(ctx, `EXPLAIN QUERY PLAN SELECT id FROM census_transfers WHERE seq > 0 ORDER BY seq LIMIT 5`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan += detail + "; "
	}
	if !strings.Contains(plan, "idx_census_transfers_seq") {
		t.Fatalf("Since's query does not use the seq index: %s", plan)
	}
}
