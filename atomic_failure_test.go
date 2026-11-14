package census

import (
	"errors"
	"testing"

	"github.com/bbmumford/nexus"
)

// A change whose event cannot be recorded does not commit, even when the function
// drops the error and returns nil: the edge write ran before the record failed,
// and committing would leave an edge the log does not name.
func TestAtomic_ADroppedRecordErrorStillRollsBack(t *testing.T) {
	db := fileDB(t)
	s, g, log := sqlGraph(t, db)
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER refuseEvent BEFORE INSERT ON censusTransfers
		BEGIN SELECT RAISE(ABORT, 'event refused'); END`); err != nil {
		t.Fatal(err)
	}
	var dropped, later error
	err := s.Atomic(ctx, func(tx *GraphTx) error {
		dropped = tx.Grant(ctx, "s1", "p", "member", nil, ChangeMeta{Partition: "p"})
		later = tx.PutEntity(ctx, &nexus.Entity{ID: "r1", Type: "role"})
		return nil
	})
	if dropped == nil {
		t.Fatal("the refused record reported no error")
	}
	if err == nil || err.Error() != dropped.Error() {
		t.Fatalf("Atomic returned %v, want the dropped write's error %v", err, dropped)
	}
	if later == nil || later.Error() != dropped.Error() {
		t.Fatalf("a write after the failure answered %v, want %v", later, dropped)
	}
	if held, _ := g.HasRelationship(ctx, "s1", "p", "member"); held {
		t.Fatal("the edge committed although its event was refused")
	}
	if _, err := g.GetEntity(ctx, "r1"); !errors.Is(err, nexus.ErrNotFound) {
		t.Fatalf("a write after the failure committed: %v", err)
	}
	if ev := since(t, log, 0); len(ev) != 0 {
		t.Fatalf("events recorded: %v", describe(ev))
	}
}

// A refusal decided before anything is written does not fail the transaction: a
// function may catch the floor and commit its other changes with their events.
func TestAtomic_ACaughtFloorStillCommits(t *testing.T) {
	eachAtomic(t, func(t *testing.T, s *GraphService, g nexus.GraphStore, log sinceLog) {
		if err := s.Grant(ctx, "s1", "p", "member", nil, ChangeMeta{Partition: "p"}); err != nil {
			t.Fatal(err)
		}
		base := int64(len(since(t, log, 0)))
		err := s.Atomic(ctx, func(tx *GraphTx) error {
			if err := tx.RevokeKeepingMin(ctx, "s1", "p", "member", 1, ChangeMeta{Partition: "p"}); !errors.Is(err, nexus.ErrCardinalityFloor) {
				t.Errorf("floor: %v", err)
			}
			if err := tx.DeleteEntity(ctx, "absent", ChangeMeta{Partition: "p"}); !errors.Is(err, nexus.ErrNotFound) {
				t.Errorf("absent entity: %v", err)
			}
			return tx.Grant(ctx, "s2", "p", "member", nil, ChangeMeta{Partition: "p"})
		})
		if err != nil {
			t.Fatalf("Atomic after a caught floor: %v", err)
		}
		if got := describe(since(t, log, base)); len(got) != 1 || got[0] != "grant s2>p:member" {
			t.Fatalf("events after the caught floor: %v, want the one grant", got)
		}
	})
}

// An event names its edge byte for byte. A field the JSON path of RecordTx would
// rewrite is refused, and the Atomic carrying it commits nothing.
func TestAtomic_RefusesAnEventItCannotRecordExactly(t *testing.T) {
	s, g, log := sqlGraph(t, fileDB(t))
	for _, from := range []string{"s\xff1", "s\xfe1"} {
		err := s.Atomic(ctx, func(tx *GraphTx) error {
			return tx.Grant(ctx, from, "p", "member", nil, ChangeMeta{Partition: "p"})
		})
		if !errors.Is(err, errEventNotUTF8) {
			t.Fatalf("%q: Atomic returned %v, want errEventNotUTF8", from, err)
		}
		if held, _ := g.HasRelationship(ctx, from, "p", "member"); held {
			t.Fatalf("%q: the edge committed without its event", from)
		}
	}
	if ev := since(t, log, 0); len(ev) != 0 {
		t.Fatalf("events recorded: %q", describe(ev))
	}
	nul := "s\x001"
	if err := s.Atomic(ctx, func(tx *GraphTx) error {
		return tx.Grant(ctx, nul, "p", "member", nil, ChangeMeta{Partition: "p"})
	}); err != nil {
		t.Fatalf("a UTF-8 id with a NUL byte: %v", err)
	}
	if ev := since(t, log, 0); len(ev) != 1 || ev[0].From != nul {
		t.Fatalf("events %q, want one naming %q", describe(ev), nul)
	}
}
