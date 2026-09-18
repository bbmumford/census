package census

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bbmumford/nexus"
	_ "modernc.org/sqlite"
)

// graphsUnderTest returns the same service over each store, because a floor that
// holds in memory and not in SQL is the half a single-store test cannot see — and
// SQL is the one deployments share between processes.
func graphsUnderTest(t *testing.T) map[string]nexus.GraphStore {
	t.Helper()
	// A FILE database, not ":memory:" — each pooled connection to an in-memory SQLite
	// gets its own empty database, so the schema would land on one connection and the
	// query run on another. These tests open several connections on purpose.
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "nexus.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sq := nexus.NewSQLStore(db)
	if err := sq.InitSchema(context.Background()); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return map[string]nexus.GraphStore{"mem": nexus.NewMemStore(), "sql": sq}
}

func TestRevokeKeepingMin_RefusesTheLastEdge(t *testing.T) {
	ctx := context.Background()
	meta := ChangeMeta{Partition: "p", Trigger: "test", Source: "test"}
	for name, g := range graphsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s, err := NewGraphService(GraphConfig{Graph: g, Log: NewMemTransferLog()})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Grant(ctx, "a", "target", "member", nil, meta); err != nil {
				t.Fatal(err)
			}
			err = s.RevokeKeepingMin(ctx, "a", "target", "member", 1, meta)
			if !errors.Is(err, ErrCardinalityFloor) {
				t.Fatalf("removing the only edge under a floor of 1: err = %v, want ErrCardinalityFloor", err)
			}
			left, err := g.InEdges(ctx, "target", "member")
			if err != nil {
				t.Fatal(err)
			}
			if len(left) != 1 {
				t.Fatalf("the refused revoke still removed the edge: %d remain", len(left))
			}
		})
	}
}

// The property the store method exists for. Two callers each see a safe total; only
// one may act on it. A count taken before a separate delete passes this test only by
// luck, which is why it runs repeatedly.
func TestRevokeKeepingMin_FloorHoldsUnderConcurrentRevokes(t *testing.T) {
	ctx := context.Background()
	meta := ChangeMeta{Partition: "p", Trigger: "test", Source: "test"}

	for name := range map[string]struct{}{"mem": {}, "sql": {}} {
		t.Run(name, func(t *testing.T) {
			for attempt := 0; attempt < 200; attempt++ {
				g := graphsUnderTest(t)[name]
				s, err := NewGraphService(GraphConfig{Graph: g, Log: NewMemTransferLog()})
				if err != nil {
					t.Fatal(err)
				}
				for _, from := range []string{"a", "b"} {
					if err := s.Grant(ctx, from, "target", "member", nil, meta); err != nil {
						t.Fatal(err)
					}
				}

				var wg sync.WaitGroup
				start := make(chan struct{})
				for _, from := range []string{"a", "b"} {
					wg.Add(1)
					go func(f string) {
						defer wg.Done()
						<-start
						_ = s.RevokeKeepingMin(ctx, f, "target", "member", 1, meta)
					}(from)
				}
				close(start)
				wg.Wait()

				left, err := g.InEdges(ctx, "target", "member")
				if err != nil {
					t.Fatal(err)
				}
				if len(left) < 1 {
					t.Fatalf("attempt %d: floor of 1 breached — %d edges remain after two concurrent revokes", attempt, len(left))
				}
			}
		})
	}
}
