package census

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bbmumford/nexus"
)

func newGraphServiceWith(t *testing.T, log TransferLog) (*GraphService, nexus.GraphStore) {
	t.Helper()
	g := nexus.NewMemStore()
	s, err := NewGraphService(GraphConfig{Graph: g, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return s, g
}

func TestGraph_RequiresLog(t *testing.T) {
	if _, err := NewGraphService(GraphConfig{Graph: nexus.NewMemStore()}); err == nil {
		t.Fatal("a nil Log must be rejected — relationship changes must be recorded")
	}
	if _, err := NewGraphService(GraphConfig{Log: NewMemTransferLog()}); err == nil {
		t.Fatal("a nil Graph must be rejected")
	}
}

func TestGraph_GrantRevokeRecordsProvenance(t *testing.T) {
	eachLog(t, func(t *testing.T, log TransferLog) {
		s, g := newGraphServiceWith(t, log)
		meta := ChangeMeta{Partition: "acme", Trigger: "admin-1", Source: "admin", Auto: false}
		if err := s.Grant(ctx, "user-1", "org-9", "member", map[string]string{"role": "admin"}, meta); err != nil {
			t.Fatal(err)
		}
		if ok, _ := g.HasRelationship(ctx, "user-1", "org-9", "member"); !ok {
			t.Fatal("Grant must create the edge")
		}
		hist, _ := s.History(ctx, "acme", "org-9")
		if len(hist) != 1 || hist[0].Change != "grant" || hist[0].Trigger != "admin-1" {
			t.Fatalf("Grant must record a provenance-stamped transfer; got %+v", hist)
		}
		if err := s.Revoke(ctx, "user-1", "org-9", "member", ChangeMeta{Partition: "acme", Source: "admin"}); err != nil {
			t.Fatal(err)
		}
		if ok, _ := g.HasRelationship(ctx, "user-1", "org-9", "member"); ok {
			t.Fatal("Revoke must remove the edge")
		}
		if hist, _ := s.History(ctx, "acme", "org-9"); len(hist) != 2 || hist[1].Change != "revoke" {
			t.Fatalf("Revoke must append a revoke event; got %+v", hist)
		}
	})
}

func TestGraph_MinIncomingGuardBlocksLastEdge(t *testing.T) {
	eachLog(t, func(t *testing.T, log TransferLog) {
		s, g := newGraphServiceWith(t, log)
		m := ChangeMeta{Partition: "acme"}
		s.Grant(ctx, "user-1", "org-9", "partition", nil, m)
		s.Grant(ctx, "user-2", "org-9", "partition", nil, m)
		// two owners: removing one is allowed (guard requires ≥1 remaining)
		if err := s.Revoke(ctx, "user-1", "org-9", "partition", m, MinIncoming("partition", "org-9", 1)); err != nil {
			t.Fatalf("removing one of two owners must be allowed; got %v", err)
		}
		// one partition left: the guard blocks removing the last, and leaves the edge intact
		if err := s.Revoke(ctx, "user-2", "org-9", "partition", m, MinIncoming("partition", "org-9", 1)); !errors.Is(err, ErrGuardViolation) {
			t.Fatalf("removing the last partition must be ErrGuardViolation; got %v", err)
		}
		if ok, _ := g.HasRelationship(ctx, "user-2", "org-9", "partition"); !ok {
			t.Fatal("a blocked revoke must leave the edge intact (fail-closed)")
		}
		// the blocked revoke recorded no event: 2 grants + 1 successful revoke = 3
		if hist, _ := s.History(ctx, "acme", "org-9"); len(hist) != 3 {
			t.Fatalf("a blocked revoke must record nothing; want 3 events, got %d", len(hist))
		}
	})
}

// TestGraph_ResolveIsGeneral proves the same resolver answers different relationship questions — not
// just ownership — by the consumer's ladder alone, over overlapping arbitrary-depth paths.
func TestGraph_ResolveIsGeneral(t *testing.T) {
	s, _ := newGraphServiceWith(t, NewMemTransferLog())
	m := ChangeMeta{Partition: "acme"}
	// graph: user-1 --member--> team-a --owns--> project-x ; user-1 --assignee--> ticket-7
	s.Grant(ctx, "user-1", "team-a", "member", nil, m)
	s.Grant(ctx, "team-a", "project-x", "owns", nil, m)
	s.Grant(ctx, "user-1", "ticket-7", "assignee", nil, m)

	// "what does user-1 own" — via their team (transitive rung)
	owns, err := s.Resolve(ctx, "user-1", Via("member", OutTargets("owns")))
	if err != nil || !owns.Resolved || owns.Value != "project-x" {
		t.Fatalf("ownership resolution: %+v err=%v", owns, err)
	}
	// the SAME resolver answers a different question — assignment — with a different ladder
	assigned, err := s.Resolve(ctx, "user-1", OutTargets("assignee"))
	if err != nil || !assigned.Resolved || assigned.Value != "ticket-7" {
		t.Fatalf("assignment resolution (same primitive): %+v err=%v", assigned, err)
	}
	// a direct edge takes precedence over a transitive one when both are on the ladder
	s.Grant(ctx, "user-1", "project-y", "owns", nil, m)
	direct, _ := s.Resolve(ctx, "user-1", OutTargets("owns"), Via("member", OutTargets("owns")))
	if !direct.Resolved || direct.Value != "project-y" {
		t.Fatalf("a direct rung must win over a transitive one; got %+v", direct)
	}
}

// The service is the handle a consumer holds, so it must answer the edge reads
// itself. A consumer that had to reach for the store to read would also acquire
// PutRelationship and DeleteRelationship, and could write memberships that
// appear in no History.
var (
	_ interface {
		OutEdges(ctx context.Context, from string, types ...string) ([]nexus.Relationship, error)
	} = (*GraphService)(nil)
	_ interface {
		InEdges(ctx context.Context, to string, types ...string) ([]nexus.Relationship, error)
	} = (*GraphService)(nil)
)

func TestGraph_EdgeReadsAnswerBothDirections(t *testing.T) {
	eachLog(t, func(t *testing.T, log TransferLog) {
		s, _ := newGraphServiceWith(t, log)
		meta := ChangeMeta{Partition: "acme", Source: "test"}
		for _, subject := range []string{"key-1", "device-7"} {
			if err := s.Grant(ctx, subject, "acme", "partition", nil, meta); err != nil {
				t.Fatal(err)
			}
		}

		// Outward: which partition does this subject belong to.
		out, err := s.OutEdges(ctx, "key-1", "partition")
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 || out[0].To != "acme" {
			t.Fatalf("OutEdges(key-1) = %+v, want one edge to acme", out)
		}

		// Inward: which subjects belong to this partition. This direction has no
		// other answer on the service, and it is the one a member listing needs.
		in, err := s.InEdges(ctx, "acme", "partition")
		if err != nil {
			t.Fatal(err)
		}
		if len(in) != 2 {
			t.Fatalf("InEdges(acme) = %+v, want both members", in)
		}
		seen := map[string]bool{}
		for _, e := range in {
			seen[e.From] = true
			if e.From == "acme" {
				t.Fatal("the partition was returned as its own member: the read took the wrong end")
			}
		}
		if !seen["key-1"] || !seen["device-7"] {
			t.Fatalf("InEdges(acme) missed a member: %+v", in)
		}
	})
}

func TestGraph_EdgeReadsNarrowByType(t *testing.T) {
	eachLog(t, func(t *testing.T, log TransferLog) {
		s, _ := newGraphServiceWith(t, log)
		meta := ChangeMeta{Partition: "acme", Source: "test"}
		if err := s.Grant(ctx, "key-1", "acme", "partition", nil, meta); err != nil {
			t.Fatal(err)
		}
		if err := s.Grant(ctx, "audit-3", "acme", "audit", nil, meta); err != nil {
			t.Fatal(err)
		}

		in, err := s.InEdges(ctx, "acme", "partition")
		if err != nil {
			t.Fatal(err)
		}
		if len(in) != 1 || in[0].From != "key-1" {
			t.Fatalf("InEdges(acme, partition) = %+v, want only the partition edge — an unnarrowed "+
				"read lists every entity that points at the partition as one of its members", in)
		}
	})
}

// TestGraph_EdgeReadsRecordNothing pins that a read is not a transition. Routing
// these through record would put an event in History for every listing, and a
// consumer reading History to audit who was granted what would find entries no
// grant produced.
func TestGraph_EdgeReadsRecordNothing(t *testing.T) {
	eachLog(t, func(t *testing.T, log TransferLog) {
		s, _ := newGraphServiceWith(t, log)
		if err := s.Grant(ctx, "key-1", "acme", "partition", nil, ChangeMeta{Partition: "acme", Source: "test"}); err != nil {
			t.Fatal(err)
		}
		before, _ := s.History(ctx, "acme", "acme")

		if _, err := s.OutEdges(ctx, "key-1", "partition"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.InEdges(ctx, "acme", "partition"); err != nil {
			t.Fatal(err)
		}

		after, _ := s.History(ctx, "acme", "acme")
		if len(after) != len(before) {
			t.Fatalf("reads recorded %d transfer event(s); a read changes no relationship",
				len(after)-len(before))
		}
	})
}

// TestTransferLog_AnUnscopedListReturnsNothing pins the partition scoping of the
// provenance log itself, on both backends.
//
// The credential/key store already has this cover; the transfer log did not, and it
// is the surface where an over-wide read is worst: this is the record of who granted
// and revoked what. A predicate admitting an empty partition would let any caller
// read every partition's grant history, and — in the direction that actually shipped
// — a reader who believes an empty partition means "everything" gets an EMPTY answer
// and reads it as "no such events occurred".
//
// The legs are asserted to DIFFER rather than only asserting the empty one is empty:
// a test that checks only the call it expects to succeed cannot tell a real filter
// from one that admits everyone.
func TestTransferLog_AnUnscopedListReturnsNothing(t *testing.T) {
	eachLog(t, func(t *testing.T, log TransferLog) {
		at := time.Unix(0, 0).UTC()
		for _, e := range []*TransferEvent{
			{ID: "ev-1", Partition: "acme", From: "key-1", To: "acme", Type: "partition", Change: "grant", Source: "test", At: at},
			{ID: "ev-2", Partition: "globex", From: "key-1", To: "globex", Type: "partition", Change: "grant", Source: "test", At: at},
		} {
			if err := log.Record(ctx, e); err != nil {
				t.Fatalf("Record(%s): %v", e.ID, err)
			}
		}

		scoped, err := log.List(ctx, "acme", "key-1")
		if err != nil {
			t.Fatal(err)
		}
		if len(scoped) != 1 || scoped[0].Partition != "acme" {
			t.Fatalf("List(acme) = %+v, want only acme's event", scoped)
		}

		other, err := log.List(ctx, "globex", "key-1")
		if err != nil {
			t.Fatal(err)
		}
		if len(other) != 1 || other[0].Partition != "globex" {
			t.Fatalf("List(globex) = %+v, want only globex's event", other)
		}

		blind, err := log.List(ctx, "", "key-1")
		if err != nil {
			t.Fatalf("an unscoped list must answer emptily, not error: %v", err)
		}
		if len(blind) != 0 {
			t.Fatalf("an unscoped list returned %d event(s); the predicate admits every partition's "+
				"grant history", len(blind))
		}
		if len(blind) == len(scoped)+len(other) {
			t.Fatal("the unscoped list saw the union of both partitions")
		}
	})
}
