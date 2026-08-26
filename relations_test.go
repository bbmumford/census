package census

import (
	"errors"
	"testing"

	"github.com/bbmumford/nexus"
)

func newGraphService(t *testing.T) (*GraphService, nexus.GraphStore, *MemTransferLog) {
	t.Helper()
	g := nexus.NewMemStore()
	log := NewMemTransferLog()
	s, err := NewGraphService(GraphConfig{Graph: g, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return s, g, log
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
	s, g, log := newGraphService(t)
	meta := ChangeMeta{Owner: "acme", Trigger: "admin-1", Source: "admin", Auto: false}
	if err := s.Grant(ctx, "user-1", "org-9", "member", map[string]string{"role": "admin"}, meta); err != nil {
		t.Fatal(err)
	}
	// the edge is in the graph
	if ok, _ := g.HasRelationship(ctx, "user-1", "org-9", "member"); !ok {
		t.Fatal("Grant must create the edge")
	}
	// the change is recorded with provenance
	hist, _ := s.History(ctx, "acme", "org-9")
	if len(hist) != 1 || hist[0].Change != "grant" || hist[0].Trigger != "admin-1" {
		t.Fatalf("Grant must record a provenance-stamped transfer; got %+v", hist)
	}
	// revoke removes the edge and records a second event
	if err := s.Revoke(ctx, "user-1", "org-9", "member", ChangeMeta{Owner: "acme", Source: "admin"}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := g.HasRelationship(ctx, "user-1", "org-9", "member"); ok {
		t.Fatal("Revoke must remove the edge")
	}
	if hist, _ := s.History(ctx, "acme", "org-9"); len(hist) != 2 || hist[1].Change != "revoke" {
		t.Fatalf("Revoke must append a revoke event; got %+v", hist)
	}
	_ = log
}

func TestGraph_MinIncomingGuardBlocksLastEdge(t *testing.T) {
	s, g, _ := newGraphService(t)
	m := ChangeMeta{Owner: "acme"}
	s.Grant(ctx, "user-1", "org-9", "owner", nil, m)
	s.Grant(ctx, "user-2", "org-9", "owner", nil, m)
	// two owners: removing one is allowed (guard requires ≥1 remaining)
	guard := MinIncoming("owner", "org-9", 1)
	if err := s.Revoke(ctx, "user-1", "org-9", "owner", m, guard); err != nil {
		t.Fatalf("removing one of two owners must be allowed; got %v", err)
	}
	// one owner left: the guard now blocks removing the last, and leaves the edge intact
	if err := s.Revoke(ctx, "user-2", "org-9", "owner", m, MinIncoming("owner", "org-9", 1)); !errors.Is(err, ErrGuardViolation) {
		t.Fatalf("removing the last owner must be ErrGuardViolation; got %v", err)
	}
	if ok, _ := g.HasRelationship(ctx, "user-2", "org-9", "owner"); !ok {
		t.Fatal("a blocked revoke must leave the edge intact (fail-closed)")
	}
	// and the blocked revoke recorded no event
	if hist, _ := s.History(ctx, "acme", "org-9"); len(hist) != 3 {
		t.Fatalf("a blocked revoke must record nothing; want 3 events (2 grant + 1 revoke), got %d", len(hist))
	}
}

// TestGraph_ResolveIsGeneral proves the same resolver answers different relationship questions — not
// just ownership — by the consumer's ladder alone, over overlapping arbitrary-depth paths.
func TestGraph_ResolveIsGeneral(t *testing.T) {
	s, _, _ := newGraphService(t)
	m := ChangeMeta{Owner: "acme"}
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
