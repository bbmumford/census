package census

import (
	"context"
	"errors"
	"testing"

	"github.com/bbmumford/nexus"
)

// refusingStore fails the test if the graph is read at all. It embeds the
// interface rather than implementing it, so any method other than the one
// overridden below panics instead of quietly returning a zero value.
type refusingStore struct {
	nexus.GraphStore
	t *testing.T
}

func (s refusingStore) OutEdges(context.Context, string, ...string) ([]nexus.Relationship, error) {
	s.t.Fatal("the graph was READ before the identifiers were checked — deny-before-read is not holding")
	return nil, nil
}

// erroringStore stands in for a graph that cannot answer.
type erroringStore struct {
	nexus.GraphStore
	err error
}

func (s erroringStore) OutEdges(context.Context, string, ...string) ([]nexus.Relationship, error) {
	return nil, s.err
}

func graphWith(t *testing.T, rels ...nexus.Relationship) nexus.GraphStore {
	t.Helper()
	g := nexus.NewMemStore()
	for i := range rels {
		r := rels[i]
		if err := g.PutRelationship(context.Background(), &r); err != nil {
			t.Fatalf("seed relationship: %v", err)
		}
	}
	return g
}

func mustService(t *testing.T, g nexus.GraphStore, types ...string) *GrantService {
	t.Helper()
	s, err := NewGrantService(GrantConfig{Graph: g, EdgeTypes: types})
	if err != nil {
		t.Fatalf("NewGrantService: %v", err)
	}
	return s
}

// TestGrantService_RefusesBeforeReading is the deny-before-read leg, and the
// store proves it: it fails the test if Resolve touches the graph at all.
func TestGrantService_RefusesBeforeReading(t *testing.T) {
	cases := []struct {
		name      string
		partition string
		subject   string
		want      error
	}{
		{"no subject", "p-1", "", ErrGrantSubject},
		{"no partition", "", "s-1", ErrGrantPartition},
		{"neither", "", "", ErrGrantSubject},
		{"blank subject", "p-1", "   ", ErrGrantSubject},
		{"blank partition", "  ", "s-1", ErrGrantPartition},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := mustService(t, refusingStore{t: t})
			got, err := s.Resolve(context.Background(), tc.partition, tc.subject)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if got != nil {
				t.Fatalf("a refused resolution returned grants: %v", got)
			}
		})
	}
}

// TestGrantService_ResolvesAGrant is the positive leg. Without it every refusal
// above would pass on a service that can never resolve anything.
func TestGrantService_ResolvesAGrant(t *testing.T) {
	g := graphWith(t, nexus.Relationship{
		From: "s-1", To: "p-1", Type: "member", Attrs: GrantAttrs("a.read", "b.write"),
	})
	got, err := mustService(t, g).Resolve(context.Background(), "p-1", "s-1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 2 || got[0] != "a.read" || got[1] != "b.write" {
		t.Fatalf("grants = %v, want [a.read b.write]", got)
	}
}

// TestGrantService_UnionsAcrossEdges is the reason this does not delegate to
// nexus.Resolve: that resolver is first-hit-wins and would return only the
// first edge's grants, silently dropping the rest.
func TestGrantService_UnionsAcrossEdges(t *testing.T) {
	g := graphWith(t,
		nexus.Relationship{From: "s-1", To: "p-1", Type: "member", Attrs: GrantAttrs("a.read")},
		nexus.Relationship{From: "s-1", To: "p-1", Type: "operator", Attrs: GrantAttrs("b.write")},
		nexus.Relationship{From: "s-1", To: "p-1", Type: "auditor", Attrs: GrantAttrs("c.list")},
	)
	got, err := mustService(t, g).Resolve(context.Background(), "p-1", "s-1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("grants = %v, want all THREE edges unioned, not first-hit", got)
	}
	for _, want := range []string{"a.read", "b.write", "c.list"} {
		if !contains(got, want) {
			t.Fatalf("grants = %v, missing %q", got, want)
		}
	}
}

// TestGrantService_OtherPartitionsNeverCount is the isolation leg: holding a
// capability in one partition must not satisfy a check in another.
func TestGrantService_OtherPartitionsNeverCount(t *testing.T) {
	g := graphWith(t,
		nexus.Relationship{From: "s-1", To: "p-1", Type: "member", Attrs: GrantAttrs("mine.read")},
		nexus.Relationship{From: "s-1", To: "p-2", Type: "member", Attrs: GrantAttrs("theirs.admin")},
	)
	got, err := mustService(t, g).Resolve(context.Background(), "p-1", "s-1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if contains(got, "theirs.admin") {
		t.Fatalf("a grant from ANOTHER partition leaked in: %v", got)
	}
	if len(got) != 1 || got[0] != "mine.read" {
		t.Fatalf("grants = %v, want only [mine.read]", got)
	}
}

// TestGrantService_DeniesSurviveVerbatim pins the layering: census accumulates
// strings and warrant judges them, so a deny must arrive intact rather than
// being resolved away here.
func TestGrantService_DeniesSurviveVerbatim(t *testing.T) {
	g := graphWith(t,
		nexus.Relationship{From: "s-1", To: "p-1", Type: "member", Attrs: GrantAttrs("a.read", "a.write")},
		nexus.Relationship{From: "s-1", To: "p-1", Type: "restriction", Attrs: GrantAttrs("-a.write")},
	)
	got, err := mustService(t, g).Resolve(context.Background(), "p-1", "s-1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !contains(got, "-a.write") {
		t.Fatalf("the deny was dropped: %v", got)
	}
	if !contains(got, "a.write") {
		t.Fatalf("census resolved the deny itself instead of passing both to warrant: %v", got)
	}
}

// TestGrantService_GraphErrorIsNotAnEmptyResult asserts an outage denies. An
// empty slice means "present, holds nothing"; the readers admit that and refuse
// an error, so collapsing the two would widen a caller during an outage.
func TestGrantService_GraphErrorIsNotAnEmptyResult(t *testing.T) {
	boom := errors.New("graph unavailable")
	s := mustService(t, erroringStore{err: boom})
	got, err := s.Resolve(context.Background(), "p-1", "s-1")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the graph's error", err)
	}
	if got != nil {
		t.Fatalf("an errored resolution returned grants: %v", got)
	}
}

// TestGrantService_EdgeTypeFilter proves an unrelated edge carrying attributes
// does not contribute capabilities when the consumer names its grant types.
func TestGrantService_EdgeTypeFilter(t *testing.T) {
	g := graphWith(t,
		nexus.Relationship{From: "s-1", To: "p-1", Type: "member", Attrs: GrantAttrs("a.read")},
		nexus.Relationship{From: "s-1", To: "p-1", Type: "routing", Attrs: GrantAttrs("should.not.count")},
	)
	got, err := mustService(t, g, "member").Resolve(context.Background(), "p-1", "s-1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if contains(got, "should.not.count") {
		t.Fatalf("an unnamed edge type contributed a capability: %v", got)
	}
	if len(got) != 1 {
		t.Fatalf("grants = %v, want only the named type's", got)
	}
}

// TestGrantService_DeduplicatesAcrossEdges keeps a capability granted twice from
// arriving twice, which would otherwise make a held-count meaningless.
func TestGrantService_DeduplicatesAcrossEdges(t *testing.T) {
	g := graphWith(t,
		nexus.Relationship{From: "s-1", To: "p-1", Type: "member", Attrs: GrantAttrs("a.read")},
		nexus.Relationship{From: "s-1", To: "p-1", Type: "operator", Attrs: GrantAttrs("a.read")},
	)
	got, _ := mustService(t, g).Resolve(context.Background(), "p-1", "s-1")
	if len(got) != 1 {
		t.Fatalf("grants = %v, want one deduplicated entry", got)
	}
}

// TestGrantService_NoGrantsIsPresentHoldingNothing distinguishes the two
// non-error outcomes: a subject with an edge but no capabilities is present and
// holds nothing, which the readers admit.
func TestGrantService_NoGrantsIsPresentHoldingNothing(t *testing.T) {
	g := graphWith(t, nexus.Relationship{From: "s-1", To: "p-1", Type: "member"})
	got, err := mustService(t, g).Resolve(context.Background(), "p-1", "s-1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("grants = %v, want none", got)
	}
}

// TestNewGrantService_RefusesANilGraph asserts a misconfigured consumer fails at
// construction rather than denying every request in a way that reads like an
// authorization outcome.
func TestNewGrantService_RefusesANilGraph(t *testing.T) {
	if _, err := NewGrantService(GrantConfig{}); !errors.Is(err, ErrGrantGraph) {
		t.Fatalf("err = %v, want ErrGrantGraph", err)
	}
	var s *GrantService
	if _, err := s.Resolve(context.Background(), "p-1", "s-1"); !errors.Is(err, ErrGrantGraph) {
		t.Fatalf("nil receiver err = %v, want ErrGrantGraph", err)
	}
}

// TestGrantAttrs pins the authoring helper against the resolver that reads it:
// whatever GrantAttrs writes, Resolve must return.
func TestGrantAttrs(t *testing.T) {
	if got := GrantAttrs(); got != nil {
		t.Fatalf("GrantAttrs() = %v, want nil for no capabilities", got)
	}
	if got := GrantAttrs("  ", ""); got != nil {
		t.Fatalf("GrantAttrs(blanks) = %v, want nil", got)
	}
	g := graphWith(t, nexus.Relationship{
		From: "s-1", To: "p-1", Type: "member", Attrs: GrantAttrs("a.read", "  ", "b.write"),
	})
	got, _ := mustService(t, g).Resolve(context.Background(), "p-1", "s-1")
	if len(got) != 2 {
		t.Fatalf("round trip = %v, want the two non-blank capabilities", got)
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
