package census

import (
	"context"
	"errors"
	"testing"

	"github.com/bbmumford/nexus"
)

// testMembershipAttrs stands in for the attributes a consumer's membership
// readers admit a member by. Its key and value mean nothing to census, which is
// the property the tests below hold: census writes what it was configured with.
var testMembershipAttrs = map[string]string{"subject_kind": "probe_kind"}

// newProvisioner builds a Provisioner over an in-memory graph whose ladder resolves
// the "member" membership edge EnsureUser writes.
func newProvisioner(t *testing.T, assign PartitionAssigner) (*Provisioner, nexus.GraphStore) {
	t.Helper()
	g := nexus.NewMemStore()
	gs, err := NewGraphService(GraphConfig{Graph: g, Log: NewMemTransferLog()})
	if err != nil {
		t.Fatalf("NewGraphService: %v", err)
	}
	p, err := NewProvisioner(ProvisionerConfig{
		Graph:           gs,
		Rules:           []nexus.Rule{OutTargets("member")},
		Assign:          assign,
		MembershipEdge:  "member",
		MembershipAttrs: testMembershipAttrs,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	return p, g
}

func TestEnsureUser_CreateThenReturning(t *testing.T) {
	const part = "partition-1"
	calls := 0
	assign := func(_ context.Context, _ ProviderIdentity, _ string) (string, error) {
		calls++
		return part, nil
	}
	p, _ := newProvisioner(t, assign)
	id := ProviderIdentity{Provider: "google", ProviderUserID: "sub-123", Email: "a@example.com", Name: "A"}

	sub1, part1, err := p.EnsureUser(ctx, id, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if sub1 == "" || part1 != part {
		t.Fatalf("create returned subject=%q partition=%q", sub1, part1)
	}

	// Returning: same identity → same subject, partition resolved via the ladder,
	// no second onboarding call.
	sub2, part2, err := p.EnsureUser(ctx, id, "")
	if err != nil {
		t.Fatalf("returning: %v", err)
	}
	if sub2 != sub1 {
		t.Fatalf("returning subject %q != original %q", sub2, sub1)
	}
	if part2 != part {
		t.Fatalf("returning partition %q != %q", part2, part)
	}
	if calls != 1 {
		t.Fatalf("assigner called %d times, want 1 (only on create)", calls)
	}
}

// A denying onboarding policy fails closed and leaves no half-provisioned subject.
func TestEnsureUser_DenyFirstTimeFailsClosed(t *testing.T) {
	assign := func(_ context.Context, _ ProviderIdentity, _ string) (string, error) {
		return "", errors.New("no invitation")
	}
	p, g := newProvisioner(t, assign)
	id := ProviderIdentity{Provider: "google", ProviderUserID: "sub-x"}

	if _, _, err := p.EnsureUser(ctx, id, ""); err == nil {
		t.Fatal("denying assigner should fail closed")
	}
	edges, _ := g.InEdges(ctx, "sub-x", "identity:google")
	if len(edges) != 0 {
		t.Fatalf("denied first-time user left %d identity edge(s)", len(edges))
	}
}

// An empty partition from the assigner is ErrNoPartition (fail closed).
func TestEnsureUser_EmptyAssignedPartition(t *testing.T) {
	assign := func(_ context.Context, _ ProviderIdentity, _ string) (string, error) {
		return "", nil
	}
	p, _ := newProvisioner(t, assign)
	_, _, err := p.EnsureUser(ctx, ProviderIdentity{Provider: "g", ProviderUserID: "u"}, "")
	if !errors.Is(err, ErrNoPartition) {
		t.Fatalf("want ErrNoPartition, got %v", err)
	}
}

// A returning subject whose membership edge the ladder does not cover resolves to
// nothing → ErrNoPartition (a caller-hint can never substitute).
func TestEnsureUser_UnresolvableReturningFailsClosed(t *testing.T) {
	g := nexus.NewMemStore()
	gs, err := NewGraphService(GraphConfig{Graph: g, Log: NewMemTransferLog()})
	if err != nil {
		t.Fatalf("NewGraphService: %v", err)
	}
	// Ladder resolves "owner" edges, but EnsureUser writes a "member" edge.
	p, err := NewProvisioner(ProvisionerConfig{
		Graph:           gs,
		Rules:           []nexus.Rule{OutTargets("owner")},
		Assign:          func(_ context.Context, _ ProviderIdentity, _ string) (string, error) { return "part-1", nil },
		MembershipEdge:  "member",
		MembershipAttrs: testMembershipAttrs,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	id := ProviderIdentity{Provider: "google", ProviderUserID: "sub-1"}
	if _, _, err := p.EnsureUser(ctx, id, ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, _, err := p.EnsureUser(ctx, id, ""); !errors.Is(err, ErrNoPartition) {
		t.Fatalf("returning want ErrNoPartition, got %v", err)
	}
}

func TestEnsureUser_IncompleteIdentity(t *testing.T) {
	p, _ := newProvisioner(t, func(_ context.Context, _ ProviderIdentity, _ string) (string, error) { return "p", nil })
	if _, _, err := p.EnsureUser(ctx, ProviderIdentity{Provider: "google"}, ""); !errors.Is(err, ErrIdentityIncomplete) {
		t.Fatalf("want ErrIdentityIncomplete, got %v", err)
	}
}

// MembershipEdge and Rules are correctness-critical: NewProvisioner fails closed
// on either omission rather than defaulting to an edge that may not match the
// consumer's other partition resolvers (a silent OAuth-vs-other-login split-brain).
func TestNewProvisioner_RequiresEdgeAndRules(t *testing.T) {
	g := nexus.NewMemStore()
	gs, err := NewGraphService(GraphConfig{Graph: g, Log: NewMemTransferLog()})
	if err != nil {
		t.Fatalf("NewGraphService: %v", err)
	}
	assign := func(_ context.Context, _ ProviderIdentity, _ string) (string, error) { return "p", nil }

	if _, err := NewProvisioner(ProvisionerConfig{Graph: gs, Assign: assign, MembershipEdge: "member", MembershipAttrs: testMembershipAttrs}); err == nil {
		t.Error("missing Rules should fail closed")
	}
	if _, err := NewProvisioner(ProvisionerConfig{Graph: gs, Assign: assign, Rules: []nexus.Rule{OutTargets("member")}, MembershipAttrs: testMembershipAttrs}); err == nil {
		t.Error("missing MembershipEdge should fail closed")
	}
}

// TestNewProvisioner_RequiresMembershipAttrs holds the membership attributes to
// the same rule as the edge: a consumer whose readers admit a member by an
// attribute census does not interpret gets a construction error, not subjects
// those readers deny.
func TestNewProvisioner_RequiresMembershipAttrs(t *testing.T) {
	g := nexus.NewMemStore()
	gs, err := NewGraphService(GraphConfig{Graph: g, Log: NewMemTransferLog()})
	if err != nil {
		t.Fatalf("NewGraphService: %v", err)
	}
	assign := func(_ context.Context, _ ProviderIdentity, _ string) (string, error) { return "p", nil }
	for name, attrs := range map[string]map[string]string{"nil": nil, "empty": {}} {
		_, err := NewProvisioner(ProvisionerConfig{
			Graph:           gs,
			Rules:           []nexus.Rule{OutTargets("member")},
			Assign:          assign,
			MembershipEdge:  "member",
			MembershipAttrs: attrs,
		})
		if err == nil {
			t.Errorf("%s MembershipAttrs should fail closed", name)
		}
	}
}

// TestEnsureUser_WritesTheConfiguredMembershipAttrs holds that a first-time
// subject's membership edge carries exactly the configured attributes, that a
// change to the caller's map after construction does not reach a later edge, and
// that a returning subject's edge is not rewritten.
func TestEnsureUser_WritesTheConfiguredMembershipAttrs(t *testing.T) {
	g := nexus.NewMemStore()
	gs, err := NewGraphService(GraphConfig{Graph: g, Log: NewMemTransferLog()})
	if err != nil {
		t.Fatalf("NewGraphService: %v", err)
	}
	configured := map[string]string{"subject_kind": "probe_kind", "origin": "probe"}
	p, err := NewProvisioner(ProvisionerConfig{
		Graph:           gs,
		Rules:           []nexus.Rule{OutTargets("member")},
		Assign:          func(_ context.Context, _ ProviderIdentity, _ string) (string, error) { return "part-1", nil },
		MembershipEdge:  "member",
		MembershipAttrs: configured,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	configured["subject_kind"] = "changed_after_construction"
	configured["late"] = "x"

	membership := func(subject string) nexus.Relationship {
		t.Helper()
		edges, err := g.OutEdges(ctx, subject, "member")
		if err != nil {
			t.Fatalf("OutEdges: %v", err)
		}
		if len(edges) != 1 {
			t.Fatalf("subject %q holds %d membership edges, want 1: %+v", subject, len(edges), edges)
		}
		return edges[0]
	}
	want := map[string]string{"subject_kind": "probe_kind", "origin": "probe"}

	id := ProviderIdentity{Provider: "google", ProviderUserID: "sub-attrs"}
	sub, _, err := p.EnsureUser(ctx, id, "")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	edge := membership(sub)
	if len(edge.Attrs) != len(want) {
		t.Fatalf("membership attrs = %v, want %v", edge.Attrs, want)
	}
	for k, v := range want {
		if edge.Attrs[k] != v {
			t.Fatalf("membership attrs = %v, want %v", edge.Attrs, want)
		}
	}

	history, err := gs.History(ctx, "part-1", sub)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	before := len(history)
	if _, _, err := p.EnsureUser(ctx, id, ""); err != nil {
		t.Fatalf("returning EnsureUser: %v", err)
	}
	history, err = gs.History(ctx, "part-1", sub)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(history) != before {
		t.Fatalf("a returning subject recorded %d further grants, want 0", len(history)-before)
	}
}

// A self-serve assigner mints a fresh partition per first-time subject via
// MintPartition; the returning login resolves that same partition.
func TestEnsureUser_SelfServeMintsFreshPartition(t *testing.T) {
	g := nexus.NewMemStore()
	gs, err := NewGraphService(GraphConfig{Graph: g, Log: NewMemTransferLog()})
	if err != nil {
		t.Fatalf("NewGraphService: %v", err)
	}
	var p *Provisioner
	assign := func(c context.Context, _ ProviderIdentity, _ string) (string, error) {
		return p.MintPartition(c, "")
	}
	p, err = NewProvisioner(ProvisionerConfig{
		Graph:           gs,
		Rules:           []nexus.Rule{OutTargets("member")},
		Assign:          assign,
		MembershipEdge:  "member",
		MembershipAttrs: testMembershipAttrs,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	id := ProviderIdentity{Provider: "github", ProviderUserID: "gh-1"}
	sub, part, err := p.EnsureUser(ctx, id, "")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	if sub == "" || part == "" {
		t.Fatalf("empty subject/partition: %q %q", sub, part)
	}
	if _, err := g.GetEntity(ctx, part); err != nil {
		t.Fatalf("minted partition is not a real entity: %v", err)
	}
	sub2, part2, err := p.EnsureUser(ctx, id, "")
	if err != nil {
		t.Fatalf("returning: %v", err)
	}
	if sub2 != sub || part2 != part {
		t.Fatalf("returning %q/%q != original %q/%q", sub2, part2, sub, part)
	}
}
