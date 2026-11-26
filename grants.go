package census

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/bbmumford/nexus"
)

// GrantAttr is the relationship attribute a grant edge carries its capability
// strings in. It is one reserved key on nexus.Relationship.Attrs rather than a
// table of its own, so the graph stays axis-blind: nexus still stores an opaque
// typed edge and learns nothing about what a capability means.
const GrantAttr = "grants"

// grantSep separates capability strings inside GrantAttr.
const grantSep = ","

// ErrGrantSubject and ErrGrantPartition are returned when a caller asks what a
// subject holds without naming both. They are errors rather than an empty
// result because the two answers are not interchangeable to the readers that
// call this: sessioncred and tokencred treat a resolver error as REFUSE the
// request, and an empty slice as "holds nothing, but is present". An unnamed
// partition resolving to "holds nothing" would admit a request that could not
// be scoped at all.
var (
	ErrGrantSubject   = errors.New("census: grant resolution requires a subject")
	ErrGrantPartition = errors.New("census: grant resolution requires a partition")
	ErrGrantGraph     = errors.New("census: grant resolution requires a graph")
)

// ErrGrantSeparator is returned by GrantAttrs for a capability holding grantSep, which the resolver
// would read back as two capabilities: one authored string must not become a second grant.
var ErrGrantSeparator = errors.New("census: a capability holds the grant separator")

// GrantService answers what capability strings a subject holds in a partition.
//
// It reads the same opaque edges GraphService.Grant writes, so authoring a grant
// and resolving one are two views of one store and cannot drift apart. What it
// adds is accumulation: GraphService.Resolve delegates to nexus.Resolve, which is
// a first-hit-wins precedence ladder answering "which single entity is the
// target". Grants are a union — a subject holding three edges into a partition
// holds the capabilities of all three — so a precedence resolver would silently
// drop every edge after the first rung.
//
// It returns the capability strings verbatim, including denies, and judges
// nothing. warrant decides what a capability covers and how a deny takes
// precedence; reproducing that ladder here would create a second judge that can
// disagree with the first. This service is the store and the accumulator.
type GrantService struct {
	graph nexus.GraphStore
	types []string
}

// GrantConfig wires a GrantService.
type GrantConfig struct {
	// Graph holds the edges. Required.
	Graph nexus.GraphStore

	// EdgeTypes restricts resolution to these edge types. Empty means every
	// edge from the subject is considered, which is the correct default while a
	// consumer has one kind of grant edge; naming types is how a consumer keeps
	// an unrelated edge (an ownership or routing edge that happens to carry
	// attributes) from contributing capabilities.
	EdgeTypes []string
}

// NewGrantService validates the config and returns the service. A nil graph is
// refused here rather than at first Resolve, so a misconfigured consumer fails
// at construction instead of denying every request at runtime for a reason that
// looks like an authorization outcome.
func NewGrantService(c GrantConfig) (*GrantService, error) {
	if c.Graph == nil {
		return nil, ErrGrantGraph
	}
	types := make([]string, 0, len(c.EdgeTypes))
	for _, t := range c.EdgeTypes {
		if t = strings.TrimSpace(t); t != "" {
			types = append(types, t)
		}
	}
	return &GrantService{graph: c.Graph, types: types}, nil
}

// Resolve returns every capability string the subject holds in the partition,
// in the order the edges yield them, deduplicated.
//
// Its signature is the sessioncred.Grants and tokencred.Grants seam, so either
// credential reader takes a *GrantService method value with no adapter.
//
// Both identifiers are checked BEFORE the graph is touched. An unproved request
// must not reach a store selector at all — a selector handed an empty partition
// is one filtering on nothing, and the refusal has to happen on this side of the
// read to be worth anything.
//
// Only edges that end at the partition contribute. A subject's edges to other
// partitions are read but never counted, so holding a capability somewhere else
// can never satisfy a check here.
func (s *GrantService) Resolve(ctx context.Context, partition, subject string) ([]string, error) {
	if s == nil || s.graph == nil {
		return nil, ErrGrantGraph
	}
	if strings.TrimSpace(subject) == "" {
		return nil, ErrGrantSubject
	}
	if strings.TrimSpace(partition) == "" {
		return nil, ErrGrantPartition
	}

	edges, err := s.graph.OutEdges(ctx, subject, s.types...)
	if err != nil {
		// A graph that cannot answer is not a subject holding nothing. Returning
		// the error keeps the readers' refuse path, rather than turning an outage
		// into a caller silently reduced to presence-only.
		return nil, err
	}

	var (
		out  []string
		seen = map[string]struct{}{}
	)
	for i := range edges {
		if edges[i].To != partition {
			continue
		}
		for _, cap := range splitGrants(edges[i].Attrs[GrantAttr]) {
			if _, dup := seen[cap]; dup {
				continue
			}
			seen[cap] = struct{}{}
			out = append(out, cap)
		}
	}
	return out, nil
}

// splitGrants parses one GrantAttr value. Blank entries are dropped so a
// trailing or doubled separator cannot produce an empty capability string, which
// warrant would otherwise have to decide the meaning of.
func splitGrants(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, grantSep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// GrantAttrs builds the attribute map a grant edge carries, for passing to
// GraphService.Grant. It exists so the reserved key is written in one place and
// an author cannot spell it differently from the resolver that reads it.
//
// Blank capabilities are dropped. Passing none yields a nil map rather than an
// edge with an empty grant string, so an edge that grants nothing is visibly
// distinct from one whose grants failed to serialise. A capability holding the
// separator is refused (ErrGrantSeparator) and no map is built: written, it
// would resolve as the pieces on either side of the separator, each of which
// may be a capability the author never granted.
func GrantAttrs(capabilities ...string) (map[string]string, error) {
	kept := make([]string, 0, len(capabilities))
	for _, c := range capabilities {
		if strings.Contains(c, grantSep) {
			return nil, fmt.Errorf("%w: %q", ErrGrantSeparator, c)
		}
		if c = strings.TrimSpace(c); c != "" {
			kept = append(kept, c)
		}
	}
	if len(kept) == 0 {
		return nil, nil
	}
	return map[string]string{GrantAttr: strings.Join(kept, grantSep)}, nil
}
