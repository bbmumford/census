package census

import (
	"context"
	"errors"
	"time"

	"github.com/bbmumford/nexus"
)

// TransferEvent is an append-only record of a relationship change — a grant or revoke of an opaque
// typed edge. Ownership/membership/role are properties recorded as a ledger of transitions, never a
// silently-mutated field: every change is provenance-stamped (who triggered it, from what source,
// whether automatic). census records these but never interprets the opaque edge type.
type TransferEvent struct {
	ID      string
	Partition   string // opaque partition-scope
	From    string // edge source entity id
	To      string // edge target entity id
	Type    string // opaque edge type
	Change  string // "grant" | "revoke"
	Trigger string // opaque actor/subject that caused the change
	Source  string // opaque origin ("invite-accept", "admin", "directory-sync")
	Auto    bool   // true when applied by an automated flow, not a human action
	At      time.Time
}

// TransferLog is the append-only sink for relationship-change provenance. A consumer supplies a
// *sql.DB-backed log (shipped) or the reference MemTransferLog.
type TransferLog interface {
	Record(ctx context.Context, e *TransferEvent) error
	List(ctx context.Context, partition, entity string) ([]*TransferEvent, error)
}

// ChangeMeta carries the provenance stamped onto a transfer event; all fields are opaque to census.
type ChangeMeta struct {
	Partition   string
	Trigger string
	Source  string
	Auto    bool
}

// Guard is a precondition checked before a Revoke commits. It fails the revoke closed when removing the
// edge would violate a cardinality rule (e.g. dropping an org's last partition). Guards are axis-blind: the
// consumer names the opaque edge type and the minimum, census counts edges without knowing the meaning.
type Guard func(ctx context.Context, g nexus.GraphStore) error

// ErrGuardViolation is returned when a Revoke would violate a Guard (a cardinality floor).
var ErrGuardViolation = errors.New("census: relationship guard violation")

// MinIncoming guards that, after a pending revoke of an edge of edgeType into `target`, at least `min`
// edges of edgeType still point at `target`. This is the axis-blind can't-remove-last-partition primitive:
// a consumer expresses "an org must keep ≥1 partition" as MinIncoming("partition", orgID, 1) without census
// knowing what "partition" or an "org" is. It is evaluated against the graph BEFORE the revoke, so a count
// of exactly `min` incoming edges blocks removing one of them.
func MinIncoming(edgeType, target string, min int) Guard {
	return func(ctx context.Context, g nexus.GraphStore) error {
		edges, err := g.InEdges(ctx, target, edgeType)
		if err != nil {
			return err
		}
		if len(edges) <= min {
			return ErrGuardViolation
		}
		return nil
	}
}

// GraphService is the account-relationship façade over a nexus graph: it grants and revokes opaque
// typed edges, records every change to an append-only TransferLog (§ recorded transitions), enforces
// axis-blind cardinality Guards, and resolves relationship questions through nexus's precedence ladder.
// The resolver is general, not ownership-specific: the same first-rung-wins walk answers "who owns
// this", "what role does this subject hold", "who is this assigned to", "which tier applies" — one
// primitive, the consumer's ladder decides the question. It interprets no axis — edge types and entity
// ids are opaque strings the consumer assigns.
type GraphService struct {
	graph nexus.GraphStore
	log   TransferLog
	now   func() time.Time
	newID func() string
}

// GraphConfig wires a GraphService. Graph and Log are required — every relationship change must be
// recorded, so a nil log is rejected rather than silently dropping provenance.
type GraphConfig struct {
	Graph nexus.GraphStore
	Log   TransferLog
	Now   func() time.Time
	NewID func() string
}

// NewGraphService validates the config and returns the service.
func NewGraphService(c GraphConfig) (*GraphService, error) {
	if c.Graph == nil {
		return nil, &configError{"census: GraphConfig.Graph is required"}
	}
	if c.Log == nil {
		return nil, &configError{"census: GraphConfig.Log is required (relationship changes must be recorded)"}
	}
	s := &GraphService{graph: c.Graph, log: c.Log, now: c.Now, newID: c.NewID}
	if s.now == nil {
		s.now = time.Now
	}
	if s.newID == nil {
		s.newID = randomID
	}
	return s, nil
}

// Grant adds an opaque typed edge (from -> to, of edgeType, with attrs) and records a "grant" transfer
// event. Adding an edge that already exists updates its attrs and still records the event, so a
// re-grant is auditable.
func (s *GraphService) Grant(ctx context.Context, from, to, edgeType string, attrs map[string]string, meta ChangeMeta) error {
	if err := s.graph.PutRelationship(ctx, &nexus.Relationship{From: from, To: to, Type: edgeType, Attrs: attrs}); err != nil {
		return err
	}
	return s.record(ctx, from, to, edgeType, "grant", meta)
}

// Revoke removes an opaque typed edge subject to every Guard, then records a "revoke" transfer event.
// If any guard fails the edge is left intact and the guard's error is returned (fail-closed); the
// event is recorded only after the edge is actually removed.
func (s *GraphService) Revoke(ctx context.Context, from, to, edgeType string, meta ChangeMeta, guards ...Guard) error {
	for _, g := range guards {
		if err := g(ctx, s.graph); err != nil {
			return err
		}
	}
	if err := s.graph.DeleteRelationship(ctx, from, to, edgeType); err != nil {
		return err
	}
	return s.record(ctx, from, to, edgeType, "revoke", meta)
}

func (s *GraphService) record(ctx context.Context, from, to, edgeType, change string, meta ChangeMeta) error {
	return s.log.Record(ctx, &TransferEvent{
		ID:      s.newID(),
		Partition:   meta.Partition,
		From:    from,
		To:      to,
		Type:    edgeType,
		Change:  change,
		Trigger: meta.Trigger,
		Source:  meta.Source,
		Auto:    meta.Auto,
		At:      s.now(),
	})
}

// Resolve runs a precedence ladder over the graph and returns the winning value with its provenance,
// retaining every candidate for a human to disambiguate an ambiguous outcome. It answers any
// relationship question — ownership, role, assignment, tier — since the consumer's ladder, not census,
// decides what is being resolved (direct edge, else via team, else via org). It is a thin passthrough
// to nexus's resolver, keeping census axis-blind. Rung constructors OutTargets/Via are re-exported below.
func (s *GraphService) Resolve(ctx context.Context, subject string, rules ...nexus.Rule) (nexus.Resolution, error) {
	return nexus.Resolve(ctx, s.graph, subject, rules...)
}

// History returns the recorded transfer events touching an entity (as edge source or target).
func (s *GraphService) History(ctx context.Context, partition, entity string) ([]*TransferEvent, error) {
	return s.log.List(ctx, partition, entity)
}

// OutTargets and Via re-export nexus's rung constructors so a consumer builds precedence ladders
// against census's Resolve without importing nexus directly for the common case.
var (
	OutTargets = nexus.OutTargets
	Via        = nexus.Via
)
