package census

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/bbmumford/nexus"
)

// TransferEvent is an append-only record of a relationship change — a grant or revoke of an opaque
// typed edge. Ownership/membership/role are properties recorded as a ledger of transitions, never a
// silently-mutated field: every change is provenance-stamped (who triggered it, from what source,
// whether automatic). census records these but never interprets the opaque edge type.
type TransferEvent struct {
	ID        string
	Partition string // opaque partition-scope
	From      string // edge source entity id
	To        string // edge target entity id
	Type      string // opaque edge type
	Change    string // "grant" | "revoke"
	Trigger   string // opaque actor/subject that caused the change
	Source    string // opaque origin ("invite-accept", "admin", "directory-sync")
	Auto      bool   // true when applied by an automated flow, not a human action
	At        time.Time
	// Seq is the event's place in the log, increasing in commit order. A log fills
	// it on the events it returns; a caller recording an event leaves it zero.
	Seq int64
}

// TransferLog is the append-only sink for relationship-change provenance. A consumer supplies a
// *sql.DB-backed log (shipped) or the reference MemTransferLog.
type TransferLog interface {
	Record(ctx context.Context, e *TransferEvent) error
	List(ctx context.Context, partition, entity string) ([]*TransferEvent, error)
}

// ChangeMeta carries the provenance stamped onto a transfer event; all fields are opaque to census.
type ChangeMeta struct {
	Partition string
	Trigger   string
	Source    string
	Auto      bool
}

// Guard is a precondition checked before a Revoke commits. It fails the revoke closed when removing the
// edge would violate a cardinality rule (e.g. dropping an org's last partition). Guards are axis-blind: the
// consumer names the opaque edge type and the minimum, census counts edges without knowing the meaning.
// Guard is a pre-condition evaluated against the graph before a Revoke.
//
// ⚠ A Guard reads the graph and returns; it does not hold across the delete that
// follows. So it can express a condition that is true independently of this revoke —
// and it CANNOT express one that the revoke itself changes, because two callers both
// pass a count-based Guard and both proceed. For a cardinality floor use
// RevokeKeepingMin, which enforces the count in the same operation as the delete.
type Guard func(ctx context.Context, g nexus.GraphStore) error

// ErrGuardViolation is returned when a Revoke would violate a Guard.
var ErrGuardViolation = errors.New("census: relationship guard violation")

// ErrCardinalityFloor is returned by RevokeKeepingMin when the revoke would leave
// fewer edges pointing at the target than the caller required. It wraps nexus's own
// sentinel, so a caller may match either.
var ErrCardinalityFloor = nexus.ErrCardinalityFloor

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

	// memAtomic serialises Atomic over the in-memory log from the graph commit to
	// the log append, so the log's order is the graph's commit order (see Atomic).
	memAtomic sync.Mutex
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

// RevokeKeepingMin removes an edge only while more than `min` edges of edgeType point
// at `to`, and returns ErrCardinalityFloor otherwise. It is the axis-blind
// cannot-remove-the-last-one primitive: a consumer expresses "this target keeps at
// least one member" as RevokeKeepingMin(..., 1) without census knowing what a member
// or a target is.
//
// The floor is enforced by the STORE, in one operation with the delete, because a
// count taken before a separate delete is not a floor: two callers each read a safe
// total, each proceed, and the last edge both were protecting is removed. A Guard
// cannot express this — it runs before the write and cannot hold across it — so the
// cardinality case is a method rather than a Guard, and Guard is left for checks that
// do not have to survive the write.
//
// The transfer event is recorded only after the delete commits, so the log names
// removals that happened rather than removals that were attempted.
func (s *GraphService) RevokeKeepingMin(ctx context.Context, from, to, edgeType string, min int, meta ChangeMeta) error {
	if err := s.graph.DeleteRelationshipKeepingMin(ctx, from, to, edgeType, min); err != nil {
		return err
	}
	return s.record(ctx, from, to, edgeType, "revoke", meta)
}

func (s *GraphService) record(ctx context.Context, from, to, edgeType, change string, meta ChangeMeta) error {
	return s.log.Record(ctx, &TransferEvent{
		ID:        s.newID(),
		Partition: meta.Partition,
		From:      from,
		To:        to,
		Type:      edgeType,
		Change:    change,
		Trigger:   meta.Trigger,
		Source:    meta.Source,
		Auto:      meta.Auto,
		At:        s.now(),
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

// OutEdges returns the edges leading out of an entity, narrowed to the given types. InEdges returns
// the edges leading in to one — the direction that answers "which subjects belong to this partition"
// where OutEdges answers "which partition does this subject belong to".
//
// They are on the service, rather than left to a consumer holding the store, because the store is not
// a read-only handle: nexus.GraphStore also carries PutRelationship and DeleteRelationship, so passing
// it to an endpoint that only wants to list members would also let that endpoint grant and remove
// memberships without recording a thing. NewGraphService refuses a nil TransferLog precisely so every
// relationship change is recorded, and an edge written through the store directly appears in no
// History. Reading through the service keeps the one handle a consumer holds the audited one.
//
// Both are passthroughs and record nothing, on the same footing as Resolve: a read changes no
// relationship, so there is no transfer event to write.
func (s *GraphService) OutEdges(ctx context.Context, from string, types ...string) ([]nexus.Relationship, error) {
	return s.graph.OutEdges(ctx, from, types...)
}

func (s *GraphService) InEdges(ctx context.Context, to string, types ...string) ([]nexus.Relationship, error) {
	return s.graph.InEdges(ctx, to, types...)
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

// ErrNoTransaction is returned by View and Atomic when the graph and its log cannot
// change in one transaction: the store is not a nexus.TxStore, its connector
// refuses the transaction, or the log cannot write inside the store's transaction.
// It is nexus's own sentinel, so a caller may match either.
var ErrNoTransaction = nexus.ErrNoTransaction

// sqlBacked is a store whose transactions are database/sql transactions on the
// *sql.DB it returns: nexus.SQLStore.
type sqlBacked interface{ DB() *sql.DB }

// View runs fn over one read-only snapshot of the graph, so a decision made from
// several reads is made from one state. It records nothing: a read changes no
// relationship.
func (s *GraphService) View(ctx context.Context, fn func(r nexus.GraphReader) error) error {
	ts, ok := s.graph.(nexus.TxStore)
	if !ok {
		return ErrNoTransaction
	}
	return ts.View(ctx, fn)
}

// Atomic runs fn in one serializable transaction: every change fn makes through
// the GraphTx and every transfer event recording it commit together, or none does.
// A check fn makes on a read is still true when its write commits.
//
// The pairs that can do this are a SQL store with the SQL log on the same *sql.DB,
// whose events are written in the store's own transaction, and the in-memory store
// with the in-memory log, whose events are appended after the graph commit while
// memAtomic is held, so the log's order is still commit order and a rolled-back fn
// leaves no event. Any other pair answers ErrNoTransaction before fn runs.
func (s *GraphService) Atomic(ctx context.Context, fn func(tx *GraphTx) error) error {
	ts, ok := s.graph.(nexus.TxStore)
	if !ok {
		return ErrNoTransaction
	}
	switch log := s.log.(type) {
	case *SQLTransferLog:
		sb, ok := s.graph.(sqlBacked)
		if !ok || sb.DB() != log.db {
			return ErrNoTransaction
		}
		return ts.Update(ctx, func(w nexus.TxWriter) error {
			sw, ok := w.(*nexus.SQLTxWriter)
			if !ok {
				return ErrNoTransaction
			}
			return s.newTx(w, func(ctx context.Context, events []*TransferEvent) error {
				return log.RecordTx(ctx, sw.Tx(), events...)
			}).run(fn)
		})
	case *MemTransferLog:
		if _, ok := s.graph.(sqlBacked); ok {
			return ErrNoTransaction
		}
		s.memAtomic.Lock()
		defer s.memAtomic.Unlock()
		var pending []*TransferEvent
		err := ts.Update(ctx, func(w nexus.TxWriter) error {
			pending = pending[:0]
			return s.newTx(w, func(_ context.Context, events []*TransferEvent) error {
				pending = append(pending, events...)
				return nil
			}).run(fn)
		})
		if err != nil {
			return err
		}
		for _, e := range pending {
			if err := log.Record(ctx, e); err != nil {
				return err
			}
		}
		return nil
	default:
		return ErrNoTransaction
	}
}

// GraphTx is the handle Atomic passes its function: the reads, and every write
// paired with the transfer event that records it. It holds no write that records
// nothing, so a consumer inside Atomic cannot change an edge the log does not name.
//
// err holds the first write that failed after it may have changed the graph, its
// event's record included: the edge write and the record are two statements, so a
// failed record follows a change already made. Once err is set every later write
// answers it and Atomic returns it even when fn returns nil, so a function that
// drops a write's error cannot commit a change without its event.
type GraphTx struct {
	w      nexus.TxWriter
	now    func() time.Time
	newID  func() string
	record func(ctx context.Context, events []*TransferEvent) error
	err    error
}

func (s *GraphService) newTx(w nexus.TxWriter, record func(context.Context, []*TransferEvent) error) *GraphTx {
	return &GraphTx{w: w, now: s.now, newID: s.newID, record: record}
}

// run is Atomic's body inside the store transaction: fn's own error first, then
// any write fn dropped, so the transaction commits only when neither is set.
func (t *GraphTx) run(fn func(tx *GraphTx) error) error {
	if err := fn(t); err != nil {
		return err
	}
	return t.err
}

// do runs one write unless an earlier one failed, and keeps its error unless it is
// a refusal nexus decides before writing (nexus.ErrNotFound,
// nexus.ErrCardinalityFloor, nexus.ErrInvalidSelector), which a function may catch
// and go on from.
func (t *GraphTx) do(write func() error) error {
	if t.err != nil {
		return t.err
	}
	err := write()
	if err != nil && !errors.Is(err, nexus.ErrNotFound) && !errors.Is(err, nexus.ErrCardinalityFloor) &&
		!errors.Is(err, nexus.ErrInvalidSelector) {
		t.err = err
	}
	return err
}

func (t *GraphTx) event(k nexus.EdgeKey, change string, meta ChangeMeta, at time.Time) *TransferEvent {
	return &TransferEvent{
		ID: t.newID(), Partition: meta.Partition, From: k.From, To: k.To, Type: k.Type,
		Change: change, Trigger: meta.Trigger, Source: meta.Source, Auto: meta.Auto, At: at,
	}
}

// revoked records one revoke event per key, in the keys' order, in one write.
func (t *GraphTx) revoked(ctx context.Context, keys []nexus.EdgeKey, meta ChangeMeta) error {
	if len(keys) == 0 {
		return nil
	}
	at := t.now()
	events := make([]*TransferEvent, len(keys))
	for i, k := range keys {
		events[i] = t.event(k, "revoke", meta, at)
	}
	return t.record(ctx, events)
}

// Grant writes the edge and records a "grant" event, a re-grant included, as the
// service's Grant does.
func (t *GraphTx) Grant(ctx context.Context, from, to, edgeType string, attrs map[string]string, meta ChangeMeta) error {
	return t.do(func() error {
		if err := t.w.PutRelationship(ctx, &nexus.Relationship{From: from, To: to, Type: edgeType, Attrs: attrs}); err != nil {
			return err
		}
		return t.record(ctx, []*TransferEvent{t.event(nexus.EdgeKey{From: from, To: to, Type: edgeType}, "grant", meta, t.now())})
	})
}

// Revoke removes the edge and records a "revoke" event when there was one to
// remove. Inside the transaction the read and the delete see the same state, so
// the log names only removals that happened.
func (t *GraphTx) Revoke(ctx context.Context, from, to, edgeType string, meta ChangeMeta) error {
	return t.do(func() error {
		held, err := t.w.HasRelationship(ctx, from, to, edgeType)
		if err != nil || !held {
			return err
		}
		if err := t.w.DeleteRelationship(ctx, from, to, edgeType); err != nil {
			return err
		}
		return t.revoked(ctx, []nexus.EdgeKey{{From: from, To: to, Type: edgeType}}, meta)
	})
}

// RevokeKeepingMin is the service's RevokeKeepingMin inside the transaction: the
// floor is counted in it, and the event is recorded only for an edge removed.
func (t *GraphTx) RevokeKeepingMin(ctx context.Context, from, to, edgeType string, min int, meta ChangeMeta) error {
	return t.do(func() error {
		held, err := t.w.HasRelationship(ctx, from, to, edgeType)
		if err != nil {
			return err
		}
		if err := t.w.DeleteRelationshipKeepingMin(ctx, from, to, edgeType, min); err != nil || !held {
			return err
		}
		return t.revoked(ctx, []nexus.EdgeKey{{From: from, To: to, Type: edgeType}}, meta)
	})
}

// RevokeWhere removes every edge sel names with one statement, records one revoke
// event per removed edge in the returned key order, and returns the keys. Removing
// a subject's records or a target's holders is one set change at any count.
func (t *GraphTx) RevokeWhere(ctx context.Context, sel nexus.EdgeSelector, meta ChangeMeta) ([]nexus.EdgeKey, error) {
	var keys []nexus.EdgeKey
	err := t.do(func() error {
		var err error
		keys, err = t.w.DeleteEdgesWhere(ctx, sel)
		if err != nil {
			return err
		}
		return t.revoked(ctx, keys, meta)
	})
	return keys, err
}

// PutEntity writes an entity. Entities are not relationships, so it records nothing.
func (t *GraphTx) PutEntity(ctx context.Context, e *nexus.Entity) error {
	return t.do(func() error {
		return t.w.PutEntity(ctx, e)
	})
}

// DeleteEntity removes the entity and every edge incident to it, recording a
// revoke event for each such edge, ordered by key, so no edge leaves the graph
// unrecorded. An unknown id answers nexus.ErrNotFound and records nothing.
func (t *GraphTx) DeleteEntity(ctx context.Context, id string, meta ChangeMeta) error {
	return t.do(func() error {
		out, err := t.w.OutEdges(ctx, id)
		if err != nil {
			return err
		}
		in, err := t.w.InEdges(ctx, id)
		if err != nil {
			return err
		}
		seen := map[nexus.EdgeKey]bool{}
		var keys []nexus.EdgeKey
		for _, r := range append(out, in...) {
			k := nexus.EdgeKey{From: r.From, To: r.To, Type: r.Type}
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := keys[i], keys[j]
			if a.From != b.From {
				return a.From < b.From
			}
			if a.To != b.To {
				return a.To < b.To
			}
			return a.Type < b.Type
		})
		if err := t.w.DeleteEntity(ctx, id); err != nil {
			return err
		}
		return t.revoked(ctx, keys, meta)
	})
}

// GetEntity, ListEntitiesByType, HasRelationship, OutEdges and InEdges read inside
// the transaction and see its own writes.
func (t *GraphTx) GetEntity(ctx context.Context, id string) (*nexus.Entity, error) {
	return t.w.GetEntity(ctx, id)
}

func (t *GraphTx) ListEntitiesByType(ctx context.Context, typ string) ([]nexus.Entity, error) {
	return t.w.ListEntitiesByType(ctx, typ)
}

func (t *GraphTx) HasRelationship(ctx context.Context, from, to, typ string) (bool, error) {
	return t.w.HasRelationship(ctx, from, to, typ)
}

func (t *GraphTx) OutEdges(ctx context.Context, from string, types ...string) ([]nexus.Relationship, error) {
	return t.w.OutEdges(ctx, from, types...)
}

func (t *GraphTx) InEdges(ctx context.Context, to string, types ...string) ([]nexus.Relationship, error) {
	return t.w.InEdges(ctx, to, types...)
}

// SQLTx returns the SQL transaction t runs in, and false over a store that is not
// SQL-backed. A table on the graph's own database is written through it, so its
// row commits or rolls back with the graph's writes and the reads fn judged it
// on: tenant/space's Space role, scope and access-list writes stamp the subject's
// live membership instance read through t and write the row in the same
// transaction. Atomic owns the transaction: a caller never commits or rolls it
// back, and a failed statement on it is returned from fn so Atomic rolls back.
func (t *GraphTx) SQLTx() (*sql.Tx, bool) {
	sw, ok := t.w.(*nexus.SQLTxWriter)
	if !ok {
		return nil, false
	}
	return sw.Tx(), true
}

// ViewSQLTx returns the SQL transaction the View that handed r reads in, and false
// when r is not a View's reader over a SQL-backed store. A table on the graph's own
// database is read through it at the snapshot fn's graph reads see, so a decision
// made from those rows and the graph's edges is made from one state. View owns the
// transaction and rolls it back when fn returns: a caller never commits or rolls it
// back, and nothing written through it is kept.
// TODO: tenant/space's Space store reads a subject's Space rows through it, in the
// View its membership writer reads the subject's live instance in.
func ViewSQLTx(r nexus.GraphReader) (*sql.Tx, bool) {
	sr, ok := r.(*nexus.SQLTxReader)
	if !ok {
		return nil, false
	}
	return sr.Tx(), true
}
