/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"errors"
	"testing"

	"github.com/bbmumford/nexus"
)

// The service's Grant, Revoke and RevokeKeepingMin change an edge only together
// with the event that records the change. With the store and the log on one
// database, a refused event leaves the edge as it was: a grant adds no edge and
// a revoke removes none.
func TestGraph_AnEdgeChangesOnlyWithItsEvent(t *testing.T) {
	db := fileDB(t)
	s, g, log := sqlGraph(t, db)
	meta := ChangeMeta{Partition: "p", Trigger: "admin", Source: "test"}
	for _, from := range []string{"keep-1", "keep-2", "keep-3"} {
		if err := s.Grant(ctx, from, "p", "member", nil, meta); err != nil {
			t.Fatal(err)
		}
	}
	base := len(since(t, log, 0))
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER refuseEvent BEFORE INSERT ON censusTransfers
		BEGIN SELECT RAISE(ABORT, 'event refused'); END`); err != nil {
		t.Fatal(err)
	}

	if err := s.Grant(ctx, "new-1", "p", "member", nil, meta); err == nil {
		t.Error("Grant reported success although its event was refused")
	}
	if held, _ := g.HasRelationship(ctx, "new-1", "p", "member"); held {
		t.Error("Grant's edge committed although its event was refused")
	}
	if err := s.Revoke(ctx, "keep-1", "p", "member", meta); err == nil {
		t.Error("Revoke reported success although its event was refused")
	}
	if held, _ := g.HasRelationship(ctx, "keep-1", "p", "member"); !held {
		t.Error("Revoke removed the edge although its event was refused")
	}
	if err := s.RevokeKeepingMin(ctx, "keep-2", "p", "member", 1, meta); err == nil {
		t.Error("RevokeKeepingMin reported success although its event was refused")
	}
	if held, _ := g.HasRelationship(ctx, "keep-2", "p", "member"); !held {
		t.Error("RevokeKeepingMin removed the edge although its event was refused")
	}
	if got := len(since(t, log, 0)); got != base {
		t.Errorf("%d events were recorded while events were refused", got-base)
	}

	// With events accepted again each change commits with exactly one event.
	if _, err := db.ExecContext(ctx, `DROP TRIGGER refuseEvent`); err != nil {
		t.Fatal(err)
	}
	if err := s.Grant(ctx, "new-1", "p", "member", nil, meta); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, "keep-1", "p", "member", meta); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeKeepingMin(ctx, "keep-2", "p", "member", 1, meta); err != nil {
		t.Fatal(err)
	}
	got := describe(since(t, log, int64(base)))
	want := []string{"grant new-1>p:member", "revoke keep-1>p:member", "revoke keep-2>p:member"}
	if len(got) != len(want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events %v, want %v", got, want)
		}
	}
}

// failingLog accepts nothing.
type failingLog struct{ MemTransferLog }

var errLogRefused = errors.New("log refused")

func (*failingLog) Record(context.Context, *TransferEvent) error { return errLogRefused }

// A store and log that cannot share a transaction still never keep a change the
// log refused: the service puts the edge back as it was and returns the log's
// error.
func TestGraph_AChangeTheLogRefusesIsUndoneWithoutATransaction(t *testing.T) {
	g := nexus.NewMemStore()
	s, err := NewGraphService(GraphConfig{Graph: g, Log: &failingLog{}})
	if err != nil {
		t.Fatal(err)
	}
	meta := ChangeMeta{Partition: "p"}
	// old's edge to a-first is stored first, so a read that took old's first
	// member edge would not be the edge the change is to.
	if err := g.PutRelationship(ctx, &nexus.Relationship{From: "old", To: "a-first", Type: "member", Attrs: map[string]string{"level": "9"}}); err != nil {
		t.Fatal(err)
	}
	if err := g.PutRelationship(ctx, &nexus.Relationship{From: "old", To: "p", Type: "member", Attrs: map[string]string{"level": "1"}}); err != nil {
		t.Fatal(err)
	}
	if err := g.PutRelationship(ctx, &nexus.Relationship{From: "other", To: "p", Type: "member"}); err != nil {
		t.Fatal(err)
	}
	levelToP := func() (string, bool) {
		out, _ := g.OutEdges(ctx, "old", "member")
		for _, r := range out {
			if r.To == "p" {
				return r.Attrs["level"], true
			}
		}
		return "", false
	}

	if err := s.Grant(ctx, "new", "p", "member", nil, meta); !errors.Is(err, errLogRefused) {
		t.Errorf("Grant: %v, want the log's error", err)
	}
	if held, _ := g.HasRelationship(ctx, "new", "p", "member"); held {
		t.Error("a new edge stayed although the log refused its event")
	}
	if err := s.Grant(ctx, "old", "p", "member", map[string]string{"level": "2"}, meta); !errors.Is(err, errLogRefused) {
		t.Errorf("re-Grant: %v, want the log's error", err)
	}
	if level, held := levelToP(); !held || level != "1" {
		t.Errorf("a re-grant the log refused changed the edge: held %v level %q", held, level)
	}
	if err := s.Revoke(ctx, "old", "p", "member", meta); !errors.Is(err, errLogRefused) {
		t.Errorf("Revoke: %v, want the log's error", err)
	}
	if level, held := levelToP(); !held || level != "1" {
		t.Errorf("a revoke the log refused removed or changed the edge: held %v level %q", held, level)
	}
	if err := s.RevokeKeepingMin(ctx, "other", "p", "member", 1, meta); !errors.Is(err, errLogRefused) {
		t.Errorf("RevokeKeepingMin: %v, want the log's error", err)
	}
	if held, _ := g.HasRelationship(ctx, "other", "p", "member"); !held {
		t.Error("a floor-checked revoke the log refused removed the edge")
	}
}
