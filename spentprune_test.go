/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"testing"
)

// A spend prunes every step spent more than SpentStepRetention before it, so the record holds one row
// per code still inside any acceptance window rather than one per code ever accepted; a step inside
// the retention is still refused a second time.
func TestSpentStepsArePrunedPastTheRetention(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		ctx := context.Background()
		const start = int64(1_000_000_000)
		for step := int64(0); step < 50; step++ {
			if _, err := store.SpendStep(ctx, "p1", "s1", step, start); err != nil {
				t.Fatal(err)
			}
		}
		later := start + int64(SpentStepRetention) + 1
		if first, err := store.SpendStep(ctx, "p1", "s2", 7, later); err != nil || !first {
			t.Fatalf("a spend past the retention = %v, %v", first, err)
		}
		if first, err := store.SpendStep(ctx, "p1", "s1", 0, later); err != nil || !first {
			t.Fatalf("a step spent before the retention still refuses: %v, %v", first, err)
		}
		if first, err := store.SpendStep(ctx, "p1", "s2", 7, later+1); err != nil || first {
			t.Fatalf("a step inside the retention was spendable twice: %v, %v", first, err)
		}
		if n := spentStepRows(t, store); n != 2 {
			t.Fatalf("the record holds %d steps after the prune, want the 2 spent since", n)
		}
	})
}

// spentStepRows counts what either store holds of spent steps.
func spentStepRows(t *testing.T, store VaultStore) int {
	t.Helper()
	switch s := store.(type) {
	case *MemStore:
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.spentSteps)
	case *SQLVaultStore:
		var n int
		if err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM censusSpentSteps`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	t.Fatalf("unknown store %T", store)
	return 0
}
