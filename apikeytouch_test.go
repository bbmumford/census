/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"errors"
	"testing"
)

// A key's use is recorded only under the partition that holds it, as its revoke is.
func TestAKeysUseIsRecordedOnlyUnderItsPartition(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		ctx := context.Background()
		k := &APIKey{Partition: "p1", Subject: "s1", KeyHash: "h1"}
		if err := store.PutAPIKey(ctx, k); err != nil {
			t.Fatal(err)
		}
		for _, other := range []string{"p2", ""} {
			if err := store.TouchAPIKeyUsed(ctx, other, k.ID, 5); !errors.Is(err, ErrNotFound) {
				t.Fatalf("TouchAPIKeyUsed under %q = %v, want ErrNotFound", other, err)
			}
		}
		if got, err := store.GetAPIKeyByHash(ctx, "h1"); err != nil || got.LastUsedAt != nil {
			t.Fatalf("after use records under other partitions: %+v, %v; want no last use", got, err)
		}
		if err := store.TouchAPIKeyUsed(ctx, "p1", k.ID, 5); err != nil {
			t.Fatalf("TouchAPIKeyUsed under its own partition: %v", err)
		}
		if got, err := store.GetAPIKeyByHash(ctx, "h1"); err != nil || got.LastUsedAt == nil {
			t.Fatalf("after its own use record: %+v, %v; want a last use", got, err)
		}
	})
}
