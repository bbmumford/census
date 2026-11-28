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

// failsOn is a Hasher that refuses one code, so a replacement can fail part way.
type failsOn struct{ code string }

var errHash = errors.New("hasher unavailable")

func (f failsOn) Hash(p string) (string, error) {
	if p == f.code {
		return "", errHash
	}
	return "h:" + p, nil
}
func (failsOn) Compare(digest, p string) bool { return digest == "h:"+p }

// A backup-code replacement that fails part way leaves the previous set whole and stores none of the
// new one, at either store.
func TestABackupCodeReplacementThatFailsLeavesThePreviousSetWhole(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		ctx := context.Background()
		s := newServiceWith(t, store)
		if err := s.ReplaceBackupCodes(ctx, "p1", "s1", []string{"old-1", "old-2", "old-3"}); err != nil {
			t.Fatal(err)
		}
		s.hasher = failsOn{code: "new-2"}
		if err := s.ReplaceBackupCodes(ctx, "p1", "s1", []string{"new-1", "new-2", "new-3"}); !errors.Is(err, errHash) {
			t.Fatalf("a replacement whose second code cannot be hashed = %v, want the hasher's error", err)
		}
		if n, err := s.BackupCodesRemaining(ctx, "p1", "s1"); err != nil || n != 3 {
			t.Fatalf("after the failed replacement %d codes remain (%v), want the previous 3", n, err)
		}
		if err := s.RedeemBackupCode(ctx, "p1", "s1", "new-1"); err == nil {
			t.Fatal("a code of the failed replacement redeemed")
		}
		if err := s.RedeemBackupCode(ctx, "p1", "s1", "old-2"); err != nil {
			t.Fatalf("a code of the previous set no longer redeems: %v", err)
		}
	})
}
