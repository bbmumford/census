/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"errors"
	"sort"
	"testing"
)

// ReplaceCredentials is all or nothing at either store: a set holding one identifier another subject
// keeps is ErrConflict and leaves the subject's previous set as it was; a set that fits replaces the
// previous one whole, and credentials of other kinds and subjects are untouched.
func TestReplaceCredentialsIsAllOrNothing(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		ctx := context.Background()
		put := func(c *Credential) {
			t.Helper()
			if err := store.PutCredential(ctx, c); err != nil {
				t.Fatal(err)
			}
		}
		put(&Credential{Partition: "p1", Subject: "s1", Kind: KindBackupCode, IdentifierHash: "s1#0", Secret: "old0"})
		put(&Credential{Partition: "p1", Subject: "s1", Kind: KindBackupCode, IdentifierHash: "s1#1", Secret: "old1"})
		put(&Credential{Partition: "p1", Subject: "s1", Kind: "password", IdentifierHash: "login", Secret: "pw"})
		put(&Credential{Partition: "p1", Subject: "s2", Kind: KindBackupCode, IdentifierHash: "taken", Secret: "other"})
		secrets := func(subject string) []string {
			t.Helper()
			cs, err := store.ListCredentialsBySubject(ctx, "p1", subject)
			if err != nil {
				t.Fatal(err)
			}
			var out []string
			for _, c := range cs {
				out = append(out, c.Kind+":"+c.Secret)
			}
			sort.Strings(out)
			return out
		}
		code := func(id, secret string) *Credential {
			return &Credential{Partition: "p1", Subject: "s1", Kind: KindBackupCode, IdentifierHash: id, Secret: secret}
		}
		if err := store.ReplaceCredentials(ctx, "p1", "s1", KindBackupCode,
			[]*Credential{code("s1#0", "new0"), code("taken", "new1")}); !errors.Is(err, ErrConflict) {
			t.Fatalf("a set holding another subject's identifier = %v, want ErrConflict", err)
		}
		if got, want := secrets("s1"), []string{"backup_code:old0", "backup_code:old1", "password:pw"}; !equalStrings(got, want) {
			t.Fatalf("after the refused replacement s1 holds %v, want %v", got, want)
		}
		if err := store.ReplaceCredentials(ctx, "p2", "s1", KindBackupCode, []*Credential{code("s1#9", "x")}); !errors.Is(err, ErrConflict) {
			t.Fatalf("a set naming another partition than the call = %v, want ErrConflict", err)
		}
		if err := store.ReplaceCredentials(ctx, "", "s1", KindBackupCode, nil); !errors.Is(err, ErrUnscoped) {
			t.Fatalf("an unscoped replacement = %v, want ErrUnscoped", err)
		}
		if err := store.ReplaceCredentials(ctx, "p1", "s1", KindBackupCode,
			[]*Credential{code("s1#0", "new0"), code("s1#1", "new1"), code("s1#2", "new2")}); err != nil {
			t.Fatalf("a replacement that fits: %v", err)
		}
		if got, want := secrets("s1"), []string{"backup_code:new0", "backup_code:new1", "backup_code:new2", "password:pw"}; !equalStrings(got, want) {
			t.Fatalf("after the replacement s1 holds %v, want %v", got, want)
		}
		if got, want := secrets("s2"), []string{"backup_code:other"}; !equalStrings(got, want) {
			t.Fatalf("s2 holds %v, want %v", got, want)
		}
	})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
