/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"testing"
	"time"
)

// Every write refuses an empty partition, at the Service and at either store, and nothing is left
// that the partition-free login or key lookup could reach.
func TestEveryWriteRefusesAnEmptyPartition(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		ctx := context.Background()
		s := newServiceWith(t, store)
		if _, err := s.RegisterPassword(ctx, "", "s1", "a@example.com", "pw"); err == nil {
			t.Fatal("RegisterPassword stored a password with no partition")
		}
		if sub, err := s.Authenticate(ctx, "a@example.com", "pw"); err == nil {
			t.Fatalf("a password registered with no partition authenticates %q", sub)
		}
		raw, _, err := s.MintAPIKey(ctx, "", "s1", "key", nil, time.Hour)
		if err == nil {
			t.Fatal("MintAPIKey minted a key with no partition")
		}
		if raw != "" {
			if k, err := s.VerifyAPIKey(ctx, raw); err == nil {
				t.Fatalf("a key minted with no partition verifies: %+v", k)
			}
		}
		if err := store.PutCredential(ctx, &Credential{Subject: "s1", Kind: "password", IdentifierHash: "h1", Secret: "x"}); err == nil {
			t.Fatal("PutCredential stored a row with no partition")
		}
		if err := store.PutAPIKey(ctx, &APIKey{Subject: "s1", KeyHash: "k1"}); err == nil {
			t.Fatal("PutAPIKey stored a key with no partition")
		}
		if _, err := store.GetCredentialByIdentifier(ctx, "password", "h1"); err == nil {
			t.Fatal("a refused credential is still found by its identifier")
		}
		if _, err := store.GetAPIKeyByHash(ctx, "k1"); err == nil {
			t.Fatal("a refused key is still found by its hash")
		}
		if first, err := store.SpendStep(ctx, "", "s1", 7, 1); err == nil || first {
			t.Fatalf("SpendStep recorded a step with no partition: %v, %v", first, err)
		}
	})
}

// countingPuts is a store that accepts every write and counts it, so only the Service's own check
// stands between an empty partition and the store.
type countingPuts struct {
	VaultStore
	puts int
}

func (c *countingPuts) PutCredential(context.Context, *Credential) error { c.puts++; return nil }
func (c *countingPuts) PutAPIKey(context.Context, *APIKey) error         { c.puts++; return nil }

// The Service refuses an empty partition itself, before it hashes or writes, whatever its store
// would have accepted.
func TestTheServiceRefusesAnEmptyPartitionBeforeItsStore(t *testing.T) {
	ctx := context.Background()
	store := &countingPuts{VaultStore: NewMemStore()}
	s := newServiceWith(t, store)
	if _, err := s.RegisterPassword(ctx, "", "s1", "a@example.com", "pw"); err == nil {
		t.Fatal("RegisterPassword accepted an empty partition")
	}
	if _, _, err := s.MintAPIKey(ctx, "", "s1", "key", nil, time.Hour); err == nil {
		t.Fatal("MintAPIKey accepted an empty partition")
	}
	if store.puts != 0 {
		t.Fatalf("an empty partition reached the store %d times", store.puts)
	}
}
