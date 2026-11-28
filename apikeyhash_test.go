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

// No two keys share a key hash, at either store and over a database whose hash index was built plain,
// so the hash lookup answers one key.
func TestTwoAPIKeysCannotShareAHash(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		ctx := context.Background()
		if err := store.PutAPIKey(ctx, &APIKey{Partition: "p1", Subject: "s1", KeyHash: "h1"}); err != nil {
			t.Fatal(err)
		}
		if err := store.PutAPIKey(ctx, &APIKey{Partition: "p2", Subject: "s2", KeyHash: "h1"}); !errors.Is(err, ErrConflict) {
			t.Fatalf("a second key under hash h1 = %v, want ErrConflict", err)
		}
	})
	ctx := context.Background()
	db := openDB(t)
	if _, err := db.ExecContext(ctx, `CREATE TABLE censusApiKeys (
			id TEXT PRIMARY KEY, partitionId TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL DEFAULT '',
			label TEXT NOT NULL DEFAULT '', keyHash TEXT NOT NULL DEFAULT '',
			capabilities TEXT NOT NULL DEFAULT '[]', createdAt INTEGER NOT NULL DEFAULT 0,
			expiresAt INTEGER, revokedAt INTEGER, lastUsedAt INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE INDEX idxCensusApikeyHash ON censusApiKeys(keyHash)`); err != nil {
		t.Fatal(err)
	}
	store := NewSQLVaultStore(db)
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema over a plain hash index: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO censusApiKeys (id, partitionId, keyHash) VALUES ('k1', 'p1', 'h1'), ('k2', 'p2', 'h1')`); err == nil {
		t.Fatal("two keys committed under one hash")
	}
}
