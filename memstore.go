/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// MemStore is the in-memory reference VaultStore — the test/dev backend and the semantic reference a
// durable (*sql.DB) store must match. Thread-safe; id generator injectable. Partition is opaque; "" on a
// partition-scoped read matches nothing — see partitionMatch, which both backends are held to.
type MemStore struct {
	mu          sync.Mutex
	credentials map[string]*Credential
	spentIDs    map[string]int64
	apiKeys     map[string]*APIKey
	spentSteps  map[spentStep]spentRecord
	newID       func() string
}

// NewMemStore builds an empty vault.
func NewMemStore() *MemStore {
	return &MemStore{
		credentials: map[string]*Credential{},
		spentIDs:    map[string]int64{},
		apiKeys:     map[string]*APIKey{},
		spentSteps:  map[spentStep]spentRecord{},
		newID:       randomID,
	}
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// partitionMatch reports whether a row held under partition `have` is visible to a
// caller asking for partition `want`. Every credential, API-key and
// transfer lookup in this store filters through it.
//
// An empty `want` names no partition and matches nothing. SQLVaultStore answers
// the same way — its predicates reject an empty partition parameter before
// comparing — and the two have to agree, because a test written against this
// store is what certifies the other's behaviour. These rows are credentials and
// keys, so a `want` that matched everything would list and revoke across
// partitions.
func partitionMatch(want, have string) bool { return want != "" && want == have }

func fromUnixNano(n int64) time.Time { return time.Unix(0, n).UTC() }

// ── Credentials ──

func (m *MemStore) PutCredential(_ context.Context, c *Credential) error {
	if c.Partition == "" {
		return ErrUnscoped
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// A credential identifier is unique per kind; a second subject cannot claim the same login. A
	// re-put of a known id keeps its partition and subject, as SQLVaultStore's does.
	for _, e := range m.credentials {
		if e.Kind == c.Kind && e.IdentifierHash == c.IdentifierHash && e.ID != c.ID {
			return ErrConflict
		}
	}
	if e, ok := m.credentials[c.ID]; ok && c.ID != "" && (e.Partition != c.Partition || e.Subject != c.Subject) {
		return ErrConflict
	}
	if c.ID == "" {
		c.ID = m.newID()
	}
	m.credentials[c.ID] = cloneCredential(c)
	return nil
}

func (m *MemStore) GetCredentialByIdentifier(_ context.Context, kind, identifierHash string) (*Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.credentials {
		if c.Kind == kind && c.IdentifierHash == identifierHash {
			return cloneCredential(c), nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) ListCredentialsBySubject(_ context.Context, partition, subject string) ([]*Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Credential
	for _, c := range m.credentials {
		if partitionMatch(partition, c.Partition) && c.Subject == subject {
			out = append(out, cloneCredential(c))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemStore) DeleteCredential(_ context.Context, partition, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.credentials[id]
	if !ok || !partitionMatch(partition, c.Partition) {
		return ErrNotFound
	}
	delete(m.credentials, id)
	return nil
}

// ── Second-factor spent steps ──

// spentStep is the key SpendStep is first on exactly once. It holds no partition
// because a code valid for a subject is spendable once however many partitions'
// requests present it; the partition a step was spent under is the value's
// companion in spentPartition.
type spentStep struct {
	subject string
	step    int64
}

// spentRecord is what a spent step holds: the partition it was spent under, so
// DeleteSpentSteps can clear a subject's rows under the store's partition rule,
// and when.
type spentRecord struct {
	partition string
	at        int64
}

func (m *MemStore) SpendStep(_ context.Context, partition, subject string, step, spentAt int64) (bool, error) {
	if partition == "" {
		return false, ErrUnscoped
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// The lock spans the read and the write, which is what the seam requires:
	// two requests presenting one stolen code arrive together, and a
	// read-then-write outside the lock would answer first to both.
	for old, rec := range m.spentSteps {
		if rec.at < spentAt-int64(SpentStepRetention) {
			delete(m.spentSteps, old)
		}
	}
	k := spentStep{subject: subject, step: step}
	if _, seen := m.spentSteps[k]; seen {
		return false, nil
	}
	m.spentSteps[k] = spentRecord{partition: partition, at: spentAt}
	return true, nil
}

func (m *MemStore) DeleteSpentSteps(_ context.Context, partition, subject string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, rec := range m.spentSteps {
		if k.subject != subject || !partitionMatch(partition, rec.partition) {
			continue
		}
		delete(m.spentSteps, k)
	}
	return nil
}

// ── Spent single-use ids ──

// SpendID holds the lock across the prune, the read and the write, for the reason SpendStep does.
func (m *MemStore) SpendID(_ context.Context, id string, expiresAt, now int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, exp := range m.spentIDs {
		if exp < now {
			delete(m.spentIDs, k)
		}
	}
	if _, seen := m.spentIDs[id]; seen {
		return false, nil
	}
	m.spentIDs[id] = expiresAt
	return true, nil
}

// ── API keys ──

func (m *MemStore) PutAPIKey(_ context.Context, k *APIKey) error {
	if k.Partition == "" {
		return ErrUnscoped
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if k.ID == "" {
		k.ID = m.newID()
	}
	m.apiKeys[k.ID] = cloneAPIKey(k)
	return nil
}

func (m *MemStore) GetAPIKeyByHash(_ context.Context, keyHash string) (*APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.apiKeys {
		if k.KeyHash == keyHash {
			return cloneAPIKey(k), nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) ListAPIKeysBySubject(_ context.Context, partition, subject string) ([]*APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*APIKey
	for _, k := range m.apiKeys {
		if partitionMatch(partition, k.Partition) && k.Subject == subject {
			out = append(out, cloneAPIKey(k))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemStore) RevokeAPIKey(_ context.Context, partition, id string, revokedAt int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.apiKeys[id]
	if !ok || !partitionMatch(partition, k.Partition) {
		return ErrNotFound
	}
	if k.RevokedAt == nil {
		t := fromUnixNano(revokedAt)
		k.RevokedAt = &t
	}
	return nil
}

func (m *MemStore) TouchAPIKeyUsed(_ context.Context, id string, usedAt int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.apiKeys[id]
	if !ok {
		return ErrNotFound
	}
	t := fromUnixNano(usedAt)
	k.LastUsedAt = &t
	return nil
}

// ── clone helpers ──

func clonePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

func cloneCredential(c *Credential) *Credential { cp := *c; return &cp }

func cloneAPIKey(k *APIKey) *APIKey {
	cp := *k
	if k.Capabilities != nil {
		cp.Capabilities = append([]string(nil), k.Capabilities...)
	}
	cp.ExpiresAt = clonePtr(k.ExpiresAt)
	cp.RevokedAt = clonePtr(k.RevokedAt)
	cp.LastUsedAt = clonePtr(k.LastUsedAt)
	return &cp
}

var _ VaultStore = (*MemStore)(nil)

// MemTransferLog is the in-memory reference TransferLog — the append-only sink a durable log must
// match. Thread-safe; events are returned in the order recorded.
type MemTransferLog struct {
	mu     sync.Mutex
	events []*TransferEvent
}

// NewMemTransferLog builds an empty transfer log.
func NewMemTransferLog() *MemTransferLog { return &MemTransferLog{} }

func (l *MemTransferLog) Record(_ context.Context, e *TransferEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := *e // TransferEvent holds no maps/pointers, so a shallow copy fully isolates it
	cp.Seq = int64(len(l.events)) + 1
	l.events = append(l.events, &cp)
	return nil
}

// Since returns up to limit events recorded after seq, across every partition, in
// seq order, as SQLTransferLog.Since does.
func (l *MemTransferLog) Since(_ context.Context, seq int64, limit int) ([]*TransferEvent, error) {
	if limit <= 0 {
		return nil, errSinceLimit
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []*TransferEvent
	for _, e := range l.events {
		if e.Seq <= seq {
			continue
		}
		cp := *e
		out = append(out, &cp)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

// List returns every recorded event where the entity is the edge source or target, scoped to one
// partition. An empty partition matches nothing (partitionMatch), so an unscoped call returns no events
// rather than every partition's provenance.
func (l *MemTransferLog) List(_ context.Context, partition, entity string) ([]*TransferEvent, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []*TransferEvent
	for _, e := range l.events {
		if !partitionMatch(partition, e.Partition) {
			continue
		}
		if e.From == entity || e.To == entity {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out, nil
}

var _ TransferLog = (*MemTransferLog)(nil)
