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
// durable (*sql.DB) store must match. Thread-safe; id generator injectable. Partition is opaque; "" on an
// partition-scoped read means any partition.
type MemStore struct {
	mu            sync.Mutex
	credentials   map[string]*Credential
	verifications map[string]*EmailVerification
	invitations   map[string]*Invitation
	apiKeys       map[string]*APIKey
	newID         func() string
}

// NewMemStore builds an empty vault.
func NewMemStore() *MemStore {
	return &MemStore{
		credentials:   map[string]*Credential{},
		verifications: map[string]*EmailVerification{},
		invitations:   map[string]*Invitation{},
		apiKeys:       map[string]*APIKey{},
		newID:         randomID,
	}
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func partitionMatch(want, have string) bool { return want == "" || want == have }

func fromUnixNano(n int64) time.Time { return time.Unix(0, n).UTC() }

// ── Credentials ──

func (m *MemStore) PutCredential(_ context.Context, c *Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// A credential identifier is unique per kind; a second subject cannot claim the same login.
	for _, e := range m.credentials {
		if e.Kind == c.Kind && e.IdentifierHash == c.IdentifierHash && e.ID != c.ID {
			return ErrConflict
		}
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

// ── Email verifications ──

func (m *MemStore) PutEmailVerification(_ context.Context, v *EmailVerification) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v.ID == "" {
		v.ID = m.newID()
	}
	m.verifications[v.ID] = cloneVerification(v)
	return nil
}

func (m *MemStore) GetEmailVerificationByToken(_ context.Context, tokenHash string) (*EmailVerification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.verifications {
		if v.TokenHash == tokenHash {
			return cloneVerification(v), nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) MarkEmailVerificationConsumed(_ context.Context, id string, consumedAt int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.verifications[id]
	if !ok {
		return ErrNotFound
	}
	if v.ConsumedAt == nil {
		t := fromUnixNano(consumedAt)
		v.ConsumedAt = &t
	}
	return nil
}

// ── Invitations ──

func (m *MemStore) PutInvitation(_ context.Context, i *Invitation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// One pending invitation per identifier + target; a re-invite must revoke/expire the prior first.
	for _, e := range m.invitations {
		if e.Status == "pending" && e.Identifier == i.Identifier && e.GrantTo == i.GrantTo && e.ID != i.ID {
			return ErrConflict
		}
	}
	if i.ID == "" {
		i.ID = m.newID()
	}
	m.invitations[i.ID] = cloneInvitation(i)
	return nil
}

func (m *MemStore) GetInvitationByToken(_ context.Context, tokenHash string) (*Invitation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, i := range m.invitations {
		if i.TokenHash == tokenHash {
			return cloneInvitation(i), nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) GetPendingInvitation(_ context.Context, identifierHash, grantTo string) (*Invitation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, i := range m.invitations {
		if i.Status == "pending" && i.Identifier == identifierHash && i.GrantTo == grantTo {
			return cloneInvitation(i), nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) ListInvitationsByPartition(_ context.Context, partition, statusFilter string) ([]*Invitation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Invitation
	for _, i := range m.invitations {
		if partitionMatch(partition, i.Partition) && (statusFilter == "" || i.Status == statusFilter) {
			out = append(out, cloneInvitation(i))
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].CreatedAt.After(out[b].CreatedAt) })
	return out, nil
}

func (m *MemStore) UpdateInvitationStatus(_ context.Context, id, status string, at int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	i, ok := m.invitations[id]
	if !ok {
		return ErrNotFound
	}
	i.Status = status
	if status == "accepted" && i.AcceptedAt == nil {
		t := fromUnixNano(at)
		i.AcceptedAt = &t
	}
	return nil
}

// ── API keys ──

func (m *MemStore) PutAPIKey(_ context.Context, k *APIKey) error {
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

func cloneStrMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func cloneCredential(c *Credential) *Credential { cp := *c; return &cp }

func cloneVerification(v *EmailVerification) *EmailVerification {
	cp := *v
	cp.ExpiresAt = clonePtr(v.ExpiresAt)
	cp.ConsumedAt = clonePtr(v.ConsumedAt)
	return &cp
}

func cloneInvitation(i *Invitation) *Invitation {
	cp := *i
	cp.GrantAttrs = cloneStrMap(i.GrantAttrs)
	cp.ExpiresAt = clonePtr(i.ExpiresAt)
	cp.AcceptedAt = clonePtr(i.AcceptedAt)
	return &cp
}

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
	l.events = append(l.events, &cp)
	return nil
}

// List returns every recorded event where the entity is the edge source or target, partition-scoped ("" =
// any partition).
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
