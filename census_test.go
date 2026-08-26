package census

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var ctx = context.Background()

// revEncryptor is a reversible test Encryptor — it proves emails round-trip through the seam without
// pulling a real cipher into the test. A production deployment injects AES-GCM/envelope crypto.
type revEncryptor struct{}

func (revEncryptor) Encrypt(p string) (string, error) { return "enc:" + p, nil }
func (revEncryptor) Decrypt(c string) (string, error) { return strings.TrimPrefix(c, "enc:"), nil }

// plainHasher is a test Hasher (NOT for production) — a tagged echo with a constant-time-shaped compare.
type plainHasher struct{}

func (plainHasher) Hash(p string) (string, error) { return "h:" + p, nil }
func (plainHasher) Compare(digest, p string) bool { return digest == "h:"+p }

func newService(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(Config{Store: NewMemStore(), Encryptor: revEncryptor{}, Hasher: plainHasher{}})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestConfig_RequiresSeams(t *testing.T) {
	if _, err := NewService(Config{Encryptor: revEncryptor{}, Hasher: plainHasher{}}); err == nil {
		t.Fatal("a nil Store must be rejected")
	}
	if _, err := NewService(Config{Store: NewMemStore(), Hasher: plainHasher{}}); err == nil {
		t.Fatal("a nil Encryptor must be rejected — email must be encrypted at rest")
	}
	if _, err := NewService(Config{Store: NewMemStore(), Encryptor: revEncryptor{}}); err == nil {
		t.Fatal("a nil Hasher must be rejected — passwords must never be stored in the clear")
	}
}

func TestCredential_RegisterAuthenticateAndSecrecy(t *testing.T) {
	s := newService(t)
	c, err := s.RegisterPassword(ctx, "acme", "user-1", "Alice@Example.com ", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	// the identifier is stored as a deterministic hash (never the plaintext), and the stored secret is
	// the injected Hasher's digest (never the raw password reaching the store directly).
	if c.IdentifierHash == "alice@example.com" || len(c.IdentifierHash) != 64 {
		t.Fatalf("identifier must be a sha256 hash, got %q", c.IdentifierHash)
	}
	if c.Secret != "h:hunter2" {
		t.Fatalf("store must hold the Hasher digest, got %q", c.Secret)
	}
	// authenticate is case/whitespace-insensitive on the identifier
	subj, err := s.Authenticate(ctx, "alice@example.com", "hunter2")
	if err != nil || subj != "user-1" {
		t.Fatalf("Authenticate: subj=%q err=%v", subj, err)
	}
	// a wrong password and an unknown identifier are indistinguishable
	if _, err := s.Authenticate(ctx, "alice@example.com", "wrong"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatal("wrong password must be ErrInvalidCredential")
	}
	if _, err := s.Authenticate(ctx, "nobody@example.com", "hunter2"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatal("unknown identifier must be ErrInvalidCredential (no enumeration)")
	}
	// a second subject cannot claim the same login
	if _, err := s.RegisterPassword(ctx, "acme", "user-2", "alice@example.com", "x"); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate identifier must be ErrConflict")
	}
}

func TestEmailVerification_ConfirmOnceAndExpiry(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	s := newService(t)
	s.now = func() time.Time { return now }
	tok, err := s.IssueEmailVerification(ctx, "acme", "user-1", "Bob@x.com", time.Hour)
	if err != nil || tok == "" {
		t.Fatalf("issue: %v", err)
	}
	// the wrong token does not confirm
	if _, err := s.ConfirmEmail(ctx, "not-the-token"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown token must be ErrNotFound")
	}
	subj, err := s.ConfirmEmail(ctx, tok)
	if err != nil || subj != "user-1" {
		t.Fatalf("confirm: subj=%q err=%v", subj, err)
	}
	// single-use: a second confirm fails
	if _, err := s.ConfirmEmail(ctx, tok); !errors.Is(err, ErrExpired) {
		t.Fatal("a consumed token must not confirm again")
	}
	// expiry
	tok2, _ := s.IssueEmailVerification(ctx, "acme", "user-1", "b2@x.com", time.Minute)
	s.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := s.ConfirmEmail(ctx, tok2); !errors.Is(err, ErrExpired) {
		t.Fatal("an expired token must be ErrExpired")
	}
}

func TestInvitation_AcceptCarriesOpaqueGrant(t *testing.T) {
	now := time.Unix(2_000_000, 0).UTC()
	s := newService(t)
	s.now = func() time.Time { return now }
	tok, inv, err := s.Invite(ctx, "acme", "carol@x.com", "org-9", "member", map[string]string{"role": "admin"}, time.Hour)
	if err != nil || tok == "" {
		t.Fatalf("invite: %v", err)
	}
	// a second pending invite for the same email + target conflicts
	if _, _, err := s.Invite(ctx, "acme", "carol@x.com", "org-9", "member", nil, time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatal("a duplicate pending invitation must be ErrConflict")
	}
	// accept returns the opaque grant for the consumer to write into the graph
	got, err := s.AcceptInvitation(ctx, tok)
	if err != nil || got.GrantTo != "org-9" || got.GrantType != "member" || got.GrantAttrs["role"] != "admin" {
		t.Fatalf("accept must carry the opaque grant; got %+v err=%v", got, err)
	}
	if got.Status != "accepted" || got.AcceptedAt == nil {
		t.Fatal("accept must mark the invitation accepted")
	}
	// re-accepting the same token fails
	if _, err := s.AcceptInvitation(ctx, tok); !errors.Is(err, ErrExpired) {
		t.Fatal("an accepted invitation must not accept again")
	}
	// once the pending one is resolved, a fresh invite to the same target is allowed
	if _, _, err := s.Invite(ctx, "acme", "carol@x.com", "org-9", "member", nil, time.Hour); err != nil {
		t.Fatalf("a re-invite after acceptance must be allowed; got %v", err)
	}
	_ = inv
}

func TestInvitation_RevokeBlocksAccept(t *testing.T) {
	s := newService(t)
	tok, inv, _ := s.Invite(ctx, "acme", "d@x.com", "org-1", "member", nil, 0)
	if err := s.RevokeInvitation(ctx, inv.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvitation(ctx, tok); !errors.Is(err, ErrExpired) {
		t.Fatal("a revoked invitation must not accept")
	}
}

func TestAPIKey_MintVerifyRevoke(t *testing.T) {
	now := time.Unix(3_000_000, 0).UTC()
	s := newService(t)
	s.now = func() time.Time { return now }
	raw, key, err := s.MintAPIKey(ctx, "acme", "svc-1", "ci", []string{"deploy", "read"}, time.Hour)
	if err != nil || raw == "" {
		t.Fatalf("mint: %v", err)
	}
	if key.KeyHash == raw {
		t.Fatal("the store must hold the key hash, not the raw key")
	}
	got, err := s.VerifyAPIKey(ctx, raw)
	if err != nil || got.Subject != "svc-1" || len(got.Capabilities) != 2 {
		t.Fatalf("verify: %+v err=%v", got, err)
	}
	// use is recorded
	if got2, _ := s.store.GetAPIKeyByHash(ctx, key.KeyHash); got2.LastUsedAt == nil {
		t.Fatal("verify must record LastUsedAt")
	}
	// revoke blocks
	if err := s.store.RevokeAPIKey(ctx, "acme", key.ID, now.UnixNano()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAPIKey(ctx, raw); !errors.Is(err, ErrExpired) {
		t.Fatal("a revoked key must be ErrExpired")
	}
	// expiry blocks a different key
	raw2, _, _ := s.MintAPIKey(ctx, "acme", "svc-1", "tmp", nil, time.Minute)
	s.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := s.VerifyAPIKey(ctx, raw2); !errors.Is(err, ErrExpired) {
		t.Fatal("an expired key must be ErrExpired")
	}
}
