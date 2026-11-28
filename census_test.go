/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"encoding/json"
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

// fakeCodes is a test EmailCodeSigner (NOT for production): the code is the facts as JSON behind a
// fixed tag, refused when the tag is missing, the JSON does not parse, or now is past its expiry. It
// stands in for the consumer's MAC so these cases exercise the service's own rules.
type fakeCodes struct{}

func (fakeCodes) SignEmailCode(c EmailCode) (string, error) {
	b, err := json.Marshal(c)
	return "code:" + string(b), err
}

func (fakeCodes) OpenEmailCode(code string, now time.Time) (EmailCode, error) {
	var c EmailCode
	body, ok := strings.CutPrefix(code, "code:")
	if !ok {
		return EmailCode{}, errors.New("not a code")
	}
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		return EmailCode{}, err
	}
	if now.After(c.ExpiresAt) {
		return EmailCode{}, errors.New("expired")
	}
	return c, nil
}

func newServiceWith(t *testing.T, store VaultStore) *Service {
	t.Helper()
	svc, err := NewService(Config{Store: store, Encryptor: revEncryptor{}, Hasher: plainHasher{}, Codes: fakeCodes{}, IdentifierKey: testIdentifierKey})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func fixedClock(s *Service, at time.Time) { s.now = func() time.Time { return at } }

func TestConfig_RequiresSeams(t *testing.T) {
	if _, err := NewService(Config{Encryptor: revEncryptor{}, Hasher: plainHasher{}, IdentifierKey: testIdentifierKey}); err == nil {
		t.Fatal("a nil Store must be rejected")
	}
	if _, err := NewService(Config{Store: NewMemStore(), Hasher: plainHasher{}, IdentifierKey: testIdentifierKey}); err == nil {
		t.Fatal("a nil Encryptor must be rejected — second-factor secrets must be encrypted at rest")
	}
	if _, err := NewService(Config{Store: NewMemStore(), Encryptor: revEncryptor{}, IdentifierKey: testIdentifierKey}); err == nil {
		t.Fatal("a nil Hasher must be rejected — passwords must never be stored in the clear")
	}
}

func TestCredential_RegisterAuthenticateAndSecrecy(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		s := newServiceWith(t, store)
		c, err := s.RegisterPassword(ctx, "acme", "user-1", "Alice@Example.com ", "hunter2")
		if err != nil {
			t.Fatal(err)
		}
		// the identifier is stored as a deterministic hash (never the plaintext), and the stored secret
		// is the injected Hasher's digest (never the raw password reaching the store directly).
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
	})
}

func TestEmailVerification_ConfirmOnceAndExpiry(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		now := time.Unix(1_000_000, 0).UTC()
		s := newServiceWith(t, store)
		fixedClock(s, now)
		tok, err := s.IssueEmailVerification(ctx, "acme", "user-1", "Bob@x.com", time.Hour)
		if err != nil || tok == "" {
			t.Fatalf("issue: %v", err)
		}
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
		// expiry: the signer refuses a code past its expiry, which is ErrNotFound as any code that
		// does not open is
		tok2, _ := s.IssueEmailVerification(ctx, "acme", "user-1", "b2@x.com", time.Minute)
		fixedClock(s, now.Add(2*time.Minute))
		if _, err := s.ConfirmEmail(ctx, tok2); !errors.Is(err, ErrNotFound) {
			t.Fatal("an expired code must not confirm")
		}
		if _, err := s.IssueEmailVerification(ctx, "acme", "user-1", "b3@x.com", 0); err == nil {
			t.Fatal("a code with no lifetime was issued")
		}
	})
}

// A used token's id is kept until the token's own expiry and then deleted: the entry is pruned on the
// next spend after that expiry, so the list holds only tokens whose signature still opens.
func TestSpentIDsArePrunedAfterTheirExpiry(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		now := time.Unix(1_000_000, 0).UTC()
		exp := now.Add(15 * time.Minute).UnixNano()
		if first, err := store.SpendID(ctx, "c1", exp, now.UnixNano()); err != nil || !first {
			t.Fatalf("first spend = %v, %v", first, err)
		}
		if first, err := store.SpendID(ctx, "c1", exp, now.Add(time.Minute).UnixNano()); err != nil || first {
			t.Fatalf("second spend before expiry = %v, %v; want refused", first, err)
		}
		later := now.Add(16 * time.Minute).UnixNano()
		if first, err := store.SpendID(ctx, "c2", later+int64(time.Minute), later); err != nil || !first {
			t.Fatalf("a spend after c1's expiry = %v, %v", first, err)
		}
		if first, err := store.SpendID(ctx, "c1", later+int64(time.Minute), later); err != nil || !first {
			t.Fatalf("c1 after its expiry = %v, %v; want its entry pruned", first, err)
		}
	})
}

// A Service with no code signer issues and redeems no code, and says so.
func TestEmailCodesNeedASigner(t *testing.T) {
	s, err := NewService(Config{Store: NewMemStore(), Encryptor: revEncryptor{}, Hasher: plainHasher{}, IdentifierKey: testIdentifierKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.IssueEmailVerification(ctx, "acme", "user-1", "b@x.com", time.Hour); !errors.Is(err, ErrNoEmailCodes) {
		t.Fatalf("issue = %v, want ErrNoEmailCodes", err)
	}
	if _, err := s.ConfirmEmail(ctx, "code:{}"); !errors.Is(err, ErrNoEmailCodes) {
		t.Fatalf("confirm = %v, want ErrNoEmailCodes", err)
	}
}

func TestAPIKey_MintVerifyRevoke(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		now := time.Unix(3_000_000, 0).UTC()
		s := newServiceWith(t, store)
		fixedClock(s, now)
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
		fixedClock(s, now.Add(2*time.Minute))
		if _, err := s.VerifyAPIKey(ctx, raw2); !errors.Is(err, ErrExpired) {
			t.Fatal("an expired key must be ErrExpired")
		}
	})
}

// TestVaultStore_EmptyPartitionReachesNothing pins the partition boundary on the
// credential and key store. An empty partition used to drop the partition
// predicate, so a caller that simply left the field unset listed and revoked
// across every partition.
//
// It compares three outcomes rather than checking each call against what that
// call expected: the right partition works, a wrong one and an empty one do not,
// and the empty one must not behave like the right one. A case that only asserts
// "the call I meant to succeed succeeded" cannot tell a filter that works from one
// that admits everyone.
func TestVaultStore_EmptyPartitionReachesNothing(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		now := time.Unix(4_000_000, 0).UTC()
		s := newServiceWith(t, store)
		fixedClock(s, now)

		_, key, err := s.MintAPIKey(ctx, "acme", "svc-1", "ci", []string{"deploy"}, time.Hour)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}

		mine, err := store.ListAPIKeysBySubject(ctx, "acme", "svc-1")
		if err != nil || len(mine) != 1 {
			t.Fatalf("the owning partition must see its key, got %d err=%v", len(mine), err)
		}
		blind, err := store.ListAPIKeysBySubject(ctx, "", "svc-1")
		if err != nil || len(blind) != 0 {
			t.Fatalf("an empty partition must list no keys, got %d err=%v", len(blind), err)
		}
		other, err := store.ListAPIKeysBySubject(ctx, "globex", "svc-1")
		if err != nil || len(other) != 0 {
			t.Fatalf("a different partition must list no keys, got %d err=%v", len(other), err)
		}
		if len(blind) == len(mine) {
			t.Fatal("an empty partition saw what the owning partition sees; the predicate admits everyone")
		}

		// The write half: revoking is the same boundary, and getting it wrong
		// destroys another partition's credential rather than merely reading it.
		if err := store.RevokeAPIKey(ctx, "", key.ID, now.UnixNano()); err == nil {
			still, _ := store.ListAPIKeysBySubject(ctx, "acme", "svc-1")
			if len(still) == 1 && still[0].RevokedAt != nil {
				t.Fatal("an empty partition revoked another partition's key")
			}
		}
		if err := store.RevokeAPIKey(ctx, "acme", key.ID, now.UnixNano()); err != nil {
			t.Fatalf("the owning partition must be able to revoke its own key: %v", err)
		}
	})
}

// Service.SpendID spends an id once until its expiry, through the store the email codes spend into,
// and refuses an empty id.
func TestServiceSpendIDSpendsOnce(t *testing.T) {
	svc, err := NewService(Config{Store: NewMemStore(), Encryptor: revEncryptor{}, Hasher: plainHasher{}, IdentifierKey: testIdentifierKey})
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Minute)
	if first, err := svc.SpendID(ctx, "handoff-1", exp); err != nil || !first {
		t.Fatalf("first spend = %v, %v", first, err)
	}
	if first, err := svc.SpendID(ctx, "handoff-1", exp); err != nil || first {
		t.Fatalf("second spend = %v, %v; want refused", first, err)
	}
	if _, err := svc.SpendID(ctx, "", exp); !errors.Is(err, ErrNoSpentID) {
		t.Fatalf("empty id: err = %v, want ErrNoSpentID", err)
	}
}

// testIdentifierKey is login-identifier key material of MinIdentifierKeyBytes bytes.
var testIdentifierKey = []byte("0123456789abcdef0123456789abcdef")
