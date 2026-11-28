/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func keyMaterial(b byte) []byte {
	return []byte(strings.Repeat(string(rune(b)), MinIdentifierKeyBytes))
}

// With an IdentifierKey a password's stored identifier is HMAC-SHA256 of the normalised address under
// the key HKDF derives from the material, never the address's SHA-256; a Service holding the same
// material finds it, and one holding other material does not.
func TestLoginIdentifiersAreKeyedUnderTheDerivedKey(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	build := func(material []byte) *Service {
		s, err := NewService(Config{Store: store, Encryptor: passEncryptor{}, Hasher: &comparingHasher{}, IdentifierKey: material})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	a := build(keyMaterial('a'))
	c, err := a.RegisterPassword(ctx, "p1", "s1", "  Person@Example.com ", "pw")
	if err != nil {
		t.Fatal(err)
	}
	derived, err := hkdf.Key(sha256.New, keyMaterial('a'), nil, "census-login-identifier-v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, derived)
	mac.Write([]byte("person@example.com"))
	if want := hex.EncodeToString(mac.Sum(nil)); c.IdentifierHash != want {
		t.Fatalf("stored identifier %q, want the HMAC under the derived key %q", c.IdentifierHash, want)
	}
	if c.IdentifierHash == hashHex("person@example.com") {
		t.Fatal("the stored identifier is the address's unkeyed SHA-256")
	}
	if sub, err := build(keyMaterial('a')).Authenticate(ctx, "person@example.com", "pw"); err != nil || sub != "s1" {
		t.Fatalf("a Service holding the same material did not authenticate: %q, %v", sub, err)
	}
	if _, err := build(keyMaterial('b')).Authenticate(ctx, "person@example.com", "pw"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("a Service holding other material found the identifier: %v", err)
	}
	if _, err := NewService(Config{Store: store, Encryptor: passEncryptor{}, Hasher: &comparingHasher{}, IdentifierKey: []byte("short")}); !errors.Is(err, ErrIdentifierKey) {
		t.Fatalf("a short IdentifierKey = %v, want ErrIdentifierKey", err)
	}
}
