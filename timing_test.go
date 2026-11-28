/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
)

// comparingHasher counts every Compare, the cost-bearing step of a real Hasher.
type comparingHasher struct{ compares atomic.Int64 }

func (h *comparingHasher) Hash(p string) (string, error) { return "h:" + p, nil }
func (h *comparingHasher) Compare(d, p string) bool {
	h.compares.Add(1)
	return d == "h:"+p
}

type passEncryptor struct{}

func (passEncryptor) Encrypt(p string) (string, error) { return p, nil }
func (passEncryptor) Decrypt(c string) (string, error) { return c, nil }

// An unknown identifier runs the Hasher as many times as a known one with a wrong password, and an
// unknown or empty backup-code set as many times as a whole set, so neither answer's time tells a
// probe which it got.
func TestUnknownIdentifiersAndSetsCostTheSameHasherWork(t *testing.T) {
	h := &comparingHasher{}
	svc, err := NewService(Config{Store: NewMemStore(), Encryptor: passEncryptor{}, Hasher: h})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := svc.RegisterPassword(ctx, "p1", "s1", "known@example.com", "pw"); err != nil {
		t.Fatal(err)
	}
	cost := func(f func() error) (int64, error) {
		before := h.compares.Load()
		err := f()
		return h.compares.Load() - before, err
	}
	unknown, e1 := cost(func() error { _, err := svc.Authenticate(ctx, "nobody@example.com", "x"); return err })
	known, e2 := cost(func() error { _, err := svc.Authenticate(ctx, "known@example.com", "wrong"); return err })
	if !errors.Is(e1, ErrInvalidCredential) || !errors.Is(e2, ErrInvalidCredential) || unknown != known || known == 0 {
		t.Fatalf("Authenticate: unknown identifier %d compares (%v), known %d (%v); want equal and nonzero", unknown, e1, known, e2)
	}

	codes := make([]string, backupCodeSetForTest)
	for i := range codes {
		codes[i] = fmt.Sprintf("code-%02d", i)
	}
	if err := svc.ReplaceBackupCodes(ctx, "p1", "s1", codes); err != nil {
		t.Fatal(err)
	}
	wrong, e3 := cost(func() error { return svc.RedeemBackupCode(ctx, "p1", "s1", "nope") })
	none, e4 := cost(func() error { return svc.RedeemBackupCode(ctx, "p1", "nobody", "nope") })
	right, e5 := cost(func() error { return svc.RedeemBackupCode(ctx, "p1", "s1", "code-00") })
	if !errors.Is(e3, ErrInvalidCredential) || !errors.Is(e4, ErrInvalidCredential) || e5 != nil {
		t.Fatalf("RedeemBackupCode answers: wrong %v, no set %v, right %v", e3, e4, e5)
	}
	if wrong != none || none != right || none == 0 {
		t.Fatalf("RedeemBackupCode compares: wrong code %d, no set %d, right code %d; want all equal", wrong, none, right)
	}
}

// backupCodeSetForTest is the size of a set the login hosts issue.
const backupCodeSetForTest = 10
