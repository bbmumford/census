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

// Enrolment holds the rule removal does: a factor held under another partition is ErrConflict, and
// nothing moves, so the partition that enrolled it still reads, spends and removes it.
func TestTOTP_AnEnrolmentFromAnotherPartitionIsRefused(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		ctx := context.Background()
		s := newServiceWith(t, store)
		if _, err := s.EnrolTOTP(ctx, "part_1", "usr_1", "JBSWY3DPEHPK3PXP"); err != nil {
			t.Fatal(err)
		}
		if first, err := s.SpendTOTPStep(ctx, "usr_1", 58000000); err != nil || !first {
			t.Fatalf("the first spend = %v, %v", first, err)
		}
		if _, err := s.EnrolTOTP(ctx, "part_2", "usr_1", "NEWSECRET234567A"); !errors.Is(err, ErrConflict) {
			t.Fatalf("EnrolTOTP over another partition's factor = %v; want ErrConflict", err)
		}
		if secret, found, err := s.TOTPSecret(ctx, "usr_1"); err != nil || !found || secret != "JBSWY3DPEHPK3PXP" {
			t.Fatalf("the refused enrolment changed the factor: %q, %v, %v", secret, found, err)
		}
		if first, err := s.SpendTOTPStep(ctx, "usr_1", 58000000); err != nil || first {
			t.Fatalf("the refused enrolment cleared the spent step: %v, %v", first, err)
		}
		if err := s.DeleteTOTP(ctx, "part_1", "usr_1"); err != nil {
			t.Fatalf("the enrolling partition could not remove its factor: %v", err)
		}
	})
}
