package census

import (
	"errors"
	"testing"
)

// The time-step factor is sealed and recoverable, where a password is hashed and
// is not: EnrolTOTP has to hand back exactly what it was given, because a code is
// recomputed from the secret on every check.
func TestTOTP_SealsTheSecretAndReplacesInPlace(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		s := newServiceWith(t, store)
		c, err := s.EnrolTOTP(ctx, "part_1", "usr_1", "JBSWY3DPEHPK3PXP")
		if err != nil {
			t.Fatalf("EnrolTOTP: %v", err)
		}
		if c.Secret != "enc:JBSWY3DPEHPK3PXP" {
			t.Fatalf("stored secret = %q; the Encryptor's ciphertext is what a verifier can decode back", c.Secret)
		}
		if c.Secret == "h:JBSWY3DPEHPK3PXP" {
			t.Fatal("a hashed secret can never be read back, so no code could be recomputed")
		}
		got, found, err := s.TOTPSecret(ctx, "usr_1")
		if err != nil || !found || got != "JBSWY3DPEHPK3PXP" {
			t.Fatalf("TOTPSecret = %q, %v, %v; want the enrolled secret", got, found, err)
		}

		// A second enrolment replaces the one row rather than adding a second
		// secret that also verifies.
		replaced, err := s.EnrolTOTP(ctx, "part_1", "usr_1", "NEWSECRET234567A")
		if err != nil {
			t.Fatalf("re-enrol: %v", err)
		}
		if replaced.ID != c.ID {
			t.Fatalf("replacement wrote a second row (%q then %q)", c.ID, replaced.ID)
		}
		got, _, _ = s.TOTPSecret(ctx, "usr_1")
		if got != "NEWSECRET234567A" {
			t.Fatalf("TOTPSecret = %q; want the replacement", got)
		}
	})
}

// An unenrolled subject is an ordinary state, not an outage.
func TestTOTP_UnenrolledIsNotAnError(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		s := newServiceWith(t, store)
		got, found, err := s.TOTPSecret(ctx, "usr_nobody")
		if err != nil || found || got != "" {
			t.Fatalf("TOTPSecret = %q, %v, %v; want \"\", false, nil", got, found, err)
		}
	})
}

// Every second-factor write is cleared again by a partition-scoped delete, so a
// write with no partition is refused rather than stored where nothing can reach
// it.
func TestTOTP_WritesRefuseAnEmptyPartition(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		s := newServiceWith(t, store)
		if _, err := s.EnrolTOTP(ctx, "", "usr_1", "JBSWY3DPEHPK3PXP"); !errors.Is(err, ErrUnscoped) {
			t.Fatalf("EnrolTOTP with no partition = %v; want ErrUnscoped", err)
		}
		if _, found, _ := s.TOTPSecret(ctx, "usr_1"); found {
			t.Fatal("the refused enrolment stored a factor")
		}
		if err := s.DeleteTOTP(ctx, "", "usr_1"); !errors.Is(err, ErrUnscoped) {
			t.Fatalf("DeleteTOTP with no partition = %v; want ErrUnscoped", err)
		}
		if err := s.ReplaceBackupCodes(ctx, "", "usr_1", []string{"AAAA"}); !errors.Is(err, ErrUnscoped) {
			t.Fatalf("ReplaceBackupCodes with no partition = %v; want ErrUnscoped", err)
		}
	})
}

// A step is spendable once. This is the whole reason the record exists: without
// it a code stays usable for the rest of its window.
func TestSpentStep_FirstOnceThenRefused(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		s := newServiceWith(t, store)
		if _, err := s.EnrolTOTP(ctx, "part_1", "usr_1", "JBSWY3DPEHPK3PXP"); err != nil {
			t.Fatal(err)
		}
		first, err := s.SpendTOTPStep(ctx, "usr_1", 58000000)
		if err != nil || !first {
			t.Fatalf("first spend = %v, %v; want true, nil", first, err)
		}
		again, err := s.SpendTOTPStep(ctx, "usr_1", 58000000)
		if err != nil || again {
			t.Fatalf("replayed spend = %v, %v; want false, nil", again, err)
		}
		// The refusal is for that step only, and for that subject only.
		if next, err := s.SpendTOTPStep(ctx, "usr_1", 58000001); err != nil || !next {
			t.Fatalf("next step = %v, %v; want true, nil", next, err)
		}
		if _, err := s.EnrolTOTP(ctx, "part_1", "usr_2", "OTHERSECRET23456"); err != nil {
			t.Fatal(err)
		}
		if other, err := s.SpendTOTPStep(ctx, "usr_2", 58000000); err != nil || !other {
			t.Fatalf("another subject's same step = %v, %v; want true, nil", other, err)
		}
	})
}

// A subject with no factor cannot have presented a code, so nothing is recorded:
// a step burned here is one the subject's later enrolment would have to wait out.
func TestSpentStep_NoFactorRecordsNothing(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		s := newServiceWith(t, store)
		if _, err := s.SpendTOTPStep(ctx, "usr_nobody", 58000000); !errors.Is(err, ErrNoFactor) {
			t.Fatalf("spend without a factor = %v; want ErrNoFactor", err)
		}
		if _, err := s.EnrolTOTP(ctx, "part_1", "usr_nobody", "JBSWY3DPEHPK3PXP"); err != nil {
			t.Fatal(err)
		}
		if first, err := s.SpendTOTPStep(ctx, "usr_nobody", 58000000); err != nil || !first {
			t.Fatalf("the step after enrolling = %v, %v; want true, nil", first, err)
		}
	})
}

// The spent steps key on (subject, step) and not on the secret, so they go with a
// replacement and with a removal — otherwise a correct code from the new secret is
// refused for the rest of a window the old one spent.
func TestSpentStep_ClearedByReplacementAndByDelete(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		s := newServiceWith(t, store)
		if _, err := s.EnrolTOTP(ctx, "part_1", "usr_1", "JBSWY3DPEHPK3PXP"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SpendTOTPStep(ctx, "usr_1", 58000000); err != nil {
			t.Fatal(err)
		}
		if _, err := s.EnrolTOTP(ctx, "part_1", "usr_1", "NEWSECRET234567A"); err != nil {
			t.Fatal(err)
		}
		if first, err := s.SpendTOTPStep(ctx, "usr_1", 58000000); err != nil || !first {
			t.Fatalf("after a replacement the step = %v, %v; want true, nil", first, err)
		}

		if err := s.DeleteTOTP(ctx, "part_1", "usr_1"); err != nil {
			t.Fatalf("DeleteTOTP: %v", err)
		}
		if _, found, _ := s.TOTPSecret(ctx, "usr_1"); found {
			t.Fatal("the factor survived DeleteTOTP")
		}
		if _, err := s.EnrolTOTP(ctx, "part_1", "usr_1", "THIRDSECRET23456"); err != nil {
			t.Fatal(err)
		}
		if first, err := s.SpendTOTPStep(ctx, "usr_1", 58000000); err != nil || !first {
			t.Fatalf("after a delete and re-enrol the step = %v, %v; want true, nil", first, err)
		}
		// Removing a factor a subject does not have is the state the caller asked for.
		if err := s.DeleteTOTP(ctx, "part_1", "usr_none"); err != nil {
			t.Fatalf("DeleteTOTP on an unenrolled subject = %v; want nil", err)
		}
	})
}

// A backup code is accepted once, and a fresh set retires the previous one.
func TestBackupCodes_AcceptedOnceAndReplaced(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		s := newServiceWith(t, store)
		if err := s.ReplaceBackupCodes(ctx, "part_1", "usr_1", []string{"AAAA1111", "BBBB2222"}); err != nil {
			t.Fatalf("ReplaceBackupCodes: %v", err)
		}
		if err := s.RedeemBackupCode(ctx, "part_1", "usr_1", "AAAA1111"); err != nil {
			t.Fatalf("redeeming a minted code = %v; want nil", err)
		}
		if err := s.RedeemBackupCode(ctx, "part_1", "usr_1", "AAAA1111"); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("redeeming it twice = %v; want ErrInvalidCredential", err)
		}
		if err := s.RedeemBackupCode(ctx, "part_1", "usr_1", "NOTACODE"); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("an unknown code = %v; want ErrInvalidCredential", err)
		}
		// The second code of the set is still good until a replacement retires it.
		if err := s.ReplaceBackupCodes(ctx, "part_1", "usr_1", []string{"CCCC3333"}); err != nil {
			t.Fatalf("replacing the set: %v", err)
		}
		if err := s.RedeemBackupCode(ctx, "part_1", "usr_1", "BBBB2222"); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("a code from the retired set = %v; want ErrInvalidCredential", err)
		}
		if err := s.RedeemBackupCode(ctx, "part_1", "usr_1", "CCCC3333"); err != nil {
			t.Fatalf("a code from the current set = %v; want nil", err)
		}
	})
}

// A subject's one factor is reached by a lookup that carries no partition, while
// the writes that clear it carry one. A replacement written under a second
// partition therefore has to clear the steps the row it replaces spent, or a
// correct code from the new secret is refused as a replay for the rest of the
// window the old one spent.
func TestTOTP_AReplacementUnderASecondPartitionClearsTheStepsTheOldRowSpent(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		s := newServiceWith(t, store)
		if _, err := s.EnrolTOTP(ctx, "part_1", "usr_1", "JBSWY3DPEHPK3PXP"); err != nil {
			t.Fatal(err)
		}
		if first, err := s.SpendTOTPStep(ctx, "usr_1", 58000000); err != nil || !first {
			t.Fatalf("the first spend under part_1 = %v, %v; want true, nil", first, err)
		}
		if _, err := s.EnrolTOTP(ctx, "part_2", "usr_1", "NEWSECRET234567A"); err != nil {
			t.Fatalf("re-enrol under a second partition: %v", err)
		}
		if first, err := s.SpendTOTPStep(ctx, "usr_1", 58000000); err != nil || !first {
			t.Fatalf("the replacement's own first spend of that step = %v, %v; want true, nil", first, err)
		}
		// The same clear still holds when both enrolments name one partition, which
		// is the ordinary path: the second call must not leave the first's steps.
		if _, err := s.EnrolTOTP(ctx, "part_2", "usr_2", "JBSWY3DPEHPK3PXP"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SpendTOTPStep(ctx, "usr_2", 58000000); err != nil {
			t.Fatal(err)
		}
		if _, err := s.EnrolTOTP(ctx, "part_2", "usr_2", "NEWSECRET234567A"); err != nil {
			t.Fatal(err)
		}
		if first, err := s.SpendTOTPStep(ctx, "usr_2", 58000000); err != nil || !first {
			t.Fatalf("one partition, replaced in place, the step = %v, %v; want true, nil", first, err)
		}
	})
}

// A removal that reaches a factor held under another partition cannot report the
// removal it did not perform: TOTPSecret carries no partition, so the factor it
// leaves behind is still read and still required at every login.
func TestTOTP_ARemovalFromAnotherPartitionIsRefusedAndNotReportedDone(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		s := newServiceWith(t, store)
		if _, err := s.EnrolTOTP(ctx, "part_1", "usr_1", "JBSWY3DPEHPK3PXP"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SpendTOTPStep(ctx, "usr_1", 58000000); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteTOTP(ctx, "part_2", "usr_1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("DeleteTOTP from a partition that does not hold the factor = %v; want ErrNotFound", err)
		}
		if _, found, _ := s.TOTPSecret(ctx, "usr_1"); !found {
			t.Fatal("the refused removal removed the factor")
		}
		// The refusal wrote nothing, so the partition that does hold the factor
		// still removes it and still clears the steps it spent.
		if err := s.DeleteTOTP(ctx, "part_1", "usr_1"); err != nil {
			t.Fatalf("DeleteTOTP from the partition holding the factor = %v; want nil", err)
		}
		if _, found, _ := s.TOTPSecret(ctx, "usr_1"); found {
			t.Fatal("the factor survived a removal from its own partition")
		}
		if _, err := s.EnrolTOTP(ctx, "part_1", "usr_1", "THIRDSECRET23456"); err != nil {
			t.Fatal(err)
		}
		if first, err := s.SpendTOTPStep(ctx, "usr_1", 58000000); err != nil || !first {
			t.Fatalf("after the removal and re-enrol the step = %v, %v; want true, nil", first, err)
		}
	})
}
