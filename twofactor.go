package census

import (
	"context"
	"errors"
	"strconv"
)

// KindTOTP and KindBackupCode are the Credential.Kind values the methods below
// write and read.
//
// They are exported because a consumer listing a subject's credentials to report
// which factors exist must name the same strings these methods write; a second
// spelling in the consumer would report "no factor" for an enrolled subject.
const (
	KindTOTP       = "totp"
	KindBackupCode = "backup_code"
)

// ErrNoFactor is returned when an operation needs the subject's enrolled
// time-step factor and the subject has none.
//
// It is distinct from ErrInvalidCredential because the callers differ: a login
// check reaching a subject with no factor is a wiring fault in the path that
// decided a factor was required, while an invalid credential is an ordinary
// failed attempt. Reporting both the same way would send an operator to the
// subject's authenticator for a fault that is in the caller.
var ErrNoFactor = errors.New("census: no time-step factor is enrolled for this subject")

// ErrUnscoped is returned when a second-factor write carries no partition.
//
// Every row these methods write is cleared again by a partition-scoped delete
// (DeleteTOTP, through the store's partition predicate, which denies an empty
// partition), so a row stored under none could never be cleared: a step spent
// under it
// would refuse a correct code from a replacement secret for the rest of its
// window.
var ErrUnscoped = errors.New("census: a second-factor write requires the partition it is scoped to")

// totpIdentifier is the lookup hash of a subject's one time-step credential.
//
// It hashes the subject rather than a login handle because this credential has
// no handle: the subject is what a verification is for. The store holds (kind,
// identifier_hash) unique, so this is also what makes a second time-step factor
// for one subject impossible, and what lets a replacement re-put the same row
// instead of leaving two secrets that both verify.
func totpIdentifier(subject string) string { return hashHex(KindTOTP + ":" + subject) }

// backupIdentifier is the lookup hash of one position in a subject's backup-code
// set. The position carries no meaning beyond keeping the set's rows distinct
// under the store's (kind, identifier_hash) uniqueness: a backup code cannot be
// looked up by its value, because the digests are the Hasher's and are compared,
// not matched.
func backupIdentifier(subject string, position int) string {
	return hashHex(KindBackupCode + ":" + subject + "#" + strconv.Itoa(position))
}

// ── Time-step second factor ──

// EnrolTOTP stores the shared secret a subject's authenticator holds, as that
// subject's one time-step factor, and returns the credential row.
//
// WHAT IT CONSUMES: secret, in whatever encoding the caller will decode back —
// this package neither reads nor interprets it. WHAT CONSUMES IT: TOTPSecret,
// which returns the same string.
//
// IT SEALS AND DOES NOT HASH, which is the difference from RegisterPassword: a
// time-step code is recomputed from the secret on every check, so the secret has
// to come back out. Credential.Secret therefore holds the Encryptor's ciphertext
// for this kind, and the Hasher — whose digests are one way — is not used.
//
// Conditions:
//   - an empty partition, subject or secret is refused (ErrUnscoped for the
//     partition), before anything is written;
//   - a subject already holding a factor has it replaced in place, re-putting
//     the row totpIdentifier names;
//   - the subject's spent steps go with the replacement, because SpendTOTPStep
//     keys on (subject, step) and not on the secret. The clear runs for the
//     partition the replaced row carried as well as for this one: totpIdentifier
//     holds no partition, so the row this re-put reaches may have been written
//     under another, and DeleteSpentSteps matches only the partition it is given.
func (s *Service) EnrolTOTP(ctx context.Context, partition, subject, secret string) (*Credential, error) {
	if partition == "" {
		return nil, ErrUnscoped
	}
	if subject == "" || secret == "" {
		return nil, errors.New("census: enrolling a time-step factor requires a subject and a secret")
	}
	sealed, err := s.enc.Encrypt(secret)
	if err != nil {
		return nil, err
	}
	identifier := totpIdentifier(subject)
	now := s.now()
	c := &Credential{
		Partition:      partition,
		Subject:        subject,
		Kind:           KindTOTP,
		IdentifierHash: identifier,
		Secret:         sealed,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	replaced := ""
	if existing, err := s.store.GetCredentialByIdentifier(ctx, KindTOTP, identifier); err == nil {
		c.ID, c.CreatedAt, replaced = existing.ID, existing.CreatedAt, existing.Partition
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err := s.store.PutCredential(ctx, c); err != nil {
		return nil, err
	}
	scopes := []string{partition}
	if replaced != "" && replaced != partition {
		scopes = append(scopes, replaced)
	}
	for _, p := range scopes {
		if err := s.store.DeleteSpentSteps(ctx, p, subject); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// TOTPSecret returns the secret EnrolTOTP stored for a subject.
//
// WHAT CONSUMES IT: the verifier that recomputes the subject's current code.
//
// found = false means the subject has enrolled no factor, which is an ordinary
// state and not an error: a caller that treated it as one would report an outage
// for every subject who has not enrolled. An error is reserved for a store or a
// seal that could not answer.
func (s *Service) TOTPSecret(ctx context.Context, subject string) (secret string, found bool, err error) {
	if subject == "" {
		return "", false, nil
	}
	c, err := s.store.GetCredentialByIdentifier(ctx, KindTOTP, totpIdentifier(subject))
	if errors.Is(err, ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	plain, err := s.enc.Decrypt(c.Secret)
	if err != nil {
		return "", false, err
	}
	return plain, true, nil
}

// SpendTOTPStep records that a subject has spent one time step, reporting
// whether this call is the first to do so.
//
// WHAT CONSUMES IT: the verifier, after it has matched a code to a step and
// before it accepts that code. first = false is the signal that the code is a
// replay.
//
// The partition is read from the subject's own credential rather than taken from
// the caller, because the seam the verifier holds names only a subject and a
// step; a partition threaded in from a request would be the request's claim
// about a row it does not own. A subject with no factor is ErrNoFactor and
// nothing is written: recording a spend for a subject who cannot have presented
// a code would burn a step the subject's later enrolment has to wait out.
func (s *Service) SpendTOTPStep(ctx context.Context, subject string, step int64) (first bool, err error) {
	c, err := s.store.GetCredentialByIdentifier(ctx, KindTOTP, totpIdentifier(subject))
	if errors.Is(err, ErrNotFound) {
		return false, ErrNoFactor
	}
	if err != nil {
		return false, err
	}
	if c.Partition == "" {
		return false, ErrUnscoped
	}
	return s.store.SpendStep(ctx, c.Partition, subject, step, s.now().UnixNano())
}

// DeleteTOTP removes a subject's time-step factor and every step it has spent.
//
// The spent steps go with it for the reason EnrolTOTP clears them: they key on
// (subject, step), so a step spent under the removed secret would refuse a
// correct code from the next enrolment until the window passed. A subject with
// no factor is not an error — the end state the caller asked for already holds.
//
// A FACTOR HELD UNDER ANOTHER PARTITION IS ErrNotFound AND NOT NIL. totpIdentifier
// carries no partition, so the lookup reaches the row whatever partition wrote it,
// while DeleteCredential matches the partition it is given; swallowing that miss
// would answer nil to a caller whose factor is still enrolled, still read by
// TOTPSecret — which is partition-free — and still required at every login.
func (s *Service) DeleteTOTP(ctx context.Context, partition, subject string) error {
	if partition == "" {
		return ErrUnscoped
	}
	c, err := s.store.GetCredentialByIdentifier(ctx, KindTOTP, totpIdentifier(subject))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if c != nil {
		// Tested on the row rather than on DeleteCredential's ErrNotFound, which
		// also answers the race where a concurrent caller removed the row first:
		// there the end state the caller asked for does hold, and here it does not.
		if c.Partition != partition {
			return ErrNotFound
		}
		if err := s.store.DeleteCredential(ctx, partition, c.ID); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	return s.store.DeleteSpentSteps(ctx, partition, subject)
}

// ── Backup codes ──

// ReplaceBackupCodes stores the digests of a fresh backup-code set and drops the
// previous one.
//
// WHAT IT CONSUMES: the raw codes, which the caller has shown the subject once
// and keeps no copy of. WHAT CONSUMES IT: RedeemBackupCode.
//
// EACH DIGEST IS THE HASHER'S, never the Encryptor's: a backup code is verified
// by comparison and never has to come back out, so sealing it would hold a
// recoverable copy of a credential for no reader. The previous set is dropped
// first, so a code from it cannot be redeemed after the subject has been shown a
// new set.
//
// A POSITION HELD UNDER ANOTHER PARTITION IS ErrConflict BEFORE ANYTHING IS
// DROPPED. backupIdentifier carries no partition, while the list and the drop
// below carry one: a set written over rows this partition cannot see would leave
// the subject holding part of one set here and the rest of another there, with
// RedeemBackupCode — which lists by partition — unable to reach either whole.
// Every position the new set will occupy is checked, not only the first, because
// RedeemBackupCode deletes the row it spends, so a set whose first codes have
// been redeemed holds its remaining positions and not position 0.
func (s *Service) ReplaceBackupCodes(ctx context.Context, partition, subject string, codes []string) error {
	if partition == "" {
		return ErrUnscoped
	}
	if subject == "" || len(codes) == 0 {
		return errors.New("census: a backup-code set requires a subject and at least one code")
	}
	for i := range codes {
		held, err := s.store.GetCredentialByIdentifier(ctx, KindBackupCode, backupIdentifier(subject, i))
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if held.Partition != partition {
			return ErrConflict
		}
	}
	existing, err := s.store.ListCredentialsBySubject(ctx, partition, subject)
	if err != nil {
		return err
	}
	for _, c := range existing {
		if c.Kind != KindBackupCode {
			continue
		}
		if err := s.store.DeleteCredential(ctx, partition, c.ID); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	now := s.now()
	for i, code := range codes {
		digest, err := s.hasher.Hash(code)
		if err != nil {
			return err
		}
		if err := s.store.PutCredential(ctx, &Credential{
			Partition:      partition,
			Subject:        subject,
			Kind:           KindBackupCode,
			IdentifierHash: backupIdentifier(subject, i),
			Secret:         digest,
			CreatedAt:      now,
			UpdatedAt:      now,
		}); err != nil {
			return err
		}
	}
	return nil
}

// RedeemBackupCode accepts one of a subject's backup codes and spends it.
//
// WHAT CONSUMES IT: the login path a subject reaches with no authenticator.
//
// The matching row is DELETED, which is what makes a code single use: the set is
// the record, so leaving the row and marking it elsewhere would need a second
// record that the compare path does not read. An unknown code and an unknown
// subject both answer ErrInvalidCredential, the way Authenticate does, so a
// probe cannot tell a wrong code from a subject with no set.
func (s *Service) RedeemBackupCode(ctx context.Context, partition, subject, code string) error {
	if partition == "" {
		return ErrUnscoped
	}
	if code == "" {
		return ErrInvalidCredential
	}
	rows, err := s.store.ListCredentialsBySubject(ctx, partition, subject)
	if err != nil {
		return err
	}
	for _, c := range rows {
		if c.Kind != KindBackupCode || !s.hasher.Compare(c.Secret, code) {
			continue
		}
		if err := s.store.DeleteCredential(ctx, partition, c.ID); err != nil {
			if errors.Is(err, ErrNotFound) {
				// Another request redeemed this row between the list and the
				// delete, so this one is not the first to present the code.
				return ErrInvalidCredential
			}
			return err
		}
		return nil
	}
	return ErrInvalidCredential
}
