/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"errors"
)

// ErrNotFound is returned by single-record reads when nothing matches.
var ErrNotFound = errors.New("census: not found")

// ErrConflict is returned when a uniqueness constraint would be violated (a duplicate credential
// identifier).
var ErrConflict = errors.New("census: conflict")

// VaultStore persists the account-feature records that carry secrets — credentials, the ids of spent
// single-use tokens, and API keys. Only sealed material reaches it: encrypted second-factor secrets,
// deterministic identifier/token hashes, and Hasher-produced password digests. The Partition is opaque and
// the store filters on it, never interprets it; an empty partition on a partition-scoped read matches
// NOTHING — every predicate rejects an empty parameter before comparing, so an unscoped read returns no
// rows rather than every partition's. These rows are credentials and keys: a blank partition that matched everything
// would list and revoke across partitions. There is no unscoped read; a caller that must cross partitions
// names the partition it means. The graph itself (entities + relationships) is the companion nexus
// store's concern, not this one. A consumer supplies a *sql.DB store (the shipped default), a
// mesh-RPC gateway, or the reference MemStore.
type VaultStore interface {
	// ── Credentials ──
	// PutCredential, PutAPIKey and SpendStep refuse a row with no partition (ErrUnscoped) before
	// anything is written: every list, revoke and delete of what they write is partition-scoped.
	PutCredential(ctx context.Context, c *Credential) error
	// GetCredentialByIdentifier finds a credential of a kind by its identifier hash (the login lookup).
	GetCredentialByIdentifier(ctx context.Context, kind, identifierHash string) (*Credential, error)
	ListCredentialsBySubject(ctx context.Context, partition, subject string) ([]*Credential, error)
	DeleteCredential(ctx context.Context, partition, id string) error
	// ReplaceCredentials replaces every credential of kind that subject holds under partition with
	// creds, as one write: either every one of creds is stored and none of the replaced remain, or
	// nothing changes. Each of creds names partition, subject and kind; one whose identifier another
	// credential keeps is ErrConflict, and an empty partition is ErrUnscoped.
	ReplaceCredentials(ctx context.Context, partition, subject, kind string, creds []*Credential) error

	// ── Spent single-use ids ──
	// SpendID records that the single-use token id is used and reports whether this call is the first
	// to record it. It holds the id alone, never the token or a hash of it, for every kind of signed
	// single-use token: emailed sign-in codes here, and the login handoff and native sign-in codes a
	// login authority issues. Their ids are random, so one list serves every kind. It MUST be atomic
	// against a concurrent call for the same id, for the reason SpendStep is. expiresAt is the token's
	// expiry and now the instant of use, both Unix nanoseconds; every call first deletes the entries
	// whose expiry is before now, since the token's signature refuses it from then on and its entry
	// has nothing left to refuse.
	SpendID(ctx context.Context, id string, expiresAt, now int64) (first bool, err error)

	// ── Second-factor spent steps ──
	// SpendStep records that a subject has spent one time step and reports whether this call is the
	// first to record it. It MUST be atomic against a concurrent call for the same (subject, step):
	// two requests arriving together with one stolen code is the case it exists for, so a
	// read-then-write admits exactly that. The key is (subject, step) and not (partition, subject,
	// step), because a code valid for a subject is spendable once however many partitions' requests
	// present it; partition is carried so DeleteSpentSteps can clear a subject's rows. spentAt is
	// the instant of use in Unix nanoseconds, and every call first deletes the steps, of any
	// subject, spent more than SpentStepRetention before it: a code is accepted only near its own
	// time step, so a step that old refuses nothing a verifier would still accept, and keeping it
	// would grow the record by one row per accepted code forever.
	SpendStep(ctx context.Context, partition, subject string, step, spentAt int64) (first bool, err error)
	// DeleteSpentSteps drops every step a subject has spent, so a replacement secret is not refused
	// for the window its predecessor already spent.
	DeleteSpentSteps(ctx context.Context, partition, subject string) error

	// ── API keys ──
	PutAPIKey(ctx context.Context, k *APIKey) error
	GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error)
	ListAPIKeysBySubject(ctx context.Context, partition, subject string) ([]*APIKey, error)
	RevokeAPIKey(ctx context.Context, partition, id string, revokedAt int64) error
	// TouchAPIKeyUsed records a key's last use. It writes only a key held under partition, as every
	// other key write does, and answers ErrNotFound for any other.
	TouchAPIKeyUsed(ctx context.Context, partition, id string, usedAt int64) error
}
