package census

import (
	"context"
	"errors"
)

// ErrNotFound is returned by single-record reads when nothing matches.
var ErrNotFound = errors.New("census: not found")

// ErrConflict is returned when a uniqueness constraint would be violated (a duplicate credential
// identifier, or a second pending invitation for the same identifier + target).
var ErrConflict = errors.New("census: conflict")

// VaultStore persists the account-feature records that carry secrets — credentials, email
// verifications, invitations, and API keys. Only sealed material reaches it: encrypted emails,
// deterministic identifier/token hashes, and Hasher-produced password digests. The Partition is opaque and
// the store filters on it, never interprets it; an empty partition ("") on a partition-scoped read matches
// NOTHING — the predicates read (? <> '' AND partition = ?), so an unscoped read returns no rows rather
// than every partition's. These rows are credentials and keys: a blank partition that matched everything
// would list and revoke across partitions. There is no unscoped read; a caller that must cross partitions
// names the partition it means. The graph itself (entities + relationships) is the companion nexus
// store's concern, not this one. A consumer supplies a *sql.DB store (the shipped default), a
// mesh-RPC gateway, or the reference MemStore.
type VaultStore interface {
	// ── Credentials ──
	PutCredential(ctx context.Context, c *Credential) error
	// GetCredentialByIdentifier finds a credential of a kind by its identifier hash (the login lookup).
	GetCredentialByIdentifier(ctx context.Context, kind, identifierHash string) (*Credential, error)
	ListCredentialsBySubject(ctx context.Context, partition, subject string) ([]*Credential, error)
	DeleteCredential(ctx context.Context, partition, id string) error

	// ── Email verifications ──
	PutEmailVerification(ctx context.Context, v *EmailVerification) error
	GetEmailVerificationByToken(ctx context.Context, tokenHash string) (*EmailVerification, error)
	MarkEmailVerificationConsumed(ctx context.Context, id string, consumedAt int64) error

	// ── Invitations ──
	PutInvitation(ctx context.Context, i *Invitation) error
	GetInvitationByToken(ctx context.Context, tokenHash string) (*Invitation, error)
	// GetPendingInvitation finds a still-pending invitation for an identifier hash + target (uniqueness).
	GetPendingInvitation(ctx context.Context, identifierHash, grantTo string) (*Invitation, error)
	ListInvitationsByPartition(ctx context.Context, partition, statusFilter string) ([]*Invitation, error)
	UpdateInvitationStatus(ctx context.Context, id, status string, at int64) error

	// ── Second-factor spent steps ──
	// SpendStep records that a subject has spent one time step and reports whether this call is the
	// first to record it. It MUST be atomic against a concurrent call for the same (subject, step):
	// two requests arriving together with one stolen code is the case it exists for, so a
	// read-then-write admits exactly that. The key is (subject, step) and not (partition, subject,
	// step), because a code valid for a subject is spendable once however many partitions' requests
	// present it; partition is carried so DeleteSpentSteps can clear a subject's rows.
	SpendStep(ctx context.Context, partition, subject string, step, spentAt int64) (first bool, err error)
	// DeleteSpentSteps drops every step a subject has spent, so a replacement secret is not refused
	// for the window its predecessor already spent.
	DeleteSpentSteps(ctx context.Context, partition, subject string) error

	// ── API keys ──
	PutAPIKey(ctx context.Context, k *APIKey) error
	GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error)
	ListAPIKeysBySubject(ctx context.Context, partition, subject string) ([]*APIKey, error)
	RevokeAPIKey(ctx context.Context, partition, id string, revokedAt int64) error
	TouchAPIKeyUsed(ctx context.Context, id string, usedAt int64) error
}
