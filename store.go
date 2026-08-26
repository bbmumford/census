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
// deterministic identifier/token hashes, and Hasher-produced password digests. The Owner is opaque and
// the store filters on it, never interprets it; an empty owner ("") on an owner-scoped read matches
// any owner (the admin view). The graph itself (entities + relationships) is the companion nexus
// store's concern, not this one. A consumer supplies a *sql.DB store (the shipped default), a
// mesh-RPC gateway, or the reference MemStore.
type VaultStore interface {
	// ── Credentials ──
	PutCredential(ctx context.Context, c *Credential) error
	// GetCredentialByIdentifier finds a credential of a kind by its identifier hash (the login lookup).
	GetCredentialByIdentifier(ctx context.Context, kind, identifierHash string) (*Credential, error)
	ListCredentialsBySubject(ctx context.Context, owner, subject string) ([]*Credential, error)
	DeleteCredential(ctx context.Context, owner, id string) error

	// ── Email verifications ──
	PutEmailVerification(ctx context.Context, v *EmailVerification) error
	GetEmailVerificationByToken(ctx context.Context, tokenHash string) (*EmailVerification, error)
	MarkEmailVerificationConsumed(ctx context.Context, id string, consumedAt int64) error

	// ── Invitations ──
	PutInvitation(ctx context.Context, i *Invitation) error
	GetInvitationByToken(ctx context.Context, tokenHash string) (*Invitation, error)
	// GetPendingInvitation finds a still-pending invitation for an identifier hash + target (uniqueness).
	GetPendingInvitation(ctx context.Context, identifierHash, grantTo string) (*Invitation, error)
	ListInvitationsByOwner(ctx context.Context, owner, statusFilter string) ([]*Invitation, error)
	UpdateInvitationStatus(ctx context.Context, id, status string, at int64) error

	// ── API keys ──
	PutAPIKey(ctx context.Context, k *APIKey) error
	GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error)
	ListAPIKeysBySubject(ctx context.Context, owner, subject string) ([]*APIKey, error)
	RevokeAPIKey(ctx context.Context, owner, id string, revokedAt int64) error
	TouchAPIKeyUsed(ctx context.Context, id string, usedAt int64) error
}
