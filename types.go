// Package census is the scope-agnostic accounts system (extracted from the HSTLES identity domain). It
// is a thin account-features service over an opaque entity-relationship graph: users, organisations,
// teams, and projects are opaque graph entities, and memberships/roles/ownership are opaque typed
// edges, so census interprets no axis — "org", "team", "user" are opaque type strings the consumer
// assigns, resolved but never understood (the loom relationship to its payload). The graph mechanics +
// precedence resolution live in the companion nexus package; this package adds the concrete account
// FEATURES that carry secrets and cannot be opaque graph attributes: credentials, email verification,
// invitations, and API keys. Those reuse the proven crypto seam — a secret is encrypted at rest behind
// an injected Encryptor with a separate deterministic hash for lookup/uniqueness, and raw tokens are
// minted once and stored only as hashes. The owner-scope is opaque; times are time.Time; a nil
// *time.Time means "not yet".
package census

import "time"

// Credential binds an opaque Subject (a graph entity id) to a verifiable secret. Kind is an opaque
// credential type the consumer names ("password", "totp"). IdentifierHash is the deterministic hash of
// the normalized login handle (email/username) used for lookup and uniqueness — the plaintext handle
// never reaches the store. Secret is the injected Hasher's output (e.g. a bcrypt/argon2 hash), never a
// plaintext password.
type Credential struct {
	ID             string
	Owner          string // opaque owner-scope
	Subject        string // opaque graph entity id this credential authenticates
	Kind           string // opaque credential type
	IdentifierHash string // deterministic hash of the normalized login identifier
	Secret         string // the Hasher's output (verifiable digest), never plaintext
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// EmailVerification is a pending email-confirmation challenge. The address is stored encrypted at rest
// with a deterministic hash for lookup; the challenge token is stored only as a hash. Consuming it
// (by the raw token) marks the subject's email verified in the consumer's graph.
type EmailVerification struct {
	ID            string
	Owner         string // opaque owner-scope
	Subject       string // opaque graph entity id being verified
	IdentifierEnc string // encrypted email address
	Identifier    string // deterministic hash of the normalized email (lookup)
	TokenHash     string // hash of the raw verification token
	CreatedAt     time.Time
	ExpiresAt     *time.Time
	ConsumedAt    *time.Time
}

// Invitation invites an email to receive a relationship on acceptance. The email is encrypted at rest
// with a deterministic hash for lookup/uniqueness-per-target; the token is stored only as a hash. The
// grant is described opaquely — GrantTo is the target entity id and GrantType the edge type to create
// in the graph on accept (e.g. a "member" edge onto an org), with GrantAttrs (e.g. a role) — census
// never interprets these; the accept step hands them to the graph.
type Invitation struct {
	ID            string
	Owner         string // opaque owner-scope
	IdentifierEnc string // encrypted invitee email
	Identifier    string // deterministic hash of the normalized email (lookup)
	TokenHash     string // hash of the raw invite token
	GrantTo       string // opaque target entity id the acceptance relates the invitee to
	GrantType     string // opaque edge type to create on accept
	GrantAttrs    map[string]string
	Status        string // "pending" | "accepted" | "revoked"
	CreatedAt     time.Time
	ExpiresAt     *time.Time
	AcceptedAt    *time.Time
}

// APIKey is a non-interactive credential. The raw key is minted once and stored only as a hash; a
// lookup hashes the presented key and matches it. Subject is the opaque graph entity the key acts as;
// Capabilities is the opaque capability set the consumer's authorizer interprets.
type APIKey struct {
	ID           string
	Owner        string // opaque owner-scope
	Subject      string // opaque graph entity id the key authenticates as
	Label        string
	KeyHash      string // hash of the raw key
	Capabilities []string
	CreatedAt    time.Time
	ExpiresAt    *time.Time
	RevokedAt    *time.Time
	LastUsedAt   *time.Time
}
