// Package census is the scope-agnostic accounts system (extracted from the HSTLES identity domain). It
// is a thin account-features service over an opaque entity-relationship graph: users, organisations,
// teams, and projects are opaque graph entities, and memberships/roles/ownership are opaque typed
// edges, so census interprets no axis — "org", "team", "user" are opaque type strings the consumer
// assigns, resolved but never understood (the loom relationship to its payload). The graph mechanics +
// precedence resolution live in the companion nexus package; this package adds the concrete account
// FEATURES that carry secrets and cannot be opaque graph attributes: credentials, email codes
// and API keys. Those reuse the proven crypto seam — a secret is encrypted at rest behind
// an injected Encryptor with a separate deterministic hash for lookup/uniqueness, and raw API keys are
// minted once and stored only as hashes; an email code is signed by the consumer's EmailCodeSigner and
// not stored at all. The partition-scope is opaque; times are time.Time; a nil
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
	Partition          string // opaque partition-scope
	Subject        string // opaque graph entity id this credential authenticates
	Kind           string // opaque credential type
	IdentifierHash string // deterministic hash of the normalized login identifier
	Secret         string // the Hasher's output (verifiable digest), never plaintext
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// EmailCode is what an emailed code carries, signed by the consumer's EmailCodeSigner so the store
// keeps no code and no hash of one. ID is drawn at issue and is what the spent list records when the
// code is used; Identifier is the deterministic hash of the normalized address it was sent to.
// Partition and Subject are "" for a code sent to an address no subject holds.
type EmailCode struct {
	ID         string
	Partition  string
	Subject    string
	Identifier string
	ExpiresAt  time.Time
}

// EmailCodeSigner signs and opens email codes. census holds no key: the consumer signs, so its key
// management stays its own. OpenEmailCode answers an error for every code it does not verify at now,
// forged, tampered or past ExpiresAt alike, and the facts the code was signed over otherwise.
type EmailCodeSigner interface {
	SignEmailCode(c EmailCode) (string, error)
	OpenEmailCode(code string, now time.Time) (EmailCode, error)
}

// APIKey is a non-interactive credential. The raw key is minted once and stored only as a hash; a
// lookup hashes the presented key and matches it. Subject is the opaque graph entity the key acts as;
// Capabilities is the opaque capability set the consumer's authorizer interprets.
type APIKey struct {
	ID           string
	Partition        string // opaque partition-scope
	Subject      string // opaque graph entity id the key authenticates as
	Label        string
	KeyHash      string // hash of the raw key
	Capabilities []string
	CreatedAt    time.Time
	ExpiresAt    *time.Time
	RevokedAt    *time.Time
	LastUsedAt   *time.Time
}
