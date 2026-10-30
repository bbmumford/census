package census

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Encryptor encrypts a secret (a second-factor secret) for storage and decrypts it just-in-time. A
// deployment holding real secrets wires AES-GCM or an envelope KEK; the account-feature services
// require a non-nil Encryptor — a second-factor secret must be encrypted at rest, never stored in the
// clear. This is the same seam the pharos subscriber layer proved.
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// Hasher verifies an interactive secret (a password) against a stored digest. census stores only the
// Hash output, never the plaintext; the consumer injects the algorithm (bcrypt, argon2, scrypt) so the
// package pulls no crypto-cost dependency and the cost parameters stay the deployment's choice.
type Hasher interface {
	Hash(plaintext string) (string, error)
	// Compare reports whether plaintext matches a digest Hash produced. It must be constant-time with
	// respect to the digest so a caller cannot time-probe the secret.
	Compare(digest, plaintext string) bool
}

// hashHex is the deterministic lookup hash for tokens and normalized identifiers — the uniqueness key
// and the way a raw token is matched without the store ever holding it. Not a password hash: password
// digests come from the injected Hasher.
func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// randomToken mints a raw 32-byte token (hex). Injectable on each service for tests.
func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// normalizeEmail lower-cases and trims so a uniqueness hash is stable across casings/whitespace.
func normalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }
