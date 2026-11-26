package census

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// IdentifierKeyLabel is the HKDF-SHA256 info a Service derives its login-identifier key under from
// Config.IdentifierKey. The label separates the purpose: key material a deployment already holds
// for another lookup digest yields, under it, a key whose digests never match that lookup's.
const IdentifierKeyLabel = "census-login-identifier-v1"

// MinIdentifierKeyBytes is the shortest Config.IdentifierKey a Service accepts: the width of the
// HMAC-SHA256 output it keys.
const MinIdentifierKeyBytes = 32

// ErrIdentifierKey is returned by NewService for a Config.IdentifierKey shorter than
// MinIdentifierKeyBytes.
var ErrIdentifierKey = errors.New("census: the login-identifier key holds fewer than 32 bytes")

// identifierKey derives the HMAC-SHA256 key login identifiers are digested under from material.
func identifierKey(material []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, material, nil, IdentifierKeyLabel, sha256.Size)
}

// identifierDigest is what a credential stores of a login identifier, and what a login looks it up
// by: HMAC-SHA256 of the normalised identifier under key, in hex. A party that can read the table
// cannot test a guessed address against a row without the key. A nil key is the unkeyed form, the
// identifier's SHA-256, for a Service built with no Config.IdentifierKey.
//
// TODO: the nil key form goes when every opener of a census vault passes Config.IdentifierKey.
func identifierDigest(key []byte, identifier string) string {
	n := normalizeEmail(identifier)
	if key == nil {
		return hashHex(n)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(n))
	return hex.EncodeToString(mac.Sum(nil))
}

// randomToken mints a raw 32-byte token (hex). Injectable on each service for tests.
func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// normalizeEmail lower-cases and trims so a uniqueness hash is stable across casings/whitespace.
func normalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }
