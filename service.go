package census

import (
	"context"
	"errors"
	"time"
)

// configError reports an invalid service configuration.
type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }

// Service is the account-features façade: it owns the crypto seam over a VaultStore and exposes the
// reusable operations (register a credential, authenticate, issue + consume email verifications and
// invitations, mint + verify API keys). It interprets no axis — Partition and Subject are opaque graph
// ids the consumer assigns. The relationship graph (memberships, roles, org hierarchy) is the nexus
// store's concern; a consumer wires the accepted invitation's opaque grant into nexus itself.
type Service struct {
	store    VaultStore
	enc      Encryptor
	hasher   Hasher
	now      func() time.Time
	newToken func() string
	newKey   func() string
}

// Config wires a Service. Store, Encryptor, and Hasher are required — emails must be encrypted at rest
// and passwords must never be stored in the clear.
type Config struct {
	Store     VaultStore
	Encryptor Encryptor
	Hasher    Hasher
	Now       func() time.Time
	// NewToken mints a raw invitation/verification token; NewKey mints a raw API key. Both default to
	// 32 random bytes hex and are injectable for tests.
	NewToken func() string
	NewKey   func() string
}

// NewService validates the config and returns the Service.
func NewService(c Config) (*Service, error) {
	if c.Store == nil {
		return nil, &configError{"census: Config.Store is required"}
	}
	if c.Encryptor == nil {
		return nil, &configError{"census: Config.Encryptor is required (invitee/verification email must be encrypted at rest)"}
	}
	if c.Hasher == nil {
		return nil, &configError{"census: Config.Hasher is required (passwords must never be stored in the clear)"}
	}
	s := &Service{store: c.Store, enc: c.Encryptor, hasher: c.Hasher, now: c.Now, newToken: c.NewToken, newKey: c.NewKey}
	if s.now == nil {
		s.now = time.Now
	}
	if s.newToken == nil {
		s.newToken = randomToken
	}
	if s.newKey == nil {
		s.newKey = randomToken
	}
	return s, nil
}

// ErrInvalidCredential is returned by Authenticate when the identifier is unknown or the secret is
// wrong — the two are indistinguishable to the caller so a probe cannot enumerate identifiers.
var ErrInvalidCredential = errors.New("census: invalid credential")

// ErrExpired is returned when a token or invitation has passed its expiry.
var ErrExpired = errors.New("census: expired")

// ── Credentials ──

// RegisterPassword creates a password credential binding an opaque subject to a login identifier. The
// identifier (email/username) is normalized and stored only as a deterministic hash; the password is
// stored only as the injected Hasher's digest. A duplicate identifier for the kind returns ErrConflict.
func (s *Service) RegisterPassword(ctx context.Context, partition, subject, identifier, password string) (*Credential, error) {
	digest, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}
	now := s.now()
	c := &Credential{
		Partition:          partition,
		Subject:        subject,
		Kind:           "password",
		IdentifierHash: hashHex(normalizeEmail(identifier)),
		Secret:         digest,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.store.PutCredential(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

// Authenticate verifies a password against the stored credential for an identifier and returns the
// authenticated subject id. An unknown identifier and a wrong password both return ErrInvalidCredential.
func (s *Service) Authenticate(ctx context.Context, identifier, password string) (subject string, err error) {
	c, err := s.store.GetCredentialByIdentifier(ctx, "password", hashHex(normalizeEmail(identifier)))
	if errors.Is(err, ErrNotFound) {
		return "", ErrInvalidCredential
	}
	if err != nil {
		return "", err
	}
	if !s.hasher.Compare(c.Secret, password) {
		return "", ErrInvalidCredential
	}
	return c.Subject, nil
}

// ── Email verification ──

// IssueEmailVerification mints a raw verification token for a subject's email and stores the challenge
// (email encrypted at rest + deterministic hash, token stored only as a hash). The RAW token is
// returned once for the confirmation link and is never recoverable from the store.
func (s *Service) IssueEmailVerification(ctx context.Context, partition, subject, email string, ttl time.Duration) (rawToken string, err error) {
	email = normalizeEmail(email)
	if email == "" {
		return "", errors.New("census: empty email")
	}
	ciphertext, err := s.enc.Encrypt(email)
	if err != nil {
		return "", err
	}
	rawToken = s.newToken()
	now := s.now()
	v := &EmailVerification{
		Partition:         partition,
		Subject:       subject,
		IdentifierEnc: ciphertext,
		Identifier:    hashHex(email),
		TokenHash:     hashHex(rawToken),
		CreatedAt:     now,
	}
	if ttl > 0 {
		exp := now.Add(ttl)
		v.ExpiresAt = &exp
	}
	if err := s.store.PutEmailVerification(ctx, v); err != nil {
		return "", err
	}
	return rawToken, nil
}

// ConfirmEmail consumes a raw verification token and returns the verified subject id. A consumed or
// expired challenge returns ErrExpired; an unknown token returns ErrNotFound.
func (s *Service) ConfirmEmail(ctx context.Context, rawToken string) (subject string, err error) {
	v, err := s.store.GetEmailVerificationByToken(ctx, hashHex(rawToken))
	if err != nil {
		return "", err
	}
	now := s.now()
	if v.ConsumedAt != nil || (v.ExpiresAt != nil && now.After(*v.ExpiresAt)) {
		return "", ErrExpired
	}
	if err := s.store.MarkEmailVerificationConsumed(ctx, v.ID, now.UnixNano()); err != nil {
		return "", err
	}
	return v.Subject, nil
}

// ── Invitations ──

// Invite creates a pending invitation for an email to receive an opaque grant (a graph edge of
// grantType onto grantTo, with grantAttrs) on acceptance. The email is encrypted at rest with a
// deterministic hash; the raw token is returned once for the invite link. A still-pending invitation
// for the same email + target returns ErrConflict.
func (s *Service) Invite(ctx context.Context, partition, email, grantTo, grantType string, grantAttrs map[string]string, ttl time.Duration) (rawToken string, inv *Invitation, err error) {
	email = normalizeEmail(email)
	if email == "" {
		return "", nil, errors.New("census: empty email")
	}
	ciphertext, err := s.enc.Encrypt(email)
	if err != nil {
		return "", nil, err
	}
	rawToken = s.newToken()
	now := s.now()
	inv = &Invitation{
		Partition:         partition,
		IdentifierEnc: ciphertext,
		Identifier:    hashHex(email),
		TokenHash:     hashHex(rawToken),
		GrantTo:       grantTo,
		GrantType:     grantType,
		GrantAttrs:    grantAttrs,
		Status:        "pending",
		CreatedAt:     now,
	}
	if ttl > 0 {
		exp := now.Add(ttl)
		inv.ExpiresAt = &exp
	}
	if err := s.store.PutInvitation(ctx, inv); err != nil {
		return "", nil, err
	}
	return rawToken, inv, nil
}

// AcceptInvitation consumes a raw invite token, marks the invitation accepted, and returns it so the
// consumer can create the opaque grant edge (GrantTo/GrantType/GrantAttrs) in the nexus graph. census
// records the acceptance but does not touch the graph — the consumer owns that write, keeping census
// axis-blind. An expired or already-resolved invitation returns ErrExpired.
func (s *Service) AcceptInvitation(ctx context.Context, rawToken string) (*Invitation, error) {
	inv, err := s.store.GetInvitationByToken(ctx, hashHex(rawToken))
	if err != nil {
		return nil, err
	}
	now := s.now()
	if inv.Status != "pending" || (inv.ExpiresAt != nil && now.After(*inv.ExpiresAt)) {
		return nil, ErrExpired
	}
	if err := s.store.UpdateInvitationStatus(ctx, inv.ID, "accepted", now.UnixNano()); err != nil {
		return nil, err
	}
	inv.Status = "accepted"
	acc := now
	inv.AcceptedAt = &acc
	return inv, nil
}

// RevokeInvitation cancels a pending invitation so its token can no longer be accepted.
func (s *Service) RevokeInvitation(ctx context.Context, id string) error {
	return s.store.UpdateInvitationStatus(ctx, id, "revoked", s.now().UnixNano())
}

// ── API keys ──

// MintAPIKey creates a non-interactive key for a subject with an opaque capability set. The RAW key is
// returned once (never recoverable from the store, which holds only its hash).
func (s *Service) MintAPIKey(ctx context.Context, partition, subject, label string, capabilities []string, ttl time.Duration) (rawKey string, key *APIKey, err error) {
	rawKey = s.newKey()
	now := s.now()
	key = &APIKey{
		Partition:        partition,
		Subject:      subject,
		Label:        label,
		KeyHash:      hashHex(rawKey),
		Capabilities: capabilities,
		CreatedAt:    now,
	}
	if ttl > 0 {
		exp := now.Add(ttl)
		key.ExpiresAt = &exp
	}
	if err := s.store.PutAPIKey(ctx, key); err != nil {
		return "", nil, err
	}
	return rawKey, key, nil
}

// VerifyAPIKey resolves a presented raw key to its record, records the use, and returns it. A revoked
// or expired key returns ErrExpired; an unknown key returns ErrNotFound.
func (s *Service) VerifyAPIKey(ctx context.Context, rawKey string) (*APIKey, error) {
	k, err := s.store.GetAPIKeyByHash(ctx, hashHex(rawKey))
	if err != nil {
		return nil, err
	}
	now := s.now()
	if k.RevokedAt != nil || (k.ExpiresAt != nil && now.After(*k.ExpiresAt)) {
		return nil, ErrExpired
	}
	_ = s.store.TouchAPIKeyUsed(ctx, k.ID, now.UnixNano())
	return k, nil
}
