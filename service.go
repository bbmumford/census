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
// reusable operations (register a credential, authenticate, issue + redeem email codes,
// mint + verify API keys). It interprets no axis — Partition and Subject are opaque graph ids the
// consumer assigns. The relationship graph (memberships, roles, org hierarchy) is the nexus store's
// concern.
type Service struct {
	store    VaultStore
	enc      Encryptor
	hasher   Hasher
	codes    EmailCodeSigner
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
	// Codes signs and opens the email codes IssueEmailVerification, ConfirmEmail and
	// ConfirmEmailAddress serve. It is optional: a Service without it answers those three
	// ErrNoEmailCodes and serves everything else.
	Codes EmailCodeSigner
	Now   func() time.Time
	// NewToken mints an email code's id; NewKey mints a raw API key. Both default to
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
		return nil, &configError{"census: Config.Encryptor is required (second-factor secrets must be encrypted at rest)"}
	}
	if c.Hasher == nil {
		return nil, &configError{"census: Config.Hasher is required (passwords must never be stored in the clear)"}
	}
	s := &Service{store: c.Store, enc: c.Encryptor, hasher: c.Hasher, codes: c.Codes, now: c.Now, newToken: c.NewToken, newKey: c.NewKey}
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

// ErrExpired is returned when a token has passed its expiry.
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

// ErrNoEmailCodes is what IssueEmailVerification, ConfirmEmail and ConfirmEmailAddress answer on a
// Service built with no Config.Codes: a code can be neither signed nor opened, and nothing is stored to
// fall back on.
var ErrNoEmailCodes = errors.New("census: no email code signer configured")

// ErrNoSpentID is returned by SpendID for an empty id.
var ErrNoSpentID = errors.New("census: no id to spend")

// IssueEmailVerification signs an email code for a subject's address that expires ttl from now, through
// Config.Codes. Nothing is stored: the code carries its id, its partition and subject, the address's
// deterministic hash and its expiry, and the RAW code returned is the only copy. ttl must be positive,
// because the spent list deletes a used code's id at its expiry and a code with none would be spendable
// again once that happened.
func (s *Service) IssueEmailVerification(ctx context.Context, partition, subject, email string, ttl time.Duration) (rawToken string, err error) {
	if s.codes == nil {
		return "", ErrNoEmailCodes
	}
	email = normalizeEmail(email)
	if email == "" {
		return "", errors.New("census: empty email")
	}
	if ttl <= 0 {
		return "", errors.New("census: an email code needs a positive lifetime")
	}
	return s.codes.SignEmailCode(EmailCode{
		ID:         s.newToken(),
		Partition:  partition,
		Subject:    subject,
		Identifier: hashHex(email),
		ExpiresAt:  s.now().Add(ttl),
	})
}

// ConfirmEmail redeems a raw email code and returns the subject it was issued for. A code that does not
// open (forged, tampered or expired) is ErrNotFound; one already redeemed is ErrExpired.
func (s *Service) ConfirmEmail(ctx context.Context, rawToken string) (subject string, err error) {
	c, err := s.openEmailCode(rawToken)
	if err != nil {
		return "", err
	}
	if err := s.spendEmailCode(ctx, c); err != nil {
		return "", err
	}
	return c.Subject, nil
}

// ConfirmEmailAddress redeems a raw email code issued for email and returns the subject it was issued
// for, which is "" for a code issued to an address no subject holds (a first-time address a sign-up
// founds). A code issued for another address is ErrNotFound and is not spent, so a code is redeemed
// only together with the address it was sent to. A code that does not open is ErrNotFound; one already
// redeemed is ErrExpired.
func (s *Service) ConfirmEmailAddress(ctx context.Context, email, rawToken string) (subject string, err error) {
	email = normalizeEmail(email)
	if email == "" {
		return "", ErrNotFound
	}
	c, err := s.openEmailCode(rawToken)
	if err != nil {
		return "", err
	}
	if c.Identifier != hashHex(email) {
		return "", ErrNotFound
	}
	if err := s.spendEmailCode(ctx, c); err != nil {
		return "", err
	}
	return c.Subject, nil
}

// openEmailCode opens a raw code at the service's clock: ErrNoEmailCodes with no signer, ErrNotFound for
// any code the signer refuses.
func (s *Service) openEmailCode(rawToken string) (EmailCode, error) {
	if s.codes == nil {
		return EmailCode{}, ErrNoEmailCodes
	}
	c, err := s.codes.OpenEmailCode(rawToken, s.now())
	if err != nil || c.ID == "" {
		return EmailCode{}, ErrNotFound
	}
	return c, nil
}

// spendEmailCode puts an opened code's id on the spent list, ErrExpired when it is already there.
func (s *Service) spendEmailCode(ctx context.Context, c EmailCode) error {
	first, err := s.store.SpendID(ctx, c.ID, c.ExpiresAt.UnixNano(), s.now().UnixNano())
	if err != nil {
		return err
	}
	if !first {
		return ErrExpired
	}
	return nil
}

// SpendID puts the id of a single-use token another component signed — a login handoff, a native
// sign-in code — on the store's spent list until expiresAt, reporting whether this call is the first
// to put it there. An empty id is refused: it names no token, and recording it would refuse every
// later empty id. The consumer verifies the token before it spends the id and refuses a token whose
// id was already spent.
func (s *Service) SpendID(ctx context.Context, id string, expiresAt time.Time) (bool, error) {
	if id == "" {
		return false, ErrNoSpentID
	}
	return s.store.SpendID(ctx, id, expiresAt.UnixNano(), s.now().UnixNano())
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
