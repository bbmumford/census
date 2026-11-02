package census

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Found creates the partition, the subject, its identity edge and its
// membership into that partition together; the identity then resolves at
// sign-in to the founded subject and partition.
func TestFoundCreatesSubjectIdentityAndPartitionTogether(t *testing.T) {
	deny := func(context.Context, ProviderIdentity, string) (string, error) { return "", errors.New("sign-in founds nothing") }
	p, g := newProvisioner(t, deny)
	id := ProviderIdentity{Provider: "google", ProviderUserID: "sub-9", Email: "f@example.com", Name: "F"}

	subject, partition, err := p.Found(ctx, id, "")
	if err != nil || subject == "" || partition == "" || subject == partition {
		t.Fatalf("Found = %q, %q, %v", subject, partition, err)
	}
	ok, err := g.HasRelationship(ctx, subject, partition, "member")
	if err != nil || !ok {
		t.Fatalf("membership into the founded partition = %v, %v", ok, err)
	}
	sub, part, err := p.EnsureUser(ctx, id, "")
	if err != nil || sub != subject || part != partition {
		t.Fatalf("sign-in after Found = %q, %q, %v; want the founded subject and partition", sub, part, err)
	}
}

// The identity edge Found writes records the address the provider asserted and,
// only when the provider marked it verified, IdentityEmailVerifiedAttr; an
// identity with no address carries neither attribute.
func TestFoundRecordsTheProvidersAddressOnTheIdentityEdge(t *testing.T) {
	deny := func(context.Context, ProviderIdentity, string) (string, error) {
		return "", errors.New("sign-in founds nothing")
	}
	p, g := newProvisioner(t, deny)
	for _, c := range []struct {
		id         ProviderIdentity
		wantEmail  string
		wantMarked string
	}{
		{ProviderIdentity{Provider: "google", ProviderUserID: "g-v", Email: "V@Example.com", EmailVerified: true}, "V@Example.com", "true"},
		{ProviderIdentity{Provider: "google", ProviderUserID: "g-u", Email: "u@example.com"}, "u@example.com", ""},
		{ProviderIdentity{Provider: "github", ProviderUserID: "gh-n"}, "", ""},
	} {
		subject, _, err := p.Found(ctx, c.id, "")
		if err != nil {
			t.Fatalf("Found(%s): %v", c.id.ProviderUserID, err)
		}
		edges, err := g.OutEdges(ctx, subject, "identity:"+c.id.Provider)
		if err != nil || len(edges) != 1 || edges[0].To != c.id.ProviderUserID {
			t.Fatalf("%s: identity edges = %v, %v", c.id.ProviderUserID, edges, err)
		}
		attrs := edges[0].Attrs
		if attrs[IdentityEmailAttr] != c.wantEmail || attrs[IdentityEmailVerifiedAttr] != c.wantMarked {
			t.Errorf("%s: identity edge attrs = %v, want email %q verified %q", c.id.ProviderUserID, attrs, c.wantEmail, c.wantMarked)
		}
	}
}

// An identity a subject already holds is ErrIdentityHeld and Found writes
// nothing, so a replayed founding creates no second account.
func TestFoundRefusesAnIdentityAlreadyHeld(t *testing.T) {
	p, g := newProvisioner(t, func(context.Context, ProviderIdentity, string) (string, error) { return "", errors.New("no") })
	id := ProviderIdentity{Provider: "email", ProviderUserID: "a@example.com", Email: "a@example.com"}
	if _, _, err := p.Found(ctx, id, ""); err != nil {
		t.Fatal(err)
	}
	before, err := g.ListEntitiesByType(ctx, "partition")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Found(ctx, id, ""); !errors.Is(err, ErrIdentityHeld) {
		t.Fatalf("second Found = %v, want ErrIdentityHeld", err)
	}
	after, err := g.ListEntitiesByType(ctx, "partition")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("partitions %d -> %d: a refused founding wrote a partition", len(before), len(after))
	}
	if _, _, err := p.Found(ctx, ProviderIdentity{Provider: "email"}, ""); !errors.Is(err, ErrIdentityIncomplete) {
		t.Errorf("incomplete identity = %v, want ErrIdentityIncomplete", err)
	}
}

// A code is redeemed only with the address it was issued to: another address
// is ErrNotFound and leaves the code redeemable; the right address returns the
// subject, "" for a code issued to an address no subject holds; a second
// redemption is ErrExpired.
func TestConfirmEmailAddressBindsTheCodeToItsAddress(t *testing.T) {
	s := newServiceWith(t, NewMemStore())
	tok, err := s.IssueEmailVerification(ctx, "", "", "New@x.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmEmailAddress(ctx, "other@x.com", tok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another address = %v, want ErrNotFound", err)
	}
	subject, err := s.ConfirmEmailAddress(ctx, " new@X.com ", tok)
	if err != nil || subject != "" {
		t.Fatalf("first-time address = %q, %v; want \"\", nil", subject, err)
	}
	if _, err := s.ConfirmEmailAddress(ctx, "new@x.com", tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("second redemption = %v, want ErrExpired", err)
	}
	held, err := s.IssueEmailVerification(ctx, "acme", "user-1", "b@x.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if subject, err := s.ConfirmEmailAddress(ctx, "b@x.com", held); err != nil || subject != "user-1" {
		t.Fatalf("held address = %q, %v; want user-1", subject, err)
	}
}
