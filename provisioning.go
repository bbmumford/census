package census

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/bbmumford/nexus"
)

// ProviderIdentity is an external (e.g. OAuth) identity a Provisioner maps to a
// census subject. Every field is an opaque string census interprets — no
// owner/tenant/org semantics; Provider/ProviderUserID are the stable identity key.
type ProviderIdentity struct {
	Provider       string // opaque provider key, e.g. "google"
	ProviderUserID string // the provider's stable user id (an OAuth "sub")
	Email          string // opaque; stored as a subject attr, never interpreted
	Name           string
	// EmailVerified is whether the provider marked Email verified. Found
	// records it on the identity edge it writes (IdentityEmailVerifiedAttr).
	EmailVerified bool
}

// IdentityEmailAttr and IdentityEmailVerifiedAttr are the attributes Found
// writes on the identity edge it creates (subject -[identity:<provider>]->
// provider user id): the address the provider's profile asserted, as given, and
// "true" when the provider marked that address verified. They record which
// provider asserted which address, which the subject's email attribute does
// not, so a consumer deciding whether a subject proved an address reads them
// from the edge. An identity with no address carries neither.
const (
	IdentityEmailAttr         = "email"
	IdentityEmailVerifiedAttr = "email_verified"
)

// emailIdentityEdge is the edge a subject holds to an address it signs in by
// emailed code with (subject -[identity:email]-> the address, lower-cased): the
// identity edge EnsureUser and Found write for a provider named "email".
const emailIdentityEdge = "identity:email"

// verifiedAddressToAttach is the address Found attaches as emailIdentityEdge for
// a provider's identity: the address lower-cased and trimmed when the provider
// marked it verified, empty when it did not, when it names no address, and for
// the email provider, whose own identity edge is that edge.
func verifiedAddressToAttach(identity ProviderIdentity) string {
	if !identity.EmailVerified || identity.Provider == "email" {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(identity.Email))
}

// identityEdgeAttrs are the identity edge's attributes for identity, nil when
// it carries no address.
func identityEdgeAttrs(identity ProviderIdentity) map[string]string {
	if identity.Email == "" {
		return nil
	}
	attrs := map[string]string{IdentityEmailAttr: identity.Email}
	if identity.EmailVerified {
		attrs[IdentityEmailVerifiedAttr] = "true"
	}
	return attrs
}

// PartitionAssigner is the onboarding policy for a FIRST-TIME subject: it returns
// the partition a brand-new subject joins, or an error to DENY creation (fail
// closed). It is injected so the accounts-onboarding choice — mint a fresh
// partition (self-serve), accept a pending invitation, or deny anonymous
// creation — is the consumer's wired decision, not baked into the primitive.
// requestedScope is an UNTRUSTED hint an assigner validates, never adopts blindly.
type PartitionAssigner func(ctx context.Context, identity ProviderIdentity, requestedScope string) (partition string, err error)

var (
	// ErrNoPartition is returned when a subject has no resolvable partition — a
	// returning subject whose ladder yields nothing/ambiguous, or an assigner that
	// returned an empty partition. The caller maps it to a denied login.
	ErrNoPartition = errors.New("census: subject has no resolvable partition")
	// ErrIdentityIncomplete is returned when the provider identity key is empty.
	ErrIdentityIncomplete = errors.New("census: provider identity incomplete")
	// ErrIdentityHeld is returned by Found when a subject already holds the
	// provider identity, so a founding write never creates a second account for
	// one identity.
	ErrIdentityHeld = errors.New("census: the provider identity already belongs to a subject")
)

// Provisioner turns an external provider identity into a census subject: it finds
// a returning subject by its identity edge (resolving its partition through the
// consumer-supplied ladder) or creates a first-time subject under the injected
// onboarding policy. Subject creation is a graph write (a new entity + identity
// edge + membership edge), which is why this is a census primitive rather than a
// consumer's — a consumer-built version would shape the shared subject model.
type Provisioner struct {
	graph          *GraphService
	rules          []nexus.Rule      // partition-resolution ladder for returning subjects
	assign         PartitionAssigner // onboarding policy for first-time subjects
	userType       string            // entity type minted for a subject
	membershipEdge string            // subject -[membershipEdge]-> partition
	// membershipAttrs are the attributes the membership edge is written with,
	// held as this Provisioner's own copy (see ProvisionerConfig.MembershipAttrs).
	membershipAttrs map[string]string
}

// ProvisionerConfig wires a Provisioner. Graph, Assign, Rules, MembershipEdge and
// MembershipAttrs are all required.
//
// MembershipEdge and Rules are correctness-critical and have NO default on
// purpose: MembershipEdge is the edge EnsureUser writes at create time, and Rules
// is the ladder that resolves a returning subject's partition — they MUST agree
// with each other AND with the edge every OTHER partition writer/resolver in the
// consumer's graph uses. A silent default here is a split-brain footgun: if
// EnsureUser wrote membership under one edge while the consumer's other login
// paths resolve over another, an OAuth-provisioned subject would authenticate but
// fail to resolve on a later email login. So the consumer states its canonical
// partition edge explicitly (e.g. its partitiongraph.EdgePartition + ladder) and
// an omission fails closed rather than diverging. UserType (the subject entity
// type) is cosmetic and defaults to "user".
//
// MembershipAttrs are the attributes EnsureUser writes on the membership edge of
// a subject it creates. They are required and have no default for the same
// reason as MembershipEdge: the consumer's membership readers decide whether the
// edge admits anyone from attributes census does not interpret — a consumer that
// admits a member through a resolver keyed on a subject-kind attribute denies
// every edge written without one — so the consumer states the attributes its
// readers need, and an empty set fails closed rather than writing members those
// readers refuse. NewProvisioner copies the map, so a change to it after
// construction does not reach later edges, and each edge is written with its
// own copy.
type ProvisionerConfig struct {
	Graph           *GraphService
	Rules           []nexus.Rule
	Assign          PartitionAssigner
	UserType        string
	MembershipEdge  string
	MembershipAttrs map[string]string
}

// NewProvisioner validates the config and returns the provisioner.
func NewProvisioner(c ProvisionerConfig) (*Provisioner, error) {
	if c.Graph == nil {
		return nil, &configError{"census: ProvisionerConfig.Graph is required"}
	}
	if c.Assign == nil {
		return nil, &configError{"census: ProvisionerConfig.Assign is required (the onboarding policy)"}
	}
	if len(c.Rules) == 0 {
		return nil, &configError{"census: ProvisionerConfig.Rules is required (the partition-resolution ladder for a returning subject)"}
	}
	if c.MembershipEdge == "" {
		return nil, &configError{"census: ProvisionerConfig.MembershipEdge is required (the edge EnsureUser writes; it MUST match the consumer's canonical partition edge, or a created subject silently fails to resolve on other login paths)"}
	}
	if len(c.MembershipAttrs) == 0 {
		return nil, &configError{"census: ProvisionerConfig.MembershipAttrs is required (the attributes the consumer's membership readers admit a member by; an edge written without them is a member those readers deny)"}
	}
	p := &Provisioner{
		graph:           c.Graph,
		rules:           c.Rules,
		assign:          c.Assign,
		userType:        c.UserType,
		membershipEdge:  c.MembershipEdge,
		membershipAttrs: copyAttrs(c.MembershipAttrs),
	}
	if p.userType == "" {
		p.userType = "user"
	}
	return p, nil
}

// EnsureUser returns the subject for identity, creating one on first sight, along
// with its partition. A returning subject (found by its identity edge) resolves
// its partition through the ladder; a first-time subject's partition comes from
// the injected assigner. FAIL-CLOSED: an empty/unresolvable partition returns
// ErrNoPartition and no session is issued upstream. requestedScope is passed to
// the assigner for a new subject and ignored for a returning one (whose partition
// comes from its actual memberships, never a caller hint).
func (p *Provisioner) EnsureUser(ctx context.Context, identity ProviderIdentity, requestedScope string) (subject string, partition string, err error) {
	if identity.Provider == "" || identity.ProviderUserID == "" {
		return "", "", ErrIdentityIncomplete
	}
	idEdge := "identity:" + identity.Provider

	// FIND a returning subject: subject -[identity:<provider>]-> providerUserID.
	edges, err := p.graph.graph.InEdges(ctx, identity.ProviderUserID, idEdge)
	if err != nil {
		return "", "", fmt.Errorf("census: lookup identity: %w", err)
	}
	if len(edges) > 0 {
		subject = edges[0].From
		partition, err = p.resolvePartition(ctx, subject)
		if err != nil {
			return "", "", err
		}
		return subject, partition, nil
	}

	// FIRST-TIME: the onboarding policy assigns the partition (or denies).
	partition, err = p.assign(ctx, identity, requestedScope)
	if err != nil {
		return "", "", fmt.Errorf("census: onboarding: %w", err)
	}
	if partition == "" {
		return "", "", ErrNoPartition
	}

	// CREATE the subject entity, its identity edge, and its partition membership.
	// Grant records each edge to the transfer log (provenance for a new account).
	subject = p.graph.newID()
	meta := ChangeMeta{Partition: partition, Trigger: "ensure_user", Source: identity.Provider, Auto: true}
	attrs := map[string]string{}
	if identity.Email != "" {
		attrs["email"] = identity.Email
	}
	if identity.Name != "" {
		attrs["name"] = identity.Name
	}
	if err := p.graph.graph.PutEntity(ctx, &nexus.Entity{ID: subject, Type: p.userType, Attrs: attrs}); err != nil {
		return "", "", fmt.Errorf("census: create subject: %w", err)
	}
	if err := p.graph.Grant(ctx, subject, identity.ProviderUserID, idEdge, nil, meta); err != nil {
		return "", "", fmt.Errorf("census: grant identity edge: %w", err)
	}
	if err := p.graph.Grant(ctx, subject, partition, p.membershipEdge, copyAttrs(p.membershipAttrs), meta); err != nil {
		return "", "", fmt.Errorf("census: grant membership: %w", err)
	}
	return subject, partition, nil
}

// Found creates, in one transaction, a fresh partition, a subject for
// identity, the subject's identity edge and its membership edge into that
// partition (written with the configured MembershipAttrs), and returns the
// subject and partition. It is the founding write a sign-up makes for a
// verified identity no subject holds; EnsureUser is the sign-in path and never
// founds unless its assigner does.
//
// The identity lookup runs inside the transaction, so an identity held by a
// subject, including one founded concurrently, is ErrIdentityHeld and nothing
// is written. partitionType defaults to "partition". A graph store that cannot
// run a transaction answers ErrNoTransaction and writes nothing.
func (p *Provisioner) Found(ctx context.Context, identity ProviderIdentity, partitionType string) (subject string, partition string, err error) {
	if identity.Provider == "" || identity.ProviderUserID == "" {
		return "", "", ErrIdentityIncomplete
	}
	if partitionType == "" {
		partitionType = "partition"
	}
	idEdge := "identity:" + identity.Provider
	err = p.graph.Atomic(ctx, func(tx *GraphTx) error {
		held, err := tx.InEdges(ctx, identity.ProviderUserID, idEdge)
		if err != nil {
			return fmt.Errorf("census: lookup identity: %w", err)
		}
		if len(held) > 0 {
			return ErrIdentityHeld
		}
		partition = tx.newID()
		if err := tx.PutEntity(ctx, &nexus.Entity{ID: partition, Type: partitionType}); err != nil {
			return fmt.Errorf("census: mint partition: %w", err)
		}
		subject = tx.newID()
		attrs := map[string]string{}
		if identity.Email != "" {
			attrs["email"] = identity.Email
		}
		if identity.Name != "" {
			attrs["name"] = identity.Name
		}
		if err := tx.PutEntity(ctx, &nexus.Entity{ID: subject, Type: p.userType, Attrs: attrs}); err != nil {
			return fmt.Errorf("census: create subject: %w", err)
		}
		meta := ChangeMeta{Partition: partition, Trigger: "found", Source: identity.Provider}
		if err := tx.Grant(ctx, subject, identity.ProviderUserID, idEdge, identityEdgeAttrs(identity), meta); err != nil {
			return fmt.Errorf("census: grant identity edge: %w", err)
		}
		// A verified address joins the subject's emailed-code sign-in, so that
		// person's later code reaches this account and not a second founding. An
		// address another subject holds stays theirs: a code consumer answers
		// nothing for an address two subjects hold, which would lock the holder out.
		if address := verifiedAddressToAttach(identity); address != "" {
			holders, err := tx.InEdges(ctx, address, emailIdentityEdge)
			if err != nil {
				return fmt.Errorf("census: lookup address: %w", err)
			}
			if len(holders) == 0 {
				if err := tx.Grant(ctx, subject, address, emailIdentityEdge, nil, meta); err != nil {
					return fmt.Errorf("census: grant address edge: %w", err)
				}
			}
		}
		if err := tx.Grant(ctx, subject, partition, p.membershipEdge, copyAttrs(p.membershipAttrs), meta); err != nil {
			return fmt.Errorf("census: grant membership: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	return subject, partition, nil
}

// copyAttrs returns an independent copy of attrs. NewProvisioner keeps its own
// copy of the configured membership attributes, and EnsureUser hands each edge a
// further copy, because the graph store may keep the map it is given: an edge
// sharing one map with the configuration, or with another edge, would change
// when either of those did.
func copyAttrs(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	for k, v := range attrs {
		out[k] = v
	}
	return out
}

// resolvePartition resolves a returning subject's partition through the ladder,
// failing closed when the outcome is unresolved or ambiguous (both leave
// Resolution.Value == "").
func (p *Provisioner) resolvePartition(ctx context.Context, subject string) (string, error) {
	res, err := p.graph.Resolve(ctx, subject, p.rules...)
	if err != nil {
		return "", fmt.Errorf("census: resolve partition: %w", err)
	}
	if !res.Resolved || res.Value == "" {
		return "", ErrNoPartition
	}
	return res.Value, nil
}

// MintPartition creates a fresh partition entity and returns its id — the building
// block for a self-serve PartitionAssigner (each first-time subject gets its own
// new partition). partitionType defaults to "partition". A self-serve assigner is
// then `func(ctx, _, _) (string, error) { return p.MintPartition(ctx, "") }`; the
// consumer bootstraps any per-partition setup (e.g. a billing profile) around it.
func (p *Provisioner) MintPartition(ctx context.Context, partitionType string) (string, error) {
	if partitionType == "" {
		partitionType = "partition"
	}
	id := p.graph.newID()
	if err := p.graph.graph.PutEntity(ctx, &nexus.Entity{ID: id, Type: partitionType}); err != nil {
		return "", fmt.Errorf("census: mint partition: %w", err)
	}
	return id, nil
}
