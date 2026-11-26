package census

import (
	"context"
	"testing"

	"github.com/bbmumford/nexus"
)

// A capability holding the grant separator is refused: written, it would resolve as two
// capabilities, and nothing is built for it.
func TestGrantAttrsRefusesACapabilityHoldingTheSeparator(t *testing.T) {
	attrs, err := GrantAttrs("orbtr:doc.read", "orbtr:doc.read,orbtr:admin.write")
	if err == nil {
		g := graphWith(t, nexus.Relationship{From: "s-1", To: "p-1", Type: "member", Attrs: attrs})
		got, _ := mustService(t, g).Resolve(context.Background(), "p-1", "s-1")
		t.Fatalf("GrantAttrs kept a capability holding the separator; it resolves as %q", got)
	}
	if attrs != nil {
		t.Fatalf("a refused GrantAttrs built %v", attrs)
	}
}
