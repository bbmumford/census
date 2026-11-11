package census

import (
	"context"
	"errors"
	"testing"

	"github.com/bbmumford/nexus"
)

// A founding seat runs inside Found's transaction after the membership edge:
// it sees that edge, what it writes is kept with the founding, and an error it
// returns aborts the founding so nothing Found wrote is kept and the identity
// stays free. WithFoundingSeat attaches a seat to a built Provisioner without
// changing the one it copies.
func TestFoundRunsTheFoundingSeatInItsTransaction(t *testing.T) {
	store := nexus.NewMemStore()
	g, err := NewGraphService(GraphConfig{Graph: store, Log: NewMemTransferLog()})
	if err != nil {
		t.Fatal(err)
	}
	deny := func(context.Context, ProviderIdentity, string) (string, error) {
		return "", errors.New("sign-in founds nothing")
	}
	base, err := NewProvisioner(ProvisionerConfig{
		Graph: g, Assign: deny, Rules: []nexus.Rule{OutTargets("member")},
		MembershipEdge: "member", MembershipAttrs: testMembershipAttrs,
	})
	if err != nil {
		t.Fatal(err)
	}

	var sawMembership bool
	var sawMeta ChangeMeta
	seated := base.WithFoundingSeat(func(ctx context.Context, tx *GraphTx, subject, partition string, meta ChangeMeta) error {
		ok, err := tx.HasRelationship(ctx, subject, partition, "member")
		if err != nil {
			return err
		}
		sawMembership, sawMeta = ok, meta
		return tx.Grant(ctx, subject, "admin-role", "assigned", nil, meta)
	})
	subject, partition, err := seated.Found(ctx, ProviderIdentity{Provider: "google", ProviderUserID: "sub-seated"}, "")
	if err != nil {
		t.Fatalf("Found: %v", err)
	}
	if !sawMembership {
		t.Error("the seat ran before the founder's membership edge was written")
	}
	if sawMeta.Partition != partition || sawMeta.Trigger != "found" || sawMeta.Source != "google" {
		t.Errorf("the seat was given meta %+v, want Found's own", sawMeta)
	}
	if ok, err := store.HasRelationship(ctx, subject, "admin-role", "assigned"); err != nil || !ok {
		t.Errorf("the seat's edge was not kept with the founding: %v, %v", ok, err)
	}

	refused := errors.New("no seat")
	failing := base.WithFoundingSeat(func(context.Context, *GraphTx, string, string, ChangeMeta) error { return refused })
	id := ProviderIdentity{Provider: "google", ProviderUserID: "sub-refused"}
	if _, _, err := failing.Found(ctx, id, ""); !errors.Is(err, refused) {
		t.Fatalf("Found with a failing seat = %v, want the seat's error", err)
	}
	held, err := store.InEdges(ctx, id.ProviderUserID, "identity:"+id.Provider)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 0 {
		t.Fatalf("a failed seat kept the identity edge %v; the founding was not aborted", held)
	}
	if _, _, err := base.Found(ctx, id, ""); err != nil {
		t.Fatalf("the identity a failed seat aborted could not found afterwards: %v", err)
	}
}
