/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"errors"
	"testing"

	"github.com/bbmumford/nexus"
)

func namingProvisioner(t *testing.T) (*Provisioner, *GraphService) {
	t.Helper()
	g, err := NewGraphService(GraphConfig{Graph: nexus.NewMemStore(), Log: NewMemTransferLog()})
	if err != nil {
		t.Fatal(err)
	}
	deny := func(context.Context, ProviderIdentity, string) (string, error) {
		return "", errors.New("sign-in founds nothing")
	}
	p, err := NewProvisioner(ProvisionerConfig{
		Graph: g, Assign: deny, Rules: []nexus.Rule{OutTargets("member")},
		MembershipEdge: "member", MembershipAttrs: testMembershipAttrs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, g
}

// A partition founded with a name holds it as its entity's PartitionNameAttr
// from the founding transaction on, and PartitionName reads it; one founded
// through Found holds none and reads empty; an unknown partition is the store's
// nexus.ErrNotFound, not an empty name.
func TestFoundNamedWritesThePartitionNameThatPartitionNameReads(t *testing.T) {
	ctx := context.Background()
	p, g := namingProvisioner(t)
	_, named, err := p.FoundNamed(ctx, ProviderIdentity{Provider: "google", ProviderUserID: "sub-named"}, "", "Acme Research")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := g.PartitionName(ctx, named); err != nil || got != "Acme Research" {
		t.Fatalf("PartitionName(named) = %q, %v; want Acme Research", got, err)
	}
	_, bare, err := p.Found(ctx, ProviderIdentity{Provider: "google", ProviderUserID: "sub-bare"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := g.PartitionName(ctx, bare); err != nil || got != "" {
		t.Fatalf("PartitionName(bare) = %q, %v; want empty", got, err)
	}
	if _, err := g.PartitionName(ctx, "no-such-partition"); !errors.Is(err, nexus.ErrNotFound) {
		t.Fatalf("PartitionName(unknown) err = %v; want nexus.ErrNotFound", err)
	}
}

// RenamePartition rewrites the name and keeps the entity's type and every other
// attribute; an empty name and an unknown partition are refused and write
// nothing.
func TestRenamePartitionRewritesOnlyTheName(t *testing.T) {
	ctx := context.Background()
	p, g := namingProvisioner(t)
	_, partition, err := p.FoundNamed(ctx, ProviderIdentity{Provider: "google", ProviderUserID: "sub-rename"}, "org", "Old")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Atomic(ctx, func(tx *GraphTx) error {
		e, err := tx.GetEntity(ctx, partition)
		if err != nil {
			return err
		}
		kept := e.Clone()
		kept.Attrs["region"] = "au"
		return tx.PutEntity(ctx, kept)
	}); err != nil {
		t.Fatal(err)
	}
	if err := g.RenamePartition(ctx, partition, "New"); err != nil {
		t.Fatal(err)
	}
	e, err := g.graph.GetEntity(ctx, partition)
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != "org" || e.Attrs[PartitionNameAttr] != "New" || e.Attrs["region"] != "au" {
		t.Fatalf("renamed entity = %+v; want type org, name New, region au", e)
	}
	if err := g.RenamePartition(ctx, partition, ""); !errors.Is(err, ErrPartitionNameRequired) {
		t.Fatalf("RenamePartition(empty) = %v; want ErrPartitionNameRequired", err)
	}
	if err := g.RenamePartition(ctx, "no-such-partition", "X"); !errors.Is(err, nexus.ErrNotFound) {
		t.Fatalf("RenamePartition(unknown) = %v; want nexus.ErrNotFound", err)
	}
	if got, _ := g.PartitionName(ctx, partition); got != "New" {
		t.Fatalf("after the refusals the name is %q; want New", got)
	}
}
