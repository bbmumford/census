package census

import (
	"context"
	"errors"
	"testing"

	"github.com/bbmumford/nexus"
)

// SetPartitionLabel writes the word and its plural and keeps the name and every
// other attribute; PartitionLabel reads them, empty before any is set and after
// both are cleared; one without the other and an unknown partition are refused
// and write nothing; one partition's word is not another's.
func TestSetPartitionLabelWritesTheWordThatPartitionLabelReads(t *testing.T) {
	ctx := context.Background()
	p, g := namingProvisioner(t)
	_, partition, err := p.FoundNamed(ctx, ProviderIdentity{Provider: "google", ProviderUserID: "sub-label"}, "org", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := p.FoundNamed(ctx, ProviderIdentity{Provider: "google", ProviderUserID: "sub-other"}, "org", "Other")
	if err != nil {
		t.Fatal(err)
	}
	if s, pl, err := g.PartitionLabel(ctx, partition); err != nil || s != "" || pl != "" {
		t.Fatalf("PartitionLabel before any = %q, %q, %v; want empty", s, pl, err)
	}
	if err := g.SetPartitionLabel(ctx, partition, "Team", "Teams"); err != nil {
		t.Fatal(err)
	}
	e, err := g.graph.GetEntity(ctx, partition)
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != "org" || e.Attrs[PartitionNameAttr] != "Acme" || e.Attrs[PartitionLabelAttr] != "Team" || e.Attrs[PartitionLabelPluralAttr] != "Teams" {
		t.Fatalf("labelled entity = %+v; want type org, name Acme, label Team, labelPlural Teams", e)
	}
	if s, pl, err := g.PartitionLabel(ctx, other); err != nil || s != "" || pl != "" {
		t.Fatalf("PartitionLabel(other) = %q, %q, %v; want empty", s, pl, err)
	}
	for name, c := range map[string][2]string{"a word alone": {"Team", ""}, "a plural alone": {"", "Teams"}} {
		if err := g.SetPartitionLabel(ctx, partition, c[0], c[1]); !errors.Is(err, ErrPartitionLabelIncomplete) {
			t.Fatalf("%s = %v; want ErrPartitionLabelIncomplete", name, err)
		}
	}
	if err := g.SetPartitionLabel(ctx, "no-such-partition", "Team", "Teams"); !errors.Is(err, nexus.ErrNotFound) {
		t.Fatalf("SetPartitionLabel(unknown) = %v; want nexus.ErrNotFound", err)
	}
	if _, _, err := g.PartitionLabel(ctx, "no-such-partition"); !errors.Is(err, nexus.ErrNotFound) {
		t.Fatalf("PartitionLabel(unknown) err = %v; want nexus.ErrNotFound", err)
	}
	if s, pl, _ := g.PartitionLabel(ctx, partition); s != "Team" || pl != "Teams" {
		t.Fatalf("after the refusals the word is %q, %q; want Team, Teams", s, pl)
	}
	if err := g.SetPartitionLabel(ctx, partition, "", ""); err != nil {
		t.Fatal(err)
	}
	if s, pl, err := g.PartitionLabel(ctx, partition); err != nil || s != "" || pl != "" {
		t.Fatalf("PartitionLabel after clearing = %q, %q, %v; want empty", s, pl, err)
	}
	if got, _ := g.PartitionName(ctx, partition); got != "Acme" {
		t.Fatalf("clearing the word changed the name to %q", got)
	}
}
