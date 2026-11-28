package census

import (
	"context"
	"errors"
	"testing"
)

// A re-put of a known credential id under another partition or subject is ErrConflict on either
// store and changes nothing: the partition that wrote the credential still lists and deletes it.
func TestARePutNeverMovesACredential(t *testing.T) {
	eachVault(t, func(t *testing.T, store VaultStore) {
		ctx := context.Background()
		c := &Credential{Partition: "p1", Subject: "s1", Kind: "password", IdentifierHash: "h1", Secret: "x"}
		if err := store.PutCredential(ctx, c); err != nil {
			t.Fatal(err)
		}
		for _, moved := range []*Credential{
			{ID: c.ID, Partition: "p2", Subject: "s1", Kind: "password", IdentifierHash: "h1", Secret: "y"},
			{ID: c.ID, Partition: "p1", Subject: "s2", Kind: "password", IdentifierHash: "h1", Secret: "y"},
		} {
			if err := store.PutCredential(ctx, moved); !errors.Is(err, ErrConflict) {
				t.Fatalf("re-put under %s/%s = %v; want ErrConflict", moved.Partition, moved.Subject, err)
			}
		}
		listed, err := store.ListCredentialsBySubject(ctx, "p1", "s1")
		if err != nil || len(listed) != 1 || listed[0].Secret != "x" {
			t.Fatalf("the writing partition lists %+v, %v; want the credential unchanged", listed, err)
		}
		same := &Credential{ID: c.ID, Partition: "p1", Subject: "s1", Kind: "password", IdentifierHash: "h1", Secret: "z"}
		if err := store.PutCredential(ctx, same); err != nil {
			t.Fatalf("a re-put in the credential's own partition and subject: %v", err)
		}
		if err := store.DeleteCredential(ctx, "p1", c.ID); err != nil {
			t.Fatalf("the writing partition could not delete its credential: %v", err)
		}
	})
}
