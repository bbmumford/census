package census

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bbmumford/nexus"
)

// provisionerOver builds a Provisioner over s whose ladder resolves the "member"
// membership edge EnsureUser writes, with assign as its onboarding policy.
func provisionerOver(t *testing.T, s *GraphService, assign PartitionAssigner) *Provisioner {
	t.Helper()
	p, err := NewProvisioner(ProvisionerConfig{
		Graph:           s,
		Rules:           []nexus.Rule{OutTargets("member")},
		Assign:          assign,
		MembershipEdge:  "member",
		MembershipAttrs: testMembershipAttrs,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	return p
}

// deferredDB opens a file database in WAL mode whose transactions begin
// DEFERRED, so a second writer whose snapshot predates the first writer's
// commit is refused rather than queued.
func deferredDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "graph.db")+
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(20000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// eachSignInGraph runs fn over the in-memory pairing and the SQL pairing whose
// writers queue (BEGIN IMMEDIATE), where every concurrent writer commits in
// turn, and over the SQL pairing whose transactions begin DEFERRED, where the
// engine refuses a writer that read before another committed (mayRefuse).
func eachSignInGraph(t *testing.T, fn func(t *testing.T, s *GraphService, g nexus.GraphStore, log sinceLog, mayRefuse bool)) {
	t.Helper()
	eachAtomic(t, func(t *testing.T, s *GraphService, g nexus.GraphStore, log sinceLog) {
		fn(t, s, g, log, false)
	})
	t.Run("sql-deferred", func(t *testing.T) {
		s, g, log := sqlGraph(t, deferredDB(t))
		fn(t, s, g, log, true)
	})
}

// Several first sign-ins of one provider identity at once make one subject. The
// assigner holds every caller until all of them are inside it, so each has
// already missed the identity lookup before any of them writes: the case two
// browsers finishing one person's OAuth sign-in at the same moment reach. Where
// the engine refuses a concurrent writer, the refused sign-in answers the
// engine's error and writes nothing; no sign-in ever answers a second subject.
func TestEnsureUser_ConcurrentFirstSignInsMakeOneSubject(t *testing.T) {
	eachSignInGraph(t, func(t *testing.T, s *GraphService, g nexus.GraphStore, log sinceLog, mayRefuse bool) {
		const n = 6
		var arrived sync.WaitGroup
		arrived.Add(n)
		release := make(chan struct{})
		go func() { arrived.Wait(); close(release) }()
		assign := func(context.Context, ProviderIdentity, string) (string, error) {
			arrived.Done()
			<-release
			return "partition-1", nil
		}
		p := provisionerOver(t, s, assign)
		id := ProviderIdentity{Provider: "google", ProviderUserID: "sub-race", Email: "r@example.com"}

		type answer struct {
			subject, partition string
			err                error
		}
		answers := make([]answer, n)
		var done sync.WaitGroup
		for i := 0; i < n; i++ {
			done.Add(1)
			go func(i int) {
				defer done.Done()
				sub, part, err := p.EnsureUser(ctx, id, "")
				answers[i] = answer{sub, part, err}
			}(i)
		}
		done.Wait()

		answered := ""
		for i, a := range answers {
			if a.err != nil {
				if !mayRefuse {
					t.Errorf("sign-in %d: %v", i, a.err)
				}
				continue
			}
			if a.partition != "partition-1" {
				t.Errorf("sign-in %d answered partition %q", i, a.partition)
			}
			if answered == "" {
				answered = a.subject
			}
			if a.subject != answered {
				t.Errorf("sign-in %d answered subject %q; another answered %q", i, a.subject, answered)
			}
		}
		if answered == "" {
			t.Fatal("no sign-in succeeded")
		}
		held, err := g.InEdges(ctx, "sub-race", "identity:google")
		if err != nil {
			t.Fatal(err)
		}
		if len(held) != 1 || held[0].From != answered {
			t.Fatalf("%d subjects hold the one provider identity (%+v), want only %q", len(held), held, answered)
		}
		subjects, err := g.ListEntitiesByType(ctx, "user")
		if err != nil {
			t.Fatal(err)
		}
		if len(subjects) != 1 {
			t.Fatalf("%d subject entities were created for one identity, want 1", len(subjects))
		}
		members, err := g.InEdges(ctx, "partition-1", "member")
		if err != nil {
			t.Fatal(err)
		}
		if len(members) != 1 || members[0].From != held[0].From {
			t.Fatalf("membership edges %+v, want one from %q", members, held[0].From)
		}
		if ev := since(t, log, 0); len(ev) != 2 {
			t.Fatalf("events %v, want the identity grant and the membership grant", describe(ev))
		}
	})
}

// A first sign-in whose membership grant fails leaves nothing behind: no subject
// entity and no identity edge, so the identity's next sign-in is a first sign-in
// again rather than a returning subject that belongs to no partition.
func TestEnsureUser_AFailedMembershipLeavesNoSubject(t *testing.T) {
	db := fileDB(t)
	s, g, log := sqlGraph(t, db)
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER refuseMembership BEFORE INSERT ON nexusEdges
		WHEN NEW.type = 'member' BEGIN SELECT RAISE(ABORT, 'membership refused'); END`); err != nil {
		t.Fatal(err)
	}
	p := provisionerOver(t, s, func(context.Context, ProviderIdentity, string) (string, error) {
		return "partition-1", nil
	})
	id := ProviderIdentity{Provider: "google", ProviderUserID: "sub-fail", Name: "F"}
	if _, _, err := p.EnsureUser(ctx, id, ""); err == nil {
		t.Fatal("EnsureUser reported success although the membership grant was refused")
	}
	if held, _ := g.InEdges(ctx, "sub-fail", "identity:google"); len(held) != 0 {
		t.Fatalf("the identity edge committed without its subject's membership: %+v", held)
	}
	if subjects, _ := g.ListEntitiesByType(ctx, "user"); len(subjects) != 0 {
		t.Fatalf("a subject entity committed without its membership: %+v", subjects)
	}
	if ev := since(t, log, 0); len(ev) != 0 {
		t.Fatalf("events recorded for a refused sign-in: %v", describe(ev))
	}

	// With the refusal gone the identity signs in as a first sign-in.
	if _, err := db.ExecContext(ctx, `DROP TRIGGER refuseMembership`); err != nil {
		t.Fatal(err)
	}
	sub, part, err := p.EnsureUser(ctx, id, "")
	if err != nil || sub == "" || part != "partition-1" {
		t.Fatalf("the next sign-in: subject %q partition %q err %v", sub, part, err)
	}
}

// A graph whose store and log cannot share a transaction gets no subject from
// EnsureUser's creation: it answers ErrNoTransaction and writes nothing, as
// FoundNamed does. A returning subject is still found on such a graph.
func TestEnsureUser_CreatesOnlyWhereTheWritesCanShareATransaction(t *testing.T) {
	g := nexus.NewMemStore()
	s, err := NewGraphService(GraphConfig{Graph: g, Log: otherLog{NewMemTransferLog()}})
	if err != nil {
		t.Fatal(err)
	}
	p := provisionerOver(t, s, func(context.Context, ProviderIdentity, string) (string, error) {
		return "partition-1", nil
	})
	id := ProviderIdentity{Provider: "google", ProviderUserID: "sub-notx"}
	if _, _, err := p.EnsureUser(ctx, id, ""); !errors.Is(err, ErrNoTransaction) {
		t.Fatalf("EnsureUser over a graph that cannot transact: %v, want ErrNoTransaction", err)
	}
	if subjects, _ := g.ListEntitiesByType(ctx, "user"); len(subjects) != 0 {
		t.Fatalf("a subject was written: %+v", subjects)
	}

	// A subject written before is found as a returning subject.
	if err := g.PutEntity(ctx, &nexus.Entity{ID: "u-old", Type: "user"}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []nexus.Relationship{
		{From: "u-old", To: "sub-notx", Type: "identity:google"},
		{From: "u-old", To: "partition-1", Type: "member"},
	} {
		r := r
		if err := g.PutRelationship(ctx, &r); err != nil {
			t.Fatal(err)
		}
	}
	sub, part, err := p.EnsureUser(ctx, id, "")
	if err != nil || sub != "u-old" || part != "partition-1" {
		t.Fatalf("returning subject on a graph that cannot transact: %q %q %v", sub, part, err)
	}
}
