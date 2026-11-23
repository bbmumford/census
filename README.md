# census

census is an accounts layer over the [nexus](https://github.com/bbmumford/nexus) relationship graph. It never decides what an "organisation", "team" or "user" means: partitions and subjects are opaque ids, and membership is edges in the graph.

- **Account secrets** that cannot be plain graph attributes, behind `Service`: password credentials, a TOTP second factor and backup codes, API keys, email-verification codes, and spent single-use ids. Secrets are hashed (`Hasher`) or sealed (`Encryptor`) before they reach the store.
- **An audited write path over the graph**, behind `GraphService`: every membership or role edge granted or revoked is written with a provenance record (`TransferLog`), optionally in one transaction with the reads the change was decided on (`Atomic`).
- **Provisioning**, behind `Provisioner`: an external sign-in identity (provider and provider user id) becomes a subject and a partition, for a returning user (`EnsureUser`) and for a sign-up that founds a new partition (`Found`, `FoundNamed`).

## Use

```sh
go get github.com/bbmumford/census
```

```go
accounts, err := census.NewService(census.Config{
	Store:     census.NewSQLVaultStore(db), // or census.NewMemStore()
	Encryptor: encryptor,
	Hasher:    hasher,
})
cred, err := accounts.RegisterPassword(ctx, partition, subject, "ada@example.com", password)
subject, err = accounts.Authenticate(ctx, "ada@example.com", password)

graph, err := census.NewGraphService(census.GraphConfig{
	Graph: graphStore,                     // a nexus.GraphStore
	Log:   census.NewSQLTransferLog(db),   // or census.NewMemTransferLog()
})
err = graph.Grant(ctx, subject, partition, "member", nil,
	census.ChangeMeta{Partition: partition, Trigger: "invite", Source: "admin"}) // recorded with the edge
```

The SQL stores create their tables with `InitSchema(ctx)`. `Config.Codes` is optional: without it the email-code calls answer `ErrNoEmailCodes` and everything else works.

## Dependencies

- `github.com/bbmumford/nexus`: the relationship graph census writes
  membership and role edges into.
- No external module in its production code: the SQL stores run on any
  `database/sql` driver. Tests only: `modernc.org/sqlite`.
- `go.mod` replaces nexus with the sibling checkout `../nexus`, so a build
  outside a workspace needs nexus checked out beside it.

## Used by

Importers in the ORBTR estate:

- `github.com/ORBTR/Library/domain/identityhost`, `domain/enrollmenthost`,
  `authadapters`, `grantwrite`, `livemembership`, `founderbackfill`,
  `provisioning`, `identity/provisioning` and more: sign-in, enrolment,
  grants and provisioning.
- `github.com/ORBTR/cortex/credential/api_key` (and `store`),
  `tenant/handlers` and `tenant/provisioning`.
- `github.com/ORBTR/constellation/domain/identity/directory` (and `handlers`)
  and `domain/ai/mcp` (and `handlers`).
- `github.com/ORBTR/api.orbtr.ai`, `github.com/ORBTR/ai/node.orbtr.ai`,
  `github.com/ORBTR/node.orbtr.io` and
  `github.com/ORBTR/tools/schemaref/manifest`.

## Platforms and build

Pure Go, no cgo and no build tags. The module's `go` directive is 1.25.0.

## Licence

MIT. Copyright (c) 2026 Brandon Miller-Mumford. The full text is in
[LICENSE](LICENSE).

## Contributing

[AGENTS.md](AGENTS.md) holds the repository's two rules, for people and coding
agents alike: no temporary documents in the repository, and conventional commit
messages that stand on their own. [CLAUDE.md](CLAUDE.md) imports it for Claude
Code.
