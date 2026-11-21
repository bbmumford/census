# census

A scope-agnostic accounts layer over the [nexus](https://github.com/bbmumford/nexus) relationship graph. It never decides what an "organisation", "team" or "user" means: partitions and subjects are opaque ids, and membership is edges in the graph.

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

The SQL stores create their tables with `InitSchema(ctx)`. census's go.mod replaces `github.com/bbmumford/nexus` with `../nexus`, so a build outside a workspace needs nexus checked out beside it (or its own replace). `Config.Codes` is optional: without it the email-code calls answer `ErrNoEmailCodes` and everything else works.

## Consumers

ORBTR library, ai cortex and the api.orbtr.ai and node.orbtr.ai endpoints, and io constellation, agent, tools and the node.orbtr.io endpoint.
