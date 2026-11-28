# Changelog

## [0.3.0](https://github.com/bbmumford/census/compare/v0.2.0...v0.3.0) (2026-11-28)


### ⚠ BREAKING CHANGES

* VaultStore gains ReplaceCredentials(ctx, partition, subject, kind, creds); an implementation outside this package must add it.
* VaultStore.TouchAPIKeyUsed takes the key's partition: TouchAPIKeyUsed(ctx, partition, id, usedAt).
* Config.IdentifierKey is required.
* GrantAttrs returns (map[string]string, error).

### Features

* login identifiers can be keyed under a key derived from the opener's material ([45e73dd](https://github.com/bbmumford/census/commit/45e73ddff610d5cb6fb87b2fca60e10e6d5761ec))


### Bug Fixes

* a backup-code replacement is one store write, so a failure leaves the previous set whole ([58a4ce1](https://github.com/bbmumford/census/commit/58a4ce155e7899d1e4e0dd79fd57e0fcd6b5187e))
* a census Service refuses to start without a login-identifier key ([8d9c1dc](https://github.com/bbmumford/census/commit/8d9c1dcf6a1340b787f7d28af8fa53e0c13dd56c))
* a credential re-put never moves the credential to another partition or subject ([5d601ea](https://github.com/bbmumford/census/commit/5d601ea1c5086f660a9aeaae08095a202ff049d7))
* a stored key that does not parse, a use that is not recorded and an unknown row count are errors ([946b4ca](https://github.com/bbmumford/census/commit/946b4cae4cea4c60e880b26db8d28c50f6795c07))
* an API key hash is unique, and a key's use is recorded only under its partition ([bd18295](https://github.com/bbmumford/census/commit/bd1829587c74ebad9a82611ce173c4981dabcbda))
* an unknown identifier costs the same Hasher work as a known one ([5a445c6](https://github.com/bbmumford/census/commit/5a445c6c522971c72528d2587d82f8d1d42d6970))
* enrolling a time-step factor holds the partition rule removal holds ([a6fe96c](https://github.com/bbmumford/census/commit/a6fe96c329593439ee78ef1c234d6979559dbda5))
* every census write refuses an empty partition ([85b934e](https://github.com/bbmumford/census/commit/85b934eed0caafcba6f0412cbd02c231e19694f2))
* GrantAttrs refuses a capability holding the grant separator ([8008e0d](https://github.com/bbmumford/census/commit/8008e0dd2d7cce90b0a9be25819e5bbb299dd89f))
* spent time steps are pruned once no verifier would accept them again ([4d48e9c](https://github.com/bbmumford/census/commit/4d48e9c66db35f968f6402d2a8275f61d48cb576))
* the transfer log refuses two events at one seq, and the stores say they need SQLite ([eccf761](https://github.com/bbmumford/census/commit/eccf7619dc71096e6aad4606c5abf11853069959))

## [0.2.0](https://github.com/bbmumford/census/compare/v0.1.0...v0.2.0) (2026-11-26)


### ⚠ BREAKING CHANGES

* a database created before this change holds the column as partition; the estate's databases are rewritten in place, with no rename migration.

### Features

* a partition's entity holds the word its people see for it, with its plural ([324f525](https://github.com/bbmumford/census/commit/324f525c8dc5ace3357e3e5120d72b8b63bd3038))
* the credential, spent-step, API-key and transfer tables store the partition as partitionId ([b19b3be](https://github.com/bbmumford/census/commit/b19b3be76a0532cadae23f31899f5682a430596c))


### Bug Fixes

* go.mod requires nexus v0.1.0, so the module builds without a workspace ([f2bd6b3](https://github.com/bbmumford/census/commit/f2bd6b33f5eed423d20091f5161eff4fda5b6980))
