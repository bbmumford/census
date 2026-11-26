# Changelog

## [0.2.0](https://github.com/bbmumford/census/compare/v0.1.0...v0.2.0) (2026-11-26)


### ⚠ BREAKING CHANGES

* a database created before this change holds the column as partition; the estate's databases are rewritten in place, with no rename migration.

### Features

* a partition's entity holds the word its people see for it, with its plural ([324f525](https://github.com/bbmumford/census/commit/324f525c8dc5ace3357e3e5120d72b8b63bd3038))
* the credential, spent-step, API-key and transfer tables store the partition as partitionId ([b19b3be](https://github.com/bbmumford/census/commit/b19b3be76a0532cadae23f31899f5682a430596c))


### Bug Fixes

* go.mod requires nexus v0.1.0, so the module builds without a workspace ([f2bd6b3](https://github.com/bbmumford/census/commit/f2bd6b33f5eed423d20091f5161eff4fda5b6980))
