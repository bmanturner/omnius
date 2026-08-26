# Search Meilisearch

`rsk-search-meilisearch` is an optional derived-search module. PostgreSQL and Meilisearch store projection control state and searchable copies only; application repositories remain authoritative.

## Request contract

Applications construct `SearchInput` without a tenant field. `SearchService` derives `TenantId` from the canonical `Principal`, validates query/filter/hit/offset bounds, and creates the only constructible `TenantScopedQuery`. The Meilisearch adapter always renders `_tenant_id = "<canonical UUID>"` before structured application filters. Raw provider filters are not accepted.

Meilisearch returns only tenant/source/revision metadata. The complete bounded page is sent once to the injected `BatchReauthorizer`. The service preserves provider order but returns only exact source ID and revision pairs confirmed by that authoritative batch. Missing sources, unauthorized sources, and sources whose current revision differs from the indexed revision are removed. Provider totals and indexed presentation fields are not returned.

## Projection and replay

`OutboxSearchProjector` implements `rsk_outbox::OutboxPublisher`. Its resolver must reload the authoritative source record rather than treating the outbox payload as document truth. Each target is claimed in `search_projection_events` by UUIDv7 event ID, alias, schema version, and a schema-version/source-scoped PostgreSQL advisory lock. Provider operations use a deterministic tenant/source document ID and complete only after the Meilisearch task is terminal and successful. A crash after provider success is safe: retry repeats the same replace/delete before fenced ledger completion.

Completed target events are idempotent, lower/equal revisions are superseded within that schema version, and active source leases serialize out-of-order delivery. Failure storage contains a bounded class only. Event payloads and document fields are never stored in the search migration.

Outbox redelivery provides event replay. Full repairs and schema changes use `ReindexCoordinator`: register immutable alias/version/digest state, prepare a versioned index, install `OutboxSearchProjector::with_reindex_target` before reading the first source page, load authoritative source pages, persist an opaque `ReindexCursor` after each completed page, mark ready, then activate. Live and backfill mutations share the staging version's source fence, so a stale copied page cannot overwrite a newer live revision. The projector completes each live target independently, allowing retry to repair only the failed target. Retain dual writes through activation, then compose a projector with the newly active schema. A cursor may identify a source-store page or an outbox replay position. The schema sentinel makes activation retry-safe after a process exits between provider swap and PostgreSQL alias commit.

## Index lifecycle

For prefix `service`, alias `records`, and schema version `4`, the adapter owns:

- stable query/write alias: `service__records`;
- versioned staging index: `service__records__v4`;
- schema marker document: `rsk_schema_marker`.

Preparing an existing staging index succeeds only when its marker matches. Activation renames the first staging index or swaps later staging data into the stable alias. A retry observes the requested marker on the stable alias and does not swap back.

## Health and secrets

`search_provider_health_check` is a degraded (not required) readiness dependency. It requires provider health, the expected active schema marker, durable alias state, and a projection/activation timestamp no older than `stale_after`.

Every SDK operation, including asynchronous task polling, runs inside `provider_timeout`. Errors expose stable classifications only. API keys, query text, filter values, captured tenants, and provider diagnostics are redacted from `Debug`/public errors.

## Migration invariants

`2026082318_create_search_projections.sql` enforces:

- immutable `(index_alias, schema_version, schema_digest)` version identity;
- one active schema version per alias;
- bounded restartable cursor/count/generation state;
- UUIDv7 event and lease fences;
- tenant and `(index_alias, schema_version)` target foreign keys, permitting pre-activation backfill;
- immutable event/tenant/alias/schema/source/revision/operation identity;
- coherent pending/processing/completed/superseded states;
- bounded portable failure classes and source identifiers;
- tenant-leading source/revision and lease/freshness indexes;
- no payload, document, or application field-content columns.
