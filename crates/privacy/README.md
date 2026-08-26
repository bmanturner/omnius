# Privacy module

`rsk-privacy` is an optional product module for tenant/subject export, deletion, anonymization,
retention, legal holds, consent evidence, and moderation.

## Lifecycle integration

Construct a `RequiredInventoryManifest` independently from the process adapters, then construct
`InventoryRegistry` with exact coverage of every authoritative PostgreSQL, object-storage, search,
queue, and approved provider member. Missing, unexpected, duplicate, category-mismatched, or
too-old adapters fail startup. `PrivacyStore` snapshots only validated manifest identities,
categories, and minimum contract revisions. Workers call `reconcile_next`; PostgreSQL leases,
monotonic fences, per-adapter reconciliation rows, bounded retries, and audited dead-letter
review/redrive make work restartable.
Completion is fail-closed: every required adapter must return operation-compatible
`AdapterEvidence`. A missing, failed, or timed-out adapter prevents completion. Evidence contains
only a closed effect, an affected-record count, and a SHA-256 digest; authorized completed-export
manifests expose opaque UUIDv7 artifact identities rather than provider URLs or payloads.

Pending, active, and release-pending legal holds pause and fence overlapping deletion,
anonymization, and retention, including live leases. A hold starts blocking before adapter
application and stops only after all release reconciliations succeed.

## Consent and moderation

Consent commands carry document, jurisdiction, and evidence digest facts but cannot choose their
persisted source, evidence format, or withdrawal capability. Injected server-owned grant rules
derive those facts from document version, jurisdiction, actor class, and trusted transport.
Independent current withdrawal-channel rules cannot retroactively revoke the immutable grant's
stored withdrawal permission. Interactive grant and withdrawal effective times come from the
server clock. Legal text and raw evidence stay in governed external systems.

Moderation APIs persist reports, governed evidence references, actions, appeals, decisions, policy
versions, actors, and subjects. Separate reporter, subject, moderator, administrator, and automated
authorization actions receive exact action, policy, reason, and duration facts. Server-owned
automation allowlists fail closed; feature flags are not an authorization boundary. Evidence rows
contain only bounded opaque references and digests.

All state changes append to the canonical PostgreSQL audit sink in the same transaction as the
protected write. Audit persistence must be enabled when constructing `PrivacyStore`.
