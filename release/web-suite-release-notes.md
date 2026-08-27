# Web application suite 0.1.0

## Added

- Deterministic OpenAPI, AsyncAPI, permission, capability, and aggregate contract artifacts.
- A generated TypeScript SDK with runtime contract checks, RFC 9457 errors, pagination, idempotency, uploads, and typed realtime clients.
- A React/Vite application shell using TanStack Query and Router with contract-backed tests.
- Production Axum static delivery, cache and security policies, a digest-pinned non-root container build, and development proxy topology.
- Actual-Axum Playwright infrastructure, declared Chromium/Firefox/WebKit tiers, accessibility checks, and performance budgets.
- Five composable web generator profiles, lifecycle upgrade rehearsal, and a fail-closed 14-profile release matrix report.
- Release evidence now uses full machine schemas with current-run, revision, specification-manifest, contract-hash, command, and artifact-digest binding. The matrix report includes complete machine-readable AC/REC coverage and distinguishes blocked work from failed evidence.

## Compatibility

- The records pagination schema now correctly declares the runtime `next_cursor` value as nullable on the terminal page. Consumers must handle `string | null`.
- Browser and SDK builds carry the aggregate contract hash and reject incompatible runtime metadata.

## Release gates

Release remains blocked until every required workflow in OMNIUS-032 is exercised against assembled backend capabilities, the manual keyboard/screen-reader review is approved, and the contract compatibility result is resolved through the documented policy. No exception is implied by these notes.

CI no longer uses the fail-open `--matrix-only` policy; CI rejects that diagnostic mode and enforces release readiness. Consequently, known absent actual-workflow and manual-accessibility evidence remains visibly blocking until contemporaneous bound artifacts are supplied.
