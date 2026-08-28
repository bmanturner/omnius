# Web application suite 0.1.0

## Added

- Deterministic OpenAPI, AsyncAPI, permission, capability, and aggregate contract artifacts.
- A generated TypeScript SDK with runtime contract checks, RFC 9457 errors, pagination, idempotency, uploads, and typed realtime clients.
- A React/Vite application shell using TanStack Query and Router with contract-backed tests.
- Production Axum static delivery, cache and security policies, a digest-pinned non-root container build, and development proxy topology.
- Actual-Axum Playwright infrastructure, declared Chromium/Firefox/WebKit tiers, accessibility checks, and performance budgets.
- Five composable web generator profiles, prior-version lifecycle rehearsal, and separate automated-evidence and fail-closed release-readiness policies for the 14-profile matrix.
- Automated release evidence is produced from retained command results and output artifacts, with schema-v2 current-run, revision, specification-manifest, contract-hash, command, and artifact-digest binding. The matrix report includes complete machine-readable AC/REC coverage and distinguishes blocked work from failed evidence.

## Compatibility

- The records pagination schema now correctly declares the runtime `next_cursor` value as nullable on the terminal page. Consumers must handle `string | null`.
- Browser and SDK builds carry the aggregate contract hash and reject incompatible runtime metadata.

## Release gates

Release remains blocked until every required automated workflow passes and externally supplied manual keyboard/screen-reader evidence is approved with the current binding. No automated mode or exception turns pending manual evidence into release approval.

Ordinary CI uses the explicit `--automated-evidence-only` policy and rejects `--matrix-only`. It may pass while reporting `release_ready: false` only for the exact committed pending manual review; default release enforcement remains nonzero for pending, missing, invalid, or failed manual evidence.
