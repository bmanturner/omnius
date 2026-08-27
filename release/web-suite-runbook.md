# Web suite release runbook

## Preconditions

- Use Node 24.19.0 and pnpm 11.23.0 from the committed pins.
- Start from a clean checkout with the committed lockfiles and contract artifacts.
- Keep production credentials out of Vite variables, browser storage, logs, and build jobs.

## Build and evidence

1. Run `cargo xtask specs verify` and `cargo xtask contracts check`.
2. Run `pnpm install --frozen-lockfile`, both TypeScript compiler lanes, SDK/web tests, and `pnpm web:build`.
3. Run `pnpm web:test:e2e`; retain the Playwright HTML report and failure traces.
4. Set `OMNIUS_RELEASE_RUN_ID` to a unique invocation identifier and `OMNIUS_RELEASE_REVISION` to the exact revision under review. CI derives both from the GitHub run ID, attempt, and SHA.
5. Record the human keyboard and screen-reader review with `pnpm web:check:a11y:manual`. Approval must satisfy `release/web-manual-accessibility-evidence.schema.json` and bind to the same run, revision, `specs/machine/spec-manifest.json` hash, and public contract aggregate hash.
6. Run `cargo xtask profiles generate-verify`; `--matrix-only` is local diagnostic mode and is rejected in CI. Review `target/profile-matrix/report.json` and require both `success: true` and `release_ready: true`.
7. Produce each JSON input under `target/web-release-evidence/` from the workflow that performed the check. Each input must satisfy `release/web-release-evidence.schema.json`, use the expected evidence ID, bind to the current run/revision/spec manifest/contract, list the actual command, and hash every retained artifact.
8. Run the Rust and Node advisory/license policies and the supply-chain workflow that emits current SBOM and provenance artifacts.
9. Review the contract compatibility and risk reports. A breaking, blocked, stale, weakly shaped, or hash-inconsistent result remains non-passing; it is never silently waived.

The generated report maps every `AC-WEB-001` through `AC-WEB-080` and paired `REC-WEB-001` through `REC-WEB-080` to concrete profile or release checks and artifacts. Missing assembled authentication, tenancy, upload, realtime, accessibility, review, risk, or supply-chain workflows remain `blocked`; a catalog gap or invalid/stale evidence is `failed`.

## Deployment preparation

- Build the digest-pinned container and verify its non-root runtime user, `/ready`, deep-link fallback, API 404 behavior, cache headers, CSP, and source-map policy.
- Verify the image contains only the API binary, runtime configuration, and `web/dist` artifacts.
- Compare the deployed contract aggregate hash with the SDK build metadata before promotion.
- Production deployment requires separate, contemporaneous operator approval; this runbook does not authorize it.

## Rollback

- Retain the prior image digest and contract aggregate hash.
- Stop promotion on readiness, contract, CSP, asset-integrity, or browser-gate failure.
- Roll back application and static assets as one image. Do not mix an older API with a newer browser bundle.
- If a database change prevents image rollback, follow the database migration runbook and restore compatibility before serving traffic.

## Incident checks

- Confirm `/ready` and static-asset health independently.
- Check request IDs across browser-visible RFC 9457 errors and server logs.
- Compare runtime and browser contract hashes.
- Inspect CSP, session-cookie, CSRF, tenant-isolation, upload, and realtime failures before relaxing any control.
- Preserve redacted Playwright traces and server logs; never attach tokens, cookies, upload contents, or PII.
