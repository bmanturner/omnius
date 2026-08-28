# Web suite release runbook

## Preconditions

- Use Node 24.19.0 and pnpm 11.23.0 from the committed pins.
- Start from a clean checkout with the committed lockfiles and contract artifacts.
- Keep production credentials out of Vite variables, browser storage, logs, and build jobs.
- When direct object-storage transfer is enabled, add the exact HTTPS storage origin to the static `connect-src` policy; otherwise select the authenticated proxied transfer path. Never broaden this to a wildcard.
- The managed Playwright fixture requires Docker and exercises PostgreSQL, filesystem-backed quarantine storage, and a digest-pinned ClamAV daemon through the live Axum process.

## Build and evidence

1. Run `cargo xtask specs verify` and `cargo xtask contracts check`.
2. Run `pnpm install --frozen-lockfile`, both TypeScript compiler lanes, SDK/web tests, and `pnpm web:build`.
3. Run `pnpm web:test:e2e` and `pnpm --dir web test:e2e:base-path`; retain both bound command logs, both Playwright HTML reports, and failure traces.
4. Set `OMNIUS_RELEASE_RUN_ID` to a unique invocation identifier and `OMNIUS_RELEASE_REVISION` to the exact revision under review. CI derives both from the GitHub run ID, attempt, and SHA.
5. Record the human keyboard and screen-reader review with `pnpm web:check:a11y:manual`. Approval must satisfy `release/web-manual-accessibility-evidence.schema.json` and bind to the same run, revision, `specs/machine/spec-manifest.json` hash, and public contract aggregate hash.
6. Use `scripts/release/web_evidence.py run` to execute each automated gate and retain its bound command result. Transfer those records and their hashed artifacts into the matrix job, then use `web_evidence.py produce` to create the schema-v2 documents under `target/web-release-evidence/`.
7. Ordinary CI runs `cargo xtask profiles generate-verify --automated-evidence-only`. This mode requires every automated document and accepts only the exact committed pending manual-review record; it reports `release_ready: false` until external manual evidence is approved. `--matrix-only` remains local diagnostic mode and is rejected in CI.
8. Release enforcement runs `cargo xtask profiles generate-verify` without a policy flag. Require `success: true`, `release_ready: true`, and `release.ready: true`; missing, pending, stale, failed, weakly shaped, or hash-inconsistent evidence remains non-passing.
9. Run the Rust and Node advisory/license policies, contract diff, prior-version lifecycle rehearsal, semantic boundary suite, risk catalog validation, full Playwright browser/accessibility/security/performance gates, the dedicated nested-public-base browser gate, and verified SBOM/provenance bundle producers. Evidence must name the actual command and hash its retained command result and output artifacts.

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
