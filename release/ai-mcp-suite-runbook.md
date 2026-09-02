# AI/MCP Suite Release Runbook

This runbook governs release of the eight generated AI/MCP profiles. A release is eligible only when the bound evidence document reports `passed` for AC-AI-113 through AC-AI-120 and its revision matches the candidate commit.

## Release evidence

Run the full generated-profile matrix, the AI architecture gate, the merged suite validator, and the generator lifecycle test. Produce `target/ai-mcp-release-evidence/evidence.json` with `scripts/release/ai_mcp_evidence.py`. Retain the evidence document, its four command-result inputs and logs, and `target/profile-matrix/report.json` together. Reject evidence with another revision, run ID, spec-manifest hash, contract aggregate hash, missing artifact, or mismatched artifact digest.

The profile set is exactly: `llm-runtime`, `llm-api`, `llm-agent`, `ai-worker`, `mcp-http`, `mcp-enterprise`, `ai-platform`, and `full-reference-ai`. Generated advanced profiles are fail-closed scaffolds, not runnable product defaults: external endpoints/credentials, providers, authorization policy, handlers, and workers must come from a named application composition. A passed generation/static check does not substitute for required runtime evidence.

## Provider operations

Before enabling provider traffic, confirm the selected model capability record, region, structured-output behavior, tool policy, media limits, timeout, and per-model price revision. Inject credentials only through the configured secret provider; never place provider keys in generated files, logs, cassettes, prompts, or evidence. Probe readiness with a bounded non-user request, then increase traffic gradually while watching provider error class, latency, retry, fallback, token, and cost metrics.

A capability mismatch, authentication failure, safety-policy downgrade, or unpriced model blocks that route. Disable the affected route or provider rather than silently reducing required capabilities. Preserve request, response, model, prompt, usage, and policy identifiers in the audit trail without storing prohibited content.

## Protocol upgrades

Upgrade RMCP, the pinned `2026-07-28` MCP revision, provider SDKs, and extension revisions only after `cargo xtask ai verify` and the protocol compatibility catalog both pass at the candidate revision. Re-run the dedicated reference app's exact metadata, bearer denial, `server/discover`, `tools/list`, `reference_records.list.v1`, unsupported-method, cancellation, and drain cases. Evaluate subscription, task, Apps, Skills, client-credentials, or enterprise behavior only for a concrete product application that actually composes it.

Drain the stateless MCP listener before an incompatible protocol change: stop admission, advertise draining readiness, wait for bounded admitted requests, then terminate remaining work with canonical errors. The reference app owns no MCP session, subscription, or task state.

## Security response

On credential exposure, revoke and rotate the provider or OAuth credential first, disable the affected route, invalidate cached authorization metadata, and inspect audit records for the exposed identity and time range. Never echo secrets or bearer tokens into incident notes.

Treat prompt injection, tool-output injection, resource URI traversal, cross-tenant access, and untrusted schema expansion as security events. Quarantine the input, disable the implicated tool/resource/prompt capability, preserve redacted evidence, and verify authorization plus data-classification boundaries before restoring traffic. MCP OAuth issuer, audience, redirect, client metadata, and delegation checks must fail closed.

## Cost controls

Every billable request requires a reservation before dispatch and reconciliation from authoritative provider usage afterward. Confirm tenant quota, hard budget, price revision, currency, token/media units, and maximum retry cost. Unknown pricing or exhausted budget blocks dispatch; it must not degrade to an unmetered route.

During a spend incident, disable fallback chains first, lower concurrency, stop durable-job admission, and reconcile outstanding reservations. Restore traffic only after ledger lag is bounded, orphaned reservations are settled, and alert thresholds match the approved budget policy.

## Operational response

Readiness reflects the checked-in reference app's required PostgreSQL and OAuth-verification state. Product applications must additionally reflect every provider, persistence, event, subscription, task, and authorization dependency they actually compose. A degraded optional provider may be removed from routing only when the requested capability remains satisfied; otherwise readiness fails. Monitor admitted MCP requests, tool cancellations, provider rate limits, queue/task/subscription signals only where composed, usage reconciliation lag, and audit delivery.

For an incident, stop admission, drain admitted request streams, cancel bounded tool executions, release or reconcile reservations, preserve any product-owned durable state, and capture redacted diagnostics. For the reference MCP app, validate `/live`, `/ready`, the resource-specific metadata URL, MCP discovery, and one bounded `reference_records.list.v1` call with an exact-audience scoped token before resuming admission.

## Rollback

Rollback the application and generated profile as one revision-bound unit. Do not roll back released migrations, durable task history, audit records, usage ledger entries, or subscription cursors. If the prior binary cannot read current durable state, keep admission disabled and roll forward with a compatible fix. After rollback, rerun readiness, protocol discovery, authorization, cancellation, and cost reconciliation checks, then issue new release evidence for the restored revision.

## Release decision

The release owner verifies all eight criteria in the evidence schema, confirms zero archive collisions, and checks that T179 remains the final append-only AI task with completed prerequisites. Automated evidence is necessary but does not authorize production deployment; production operations still require an explicit release decision and contemporaneous approval.
