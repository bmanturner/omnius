---
spec_id: OMNIUS-INDEX
title: Specification Index
version: 0.1.0
status: informative
last_verified: 2026-08-23
---

# Specification Index


| Document | Subject |
|---|---|
| `00-scope-and-principles.md` | Goals, non-goals, quality attributes, no-reinvention policy |
| `01-system-architecture.md` | Workspace, layers, dependency rules, process topology |
| `02-module-system-and-generator.md` | Module contract, provider slots, profiles, generator ownership |
| `03-core-runtime-and-lifecycle.md` | Bootstrap, supervision, health, graceful shutdown |
| `04-configuration-and-secrets.md` | Typed configuration, validation, secret handling |
| `05-http-api-contract.md` | HTTP conventions, middleware, validation, OpenAPI |
| `06-postgres-persistence.md` | SQLx, pools, migrations, transactions, test databases |
| `07-redis-cache-and-rate-limits.md` | Redis roles, Moka, cache semantics, limiting |
| `08-authentication-and-identity.md` | Sessions, password, JWT, OIDC, API keys, WebAuthn, TOTP |
| `09-authorization-tenancy-and-audit.md` | RBAC/ownership, Cedar, tenant isolation, audit |
| `10-jobs-events-outbox-and-scheduling.md` | Durable work, events, outbox/inbox, schedulers |
| `11-realtime-websockets-and-sse.md` | Long-lived transports, fan-out, backpressure |
| `12-object-storage-email-and-notifications.md` | Blob storage, templates, providers, preferences |
| `13-webhooks-and-outbound-integrations.md` | Svix, inbound verification, outbound clients, SSRF |
| `14-observability-health-and-operations.md` | Logs, traces, metrics, probes, diagnostics |
| `15-security-and-supply-chain.md` | Threat model, dependency controls, SBOM, hardening |
| `16-testing-and-quality.md` | Test layers, containers, fuzzing, load, conformance |
| `17-deployment-and-runtime-topology.md` | Binaries, containers, rollout, backup/recovery |
| `18-optional-product-modules.md` | SaaS, GraphQL/gRPC, search, localization, lifecycle |
| `19-profiles-and-acceptance.md` | Named compositions and profile definition of done |
| `20-implementation-roadmap.md` | Ordered phases and exits |
| `21-crate-selection-matrix.md` | Approved dependencies and rejected defaults |
| `22-recommendation-traceability.md` | Complete coverage of the original design |
| `23-agent-task-graph.md` | Executable task decomposition |
| `24-risk-register.md` | Known risks, triggers, mitigations |
| `adr/*.md` | Binding architecture decisions |
| `machine/*` | Derived catalogs, schemas, profiles, acceptance data |
| `examples/*` | Contract examples |
| `research/*` | Evidence and selection method |

## Validation

`cargo xtask specs verify` MUST:

- Confirm unique `spec_id`, version, status, and verification date.
- Confirm every catalog module appears in a specification.
- Confirm every profile references known modules and satisfies dependencies/conflicts.
- Confirm every referenced acceptance ID exists.
- Confirm every recommendation has a destination and verification method.
- Confirm every source ID exists in `research/sources.md`.
- Reject unresolved placeholder markers in normative files.
