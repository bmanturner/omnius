---
title: Security model
description: Define Omnius assets, actors, trust boundaries, threats, cross-surface controls, unsafe interpretations, and verification evidence.
status: experimental
implementation: implemented
profile_availability:
  - authenticated-api
  - oauth-provider
  - saas
  - saas-pgmq
  - realtime
  - realtime-durable
  - full-reference
  - ai-worker
public_exposure: library-only
audience:
  - security-analyst
  - architect
  - operator
topics:
  - security
  - threat-model
  - trust-boundaries
capabilities:
  - audit-security-events
source:
  - crates/audit/src/lib.rs
  - crates/http/src/lib.rs
  - crates/auth-core/src/lib.rs
  - crates/authz-basic/src/lib.rs
  - apps/api-server/src/main.rs
evidence:
  - docs/coverage-matrix.md
  - specs/24-risk-register.md
last_verified: 2026-09-03
---

# Security model

Omnius is a modular service kit, not one universal runtime. Security claims attach to a concrete composition. The OAuth-provider reference API assembles password accounts, PostgreSQL browser sessions, API keys/service accounts, basic authorization, tenancy, OAuth/OIDC, HTTP security middleware, and conditional email. Other controls are library-only, generated-only, partial, or unassembled.

Profiles, generated contracts, migrations, tests, and library source do not prove runtime assembly or public exposure. Use [modules, profiles, and composition](../concepts/modules-profiles-and-composition.md) and the [availability and exposure matrix](../reference/availability-and-exposure-matrix.md) before threat modeling a deployment.

## Assets

- customer and tenant data, including identifiers and content;
- credentials, session cookies, API keys, signing keys, peppers, provider tokens, and recovery material;
- authorization policy, membership, tenant context, consent, moderation, and legal-hold state;
- PostgreSQL and any composed cache, object, queue, event, or search state;
- OAuth grants, clients, redirect policy, authorization codes, and tokens;
- LLM prompts, outputs, media, tools, approvals, usage, budgets, and provider correlations;
- MCP tool/resource/prompt registries, task/elicitation/subscription state, and client identity;
- generated contracts, source, dependencies, build provenance, SBOMs, release evidence, and deployed artifacts;
- audit and telemetry evidence used for accountability and incident response.

## Actors

- end users and tenant members;
- tenant owners/administrators;
- service accounts and API-key clients;
- OAuth clients and relying parties;
- operators, database administrators, security reviewers, and release managers;
- browser applications and generated SDK consumers;
- external providers: email, identity, object, webhook, model, cloud, and broker services;
- model output and MCP clients, which are untrusted inputs rather than authorities;
- attackers with network access, stolen credentials, malicious tenant input, compromised dependencies, or insider access.

## Trust boundaries

1. **Public network to HTTP shell.** Unconditional removal of the shell's recognized forwarding headers, reference-side ignoring of external request IDs, CORS, CSRF, body/deadline/concurrency limits, panic containment, sensitive headers, and security response headers are assembled for the reference API. No reference trusted-proxy allowlist or header-repopulation path is assembled.
2. **Authentication to principal.** Each mechanism normalizes an authenticated principal; credentials and session state must not be treated as authorization.
3. **Principal to authorization/tenant context.** Services enforce permission and tenant membership. Frontend guards and capability metadata are presentation/contracts, not authority.
4. **Application to data providers.** PostgreSQL is authoritative in the reference API. Cache/search/realtime copies are not authority and several are unassembled.
5. **Application to external providers.** Protect secrets, constrain destinations, classify payloads, bound retries, and reconcile ambiguous effects.
6. **Model/MCP to effects.** Model text and MCP parameters remain untrusted. Authorization, policy, approval, budgets, schema validation, and audit precede effects.
7. **Source to release.** Dependency review, pinning, provenance, SBOM, signing, promotion, and admission are separate controls; current workflow definitions do not prove passing or deployment.

## Threats and controls

| Threat | Required control | Current evidence boundary |
|---|---|---|
| Credential theft or disclosure | Protected injection, redaction, least privilege, rotation/revocation, no secrets in diagnostics | Secret wrappers/config validation assembled; general secret manager/rotation is deployment-owned |
| Cross-tenant access | Authoritative tenant context and service-layer permission checks | Basic authz/tenancy assembled in OAuth-provider API; optional Cedar unassembled |
| Session/API-key abuse | Secure cookies, hashed keys, bounded lifecycle, uniform failures, audit | PostgreSQL sessions and API keys assembled |
| Request forgery/smuggling | Unconditional removal of recognized forwarding headers at the reference boundary, CORS/CSRF, limits/deadlines, and TLS at the deployment boundary | HTTP shell assembled without a reference proxy allowlist; ingress/TLS and any separately verified client-address trust chain are platform-owned |
| Duplicate external effects | Stable operation/effect identity, idempotency, reconciliation | Assembled for limited reference CRUD; async providers unassembled |
| Sensitive telemetry | Field classification, redaction, bounded labels, access/retention | Utilities and structured signals exist; sink/retention deployment-owned |
| Browser token/content exposure | Same-origin credentials, no browser secret persistence, CSP, safe fragments, atomic assets | Generated/browser source and conditional static delivery; active web capability false |
| Prompt/tool injection | Treat model output as untrusted, authorize and approve tools, constrain data/retention | Libraries implemented; enforcement composition and approval persistence unproven |
| MCP registry or confused-deputy abuse | Auth before discovery/use, tenant filtering, schema limits, transport binding | Libraries implemented; no authenticated server/listener |
| Supply-chain compromise | Review dependencies/actions/materials, SBOM/provenance, signed publication/admission | Workflow/scripts exist; no passing run, signing, or admission proof |

## Unsafe patterns

- infer a route or permission from OpenAPI, a catalog, a fixture, or a profile;
- use frontend role checks or model output as authorization;
- log secrets, cookies, headers, database URLs, prompts, tool arguments, or customer bodies;
- expose diagnostics, metrics, audit queries, MCP discovery, or provider proxies without explicit auth and composition;
- weaken CSRF/CORS/CSP/tenant checks to resolve integration failures;
- treat cache/search/realtime data as authoritative;
- blindly retry ambiguous jobs, webhooks, LLM calls, or tools;
- enable executable MCP skills without a reviewed sandbox (current implementation rejects them);
- treat workflow YAML, a generated SBOM, or retained artifacts as a signed release.

## Verification evidence

A security review should retain the concrete composition root, enabled configuration with secret values redacted, mounted-route evidence, principal/tenant/permission mapping, provider destinations, lifecycle hooks, contract hashes, dependency/SBOM/provenance material, and exercised failure observations. Separate observation from source inspection and specification.

No security test, runtime exercise, or workflow was run while writing this page. The verification status remains `not run` in the [verification plan](../verification-plan.md).

Surface-specific controls:

- [Deployment hardening](deployment-hardening.md)
- [Browser security](browser-security.md)
- [LLM safety and data governance](llm-safety-and-data-governance.md)
- [MCP security](mcp-security.md)
- [Privacy, consent, and moderation](privacy-consent-and-moderation.md)
- [Supply chain](supply-chain.md)