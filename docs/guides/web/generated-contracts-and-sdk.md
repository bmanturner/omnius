---
title: Generated contracts and web SDK
description: Canonical inputs, generated artifacts, transport behavior, capability parsing, and drift boundaries for the web SDK.
status: experimental
implementation: implemented
profile_availability:
  - web-sdk-only
  - web
  - realtime-web
  - saas-web
  - full-reference-web
public_exposure: generated-only
audience:
  - web developers
  - API integrators
  - release reviewers
topics:
  - web-sdk
  - contracts
  - generation
  - transport
capabilities:
  - web-contracts
  - web-sdk-transport
  - web-capabilities
source:
  - packages/web-sdk/package.json
  - packages/web-sdk/scripts/generate-http-client.mjs
  - packages/web-sdk/scripts/generate-contract-metadata.mjs
  - packages/web-sdk/scripts/check-boundaries.mjs
  - packages/web-sdk/src/client/transport.ts
  - packages/web-sdk/src/capabilities/index.ts
evidence:
  - contracts/contract-manifest.json
  - contracts/openapi.json
  - contracts/capabilities.json
  - packages/web-sdk/src/internal/generated/http/core.ts
last_verified: 2026-08-30
---

# Generated contracts and web SDK

The web SDK has two evidence boundaries:

- generated contract artifacts are **generated-only** exposure;
- the framework-neutral transport is an implemented **library-only** surface.

Neither boundary proves that a backend operation is compiled, mounted, or publicly exposed. Use the [contract generation reference](../../reference/contracts-and-code-generation.md) for canonical artifact roles, the [web SDK reference](../../reference/web-sdk.md) for exact entry points, and the [availability matrix](../../reference/availability-and-exposure-matrix.md) for profile status.

## Package boundaries

`@omnius/web-sdk` is a private package with explicit entry points for client, authentication, authorization, realtime, uploads, LLM integration, capabilities, React integration, and test support. Consumers should import the narrow entry point that matches their layer.

The principal split is:

| Boundary | Intended use |
|---|---|
| Framework-neutral entry points | Transport, auth adapters, authorization decisions, capability parsing, realtime, uploads, and other non-React code. |
| `@omnius/web-sdk/react` | Provider, query, mutation, form, tenant-transition, and React-specific helpers. |
| Internal generated modules | Generator-owned implementation detail; do not import directly. |
| Testing entry point | Deterministic fixtures and test helpers; never runtime evidence. |

The entry-point boundary check prevents neutral code from depending on React. Preserve that direction when adding generated operations or helpers.

## Canonical HTTP generation

The HTTP generator reads only `contracts/openapi.json`. It validates the expected OpenAPI version and local-reference/operation-identifier constraints before producing the internal HTTP module. Its determinism check generates output twice, while its check mode byte-compares the expected output to the checked-in generated file.

Contract metadata has a separate generator. It validates the contract hash and version, emits the SDK metadata module, and uses a byte comparison in check mode. This keeps transport identity distinct from endpoint generation.

A generated operation establishes that:

1. a canonical contract described the operation at generation time;
2. the generator accepted that input; and
3. checked-in output exists.

It does not establish that the selected backend profile compiles the owning capability, that a router mounts the operation, or that an environment exposes it. Those claims require runtime and exposure evidence described in [capability and consumer contracts](../../concepts/capability-and-consumer-contracts.md).

## Client configuration

`createServiceClient` accepts an absolute HTTP(S) origin or a root-relative base URL. It also accepts a fetch implementation, credential policy, additional headers, an authentication adapter, retry configuration, and observers. The checked-in web application composes it with a root-relative base and `same-origin` credentials.

Configuration must not embed real credentials. In particular:

- bearer values belong to an in-memory auth adapter, not committed client configuration;
- session cookies remain browser-managed and are not read into application code;
- one-time secrets and API keys must not enter base URLs or default headers;
- observers must redact sensitive headers and response bodies before telemetry.

If base URL or authentication configuration is invalid, the transport reports a configuration-class failure. Correct the integration rather than falling back to an unscoped origin or anonymous request.

## Transport behavior

The transport composes request cancellation and deadlines, guarded retry policy, response parsing, request metadata, and contract identity checks. It recognizes these failure families:

- configuration;
- RFC 9457 problem details;
- network failure;
- abort;
- invalid response;
- contract mismatch.

A response contract hash can be compared with the SDK's generated identity through `X-Omnius-Contract-Hash`. A mismatch is not a routine server error: it means the client and responding service disagree about their contract artifact. Stop the affected workflow and deploy compatible artifacts together.

Retries are deliberately constrained. Safe/idempotent requests may qualify under policy; mutation retries require an operation-specific idempotency guarantee. Observers are isolated so a faulty callback cannot change request semantics. Servers remain authoritative for authorization, validation, conflict detection, and retry timing.

## Authentication adapters

The neutral client supports none, session, bearer, and OIDC redirect-oriented authentication adapters. This catalog is a library surface, not a statement that each mode is enabled by every profile. Adapters do not create backend support or profile availability.

For browser applications, prefer session credentials where the assembled backend and security model select them. A bearer adapter must keep its value outside committed source, persistent browser state, logs, and examples. The checked-in account application uses a dedicated browser session manager described in [authentication and account flows](authentication-and-account-flows.md).

## Capability parsing

The capabilities entry point parses and validates the runtime capability document, including contract/profile identity and compiled/runtime availability. Capability-based UI must use that runtime document instead of inferring support from:

- package exports;
- generated TypeScript types;
- a component in source;
- a profile catalog entry;
- a fixture response;
- a passing unit test.

The checked `contracts/capabilities.json` artifact selects `oauth-provider` and records `web-auth` as neither compiled nor runtime-available. That is the authoritative checked capability state for the artifact, not proof about a differently assembled environment.

## Generation and runtime troubleshooting

| Observation | Interpretation | Failure path |
|---|---|---|
| OpenAPI generation output differs | Canonical input, generator, or checked output changed. | Review the contract change and regenerate coherently; do not hand-edit the internal module. |
| Contract metadata differs | SDK contract identity is stale or inconsistent. | Reconcile canonical contract identity before release. |
| An operation is generated but returns not found | Generation and runtime assembly disagree. | Inspect selected capability, route mounting, and exposure; do not special-case the generated call. |
| Runtime reports a contract mismatch | Client and service contract identities differ. | Stop affected actions and deploy compatible API and web artifacts. |
| A feature has an export but capability is unavailable | Library surface exists without runtime support. | Keep the UI unavailable. |
| Problem response is invalid | Service violated the expected error contract or an intermediary changed it. | Preserve the invalid-response failure and request metadata for diagnosis. |

## Realtime generation gap

Realtime has a distinct unresolved drift boundary. `packages/web-sdk/scripts/generate-realtime.mjs` reads the contract manifest. When the manifest does not select `contracts/asyncapi.json`, the script reports that realtime generation is not selected and exits successfully before it checks the existing generated realtime output.

At the same time:

- `packages/web-sdk/src/internal/generated/realtime.ts` is checked in; and
- the package exports `./realtime`.

Therefore, a successful current realtime generation check cannot prove that the checked-in realtime module matches a canonical AsyncAPI contract. The absence of AsyncAPI must be represented by the manifest, but the remaining generated output and public export still require explicit lifecycle handling. Do not describe realtime drift as verified until the selected contract and checked output are compared coherently. See [realtime and uploads](realtime-and-uploads.md).

## Verification responsibilities

An independent verification should establish, separately:

1. canonical contract validation;
2. deterministic generated HTTP and metadata output;
3. package entry-point boundaries;
4. transport behavior against a controlled service;
5. contract mismatch behavior;
6. runtime capability agreement;
7. route mounting and public exposure;
8. coherent realtime manifest and generated-output handling.

No generation, type check, package test, or runtime request was run for this page. Script and test presence is evidence of intended checks only; it is not a reported result.
