---
spec_id: RSK-AI-SUITE-COMPLETE
title: "Complete LLM and MCP Feature Suite"
version: 0.1.0
status: reference
last_verified: 2026-08-24
---

# Complete LLM and MCP Feature Suite

This document concatenates the LLM/MCP extension specifications, ADRs, handoff, integration instructions, and research summaries. Machine-readable files remain authoritative for IDs and graph validation.


---

---
spec_id: RSK-035
title: LLM and MCP Feature-Suite Architecture
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# LLM and MCP Feature-Suite Architecture

## 1. Purpose

This specification adds external large-language-model execution and a standards-conformant MCP server to the Rust Service Kit as append-only capabilities. The suite MUST compose with the existing runtime, HTTP, identity, authorization, tenancy, audit, jobs, events, storage, observability, web SDK, generator, and testing contracts. It MUST NOT create a parallel application architecture.

## 2. Architectural boundary

The suite introduces a framework-owned `agent-capability-registry`. A capability is an application operation or read model with stable identity, schemas, authorization metadata, side-effect classification, idempotency requirements, tenancy rules, and adapters. The same capability MAY be exposed through:

- ordinary Rust application services;
- HTTP endpoints;
- durable jobs;
- LLM tool execution;
- MCP tools, resources, or prompts;
- browser SDK utilities.

Business logic MUST remain behind the registry adapter. MCP handlers and LLM-provider handlers MUST NOT directly query product tables or reproduce authorization rules.

## 3. Composition model

The suite is source-composed through workspace crates and generated module manifests. Runtime toggles MAY disable already-compiled providers or exposures, but runtime toggles MUST NOT be used as a substitute for compile-time module selection. Every module participates in typed configuration, startup, health, telemetry, shutdown, testing, documentation, and removal behavior.

Provider SDK types, MCP SDK types, and provider wire objects MUST terminate at adapter boundaries. Public application contracts use service-kit-owned, versioned types.

## 4. Trust boundaries

The following inputs are untrusted:

- prompts, documents, images, audio, and files supplied by users;
- model output, including tool arguments and structured output;
- MCP client metadata, capabilities, tool parameters, and extension declarations;
- tool descriptions or annotations received from outside the service;
- provider error bodies and provider-specific metadata;
- resource URIs, webhook-like URLs, and remote references.

Every operation MUST retain the canonical request context: request ID, trace context, principal, tenant, authorization decision, data-classification policy, budget, deadline, and cancellation token.

## 5. Standards baseline

MCP implementation targets protocol revision `2026-07-28` and uses the official Rust SDK. New profiles MUST be stateless, discovery-first, and extension-aware. They MUST NOT adopt deprecated Roots, Sampling, Logging, HTTP+SSE, protocol sessions, or initialization semantics. Direct LLM provider APIs replace deprecated MCP Sampling.

Compatibility with older clients MAY be enabled through the official SDK's explicit compatibility modes, but compatibility MUST be tested, observable, and disabled from shaping the new internal architecture.

## 6. LLM output completeness

The LLM boundary MUST represent ordered plaintext, structured JSON, tool calls, tool results, citations, annotations, refusals and safety outcomes, images, audio, video, files, provider resources, provider-executed steps, safe reasoning summaries or opaque reasoning state, alternative candidates, token/log-probability metadata, usage, finish information, provider identifiers, and unknown future content without silent loss. Raw provider payload retention is policy-controlled and never the only source of normalized behavior.

## 7. Explicit non-goals

The suite does not define a general autonomous-agent product, a vector database, a RAG opinion, a model marketplace, a hidden-chain-of-thought store, an MCP client, or a replacement identity provider. Those require separate suites or product decisions.

## 8. Implementation invariant

Adding this suite MUST NOT restart completed base or web work. New tasks depend on existing prerequisites. A deficiency in an accepted subsystem requires a narrowly scoped amendment ADR and task; it does not authorize silent redesign.

## 9. Acceptance linkage

This specification is verified by `AC-AI-001` through `AC-AI-008`.


---

---
spec_id: RSK-036
title: LLM Domain Contracts and Complete Content Model
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# LLM Domain Contracts and Complete Content Model

## 1. Canonical request

`LlmRequest` MUST be provider-neutral and versioned. It includes a stable request ID, route/model requirements, ordered messages, generation controls, desired output mode, tool declarations, response schema reference, metadata, deadline, cancellation, tenant/principal context, and data-handling policy.

Messages MUST support system, developer, user, assistant, and tool roles. Input parts MUST support text, images, audio, files, resource references, structured values, and prior tool results. Large binary payloads SHOULD use the object-storage abstraction rather than duplicated base64 values.

## 2. Canonical response

`LlmResponse` MUST retain stable response identity, provider/model identity, ordered output parts, stop/termination information, usage, latency, warnings, provider request IDs, and policy-controlled provider metadata. Output parts are discriminated and non-exhaustive at the serialization boundary.

Required normalized variants are:

| Variant | Required semantics |
|---|---|
| `text` | Ordered plaintext or markdown fragments with optional annotations |
| `structured` | Any JSON value, schema identity, validation result, and repair history |
| `tool_call` | Stable call ID, capability/tool name, complete JSON arguments, provenance |
| `tool_result` | Stable call ID, success/error classification, ordered result content |
| `citation` | Source identity, location/offset metadata, and association to output |
| `refusal` | Provider or policy refusal with safe category and message |
| `image` | MIME type plus bytes, URL, or object reference and dimensions when known |
| `audio` | MIME/codec plus bytes, URL, or object reference and timing when known |
| `video` | MIME/codec plus bytes, URL, object reference, duration, and dimensions when known |
| `file` | Filename, MIME type, bytes/URL/object reference, checksum when available |
| `resource` | Provider- or application-hosted resource identity, URI/object reference, media type, and lifecycle metadata |
| `annotation` | Typed grounding, citation, safety, token-score/log-probability, URL/file-path, or provider annotation associated with a part |
| `execution_step` | Provider-executed search, code, computer-use, shell, file-search, image-generation, MCP, or future built-in operation with inputs, outputs, status, and provenance |
| `safety` | Provider or application safety/guardrail classification, blocked category, scores, and disposition |
| `reasoning` | Provider-sanctioned summary, signature, or opaque encrypted state only |
| `unknown` | Namespaced provider kind and losslessly retained policy-approved payload |

A response MAY contain several different part types and more than one candidate/choice. The selected `output` remains convenient for common callers, while every provider-returned alternative MUST be retained in ordered `candidates` when available. Text MUST NOT be assumed to be the only final answer.

## 3. Specialized model-operation responses

Completion/chat generation is not the only provider operation. The public model boundary MUST also define normalized, versioned responses for:

| Operation | Required retained output |
|---|---|
| `embeddings` | One result per input with stable input identity/index; dense, sparse, binary/quantized, or multi-vector representation; dimensions; usage; and provider metadata |
| `rerank` | Original document identity/index, deterministic rank, relevance score, optional returned document/explanation metadata, usage, and provider metadata |
| `transcription` | Full text, detected language, duration, timestamped segments and words, channels/speakers where supplied, confidence, and provider metadata |
| `speech` | Generated audio reference/bytes, MIME and codec, voice, duration/sample rate/channels, timing marks or visemes, subtitles/transcript where supplied, and provider metadata |
| `media_generation` | Every generated image/audio/video/file/resource candidate, generation and asset IDs, revised prompt, seed, parameters, provenance, safety outcomes, and usage |
| `classification` | Per-input labels/categories, scores, dispositions, explanation metadata when available, and provider metadata; moderation is represented as a policy-specialized classification |

Specialized responses MUST preserve provider request/response IDs, warnings, status, usage, cost, and unknown namespaced metadata under the same governance rules as `LlmResponse`. Batch and durable forms wrap these contracts in the existing job/task abstractions rather than inventing incompatible result types.

`model-response.schema.json` is the machine-readable union of completion and specialized response families. Adapters MUST NOT coerce embeddings, rerank results, transcripts, generated audio/media, or moderation/classification results into plaintext merely to fit a chat-completion abstraction.

## 4. Reasoning privacy

The kit MUST NOT request, synthesize, expose, or persist hidden private chain-of-thought. It MAY retain provider-supported reasoning summaries, signatures, and encrypted continuation blocks where required to preserve a provider conversation. These values MUST be separately classified, redacted from ordinary logs, and never presented as verified factual explanations.

## 5. Usage and identities

Usage MUST distinguish input, output, cache reads, cache writes, reasoning, audio, image, video, tool/execution, and provider-specific billable units when supplied. Unknown counters remain namespaced metadata. Native response IDs and transport request IDs MUST be retained because retries, provider support, audits, and cost reconciliation require both.

## 6. Serialization compatibility

Canonical contracts MUST use explicit schema versions and stable discriminators. Readers MUST ignore unknown optional fields and preserve unknown output variants where policy permits. Writers MUST produce deterministic ordering for stable fields and parts.

## 7. Validation and size limits

Every content part has explicit byte, item-count, and nesting limits. URLs and object references pass centralized outbound and storage policy. MIME types are validated independently of filenames. Unknown provider payloads are bounded before parsing or persistence.

## 8. Acceptance linkage

This specification is verified by `AC-AI-009` through `AC-AI-016`.


---

---
spec_id: RSK-037
title: LLM Provider Adapters and Model Capability Registry
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# LLM Provider Adapters and Model Capability Registry

## 1. Default provider framework

The default provider abstraction is Rig, pinned and audited as specified in the extension dependency baseline. Rig is an implementation detail behind `LlmProvider`, `EmbeddingProvider`, and media-provider ports. Service-kit callers MUST NOT import Rig response, message, agent, or streaming types outside adapter crates.

The initial built-in provider family includes Rig-supported direct APIs and OpenAI-compatible endpoints. AWS Bedrock and Google Vertex AI are optional companion adapters because their credentials, endpoints, model catalogs, and dependency graphs differ materially.

## 2. Provider contract

Every provider adapter MUST implement:

- request conversion and unsupported-feature detection;
- non-streaming and streaming execution where supported;
- normalized identities, stop reasons, usage, warnings, and content parts;
- typed provider, transport, timeout, throttling, safety, and schema errors;
- explicit retry classification and retry-after extraction;
- capability discovery or configured capability declarations;
- redacted diagnostics and health evidence;
- deterministic cassette fixtures from representative provider responses.

Adapters MUST retain policy-approved raw terminal responses and unmodeled stream items so new provider behavior is detectable rather than discarded.

Completion, embeddings, reranking, transcription, speech generation, image/media generation, and classification/moderation adapters MAY share provider clients, transport policy, and telemetry, but each operation MUST implement its operation-specific request/response port and compatibility fixtures. A generic completion method MUST NOT be used as a lossy substitute for a provider's dedicated operation API.

## 3. Capability registry

Capabilities are associated with provider/model revisions, not inferred from marketing names. The registry distinguishes at least:

- text, image, audio, video, file, and resource input;
- text, structured, image, audio, video, file, resource, annotation, and execution-step output;
- strict JSON Schema support;
- tools and parallel tool calls;
- streaming and resumable provider conversations;
- citations, grounding annotations, token scores/log probabilities, safety metadata, search results, and provider-executed steps;
- reasoning summaries or opaque state;
- embeddings, reranking, transcription, speech, image generation, and video generation;
- prompt caching and cache controls;
- context/output limits and regional availability.

A route MUST state required and preferred capabilities. Selection MUST fail with an actionable error when requirements cannot be satisfied.

## 4. No silent downgrade

The system MUST NOT silently replace strict structured output with prompt-only JSON, drop media, remove citations, disable tools, weaken data residency, or route to a different provider. Any allowed fallback is an explicit route policy with compatibility tests and observable reason codes.

## 5. Credentials and endpoints

Provider secrets use the existing secret-wrapper and configuration system. Endpoint overrides are allowlisted and pass the outbound HTTP/SSRF policy. Tenant-supplied credentials require separate encryption, access control, rotation, audit, and deletion policies; they are not enabled merely by accepting arbitrary configuration strings.

## 6. Upgrade policy

Provider SDK upgrades are treated as contract work. CI MUST diff normalized cassettes, feature support, dependency advisories, raw response handling, and request conversion. Model IDs are runtime configuration or provider discovery data, not hard-coded global enums.

## 7. Acceptance linkage

This specification is verified by `AC-AI-017` through `AC-AI-024`.


---

---
spec_id: RSK-038
title: Structured Output, Tool Execution, and Streaming
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Structured Output, Tool Execution, and Streaming

## 1. Structured output

The canonical schema dialect is JSON Schema Draft 2020-12. Rust-owned output types SHOULD derive schemas with Schemars; arbitrary approved schemas MAY be supplied as JSON. Schemas MUST be locally compiled and validated with bounded reference resolution before being sent to a provider.

Output strategies, in preference order, are:

1. provider-native strict structured output;
2. provider-native strict tool/function output;
3. explicitly configured constrained fallback;
4. prompt-only JSON only when a route knowingly permits weaker guarantees.

A response is successful only after local validation. Repair retries are bounded, separately metered, preserve the original invalid output for controlled diagnostics, and MUST NOT execute tools while repairing data.

## 2. Tool runtime

Tool definitions derive from the shared capability registry. The runtime validates arguments, authenticates the principal, authorizes the exact capability/resource/action, applies tenant scope, enforces confirmation policy, derives or verifies idempotency keys, imposes deadlines and output limits, and records an audit event.

Tool annotations and model-supplied arguments are untrusted. Side-effecting tools MUST require explicit policy approval; high-impact tools SHOULD support a human-confirmation state. The runtime MUST prevent recursive or duplicate invocation from bypassing controls.

Agent loops have explicit budgets for model turns, tool calls, wall-clock time, tokens, cost, and concurrent work. A zero or exhausted budget terminates deterministically.

## 3. Streaming model

`LlmStreamEvent` is an ordered, sequence-numbered event algebra. It includes response start, part start, text delta, structured-data delta or buffered completion, tool-call delta, safe reasoning-summary delta, media reference/delta, citation, usage update, warning, part completion, response completion, cancellation, and failure.

Partial tool arguments or structured JSON MUST NOT be exposed as complete data. Consumers either use a provider-specific incremental parser behind the adapter or wait for a validated complete value.

## 4. Backpressure and cancellation

Streaming uses bounded channels. Slow consumers trigger configured coalescing, backpressure, cancellation, or disconnect behavior; memory growth is never unbounded. Client cancellation propagates through the service, provider request, tool loop, jobs, and media upload. Disconnect is not automatically treated as cancellation when a durable job owns the request.

## 5. Error semantics

Protocol/transport failure, provider refusal, safety refusal, invalid structured data, tool execution error, budget exhaustion, cancellation, and partial-stream interruption are distinct terminal states. A provider stream that fails after content has been delivered MUST retain partial output and an incomplete status.

## 6. Acceptance linkage

This specification is verified by `AC-AI-025` through `AC-AI-032`.


---

---
spec_id: RSK-039
title: LLM Routing, Reliability, Cost, and Quotas
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# LLM Routing, Reliability, Cost, and Quotas

## 1. Route definition

A model route is versioned configuration containing allowed providers/models, required and preferred capabilities, data residency, maximum data classification, latency target, retry/fallback policy, context/output limits, budget, and observability name. Application code requests a route, not a provider-specific model constant.

## 2. Selection

Selection first filters on hard requirements. It MAY then rank by explicit policy such as quality tier, latency, cost, provider health, regional availability, or tenant entitlement. The chosen provider/model and every rejected candidate reason are observable without exposing secrets.

## 3. Reliability

The kit defines separate connect, first-byte, idle-stream, total, and tool-turn deadlines. Retries apply only to classified transient failures and respect idempotency, retry-after, total deadline, and budget. Jittered exponential backoff is the default. A stream is never transparently retried after externally visible output unless the consumer requested a restartable durable operation.

Hedging is disabled by default because it multiplies cost and can duplicate side effects. It MAY be enabled only for non-tool, idempotent requests with explicit cancellation and billing policy.

## 4. Fallback

Fallback requires declared semantic compatibility. It MUST NOT weaken strict schema guarantees, tool availability, data boundaries, safety configuration, context requirements, or output modalities. Fallback reason and route revision are recorded. The caller MAY prohibit fallback.

## 5. Quotas and budgets

Limits may be applied by principal, tenant, API key, route, provider, model, and operation. They include requests, concurrent streams, tokens/units, tool calls, media bytes, and estimated/actual cost. Reservation occurs before dispatch and reconciliation occurs after provider usage is known. Ambiguous usage is retained rather than silently treated as zero.

## 6. Provider health

Circuit state is based on bounded rolling evidence and distinguishes provider-wide, endpoint, region, and model failures. Health status affects routing but does not expose credential or tenant-specific failures globally. Readiness depends on whether required routes retain at least one usable candidate.

## 7. Acceptance linkage

This specification is verified by `AC-AI-033` through `AC-AI-040`.


---

---
spec_id: RSK-040
title: Prompts, Context, Caching, and Data Governance
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Prompts, Context, Caching, and Data Governance

## 1. Prompt catalog

Reusable prompts are versioned artifacts with stable IDs, owners, input schemas, allowed routes, tool sets, data-classification limits, evaluation sets, rollout metadata, and deprecation state. Published prompt revisions are immutable. Draft editing and production publication are separate permissions.

Prompt templates use the established safe template engine rather than ad hoc string replacement. Variables are typed and size-limited. System/developer instructions are stored separately from untrusted user or retrieved content.

## 2. Context assembly

Context assembly is deterministic and records provenance. It applies tenant and authorization filters before retrieval, enforces content and token budgets, and uses explicit ordering and truncation strategies. Documents, tool output, web content, and model output are marked as untrusted data and MUST NOT be concatenated into privileged instruction channels.

The suite intentionally does not select a vector database or RAG framework. Retrieval ports MAY be implemented later, but they must return authorized, provenance-bearing context records.

## 3. Prompt caching

Provider prompt-cache behavior is represented as a capability and route policy. Cache breakpoints, TTLs, and provider-specific controls remain adapter metadata. Cache keys MUST include all security- and semantics-relevant inputs and MUST NOT allow cross-tenant or cross-principal reuse of private content.

Application caches store normalized, policy-approved values and include route, model revision, prompt revision, tool/schema revisions, tenant scope, and data classification. Sensitive responses are not cached merely because a provider supports caching.

## 4. Data governance

Every request has a data-handling policy covering provider allowlist, region, training/retention restrictions, storage, raw payload retention, logging, and deletion. Prompts, responses, tool arguments, citations, files, and opaque reasoning state receive independent classifications.

Default telemetry excludes prompt and response content. Diagnostic capture is time-bounded, access-controlled, sampled, encrypted, audited, and redacted. User deletion and tenant retention operations propagate to conversations, usage metadata where legally permitted, media objects, caches, eval artifacts, and provider-side deletion APIs when available.

## 5. Prompt-injection defenses

Prompt injection is treated as a confused-deputy and data-flow problem, not solved by a single classifier. The design combines least-privilege tools, provenance, instruction/data separation, output encoding, human confirmation, egress policy, authorization at execution time, and adversarial tests.

## 6. Acceptance linkage

This specification is verified by `AC-AI-041` through `AC-AI-048`.


---

---
spec_id: RSK-041
title: LLM HTTP, Jobs, Web SDK, and Observability
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# LLM HTTP, Jobs, Web SDK, and Observability

## 1. HTTP surface

The `llm-http-api` module contributes OpenAPI-described endpoints for model-route discovery, synchronous and streaming generation responses, embeddings, reranking, transcription, speech synthesis, media generation, classification/moderation, durable operation jobs, job status/cancellation, and approved conversation operations. Endpoint names are product-neutral and versioned. Provider keys, raw payloads, and unrestricted model IDs are never accepted as ordinary public parameters.

Synchronous, streaming, and durable generation modes consume the same canonical request and produce the same canonical output algebra. Dedicated model operations return the corresponding member of `model-response.schema.json`. Transport-specific wrappers MUST NOT create incompatible response types, and asynchronous wrappers MUST retain the original operation response unchanged as the completed job result.

## 2. Durable execution

Long-running or disconnect-resilient generation uses the existing jobs, outbox, inbox, idempotency, and object-storage modules. Job payloads reference versioned prompt/route/schema/tool definitions. Retries preserve idempotency and budget reservations. Partial outputs are marked incomplete and never presented as completed structured results.

## 3. Browser integration

The optional `web-llm` module extends the generated web SDK with typed utilities and React integrations for response creation, streaming, cancellation, durable jobs, embeddings, reranking, transcription, speech/media generation, classification results, conversation state, structured data, tool-approval states, citations, media, and usage visibility. TanStack Query owns server state; streaming updates are reconciled into canonical query keys.

The web layer MUST render unknown output parts safely, distinguish refusal/error/cancellation, and avoid interpreting model HTML or markdown as trusted code. It MUST expose request IDs for support without exposing secrets or provider credentials.

## 4. Media handling

Large image, audio, and file inputs/outputs use object-storage references with authorization, expiration, checksum, MIME validation, quarantine/scanning hooks, and lifecycle cleanup. Inline content has strict limits. Generated media is not assumed safe merely because it came from a provider.

## 5. Observability

Telemetry follows OpenTelemetry generative-AI semantic conventions where stable and uses service-kit namespaced attributes for gaps. It records route, provider, model, operation, latency phases, usage, cost, finish state, retry/fallback, tool names, task IDs, and error classification. High-cardinality IDs are restricted to traces/logs and not metric labels.

Prompts, responses, tool arguments, files, authorization headers, and opaque reasoning state are excluded by default. Audit and usage ledgers are separate from debug logs.

## 6. Acceptance linkage

This specification is verified by `AC-AI-049` through `AC-AI-056`.


---

---
spec_id: RSK-042
title: MCP Server Architecture and Capability Exposure
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# MCP Server Architecture and Capability Exposure

## 1. Protocol adapter

The MCP server is a transport and protocol adapter over the shared agent-capability registry. It MUST NOT become a second domain/service layer. MCP tools, resources, and prompts are explicit projections of registered capabilities and retain their schemas, side-effect classification, authorization, tenant scope, idempotency, audit, and lifecycle behavior.

## 2. Current baseline

The baseline is MCP revision `2026-07-28` implemented with the official Rust SDK (`rmcp`). Requests are stateless and self-contained. Capability/version metadata and identity are evaluated per request. The server implements mandatory discovery and supports optional extensions only after explicit negotiation.

## 3. Exposure declarations

Every MCP-facing capability has a machine-readable declaration containing:

- stable MCP name and kind;
- internal capability ID and version;
- description and annotations;
- input/output or resource schemas;
- required permissions, tenant modes, and principal types;
- side-effect and confirmation policy;
- cache scope/TTL and list-change behavior;
- transport availability;
- required MCP/client extensions;
- deprecation and compatibility state.

Capabilities are deny-by-default. Merely compiling a module MUST NOT automatically expose it over MCP.

## 4. Request context

Each request constructs a canonical principal and request context from the transport/auth layer. The MCP client identity, workload identity, user delegation, tenant, scopes, protocol version, client capabilities, extension set, request ID, trace context, deadline, and log-level request are retained. Client-supplied metadata is untrusted until validated.

## 5. Deprecated features

New profiles MUST NOT implement deprecated MCP Roots, Sampling, Logging, or HTTP+SSE. The LLM suite calls providers directly rather than through Sampling. Files and directories are passed as tool parameters, resource URIs, or typed server configuration. Logs use stderr for stdio and OpenTelemetry for services.

## 6. Error boundary

Application errors are mapped deliberately to protocol errors, tool-level errors, structured results, or input-required results. Internal error details and authorization distinctions are not leaked. Unknown MCP methods and unsupported versions follow specification error codes.

## 7. Acceptance linkage

This specification is verified by `AC-AI-057` through `AC-AI-064`.


---

---
spec_id: RSK-043
title: MCP Versioning, Discovery, Caching, and Transports
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# MCP Versioning, Discovery, Caching, and Transports

## 1. Discovery-first lifecycle

The server MUST implement `server/discover` and advertise supported protocol versions, server identity, core capabilities, and supported extensions. The preferred lifecycle is discovery-first. The legacy initialization lifecycle MAY be accepted only through an explicit compatibility policy in the official SDK and MUST NOT be required by internal state.

Every request validates `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities`. Clients SHOULD identify themselves per request; server results include server identity metadata. Unsupported versions and header/body mismatches produce the specified errors.

## 2. Deterministic and cacheable discovery

Tool, resource, template, and prompt lists are deterministically ordered. Cacheable results provide `ttlMs` and `cacheScope`; private results are never shared across principals or tenants. Catalog hashes and list-change events are derived from the same registry revision.

## 3. Streamable HTTP

Remote MCP uses stateless Streamable HTTP POST handling integrated with Axum/Tower. It enforces standard `Mcp-Method` and `Mcp-Name` headers, body/header limits, content types, origin policy, authentication, request deadlines, bounded response streams, graceful drain, and trace propagation.

There is no `Mcp-Session-Id`, HTTP GET event endpoint, or resumable SSE event ID. If an in-flight response stream breaks, the client must issue a new request with a new JSON-RPC request ID; server idempotency is supplied by explicit operation handles or arguments.

## 4. Stdio

Local transport uses stdin/stdout strictly for protocol framing and stderr for diagnostics. It honors cancellation and process shutdown, bounds message sizes, closes cleanly on EOF, and never emits logs or banners on stdout. Credentials are delivered through process environment or platform credential mechanisms rather than the HTTP OAuth flow.

## 5. Subscriptions

`subscriptions/listen` is a long-lived POST-response stream distinct from request-scoped progress/message notifications. The JSON-RPC request ID of `subscriptions/listen` is the subscription ID. The first server message carrying that ID MUST be `notifications/subscriptions/acknowledged`; every later notification and graceful-close response MUST carry the same value in `_meta["io.modelcontextprotocol/subscriptionId"]`. The server authorizes requested event classes, acknowledges only the supported subset, bounds queues, and tears subscriptions down on cancellation or disconnect.

## 6. Transport abstraction

Protocol dispatch is independent of HTTP and stdio framing. This prepares the kit for the roadmap direction of Streamable HTTP over stdio/HTTP2 without inventing a non-standard transport today.

## 7. Acceptance linkage

This specification is verified by `AC-AI-065` through `AC-AI-072`.


---

---
spec_id: RSK-044
title: MCP Tools, Resources, Prompts, and Result Contracts
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# MCP Tools, Resources, Prompts, and Result Contracts

## 1. Tools

MCP tool schemas use JSON Schema Draft 2020-12 and may describe any JSON type. Tool names are stable public identifiers and results are deterministic with respect to an explicit capability revision. Input is validated before authorization-sensitive execution; authorization is checked again against the resolved resource and tenant.

A canonical tool result is produced internally and then adapted to the current MCP representation. This seam is mandatory because the roadmap identifies tool-result ambiguity as a target for redesign. A tool MUST NOT independently emit conflicting textual and structured versions of the same output without an explicit compatibility policy.

`structuredContent` may contain any JSON value. Ordered content blocks may include text, image, audio, and embedded resources. Tool-level failures are distinguished from protocol routing/validation failures.

## 2. Resources

Resources expose authorized context through stable URIs and resource templates. Reads support text or binary content, MIME type, provenance, cache metadata, and bounds. URI parsing and resolution are centralized; path traversal, scheme confusion, SSRF, cross-tenant access, and oversized content are rejected.

The internal resource port anticipates byte ranges, hierarchical listing, checksums, and object-storage references, but the server exposes only standardized behavior available in the negotiated protocol revision.

## 3. Prompts

MCP prompts are projections of published prompt-catalog revisions. Arguments are typed, validated, authorized, and size-limited. Prompt lists and prompt results are deterministic and cacheable. Untrusted user data is kept separate from privileged instructions in returned messages.

## 4. Naming and versioning

Public names use a stable namespace and are never generated from Rust function paths. Breaking schema or semantic changes require a new version/name or a documented compatibility window. Descriptions and annotations are treated as public API and reviewed for accuracy and safety.

## 5. Results and MRTR

All current-protocol results include `resultType`. Ordinary results are `complete`; additional-input flows use `input_required`. Earlier-protocol results that omit the discriminator are accepted only within compatibility behavior and interpreted as complete as required by the protocol.

## 6. Acceptance linkage

This specification is verified by `AC-AI-073` through `AC-AI-080`.


---

---
spec_id: RSK-045
title: MCP Authentication, Authorization, Tenancy, and Security
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# MCP Authentication, Authorization, Tenancy, and Security

## 1. Core authorization profile

Remote HTTP authorization follows the current MCP authorization specification and existing standards rather than a custom token format. The server acts as a protected resource and uses protected-resource metadata, authorization-server metadata, resource indicators, bearer-token validation, issuer validation, and appropriate OAuth/OIDC discovery.

Client ID Metadata Documents are the preferred client-registration path. Dynamic Client Registration is compatibility-only. Credentials and registrations are keyed by issuer and MUST NOT be reused across authorization servers.

## 2. Principal construction

Validated token, workload, client, and delegation claims map into the canonical `Principal`. The context distinguishes interactive user, service account, workload/agent, delegated-on-behalf-of identity, and anonymous local process where explicitly permitted. The MCP client application is not conflated with the end user.

Every list, read, prompt, and tool call is authorized. Catalog discovery MUST NOT leak the existence of tenant-private capabilities. List caching keys include principal/tenant and authorization revision when private.

## 3. Non-interactive and enterprise extensions

OAuth Client Credentials and Enterprise-Managed Authorization are optional modules negotiated as extensions. Client credentials remain issuer-bound and scoped to the MCP resource. Enterprise flow validates ID-JAG issuer, audience, signature, subject, expiry, resource, and delegation claims and maps them through ordinary authorization policies.

The identity layer provides extension points for DPoP, workload identity federation, and RFC 8693 token exchange as the MCP roadmap matures. These mechanisms MUST NOT be simulated with pasted long-lived API keys.

## 4. Transport security

The HTTP module enforces TLS deployment assumptions, origin checks where applicable, CORS denial by default, trusted proxy rules, header allowlists, duplicate-header handling, and centralized SSRF/egress policy. `x-mcp-header` parameters are allowlisted by capability and cannot set authorization, host, hop-by-hop, proxy, or tracing-control headers unless explicitly safe.

## 5. Consent and audit

Side-effecting and sensitive tools expose clear descriptions, required permissions, confirmation state, and consequence metadata. User or policy consent is recorded with capability revision and arguments summary. Audit records include client identity, principal, tenant, action, decision, result, request ID, trace ID, and extension use without recording raw secrets or sensitive payloads.

## 6. Acceptance linkage

This specification is verified by `AC-AI-081` through `AC-AI-088`.


---

---
spec_id: RSK-046
title: MCP MRTR, Elicitation, Tasks, Subscriptions, and Progress
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# MCP MRTR, Elicitation, Tasks, Subscriptions, and Progress

## 1. Multi Round-Trip Requests

Server-initiated requests are modeled with the current Multi Round-Trip Requests pattern. When additional input is required, the server returns `InputRequiredResult` with stable `requestState` and typed `inputRequests`. The client retries the original request with `inputResponses`; the server validates that state, principal, tenant, capability revision, and prior arguments still match.

State is an explicit signed/encrypted or server-minted bounded handle, never an implicit protocol session. It has expiry, replay policy, maximum rounds, and audit history.

## 2. Elicitation

Elicitation schemas are narrowly scoped to required data. Sensitive fields are identified and MAY require out-of-band URL mode or stronger confirmation. The server MUST NOT ask for provider API keys, passwords, or broad credentials through an ordinary free-text field. User decline and cancellation are normal outcomes.

## 3. Tasks extension

Long-running MCP operations use the official `io.modelcontextprotocol/tasks` extension only after negotiated support. A `CreateTaskResult` is returned only after the task is durably created and immediately resolvable by `tasks/get`. Its flattened task state includes `taskId`, `status`, `createdAt`, `lastUpdatedAt`, and `ttlMs`, with optional `statusMessage` and `pollIntervalMs`. Task IDs map to the existing job abstraction and retain principal, tenant, capability revision, idempotency, budget, and expiration.

`tasks/get` returns `resultType: "complete"` plus the current detailed task, including `inputRequests`, a final result, or a JSON-RPC error as required by status. `tasks/update` and `tasks/cancel` return empty `resultType: "complete"` acknowledgements; their observable effects are eventually consistent. There is no invented `tasks/list` or `tasks/result`. Task results use the same canonical capability result as synchronous execution. Streamable HTTP requests for `tasks/get`, `tasks/update`, and `tasks/cancel` set `Mcp-Name` to `taskId` and `Mcp-Method` to the JSON-RPC method.

## 4. Subscriptions and progress

`subscriptions/listen` maps to the existing event providers through one selected backplane module. Its JSON-RPC request ID is the subscription ID; acknowledgment is the first message for that ID and every delivered notification carries the same subscription metadata. Subscription filters are explicit, authorized, bounded, and tenant-scoped.

Progress for an ordinary synchronous request remains on that request's response stream. Task progress is represented by `Task.status` and `statusMessage`, observed through `tasks/get` and optionally complete `notifications/tasks` snapshots requested through the Tasks extension's `taskIds` subscription filter. `notifications/progress` and `notifications/message` are not supported for Tasks and MUST NOT be sent on a task subscription stream. No path promises exactly-once delivery.

Redis pub/sub is ephemeral; NATS JetStream is durable only where the selected event contract provides durability. Local subscriptions are single-instance development/reference behavior.

## 5. Failure behavior

Broken in-flight HTTP streams are not resumed. A client retries with a new request ID and any explicit idempotency/task handle. Cancellation is best-effort at external providers but authoritative state records whether work was stopped, completed before cancellation, or became indeterminate.

## 6. Acceptance linkage

This specification is verified by `AC-AI-089` through `AC-AI-096`.


---

---
spec_id: RSK-047
title: MCP Extensions, Apps, Skills, and Roadmap Readiness
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# MCP Extensions, Apps, Skills, and Roadmap Readiness

## 1. Extension lifecycle

Extensions are isolated modules with stable IDs, capability declarations, version/status metadata, negotiation tests, and removal behavior. Stable, draft, and experimental extensions are not conflated. Unsupported extensions are ignored or rejected according to the specification; they never activate from untrusted metadata alone.

## 2. MCP Apps

The optional Apps module negotiates the official `io.modelcontextprotocol/ui` extension and serves `ui://` resources and tool metadata according to the MCP Apps specification. UI assets are immutable/versioned, content-security-policy constrained, permission-minimized, origin isolated, and safe for sandboxed iframe execution. PostMessage traffic is schema-validated and correlated to the owning tool/resource. Apps do not bypass ordinary tool authorization.

## 3. Skills

Skills over MCP remain an experimental Working Group extension rather than a production-stable MCP extension. The `mcp-skills` module is therefore opt-in, excluded from baseline and production-oriented profiles, and included only in the full reference profile or by explicit selection until an accepted SEP, SDK support, and conformance gates pass. Skill artifacts are versioned, signed or provenance-bearing where possible, size-limited, and treated as untrusted instructions. A skill cannot grant tools or data permissions beyond the principal and server policy.

## 4. Server metadata preview

The roadmap references `.well-known` server-card work that is not yet a settled wire contract. The preview module MAY generate internal/public metadata behind an experimental flag, but it MUST NOT claim conformance, publish an invented stable schema, or be enabled in production profiles without a new ADR tied to an accepted standard.

## 5. Progressive discovery preparation

The registry supports catalog partitions, tags, search metadata, compact entry capabilities, and deterministic hashes so future progressive discovery can be adopted. The current server still uses standardized discovery and list methods; it MUST NOT invent proprietary progressive-discovery RPCs.

## 6. Future-facing seams

The architecture deliberately isolates:

- the canonical tool result from MCP's current result representation;
- protocol dispatch from HTTP/stdio framing;
- identity evidence from the canonical principal;
- task/subscription behavior from transport;
- resources from storage/range/hierarchy implementation;
- extension declarations from core capabilities.

These seams align with roadmap work on agentic messaging, HTTP-native transport unification, agent identity, improved results, progressive discovery, and generated/conformant SDKs.

## 7. Acceptance linkage

This specification is verified by `AC-AI-097` through `AC-AI-104`.


---

---
spec_id: RSK-048
title: AI and MCP Testing, Conformance, Evaluations, and Operations
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# AI and MCP Testing, Conformance, Evaluations, and Operations

## 1. Test layers

The suite requires unit, property, contract, integration, cassette, conformance, security, load, soak, and failure tests. Live-provider tests are quarantined, budget-capped, opt-in, and never required for ordinary local development. Deterministic provider cassettes and synthetic MCP clients cover the default CI path.

## 2. Provider tests

Each provider adapter has fixtures for text, structured output, tools, streaming, refusals, citations, media, usage, unknown content, malformed events, throttling, timeout, and partial-stream failure where supported. Fixtures assert normalized output and retained raw metadata. Secret scanners verify that recordings contain no credentials or personal data.

## 3. Schema and streaming tests

JSON Schema generation/validation uses official conformance suites where practical plus property and fuzz tests for references, composition, nesting, limits, and arbitrary JSON roots. Stream tests vary chunk boundaries, ordering, duplicate/unknown events, cancellation, backpressure, and truncated tool/JSON deltas.

## 4. MCP conformance

The official MCP conformance framework is a release gate for supported protocol revisions and transports. The MCP Inspector is used for interactive and CLI/TUI diagnostics. Tests cover `server/discover`, per-request negotiation, cache metadata, standard headers, tools/resources/prompts, result types, MRTR, subscriptions, Tasks, auth extensions, cancellation, errors, and legacy compatibility modes.

## 5. Security matrix

Tests attempt horizontal/vertical/cross-tenant access, hidden catalog enumeration, prompt injection, tool-confused-deputy attacks, forged MRTR state, replayed tasks, malicious resource URIs, header injection, oversized payloads, unsafe media, token issuer confusion, client credential reuse, and secret/content leakage through telemetry.

## 6. Evaluations

LLM evaluations are versioned datasets with prompt, route, model/provider revision, expected properties, judge methodology, tolerances, and cost. Deterministic assertions are preferred. Model-graded evaluations require calibration, blinded comparisons where useful, and recorded judge/version. Evals never replace correctness or authorization tests.

## 7. Operations

Runbooks cover provider outage, quota exhaustion, cost anomaly, compromised key, partial stream, stuck tool/job, task/subscription backlog, MCP compatibility failure, and extension rollback. Dashboards separate request, provider, tool, job, and protocol layers.

## 8. Acceptance linkage

This specification is verified by `AC-AI-105` through `AC-AI-112`.


---

---
spec_id: RSK-049
title: AI/MCP Profiles, Generator, Roadmap, and Suite Acceptance
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# AI/MCP Profiles, Generator, Roadmap, and Suite Acceptance

## 1. Profiles

The extension defines coherent profiles for an LLM runtime, authenticated LLM API, SaaS agent platform, AI worker, local stdio MCP server, remote MCP server, enterprise MCP server, combined web AI platform, and full reference matrix. Profiles select compatible event backplanes and MUST satisfy transitive module dependencies without hidden runtime requirements.

## 2. Generator behavior

The generator supports adding and removing LLM/MCP modules and profiles in existing projects. Operations are idempotent, use managed regions, preserve released migrations and application-owned source, and produce a reviewable change plan. Removing a provider does not delete conversations, audit, usage, media, task, or prompt data automatically.

Commands SHOULD include equivalents of:

```text
cargo service add llm-api
cargo service add mcp-http
cargo service add ai-platform
cargo service doctor
cargo service contracts generate
cargo service mcp conformance
cargo service llm eval
```

The exact CLI remains governed by the base generator specification.

## 3. Append-only adoption

This archive has no enclosing directory and is intended for direct extraction into `./specs`. It MUST introduce no path collisions with the validated base and web bundles. Existing IDs are unchanged. New tasks begin at `T150`, new ADRs at `0015`, and new numbered specifications at `35`.

Current unblocked implementation work continues. The autonomous agent begins a new task only after its declared prerequisites are satisfied. No existing task is restarted solely because this suite was added.

## 4. Upgrade and protocol watch

The suite pins the current MCP revision and crate baseline but treats protocol evolution as expected. A scheduled review compares the official changelog, roadmap, extension status, Rust SDK conformance, provider SDK releases, JSON Schema libraries, and OpenTelemetry GenAI conventions. Changes are adopted through ADR amendments and compatibility fixtures.

Preview modules never become default merely because a roadmap item exists. Conversely, settled standard behavior should replace preview scaffolding rather than coexist indefinitely.

## 5. Release evidence

A release includes resolved Cargo graph, advisory/license report, profile builds, contract schemas/examples, provider cassette report, MCP conformance report, security matrix, load/failure evidence, eval report, operational runbooks, recommendation traceability, manifest hashes, and extraction rehearsal.

## 6. Suite-wide definition of done

All 120 acceptance criteria are independently verifiable and mapped to implementation tasks. Every recommendation has an acceptance criterion. Every module has an explicit frontend exposure declaration and appears in at least one profile. The base and web bundle validators and this extension validator all pass on the merged tree.

## 7. Acceptance linkage

This specification is verified by `AC-AI-113` through `AC-AI-120`.


---

---
spec_id: RSK-ADR-0015
title: Use Rig as the Default LLM Provider Abstraction
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Use Rig as the Default LLM Provider Abstraction

## Context

The kit needs mature multi-provider support without hand-building every wire client. Rig has broad current provider coverage, streaming, tools, structured output, media/embedding capabilities, provider response identities, raw output access, and GenAI telemetry integration.

## Decision

Pin Rig 0.42.0 as the default provider implementation. Keep Rig entirely behind service-kit-owned provider ports and canonical content contracts. Optional Bedrock and Vertex companion crates remain separate modules.

## Consequences

Provider integration effort is reduced while application contracts remain stable. Rig upgrades require cassette and normalization review. Direct provider adapters remain possible when a capability cannot be represented safely.

## Rejected alternatives

- Expose Rig types throughout the application.
- Write every provider HTTP client from scratch.
- Use several competing provider frameworks simultaneously.


---

---
spec_id: RSK-ADR-0016
title: Own an Extensible Lossless LLM Content Contract
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Own an Extensible Lossless LLM Content Contract

## Context

Provider APIs return more than strings and evolve faster than any one abstraction. Existing libraries commonly model a useful subset but may omit citations, refusals, files, audio, provider-only items, or future modalities.

## Decision

Define non-exhaustive, versioned service-kit request, response, output-part, stream-event, usage, and metadata contracts. Include an `unknown` provider part and policy-controlled raw terminal payload.

## Consequences

Callers can consume stable semantics and future provider output is detected rather than silently dropped. Adapter work is required for every provider change.

## Rejected alternatives

- Return only plaintext.
- Expose provider JSON directly.
- Use an untyped `serde_json::Value` for the entire response.


---

---
spec_id: RSK-ADR-0017
title: Use JSON Schema 2020-12 as the Structured Output Boundary
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Use JSON Schema 2020-12 as the Structured Output Boundary

## Context

LLM providers and MCP 2026-07-28 both converge on JSON Schema 2020-12, including non-object roots and composition keywords.

## Decision

Generate owned schemas with Schemars 1.2.2, validate with jsonschema 0.51.0, bound reference resolution, and locally validate every structured result. Provider-native strict output is preferred but never replaces local validation.

## Consequences

One schema dialect serves LLM outputs, tools, MCP, and generated contracts. Complex schemas require explicit resource limits and compatibility tests.

## Rejected alternatives

- Provider-specific schema dialects in domain code.
- Prompt-only JSON as the default.
- Assume structured roots are always objects.


---

---
spec_id: RSK-ADR-0018
title: Require Explicit Model Capabilities and Forbid Silent Downgrades
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Require Explicit Model Capabilities and Forbid Silent Downgrades

## Context

Provider and model support differs across structured output, tools, media, citations, reasoning, caching, regions, and limits. Name-based assumptions become stale.

## Decision

Routes declare hard and preferred capabilities. Provider/model revisions declare evidence-backed capabilities. Unsupported routes fail or use explicitly authorized semantically compatible fallback; silent weakening is prohibited.

## Consequences

Routing is predictable and auditable. Capability metadata needs maintenance and provider tests.

## Rejected alternatives

- Best-effort conversion with hidden feature loss.
- Global model enums.
- Provider choice embedded in product handlers.


---

---
spec_id: RSK-ADR-0019
title: Use Official RMCP and MCP 2026-07-28 as the Baseline
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Use Official RMCP and MCP 2026-07-28 as the Baseline

## Context

MCP changed substantially in July 2026: stateless requests, discovery, per-request negotiation, cacheable lists, subscriptions/listen, MRTR, and Tasks as an extension.

## Decision

Pin official `rmcp` 3.1.4 and implement MCP `2026-07-28` as the default. Compatibility is explicit and tested. Deprecated features do not enter new profiles.

## Consequences

The implementation follows the authoritative SDK and current protocol rather than older tutorials. SDK upgrades remain protocol-sensitive work.

## Rejected alternatives

- Unofficial protocol structs.
- Base the design on 2025 Streamable HTTP sessions.
- Implement deprecated HTTP+SSE.


---

---
spec_id: RSK-ADR-0020
title: Make MCP Stateless over Streamable HTTP and Stdio
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Make MCP Stateless over Streamable HTTP and Stdio

## Context

Protocol-level sessions and initialization no longer fit horizontally scalable servers. The roadmap is moving toward HTTP-native transport unification.

## Decision

Use stateless Streamable HTTP POST and stdio adapters around transport-neutral dispatch. No Mcp-Session-Id, initialization dependency, GET event endpoint, or SSE resume logic is introduced.

## Consequences

Remote servers scale like ordinary HTTP workloads, and local transport shares semantics. Cross-call state must use explicit handles.

## Rejected alternatives

- Implicit in-memory client sessions.
- Custom WebSocket MCP transport.
- Treat stdio as a separate protocol.


---

---
spec_id: RSK-ADR-0021
title: Use One Agent Capability Registry Across HTTP, Jobs, LLM Tools, and MCP
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Use One Agent Capability Registry Across HTTP, Jobs, LLM Tools, and MCP

## Context

Duplicated tool definitions and handlers drift in schemas, authorization, tenancy, idempotency, and audit behavior.

## Decision

Create one registry of stable application capabilities and explicit projections. Adapters invoke application services through the registry and cannot bypass its policy metadata.

## Consequences

Business behavior stays consistent across interfaces. The registry becomes a critical reviewed contract and must avoid becoming a service locator for unrelated infrastructure.

## Rejected alternatives

- Separate MCP-only business services.
- Generate capabilities directly from every public HTTP route.
- Let model SDK tools call repositories.


---

---
spec_id: RSK-ADR-0022
title: Map MCP Identity to the Canonical Principal and Authorization System
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Map MCP Identity to the Canonical Principal and Authorization System

## Context

MCP callers may be users, client applications, workloads, delegated agents, or local processes. Treating all bearer tokens alike loses identity and policy information.

## Decision

Validate current MCP/OAuth metadata and map evidence to the canonical Principal, retaining client, workload, user, delegation, tenant, scopes, and issuer. Use ordinary authorization and audit for every primitive.

## Consequences

MCP gains the same cross-tenant and least-privilege controls as other transports. Identity evidence and principal semantics remain separate.

## Rejected alternatives

- MCP-specific roles table.
- Trust tool annotations as authorization.
- Authorize only the transport endpoint.


---

---
spec_id: RSK-ADR-0023
title: Map MCP Tasks to Jobs and Subscriptions to Event Providers
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Map MCP Tasks to Jobs and Subscriptions to Event Providers

## Context

The base kit already owns durable jobs, outbox/inbox, cancellation, Redis pub/sub, and NATS. Reimplementing these inside MCP would duplicate difficult infrastructure.

## Decision

Implement Tasks as an adapter over jobs and explicit task state. Implement subscriptions/listen over one selected event backplane. Request progress remains request-scoped.

## Consequences

MCP long-running and event behavior inherits existing durability and operational semantics. Provider-specific guarantees must remain visible.

## Rejected alternatives

- A second MCP queue.
- Store task state only in process memory.
- Promise durable subscriptions over Redis pub/sub.


---

---
spec_id: RSK-ADR-0024
title: Isolate Extensions and Preserve Roadmap-Facing Seams
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Isolate Extensions and Preserve Roadmap-Facing Seams

## Context

MCP is actively settling agentic messaging, HTTP unification, agent identity, result contracts, progressive discovery, file/resource improvements, and SDK generation.

## Decision

Keep extensions as opt-in modules and isolate canonical results, dispatch, identity evidence, tasks/subscriptions, resources, and discovery metadata. Preview modules may prepare internal structures but cannot invent stable wire contracts.

## Consequences

Settled standards can replace adapters without redesigning the application. Some preview code may be deleted rather than promoted.

## Rejected alternatives

- Implement roadmap proposals as proprietary RPCs.
- Put all extensions in core.
- Freeze the internal model to the current tools/call result shape.


---

---
spec_id: RSK-AI-SUITE-AGENT-HANDOFF
title: "Autonomous Agent Handoff: LLM and MCP Suite"
version: 0.1.0
status: guide
last_verified: 2026-08-24
---

# Autonomous Agent Handoff: LLM and MCP Suite

## Mission

Implement the append-only LLM and MCP suite without destabilizing work already completed from the base and web bundles. Treat the numbered specifications and accepted ADRs as normative; machine catalogs are execution inputs and validation evidence.

## Non-negotiable constraints

1. Business capabilities are defined once in `agent-capability-registry` and projected into HTTP, jobs, LLM tools, MCP, and browser adapters.
2. Service-kit-owned types form the public boundary. Rig and RMCP types remain inside adapter crates.
3. LLM responses are not strings: preserve every normalized output kind, specialized model-operation result, and unknown future provider part.
4. Structured output is JSON Schema 2020-12 and locally validated.
5. Model features and fallbacks are explicit; no silent downgrade.
6. Tool calls are untrusted and pass validation, authorization, tenancy, confirmation, idempotency, deadline, budget, and audit controls.
7. MCP defaults to `2026-07-28`, `server/discover`, stateless requests, Streamable HTTP POST/stdio, per-request negotiation, and extension isolation.
8. Do not implement deprecated MCP Roots, Sampling, Logging, HTTP+SSE, sessions, initialization, or SSE request resumption.
9. Do not implement roadmap proposals as proprietary stable RPCs.
10. Treat Skills over MCP as experimental and exclude it from production-oriented profiles until an accepted SEP, SDK support, and conformance gates pass.
11. Prompts, responses, tool arguments, media, credentials, and reasoning state are absent from default telemetry.

## Work selection

Select only a task whose dependencies are complete. Do not restart an existing task because this suite was added. When an existing implementation lacks a required seam, create the smallest amendment and prerequisite task that satisfies the new acceptance criteria.

## Verification loop

For each task:

- identify every acceptance criterion it owns;
- implement source, configuration, lifecycle, health, telemetry, tests, docs, and generator wiring;
- run the resolved profile build and focused tests;
- update machine evidence without changing stable IDs;
- preserve raw provider/MCP compatibility fixtures needed to prove behavior;
- run all three validators on the merged tree.

## Required release gates

Cargo graph and advisory review, provider cassettes, schema/property/fuzz tests, MCP official conformance, Inspector smoke tests, authorization matrix, load/failure tests, eval report, profile matrix, extraction rehearsal, traceability, and manifest hashes must pass.


---

---
spec_id: RSK-AI-SUITE-INTEGRATION
title: LLM/MCP Suite Integration Instructions
version: 0.1.0
status: guide
last_verified: 2026-08-24
---

# LLM/MCP Suite Integration Instructions

## Preconditions

The target `./specs` tree contains the validated Rust Service Kit base bundle `0.1.0` and Web Application feature suite `0.1.0`. This extension intentionally uses the next numbered specification, ADR, task, and acceptance ranges and provides frontend exposure declarations for its modules.

## Apply

```bash
unzip -n rust-service-kit-llm-mcp-feature-suite-v0.1.0.zip -d ./specs
python ./specs/tools/validate_llm_mcp_feature_suite.py ./specs
```

The ZIP does not overwrite canonical machine catalogs. New catalog entries live under `machine/extensions/llm-mcp-suite/`. Consumers may read overlays directly or apply `merge-plan.yaml` deterministically with stable unique keys.

## Implementation ordering

1. Complete currently unblocked prerequisite work.
2. Run `T150` to make validators and generator overlay-aware.
3. Run `T151` to resolve the pinned Rust graph and verify protocol/provider compatibility.
4. Implement the shared capability registry before LLM tools or MCP projections.
5. Implement canonical LLM contracts before provider adapters.
6. Implement current MCP core/discovery before transports and primitive projections.
7. Add extensions only after core conformance.
8. Generate/rehearse profiles and release evidence last.

## Amendments

Do not edit or renumber existing requirements because a new suite exposes an issue. Create an amendment ADR and a narrowly scoped prerequisite task. Preserve completed work unless a verified defect requires a change.

## Compatibility

The core LLM/MCP modules do not require a browser application. The `web-llm` module and combined `ai-platform` profiles depend on the web suite. The validator requires the web extension because the user's merged spec tree already includes it and frontend exposure coverage must remain complete.

## Removal

Removing specification files is not the same as removing implemented modules. Generator removal preserves released migrations and stored prompts, conversations, usage, media, audit, tasks, and application-owned source. It produces an explicit cleanup plan.


---

---
spec_id: RSK-AI-RESEARCH-CRATE-EVALUATION
title: Rust LLM and MCP Crate Evaluation
version: 0.1.0
status: research
last_verified: 2026-08-24
---

# Rust LLM and MCP Crate Evaluation

## Selected foundation

### Rig

Rig 0.42.0 is selected as the default LLM provider implementation because its current workspace provides a portable provider layer, broad direct-provider coverage, tools, structured output, streaming, embeddings, transcription/audio/image capabilities, provider response identifiers, unknown/raw streaming data, and GenAI telemetry integration. Recent releases include extensive provider cassette fixes and explicit preservation of provider-only response data. See `SRC-AI-030` through `SRC-AI-038`.

Rig is not the public contract. The kit owns its content algebra, route/capability registry, errors, budgets, tools, and stream events. This makes replacing or supplementing an adapter possible without rewriting application code.

### RMCP

RMCP 3.1.4 is selected because it is the official Rust MCP SDK, targets `2026-07-28`, supports discovery lifecycle, current tools/resources/prompts, cache hints, MRTR, subscriptions, Tasks, standard headers, and compatibility modes, and participates in the official conformance program. See `SRC-AI-024` through `SRC-AI-028`.

### Schemars and jsonschema

Schemars 1.2.2 and jsonschema 0.51.0 establish a Rust-native JSON Schema 2020-12 generation and validation path used by LLM structured output, tools, MCP, prompts, and machine contracts. Remote-reference fetching is disabled by default and composition/resource limits are mandatory. See `SRC-AI-055` through `SRC-AI-057`.

## Not selected as the default

- Hand-written provider clients: retained only for a proven missing capability because they recreate authentication, streaming, error mapping, usage, and provider evolution work.
- Provider SDK types as domain types: rejected because they create lock-in and output loss at cross-provider boundaries.
- Multiple generic LLM frameworks: rejected because simultaneous abstractions multiply conversions and ambiguity. A second implementation must satisfy the same provider port and compatibility suite.
- Unofficial MCP frameworks: rejected for the baseline because the official SDK tracks the authoritative schema and conformance work.
- A homegrown JSON Schema subset: rejected because both providers and MCP now require full 2020-12 semantics, including non-object roots.

## Upgrade gates

Crate popularity alone is not an upgrade signal. Rig upgrades require normalized cassette and raw-output review. RMCP upgrades require official changelog and conformance review. Schema upgrades require conformance and adversarial limits. Cloud companion crates require a resolved Cargo graph and workload-identity review.


---

---
spec_id: RSK-AI-RESEARCH-MCP-CURRENT
title: MCP 2026-07-28 Findings
version: 0.1.0
status: research
last_verified: 2026-08-24
---

# MCP 2026-07-28 Findings

## Required architectural corrections from earlier MCP designs

The current protocol is stateless. Protocol sessions, `Mcp-Session-Id`, `initialize`, and `notifications/initialized` are not part of the preferred lifecycle. `server/discover` is mandatory. Version and client capabilities travel per request; server identity travels in results. This supports horizontal scaling and eliminates hidden per-client server state.

`subscriptions/listen` replaces the old HTTP GET event endpoint and resource subscribe/unsubscribe methods. Request progress remains on the request response stream. Broken response streams are not resumable through SSE IDs; clients re-issue with a new request ID.

All results carry `resultType`. MRTR replaces server-initiated requests with `input_required` results and retries of the original request. Tasks are an official extension with get/update/cancel and no list method.

List/read results are cacheable through TTL and public/private scope. Tools should be deterministically ordered. Schemas use JSON Schema 2020-12 and structured content may be any JSON value.

Roots, Sampling, Logging, and HTTP+SSE are deprecated for new implementations. Direct LLM provider calls replace Sampling, resource URIs/configuration replace Roots, and stderr/OpenTelemetry replace protocol logging.

## Consequences for this kit

The MCP server is a stateless adapter over the capability registry. Cross-call workflows use explicit task or MRTR handles. Auth and tenancy are evaluated on every request and catalog operation. Compatibility with older clients stays in RMCP modes and never drives core state design. See `SRC-AI-003` through `SRC-AI-016`.


---

---
spec_id: RSK-AI-RESEARCH-MCP-ROADMAP
title: MCP Roadmap-Forward Design
version: 0.1.0
status: research
last_verified: 2026-08-24
---

# MCP Roadmap-Forward Design

## Settling direction

The August 22, 2026 roadmap prioritizes agentic messaging primitives, HTTP-native transport unification, agent identity and enterprise security, improved tool/result and discovery primitives, and SDK conformance/developer experience. See `SRC-AI-001` and `SRC-AI-002`.

## Prepared seams

- Tasks, subscriptions, progress, and MRTR use independent ports so future server-initiated events or channels can compose without changing domain services.
- Protocol dispatch is independent of framing so Streamable HTTP over stdio can be adopted later.
- Identity evidence is separate from the canonical Principal so workload identity, DPoP, ID-JAG, and token exchange can evolve.
- Tool execution produces one canonical result before MCP rendering so a future tools/call result contract can replace the adapter.
- The capability registry supports partitions, tags, compact metadata, deterministic hashes, and authorization-filtered views for progressive discovery.
- Resources are abstracted from storage and anticipate ranges, hierarchy, checksums, and object references.
- Extensions are isolated and status-tagged so experimental work cannot silently become core.

## Deliberate restraint

The suite does not invent a server-card schema, progressive-discovery RPC, HTTP-over-stdio framing, agent-identity token, or future tool-result wire object. Preview modules prepare internal data and tests only. Accepted standards replace previews through an ADR and compatibility transition.


---

---
spec_id: RSK-AI-RESEARCH-PROVIDER-OUTPUTS
title: External LLM Provider Output Findings
version: 0.1.0
status: research
last_verified: 2026-08-24
---

# External LLM Provider Output Findings

## Common output families

First-party provider APIs now expose typed items beyond plaintext: structured JSON, function/tool calls, refusals and safety decisions, citations/grounding and token annotations, provider-executed search/code/computer/file/MCP steps, images, audio, video, files/resources, reasoning summaries or signed/encrypted continuation state, multiple candidates, usage/cache counters, request/response IDs, and provider-specific events. Streaming APIs split these into start/delta/complete events with provider-specific chunking.

No single provider-neutral library type should be assumed to cover every future item. The kit therefore uses a versioned ordered content algebra plus `unknown` and policy-controlled raw metadata. See `SRC-AI-039` through `SRC-AI-054`.

Dedicated provider operations also return shapes that should not be flattened into chat messages: dense/sparse/binary or multi-vector embeddings; ranked document identities and relevance scores; transcripts with language, segments, words, speakers and timing; generated speech with timing marks or visemes; multiple generated media assets with revised prompts, seeds, provenance and safety outcomes; and moderation/classification label-score sets. The suite therefore defines an explicit model-response union in addition to the heterogeneous generation content algebra.

## Structured output

Provider-native strict output materially improves adherence but does not remove the need for local validation, schema limits, explicit refusal/error handling, or compatibility checks. Citation and strict structured-output features may conflict on some providers, reinforcing the need for route capabilities rather than feature assumptions.

## Reasoning state

Some providers return safe summaries; some require signed or encrypted blocks to continue a tool conversation. These are not treated as hidden chain-of-thought suitable for display or logging. The kit preserves only provider-sanctioned summaries or opaque continuation state under separate policy.

## Streaming

Chunk boundaries are not semantic boundaries. Tool arguments and JSON can be partial; usage may arrive only at the end; a stream can fail after visible output. The canonical event model records sequence, part identity, partial status, terminal state, and cancellation while refusing to label incomplete values as complete.
