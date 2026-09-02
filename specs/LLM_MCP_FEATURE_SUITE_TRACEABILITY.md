---
spec_id: OMNIUS-AI-SUITE-TRACEABILITY
title: LLM and MCP Recommendation Traceability
version: 0.1.0
status: report
last_verified: 2026-09-01
---

# LLM and MCP Recommendation Traceability

## Coverage summary

- Recommendations: 118
- Acceptance criteria: 118
- Omitted recommendations: 0
- Mapping cardinality: one recommendation per acceptance criterion

| Recommendation | Acceptance | Specification | Requirement |
|---|---|---|---|
| `REC-AI-001` | `AC-AI-001` | `OMNIUS-035` | Suite applies append-only without modifying prior bundle files |
| `REC-AI-002` | `AC-AI-002` | `OMNIUS-035` | One agent capability registry serves HTTP jobs LLM tools and MCP projections |
| `REC-AI-003` | `AC-AI-003` | `OMNIUS-035` | Public application code imports no Rig or RMCP domain types |
| `REC-AI-004` | `AC-AI-004` | `OMNIUS-035` | Compiled and runtime AI capabilities are explicit and observable |
| `REC-AI-005` | `AC-AI-005` | `OMNIUS-035` | Principal tenant trace deadline cancellation and policy context survive every adapter |
| `REC-AI-006` | `AC-AI-006` | `OMNIUS-035` | Default profiles contain no deprecated MCP feature implementation |
| `REC-AI-007` | `AC-AI-007` | `OMNIUS-035` | Every AI and MCP module participates in configuration lifecycle health telemetry and tests |
| `REC-AI-008` | `AC-AI-008` | `OMNIUS-035` | HTTP job browser and MCP paths execute the same application capability behavior |
| `REC-AI-009` | `AC-AI-009` | `OMNIUS-036` | Canonical response preserves ordered heterogeneous output parts |
| `REC-AI-010` | `AC-AI-010` | `OMNIUS-036` | Plaintext output is returned without provider-specific wrappers |
| `REC-AI-011` | `AC-AI-011` | `OMNIUS-036` | Structured output accepts any JSON value and records schema validation |
| `REC-AI-012` | `AC-AI-012` | `OMNIUS-036` | Tool calls and results retain stable IDs names arguments and provenance |
| `REC-AI-013` | `AC-AI-013` | `OMNIUS-036` | Citations and refusals remain first-class typed output |
| `REC-AI-014` | `AC-AI-014` | `OMNIUS-036` | Image audio video file and generated-media outputs support bounded inline URL and object references |
| `REC-AI-015` | `AC-AI-015` | `OMNIUS-036` | Reasoning output exposes only provider-sanctioned summaries signatures or opaque state |
| `REC-AI-016` | `AC-AI-016` | `OMNIUS-036` | Completion and specialized model-operation contracts retain unknown provider content without silent loss |
| `REC-AI-017` | `AC-AI-017` | `OMNIUS-037` | Rig 0.42.0 provider adapter resolves and passes compatibility fixtures |
| `REC-AI-018` | `AC-AI-018` | `OMNIUS-037` | Provider catalog covers every configured provider and adapter module |
| `REC-AI-019` | `AC-AI-019` | `OMNIUS-037` | Adapters normalize response IDs request IDs stop reasons usage and warnings |
| `REC-AI-020` | `AC-AI-020` | `OMNIUS-037` | Raw provider payload retention follows explicit redaction and retention policy |
| `REC-AI-021` | `AC-AI-021` | `OMNIUS-037` | Model capabilities are revisioned and evidence-backed |
| `REC-AI-022` | `AC-AI-022` | `OMNIUS-037` | Unsupported requirements never silently downgrade or reroute |
| `REC-AI-023` | `AC-AI-023` | `OMNIUS-037` | Provider credentials and endpoint overrides pass secret and outbound policies |
| `REC-AI-024` | `AC-AI-024` | `OMNIUS-037` | Provider failures are typed and correctly classified for retry |
| `REC-AI-025` | `AC-AI-025` | `OMNIUS-038` | Structured output uses JSON Schema Draft 2020-12 |
| `REC-AI-026` | `AC-AI-026` | `OMNIUS-038` | Native strict structured output is preferred when supported |
| `REC-AI-027` | `AC-AI-027` | `OMNIUS-038` | Every structured result is locally validated with bounded repair attempts |
| `REC-AI-028` | `AC-AI-028` | `OMNIUS-038` | Streaming events preserve part order sequence identity and terminal state |
| `REC-AI-029` | `AC-AI-029` | `OMNIUS-038` | Backpressure and cancellation remain bounded through provider and tool execution |
| `REC-AI-030` | `AC-AI-030` | `OMNIUS-038` | Tool execution enforces validation authorization confirmation idempotency and audit |
| `REC-AI-031` | `AC-AI-031` | `OMNIUS-038` | Agent loops enforce model tool time token cost and concurrency budgets |
| `REC-AI-032` | `AC-AI-032` | `OMNIUS-038` | Partial JSON and tool arguments are never exposed as complete values |
| `REC-AI-033` | `AC-AI-033` | `OMNIUS-039` | Routes filter candidates by hard capabilities and policy before ranking |
| `REC-AI-034` | `AC-AI-034` | `OMNIUS-039` | Estimated and actual usage costs are reserved and reconciled |
| `REC-AI-035` | `AC-AI-035` | `OMNIUS-039` | Timeout and retry policy respects total deadline idempotency and retry-after |
| `REC-AI-036` | `AC-AI-036` | `OMNIUS-039` | Hedging is disabled by default and restricted to safe requests |
| `REC-AI-037` | `AC-AI-037` | `OMNIUS-039` | Fallback proves semantic compatibility and records its reason |
| `REC-AI-038` | `AC-AI-038` | `OMNIUS-039` | Quotas apply by tenant principal route provider model and operation |
| `REC-AI-039` | `AC-AI-039` | `OMNIUS-039` | Circuit health distinguishes provider endpoint region model and credential failures |
| `REC-AI-040` | `AC-AI-040` | `OMNIUS-039` | Required routes affect readiness when no compliant provider remains |
| `REC-AI-041` | `AC-AI-041` | `OMNIUS-040` | Published prompts are immutable versioned and schema-backed |
| `REC-AI-042` | `AC-AI-042` | `OMNIUS-040` | Context assembly preserves authorization provenance and instruction boundaries |
| `REC-AI-043` | `AC-AI-043` | `OMNIUS-040` | Prompt and response caches cannot cross tenant or principal boundaries |
| `REC-AI-044` | `AC-AI-044` | `OMNIUS-040` | Retention and deletion cover conversations media caches eval artifacts and provider APIs |
| `REC-AI-045` | `AC-AI-045` | `OMNIUS-040` | Default logs and metrics exclude prompt response and reasoning content |
| `REC-AI-046` | `AC-AI-046` | `OMNIUS-040` | Untrusted documents tool output and model output cannot become privileged instructions |
| `REC-AI-047` | `AC-AI-047` | `OMNIUS-040` | Context truncation and ordering are deterministic and observable |
| `REC-AI-048` | `AC-AI-048` | `OMNIUS-040` | Provider prompt-cache controls remain explicit adapter capabilities |
| `REC-AI-049` | `AC-AI-049` | `OMNIUS-041` | LLM HTTP operations are complete and deterministically described by OpenAPI |
| `REC-AI-050` | `AC-AI-050` | `OMNIUS-041` | Synchronous streaming and durable modes share canonical request and response contracts |
| `REC-AI-051` | `AC-AI-051` | `OMNIUS-041` | Streaming transport distinguishes completion refusal cancellation and partial failure |
| `REC-AI-052` | `AC-AI-052` | `OMNIUS-041` | Web SDK supports typed generation streaming jobs tool approval citations and media |
| `REC-AI-053` | `AC-AI-053` | `OMNIUS-041` | Large media uses authorized scanned lifecycle-managed object references |
| `REC-AI-054` | `AC-AI-054` | `OMNIUS-041` | Telemetry follows GenAI conventions without high-cardinality metric labels |
| `REC-AI-055` | `AC-AI-055` | `OMNIUS-041` | Usage and audit ledgers reconcile provider tool job principal and tenant identities |
| `REC-AI-056` | `AC-AI-056` | `OMNIUS-041` | Diagnostic content capture is disabled by default and access-controlled when enabled |
| `REC-AI-057` | `AC-AI-057` | `OMNIUS-042` | MCP baseline is protocol revision 2026-07-28 |
| `REC-AI-058` | `AC-AI-058` | `OMNIUS-042` | MCP implementation uses official RMCP with a resolved pinned graph |
| `REC-AI-059` | `AC-AI-059` | `OMNIUS-042` | MCP request processing is stateless and self-contained |
| `REC-AI-060` | `AC-AI-060` | `OMNIUS-042` | MCP exposures derive from the shared agent capability registry |
| `REC-AI-061` | `AC-AI-061` | `OMNIUS-042` | Roots Sampling Logging and HTTP plus SSE are absent from new profiles |
| `REC-AI-062` | `AC-AI-062` | `OMNIUS-042` | Every MCP request maps to a canonical Principal and request context |
| `REC-AI-063` | `AC-AI-063` | `OMNIUS-042` | MCP extensions activate only after explicit negotiated support |
| `REC-AI-064` | `AC-AI-064` | `OMNIUS-042` | Capability discovery is filtered by tenant principal and authorization |
| `REC-AI-065` | `AC-AI-065` | `OMNIUS-043` | Server implements server/discover and advertises versions capabilities and identity |
| `REC-AI-066` | `AC-AI-066` | `OMNIUS-043` | Per-request version client capability client identity and server identity metadata are validated |
| `REC-AI-067` | `AC-AI-067` | `OMNIUS-043` | Tool resource prompt and template lists are deterministic and cacheable |
| `REC-AI-068` | `AC-AI-068` | `OMNIUS-043` | Streamable HTTP enforces current POST headers limits security and drain semantics |
| `REC-AI-070` | `AC-AI-070` | `OMNIUS-043` | Authenticated Streamable HTTP uses no session ID initialization dependency GET event endpoint or SSE resume |
| `REC-AI-071` | `AC-AI-071` | `OMNIUS-043` | subscriptions/listen is isolated from request-scoped progress streams |
| `REC-AI-072` | `AC-AI-072` | `OMNIUS-043` | Unsupported revisions and initialization-era methods are rejected without downgrade |
| `REC-AI-073` | `AC-AI-073` | `OMNIUS-044` | MCP tool input and output schemas support any JSON Schema 2020-12 type |
| `REC-AI-074` | `AC-AI-074` | `OMNIUS-044` | Canonical tool result maps unambiguously to structured and content representations |
| `REC-AI-075` | `AC-AI-075` | `OMNIUS-044` | Tool listing and calling enforce authorization consent side-effect and confirmation policy |
| `REC-AI-076` | `AC-AI-076` | `OMNIUS-044` | Resources safely support text binary MIME provenance and range/hierarchy-ready ports |
| `REC-AI-077` | `AC-AI-077` | `OMNIUS-044` | Prompts derive from immutable prompt catalog revisions and validate arguments |
| `REC-AI-078` | `AC-AI-078` | `OMNIUS-044` | Current results carry complete or input_required resultType |
| `REC-AI-079` | `AC-AI-079` | `OMNIUS-044` | Public MCP names and schema revisions follow compatibility and deprecation policy |
| `REC-AI-080` | `AC-AI-080` | `OMNIUS-044` | Internal result adapter can absorb future MCP result redesign without domain changes |
| `REC-AI-081` | `AC-AI-081` | `OMNIUS-045` | Remote MCP auth follows current OAuth protected-resource and resource-indicator requirements |
| `REC-AI-082` | `AC-AI-082` | `OMNIUS-045` | Issuer validation and Client ID Metadata Documents pass negative tests |
| `REC-AI-083` | `AC-AI-083` | `OMNIUS-045` | Client credentials remain issuer-bound and resource-scoped |
| `REC-AI-084` | `AC-AI-084` | `OMNIUS-045` | Enterprise authorization validates ID-JAG and maps delegation to ordinary policy |
| `REC-AI-085` | `AC-AI-085` | `OMNIUS-045` | Identity evidence ports can adopt DPoP workload federation and token exchange |
| `REC-AI-086` | `AC-AI-086` | `OMNIUS-045` | Every list read prompt and tool call enforces principal tenant and authorization |
| `REC-AI-087` | `AC-AI-087` | `OMNIUS-045` | Origin proxy SSRF URL and x-mcp-header policies reject unsafe input |
| `REC-AI-088` | `AC-AI-088` | `OMNIUS-045` | Consent audit and telemetry redact credentials tokens and sensitive payloads |
| `REC-AI-089` | `AC-AI-089` | `OMNIUS-046` | MRTR input_required state is bounded authenticated expiring and replay-safe |
| `REC-AI-090` | `AC-AI-090` | `OMNIUS-046` | Elicitation validates schemas decline cancellation and sensitive-field policy |
| `REC-AI-091` | `AC-AI-091` | `OMNIUS-046` | Tasks extension is explicit negotiated and absent when unsupported |
| `REC-AI-092` | `AC-AI-092` | `OMNIUS-046` | Task creation persists durable work before returning its handle |
| `REC-AI-093` | `AC-AI-093` | `OMNIUS-046` | Task get update and cancel enforce identity tenancy idempotency and state transitions |
| `REC-AI-094` | `AC-AI-094` | `OMNIUS-046` | Subscriptions use exactly one selected authorized event backplane |
| `REC-AI-095` | `AC-AI-095` | `OMNIUS-046` | Progress cancellation and task status retain correct request correlation |
| `REC-AI-096` | `AC-AI-096` | `OMNIUS-046` | Broken response streams require a new request ID and explicit idempotency or task handle |
| `REC-AI-097` | `AC-AI-097` | `OMNIUS-047` | MCP Apps serve versioned sandboxed CSP-constrained ui resources |
| `REC-AI-098` | `AC-AI-098` | `OMNIUS-047` | Experimental Skills are opt-in provenance-bearing bounded and cannot grant authority |
| `REC-AI-099` | `AC-AI-099` | `OMNIUS-047` | Extension registry distinguishes stable draft experimental deprecated and removed states |
| `REC-AI-100` | `AC-AI-100` | `OMNIUS-047` | Server-card preview publishes no invented conformant wire contract |
| `REC-AI-101` | `AC-AI-101` | `OMNIUS-047` | Progressive-discovery preparation introduces no proprietary RPC |
| `REC-AI-103` | `AC-AI-103` | `OMNIUS-047` | Identity evidence boundary can adopt standardized workload and delegated agent identity |
| `REC-AI-104` | `AC-AI-104` | `OMNIUS-047` | Resource and result seams are ready for range hierarchy and result-contract evolution |
| `REC-AI-105` | `AC-AI-105` | `OMNIUS-048` | Official MCP conformance suite passes every declared revision transport and extension |
| `REC-AI-106` | `AC-AI-106` | `OMNIUS-048` | MCP Inspector CLI or TUI smoke tests pass against generated profiles |
| `REC-AI-107` | `AC-AI-107` | `OMNIUS-048` | Provider cassettes cover normalized and unknown output plus failure modes |
| `REC-AI-108` | `AC-AI-108` | `OMNIUS-048` | Schema and stream parsers pass property and fuzz suites with resource limits |
| `REC-AI-109` | `AC-AI-109` | `OMNIUS-048` | Cross-transport capability authorization matrix prevents horizontal vertical and tenant bypass |
| `REC-AI-110` | `AC-AI-110` | `OMNIUS-048` | Load soak cancellation backpressure and failure tests remain bounded |
| `REC-AI-111` | `AC-AI-111` | `OMNIUS-048` | Evaluation datasets record prompt route provider model judge cost and tolerances |
| `REC-AI-112` | `AC-AI-112` | `OMNIUS-048` | Adversarial tests cover prompt injection exfiltration forged state malicious URIs and token confusion |
| `REC-AI-113` | `AC-AI-113` | `OMNIUS-049` | All eight AI and MCP profiles resolve build and pass their declared test matrix |
| `REC-AI-114` | `AC-AI-114` | `OMNIUS-049` | Generator add remove doctor diff and upgrade operations are idempotent and preserve application files |
| `REC-AI-115` | `AC-AI-115` | `OMNIUS-049` | Archive extraction has zero collisions with base and web bundles |
| `REC-AI-116` | `AC-AI-116` | `OMNIUS-049` | Pinned dependency and protocol compatibility gate passes before implementation |
| `REC-AI-117` | `AC-AI-117` | `OMNIUS-049` | Machine catalogs merge deterministically with unique stable identifiers |
| `REC-AI-118` | `AC-AI-118` | `OMNIUS-049` | Every suite recommendation maps to an independently verifiable acceptance criterion |
| `REC-AI-119` | `AC-AI-119` | `OMNIUS-049` | Provider protocol security cost and operations runbooks are complete |
| `REC-AI-120` | `AC-AI-120` | `OMNIUS-049` | New tasks remain append-only and do not restart completed prerequisite work |

## Effective task ownership amendment

ADR-0033 corrects mechanically rotated task ownership without changing any recommendation, acceptance, or task identifier. The effective amended allocations are:

| Task | Acceptance criteria |
|---|---|
| `T150` | `AC-AI-001` |
| `T151` | `AC-AI-002`–`AC-AI-008` |
| `T172` | `AC-AI-089`, `AC-AI-090` |
| `T173` | `AC-AI-091`–`AC-AI-093` |
| `T174` | `AC-AI-094`–`AC-AI-096` |
| `T175` | `AC-AI-097`–`AC-AI-099` |
| `T176` | `AC-AI-100`–`AC-AI-104` |
| `T177` | `AC-AI-107`, `AC-AI-108`, `AC-AI-111` |
| `T178` | `AC-AI-105`, `AC-AI-106`, `AC-AI-109`, `AC-AI-110`, `AC-AI-112` |
| `T179` | `AC-AI-113`–`AC-AI-120` |

All `REC-AI-*` rows above retain their original one-to-one acceptance mappings. Risk `R-AI-037` and the merged task validator guard this execution ownership from drifting again.
