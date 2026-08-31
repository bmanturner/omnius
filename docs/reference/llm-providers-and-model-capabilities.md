---
title: LLM providers and model capabilities
description: Provider adapter inventory, authentication modes, model-source policy, exact capability identifiers, and evidence-backed admission.
status: experimental
implementation: implemented
profile_availability:
  - llm-runtime
  - llm-api
  - llm-agent
  - ai-worker
  - ai-platform
  - full-reference-ai
public_exposure: library-only
audience:
  - ai-developer
  - operator
topics:
  - llm
  - providers
  - model-capabilities
capabilities: []
source:
  - crates/llm-core/src/capability.rs
  - crates/llm-provider-rig/src/catalog.rs
  - specs/machine/extensions/llm-mcp-suite/provider-catalog.yaml
evidence:
  - crates/llm-core/tests/contracts.rs
  - crates/llm-provider-rig/tests/public_api.rs
last_verified: 2026-08-30
---

# LLM providers and model capabilities

Provider crates and registries are implemented libraries. No checked-in non-test composition proves provider credentials, routing, health, or HTTP exposure. Profile selection and provider catalog entries are not runtime assembly evidence.

## Provider inventory

| Provider ID | Adapter owner | Protocol | Authentication modes | Model source | Important distinction |
|---|---|---|---|---|---|
| `openai` | `llm-provider-rig` | OpenAI Responses compatible | `bearer-api-key`, `oauth-where-supported` | runtime discovery | Region is configurable; tenant credentials are optional and policy-gated. Catalog capabilities are not guaranteed for every model. |
| `anthropic` | `llm-provider-rig` | Anthropic Messages | `api-key` | configuration | Signed or opaque thinking-continuation state is preserved without exposing private reasoning. |
| `gemini` | `llm-provider-rig` | Google Gemini API | `api-key`, `oauth` | runtime discovery | Direct Gemini is separate from Vertex deployment behavior. |
| `openrouter` | `llm-provider-rig` | OpenAI-compatible aggregation | `bearer-api-key` | runtime discovery | Capability evidence must be configured or tested for each upstream model. |
| `bedrock` | `llm-provider-bedrock` | AWS Bedrock Converse | `aws-workload-identity`, `aws-sigv4` | runtime discovery | Region is configurable; tenant credentials are disabled by default; capabilities vary within Bedrock. |
| `vertex` | `llm-provider-vertex` | Google Vertex AI | `google-workload-identity`, `oauth` | configuration | Region is configurable; tenant credentials are disabled by default; project, region, credentials, and endpoint behavior are distinct from direct Gemini. |

`DirectProvider::ALL` is exactly `openai`, `anthropic`, `gemini`, and `openrouter`. Bedrock and Vertex are catalog providers but have no `DirectProvider` variant. Their adapter profile availability is narrower: `llm-provider-bedrock` and `llm-provider-vertex` are selected only by `llm-agent` and `full-reference-ai`.

The provider module catalog declares no routes for Rig, Bedrock, or Vertex. Its health-check names are declarations, not evidence that a process runs those checks.

## Exact model-capability identifiers

`ModelCapability` serializes these snake-case values:

| Input | Output | Tools and structure | Context and provider features | Specialized tasks |
|---|---|---|---|---|
| `text_input` | `text_output` | `strict_json_schema` | `streaming` | `embeddings` |
| `image_input` | `structured_output` | `strict_tool_output` | `resumable_conversations` | `reranking` |
| `audio_input` | `image_output` | `tools` | `citations` | `transcription` |
| `video_input` | `audio_output` | `parallel_tool_calls` | `grounding` | `speech_generation` |
| `file_input` | `video_output` |  | `token_scores` | `image_generation` |
| `resource_input` | `file_output` |  | `safety_metadata` | `video_generation` |
|  | `resource_output` |  | `search_results` | `prompt_caching` |
|  | `annotation_output` |  | `provider_executed_steps` | `cache_controls` |
|  | `execution_step_output` |  | `reasoning_summaries` |  |
|  |  |  | `opaque_reasoning_state` |  |

Catalog YAML uses separate hyphenated vocabulary such as `text-input`, `structured-output`, and `prompt-cache`. Those catalog labels must not be copied as `ModelCapability` wire identifiers, and they do not automatically create registry evidence.

## Evidence-backed capability admission

A registry claim is keyed by exact:

```text
{ provider, model, revision }
```

Revision is part of model identity. A claim also carries the registry revision, a capability-to-evidence map, supported regions, and optional maximum context and output-token values.

Evidence source is exactly one of:

- `configured`;
- `provider_documentation`;
- `cassette`;
- `provider_discovery`.

Requirements contain required and preferred capability sets, optional region, and optional minimum context/output limits. Required and preferred sets may not overlap; zero minimum limits are rejected.

Admission must use the exact provider/model/revision evidence record. Do not infer capability from:

- a model-name substring;
- provider-wide marketing or catalog entries;
- another revision of the same model;
- successful generation that did not exercise the requested capability;
- profile selection, crate presence, fixtures, or tests alone.

## Provider-neutral route names

The route contract in [LLM contracts](llm-contracts.md) carries required and preferred capabilities as strings rather than this enum. Composition code must deliberately map route policy to evidence-backed typed capabilities; identical spelling alone is not proof that mapping occurred.

## Credentials and tenant policy

The catalog distinguishes provider authentication mechanisms and whether tenant credentials are configurable. It does not implement credential storage, rotation, workload identity, or tenant isolation by itself. Bedrock and Vertex explicitly default tenant credentials off in catalog policy; OpenAI permits them only through policy. No repository evidence establishes current production credentials for any provider.
