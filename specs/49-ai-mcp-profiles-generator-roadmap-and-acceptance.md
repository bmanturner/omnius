---
spec_id: OMNIUS-049
title: AI/MCP Profiles, Generator, Roadmap, and Suite Acceptance
version: 0.1.0
status: normative
last_verified: 2026-09-03
---

# AI/MCP Profiles, Generator, Roadmap, and Suite Acceptance

## 1. Profiles

The extension defines eight coherent profiles: four LLM profiles, exactly two
MCP profiles (`mcp-http` and `mcp-enterprise`), and two combined AI/MCP
profiles. Profiles select runtime modules only. LLM evaluation, MCP preview,
Inspector, and conformance harnesses are tooling and MUST remain outside
runtime profile/state. Safe framework-owned local infrastructure may be
rendered by Compose; external endpoints, credentials, authorization policy,
product handlers, and advanced provider/application requirements remain
explicit and fail closed until supplied.

## 2. Generator behavior

Install the lifecycle CLI from the canonical repository at a full immutable
release revision:

```bash
REV=<full-lowercase-40-hex-revision>
OMNIUS_RELEASE_REVISION="$REV" cargo install --locked \
  --git https://github.com/bmanturner/omnius.git \
  --rev "$REV" \
  --bin cargo-service \
  omnius-generator
```

The installed manager supports:

```text
cargo service add <MODULE> [--project <PATH>]
cargo service remove <MODULE> [--project <PATH>]
cargo service profile set <PROFILE> [--project <PATH>]
cargo service update [--project <PATH>]
cargo service doctor [--project <PATH>]
cargo service diff [--project <PATH>]
```

There is no project-owned service xtask, caller-selected framework source, or
version-only upgrade command. Mutations bind strict schema-2 state, the managed
`omnius-service-kit` dependency, and the semantic Cargo lock/package graph to
the executing CLI's canonical Git URL, exact package version, and full
revision.

Operations are idempotent, resolve and seal the dependency lock once in a
sibling stage, and apply through a durable recovery journal. They preserve
application-owned source/templates and historical application migrations.
Removing a provider does not delete conversations, audit, usage, media, task,
or prompt data. MCP conformance and LLM evaluation remain separate explicit
repository tools rather than lifecycle selections or generated runtime
commands.

## 3. Append-only adoption

This archive has no enclosing directory and is intended for direct extraction into `./specs`. It MUST introduce no path collisions with the validated base and web bundles. Existing IDs are unchanged. New tasks begin at `T150`, new ADRs at `0015`, and new numbered specifications at `35`.

Current unblocked implementation work continues. The autonomous agent begins a new task only after its declared prerequisites are satisfied. No existing task is restarted solely because this suite was added.

## 4. Update and protocol watch

`cargo service update` is the only release-identity transition. The suite pins
the current MCP revision and crate baseline but treats protocol evolution as
expected. A scheduled review compares the official changelog, roadmap,
extension status, Rust SDK conformance, provider SDK releases, JSON Schema
libraries, and OpenTelemetry GenAI conventions. Changes are adopted through
ADR amendments and compatibility fixtures.

Preview and conformance tooling never enters a runtime profile merely because
a roadmap item exists. Conversely, settled standard behavior should replace
preview scaffolding rather than coexist indefinitely.

## 5. Release evidence

A release includes resolved Cargo graph, advisory/license report, profile builds, contract schemas/examples, provider cassette report, MCP conformance report, security matrix, load/failure evidence, eval report, operational runbooks, recommendation traceability, manifest hashes, and extraction rehearsal.

## 6. Suite-wide definition of done

All 118 acceptance criteria are independently verifiable and mapped to implementation tasks. Every recommendation has an acceptance criterion. Every runtime module has an explicit frontend exposure declaration and appears in at least one profile; tooling modules remain outside runtime profiles and run through their dedicated evidence commands. The base and web bundle validators and this extension validator all pass on the merged tree.

## 7. Acceptance linkage

This specification is verified by `AC-AI-113` through `AC-AI-120`.
