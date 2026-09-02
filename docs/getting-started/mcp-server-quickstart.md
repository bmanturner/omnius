---
title: Authenticated MCP server quickstart
description: Run and inspect the dedicated OAuth-authenticated reference MCP application over stateless Streamable HTTP.
status: experimental
implementation: implemented
profile_availability:
  - mcp-http
  - mcp-enterprise
  - ai-platform
  - full-reference-ai
public_exposure: assembled
audience:
  - mcp-developer
  - evaluator
topics:
  - mcp
  - quickstart
  - oauth
  - verification
capabilities: []
source:
  - apps/mcp-server/src/main.rs
  - apps/mcp-server/src/lib.rs
  - crates/reference-api/src/oauth_provider.rs
  - crates/mcp-transport-http/src/lib.rs
  - specs/42-mcp-server-architecture-and-capability-exposure.md
evidence:
  - apps/mcp-server/tests/authenticated_mcp.rs
  - apps/mcp-server/tests/process_lifecycle.rs
  - apps/api-server/tests/api_service.rs
last_verified: 2026-09-02
---

# Authenticated MCP server quickstart

The checked-in `apps/mcp-server` process serves one authenticated, globally scoped reference capability over stateless Streamable HTTP. It mounts:

- `POST /mcp`;
- `GET /.well-known/oauth-protected-resource/mcp`;
- the single tool `reference_records.list.v1`.

`apps/api-server` remains the authorization-server and REST application. It issues tokens for the separately declared MCP resource but does not mount `/mcp` or the MCP protected-resource metadata route. The MCP process does not mount authorization-server routes.

## Prerequisites

Work from the repository root with:

1. PostgreSQL reachable through the resolved `postgres` configuration and the repository migrations applied according to the selected launch policy;
2. a fully resolved `config/reference.toml` layer plus `config/mcp.toml`, or equivalent hierarchical `OMNIUS__SECTION__FIELD` environment keys;
3. an authorization-server issuer configured with exactly two reference resources: the issuer-root API resource and the same issuer with `/mcp` appended;
4. the exact MCP resource scope `reference-records:read` and valid RSA signing material;
5. a live, non-tenant OAuth grant and access token whose audience is the exact MCP resource.

TOML strings are literal. Do not put shell-style placeholders in a TOML layer and expect the loader to interpolate them.

## Start the dedicated process

```bash
cargo run -p omnius-mcp-server -- server \
  --config config/reference.toml \
  --environment-config config/mcp.toml
```

The development overlay listens on `127.0.0.1:8090`. The process validates configuration, applies the configured direct-launch migration policy, connects its own PostgreSQL pool and token-state verifier, assembles MCP, and then marks readiness. `migrate`, `migration-status`, and `profile-info` are separate subcommands.

## Inspect protected-resource metadata

```bash
curl --fail --silent --show-error \
  http://127.0.0.1:8090/.well-known/oauth-protected-resource/mcp
```

The response names the exact issuer-plus-`/mcp` resource, the issuer as its sole authorization server, `reference-records:read` as its sole scope, header bearer presentation, and `RS256`. The route is public metadata; bearer authentication applies only to the MCP router.

## List the reference tool

Set `MCP_ACCESS_TOKEN` to a live access token minted by the configured authorization server for the exact MCP resource and scope. Then send a complete stateless request:

```bash
curl --fail-with-body --silent --show-error \
  -H 'Host: localhost' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Mcp-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/list' \
  -H "Authorization: Bearer $MCP_ACCESS_TOKEN" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"reference-quickstart","version":"1.0.0"}}}}' \
  http://127.0.0.1:8090/mcp
```

The result contains exactly `reference_records.list.v1`. Call it with `tools/call`, matching `Mcp-Method: tools/call` and `Mcp-Name: reference_records.list.v1`; accepted arguments are optional `limit` (1–100), `cursor`, and `name`. The tool reads one bounded page from the PostgreSQL reference-record repository.

Resources, resource templates, prompts, elicitation, subscriptions, tasks, Apps, Skills, completion, and progress are not contributed by this reference application. Their methods are unadvertised and return JSON-RPC method-not-found (`-32601`; HTTP 404) rather than an empty or synthetic implementation.

## Authentication failures

Every MCP request requires exactly one well-formed Authorization-header bearer credential. Query tokens are forbidden.

| Failure | HTTP status | Challenge error |
|---|---:|---|
| Missing bearer credential | 401 | no `error` parameter |
| Duplicate, malformed, or query bearer presentation | 400 | `invalid_request` |
| Bad signature, expiry, revocation/live-state failure, wrong issuer, or wrong audience/resource | 401 | `invalid_token` |
| Authenticated token missing `reference-records:read` | 403 | `insufficient_scope` |

Every rejection includes `WWW-Authenticate: Bearer ... resource_metadata="<issuer>/.well-known/oauth-protected-resource/mcp", scope="reference-records:read"` and `Cache-Control: no-store`. The boundary intentionally does not disclose which cryptographic, lifetime, revocation, or live-state check failed. A tenant-bearing identity is also rejected because the reference tool is globally scoped.

## Continue

- [Server architecture and capability exposure](../guides/mcp/server-architecture.md)
- [Authentication, authorization, and tenancy](../guides/mcp/authentication-authorization-and-tenancy.md)
- [Discovery, versioning, and transports](../guides/mcp/discovery-versioning-and-transports.md)
- [MCP protocol support](../reference/mcp-protocol-support.md)
