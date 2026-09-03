---
title: Minimal-service quickstart
description: Run the checked-in no-external-service reference process and verify its assembled HTTP and lifecycle surface without implying broader profile availability.
status: experimental
implementation: implemented
profile_availability: []
public_exposure: assembled
audience:
  - evaluator
  - rust-application-developer
topics:
  - getting-started
  - quickstart
  - http
  - health
capabilities:
  - minimal-reference-service
  - minimal-http-surface
source:
  - apps/server/src/main.rs
  - apps/server/Cargo.toml
  - config/minimal.toml
evidence:
  - apps/server/tests/minimal_service.rs
  - crates/health/src/lib.rs
last_verified: 2026-08-30
---

# Minimal-service quickstart

This path runs the checked-in `omnius-minimal-server` package. It needs no database, cache, broker, identity provider, LLM provider, or MCP client.

> **Composition boundary:** this proves only the checked-in `apps/server` composition. Its public routes are `/live`, `/ready`, `/startup`, `/version`, and `/example`. It does not assemble identity, persistence, jobs, realtime, web assets, LLM, MCP, or an operator/admin listener. The app's compiled metadata is also not proof that every module selected by the machine `minimal` profile was rendered into this checked-in app.

## Audience path

Use this page for the shortest concrete evaluation. Continue to configuration and HTTP guidance before changing the service, or to [choose a profile](choose-a-profile.md) before selecting additional modules.

## Prerequisites

Run every command from the repository root. You need:

1. the Rust toolchain selected by `rust-toolchain.toml`;
2. Cargo access to already cached dependencies or the configured dependency sources;
3. `curl` for the HTTP checks;
4. local TCP port `8080` available on `127.0.0.1`.

No secret or external-service configuration is required by `config/minimal.toml`.

## 1. Start the service

In terminal A, from the repository root:

```bash
cargo run --locked -p omnius-minimal-server -- server --config config/minimal.toml
```

**Expected result:** after compilation and bootstrap messages, the process reports:

```text
startup complete listen_address=127.0.0.1:8080
```

The process remains attached to the terminal. Startup is not complete until that line appears.

**Failure path:**

- If Cargo cannot compile or resolve dependencies, fix the pinned Rust toolchain or dependency access before continuing.
- If configuration loading or validation fails, the process exits nonzero and prints `service failed code=...`; correct the named configuration source rather than adding secrets to the checked-in file.
- If port `8080` is occupied, stop the conflicting local process or restart this service with the source-supported override:

  ```bash
  cargo run --locked -p omnius-minimal-server -- server --config config/minimal.toml --listen-address 127.0.0.1:8081
  ```

  Use port `8081` in every following URL when choosing that override.

## 2. Check readiness and metadata

In terminal B, from the repository root:

```bash
curl --fail-with-body --silent --show-error http://127.0.0.1:8080/ready
curl --fail-with-body --silent --show-error http://127.0.0.1:8080/version
```

**Expected result:** readiness returns HTTP 200 with JSON containing `"status":"ready"`; version returns HTTP 200 with JSON containing `"profile":"minimal"` and the app's safe compiled module metadata.

**Failure path:** a connection failure means the listener did not start at that address. A non-2xx response means the probe is not successful; read terminal A's safe error code and startup phase before retrying. Do not treat `/live` as a substitute for `/ready`.

## 3. Call the example route

```bash
curl --fail-with-body --silent --show-error http://127.0.0.1:8080/example
```

**Expected result:**

```json
{"message":"hello from minimal-reference"}
```

**Failure path:** HTTP 404 means the request reached a different composition or path. Other non-2xx responses are emitted through the HTTP error boundary; preserve the response's request ID when diagnosing the failure.

## 4. Stop cleanly

Press `Ctrl-C` once in terminal A.

**Expected result:** the service marks itself draining, stops accepting new traffic, shuts down supervised work, flushes telemetry within its configured deadline, and exits successfully.

**Failure path:** a second termination signal forces cancellation and exit status 130. Use it only when the first bounded drain cannot complete; a listener-drain deadline is reported as a nonzero service failure.

## What this proves

This quickstart proves a local execution path for one checked-in application and the five routes its source mounts. It does not prove that another profile has been generated, that optional libraries are assembled, or that a committed consumer artifact is served by this process. Apply the classifications in the [availability and exposure matrix](../reference/availability-and-exposure-matrix.md) to every next capability.

## Evidence

- [Minimal binary and composition root](../../apps/server/src/main.rs)
- [Minimal package identity](../../apps/server/Cargo.toml)
- [Secret-free local configuration](../../config/minimal.toml)
- [Black-box route and drain contract](../../apps/server/tests/minimal_service.rs)
- [Authoritative profile selection data](../../specs/machine/profiles.yaml)

## Next

- [Configuration and secrets](../guides/backend/configuration-and-secrets.md)
- [HTTP APIs](../guides/backend/http-apis.md)
- [Health, readiness, and shutdown](../operations/health-readiness-and-shutdown.md)
