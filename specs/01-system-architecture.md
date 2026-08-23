---
spec_id: RSK-001
title: System Architecture
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# System Architecture


## Style

Use a Cargo workspace with explicit source composition. Major capabilities are crates; Cargo features are reserved for additive implementation details within a crate.

```text
service/
├── apps/
│   ├── server/
│   ├── worker/
│   ├── scheduler/
│   └── admin-cli/
├── crates/
│   ├── core/
│   ├── runtime/
│   ├── http-api/
│   ├── domain/
│   ├── persistence-postgres/
│   ├── cache-redis/
│   ├── auth-*/
│   ├── authorization/
│   ├── jobs-*/
│   ├── realtime/
│   ├── integrations-*/
│   └── test-support/
├── migrations/
├── config/
├── deploy/
├── specs/
└── xtask/
```

Small capabilities may share a crate when separation would be ceremonial.

## Dependency direction

```text
apps -> transport/infrastructure adapters -> application services -> domain/core
```

- Domain code does not depend on Axum, SQLx, Redis, reqwest, sessions, JWT, or telemetry.
- Transport adapters call application services.
- Persistence adapters do not leak row types.
- Application services depend on narrow ports only where a real volatile boundary exists.
- No global service locator or circular workspace dependency.

## Composition root

Each executable owns composition:

1. Parse CLI.
2. Load and validate config.
3. Initialize bootstrap logging and telemetry.
4. Build dependencies in order.
5. Verify migration compatibility.
6. Construct typed state.
7. Mount routes/start supervised tasks.
8. Mark startup complete and evaluate readiness.
9. Run until termination.
10. Drain and close in reverse order.

## State

Do not create a global structure full of optional infrastructure. Mount routes only when their dependencies exist and give route groups typed state containing exactly their capabilities.

## Request context

Canonical context includes:

- Request ID.
- Trace context.
- `Principal` or anonymous state.
- Tenant/organization context.
- Locale/time-zone hints.
- Client metadata after trusted-proxy processing.
- Deadline/cancellation signal.

Domain services receive only needed fields.

## Executable modes

The reference implementation supports:

```text
server
worker
scheduler
migrate
migration-status
seed
create-admin
backfill
reindex
replay-outbox
inspect-config
doctor
profile-info
```

## Command flow

```text
transport input
 -> boundary validation
 -> authentication
 -> request/tenant context
 -> application authorization
 -> use case/transaction
 -> outbox or durable job in same transaction when needed
 -> response
```

## Event flow

```text
domain event
 -> transactional outbox
 -> relay/worker
 -> broker, realtime projection, webhook, search, notification
 -> inbox/deduplication
```

Never publish externally before the state transaction commits.

## Criticality

Each module is:

- **Required:** failure prevents readiness.
- **Degraded:** affected capability is impaired but core service may remain ready.
- **Best effort:** failure is visible but does not affect serving.

Examples: primary PostgreSQL required; authoritative session store required; cache degraded; telemetry exporter best effort.

## Source composition

Modules are compiled into the service. Runtime settings can enable compiled routes/workers but do not remove dependencies or attack surface. Product feature flags are separate. Dynamic Rust library loading is out of scope.
