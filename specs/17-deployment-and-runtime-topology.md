---
spec_id: OMNIUS-017
title: Deployment and Runtime Topology
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Deployment and Runtime Topology


## Process topology

Supported deployable roles:

- Public API/server.
- Worker.
- Scheduler.
- Migration/admin job.
- Optional internal/admin API.

A small service may package subcommands in one image. Production permissions/config are role-specific.

## Container

Multi-stage build, reproducible dependency caching, pinned toolchain, non-root runtime, minimal filesystem, explicit CA certs/time-zone data needs, correct signal handling, read-only root where practical, writable temp policy, no compiler/package manager in runtime, healthcheck guidance, and OCI labels/SBOM/provenance.

Do not choose musl solely for image size without testing TLS/DNS/native dependencies and performance. Glibc slim is an acceptable default.

## Networking/TLS

Document whether TLS terminates at load balancer/proxy or process. Honor forwarded headers only from configured proxies. Admin listener is separately bound/restricted. Egress policy protects metadata/internal services.

## Migrations and rollout

Production deployment sequence:

1. Backup/restore readiness confirmed for risky changes.
2. Run expand-compatible migration under lock.
3. Deploy compatible new code gradually.
4. Monitor readiness/errors/queue/outbox.
5. Run restartable backfill.
6. Verify old-version absence.
7. Contract in a later release.

Server startup verifies schema range and refuses incompatible schema.

## Graceful rollout

Readiness turns false before listener drain. Termination grace exceeds service shutdown deadline plus margin. Workers stop leasing. Realtime clients receive reconnect guidance where possible.

## Configuration/secrets

Environment or mounted secret integration, no baked secrets, least privilege per role, rotation procedures, and startup validation.

## Local development

Compose file or equivalent starts only profile dependencies, has health checks, persists optional dev data, exposes no default credentials outside localhost, and provides reset/seed commands.

## Backup/recovery

Per stateful dependency define owner, backup/replication, retention, encryption, RPO/RTO, restore procedure, and rehearsal schedule. Object storage, PostgreSQL, NATS/queue state, feature provider, and identity-provider configuration are considered.

## Operational commands

`migrate`, `migration-status`, `backfill`, `reindex`, `replay-outbox`, `doctor`, and `inspect-config` are safe, idempotent where possible, observable, authorized by deployment permissions, and have dry-run for destructive/high-volume work.
