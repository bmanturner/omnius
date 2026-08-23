---
spec_id: ADR-0007
title: Use object_store as the Default Blob Abstraction
version: 0.1.0
status: accepted
last_verified: 2026-08-23
---

# Use object_store as the Default Blob Abstraction


## Context

The service kit needs local development, tests, and production object storage without exposing provider SDKs throughout the application. Several broad storage abstraction crates exist.

## Decision

Use Apache Arrow's `object_store` crate as the default provider abstraction.

Default supported backends:

- In-memory.
- Local filesystem.
- S3-compatible.
- Google Cloud Storage.
- Azure Blob Storage.

OpenDAL is an optional replacement only when its broader service matrix is required and compatibility/security review passes.

The service kit adds a narrow product-facing `BlobStore` capability for ownership, authorization, signed access, quarantine, retention, and reconciliation.

## Consequences

- Provider-specific advanced features may require an escape hatch or dedicated adapter.
- Application code does not depend on AWS/GCS/Azure SDK types.
- Object/database consistency remains an application workflow, not a fake distributed transaction.
- Upload scanning and media processing are external worker/service hooks.

## Validation

The same contract suite runs against memory, local filesystem, and an S3-compatible Testcontainer/emulator where practical. Range requests, multipart limits, checksums, signed access, and orphan reconciliation are tested.
