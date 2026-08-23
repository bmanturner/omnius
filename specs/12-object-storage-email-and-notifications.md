---
spec_id: RSK-012
title: Object Storage, Email, and Notifications
version: 0.1.0
status: normative
last_verified: 2026-08-23
---

# Object Storage, Email, and Notifications


## Object storage

Use Apache Arrow `object_store` by default. OpenDAL is optional only when its broader backend matrix is needed.

Default adapters: in-memory tests, local development, S3-compatible, GCS, Azure.

## Blob port

Support streaming put/get/range, metadata/head, delete, copy/move semantics, multipart upload, checksum/conditional operations, signed upload/download, and stable object keys. Handlers do not receive provider credentials/clients.

## Upload security

- Random server object keys.
- Normalized original filename only as metadata.
- Re-detect content where required.
- Size/multipart limits and checksums.
- Authorize signed URL issuance.
- Short expiry.
- Quarantine before processing/publication.
- External malware-scanner hook.
- Constrained parsing workers for risky media.
- Safe content disposition; never execute uploaded content.

## Lifecycle

Define owner/tenant prefix, retention, orphan cleanup, soft-delete window, legal hold, encryption, replication/backup ownership, and audit. Database/object changes use intent/job reconciliation; they are not one transaction.

## Email

Use `lettre` for message/SMTP and MiniJinja for runtime templates. Provider HTTP APIs use mature official SDKs or narrow reqwest adapters.

Support text+HTML, bounded attachments, internationalized headers, provider ID, idempotency, retry classification, bounce/complaint/delivery events, test sinks, preview command, template linting, snapshots, and redaction.

## Notifications

Product orchestration defines event, recipient, channels, preference category, mandatory exception, locale/time zone, template version, dedupe/digest, and delivery status. Normal delivery is a durable job, not synchronous HTTP work.

## Preferences/unsubscribe

Scoped optional-category unsubscribe; separate security/transactional classification; authenticated or signed single-purpose changes; opaque/signed tokens; audit.
