---
title: Identity and permissions troubleshooting
description: Diagnose Omnius password, session, API-key, OAuth, permission, membership, tenant, email, and audit symptoms without weakening security controls.
status: experimental
implementation: implemented
profile_availability:
  - authenticated-api
  - oauth-provider
  - saas
  - saas-pgmq
  - realtime
  - realtime-durable
  - full-reference
public_exposure: assembled
audience:
  - operator
  - developer
  - security-analyst
topics:
  - troubleshooting
  - identity
  - authorization
capabilities: []
source:
  - crates/reference-api/src/account_auth.rs
  - apps/api-server/src/main.rs
  - crates/auth-core/src/lib.rs
  - crates/authz-basic/src/lib.rs
  - crates/tenancy/src/lib.rs
evidence:
  - apps/api-server/tests/api_profile.rs
  - docs/coverage-matrix.md
last_verified: 2026-09-02
---

# Identity and permissions troubleshooting

The OAuth-provider reference API assembles password accounts, PostgreSQL browser sessions, API keys/service accounts, basic authorization, tenancy, hosted OAuth/OIDC behavior, and account email. JWT source is selected but disabled in the reference configuration. Redis sessions, upstream OIDC login, TOTP, WebAuthn, Cedar, privacy lifecycle, and audit query surfaces are not assembled.

Use the canonical [identity, authorization, and tenancy](../concepts/identity-authorization-and-tenancy.md) and exact [permission reference](../reference/permissions.md). Never reveal whether a secret credential, email, client, or account exists beyond the public error contract.

## Every API key attempt returns the same authentication failure

**Discriminating evidence:** safe authentication code, request correlation, key lifecycle metadata visible to an authorized operator, and server revision.

**Likely causes:** malformed/unknown/revoked/expired key, wrong key scope, disabled service account, or tenant mismatch. Uniform failure is intentional and prevents credential discovery.

**Safe diagnostic:** under approved operator access, inspect hashed-key metadata and service-account state by internal identifier. Never request the raw key or add distinct external errors.

**Resolution:** correct state/scope or issue a new key through the assembled administrative flow. Display secret material only at its defined one-time boundary and revoke compromised keys.

**Escalation data:** correlation, safe code, non-secret key/account identifier, status/expiry/scope, tenant, revision, and time.

No identity scenario was run while writing this page.

## A browser session is not accepted or repeatedly expires

**Discriminating evidence:** cookie presence attributes without value, session-record status/expiry, principal method/AAL, tenant membership, CSRF outcome, and server time.

**Likely causes:** missing/expired/revoked session, cookie origin/security mismatch, CSRF rejection, inactive user/membership, or database/session lookup failure.

**Safe diagnostic:** inspect cookie metadata in an approved browser and the protected session record. Do not copy cookie values into tickets, logs, or screenshots.

**Resolution:** correct origin/cookie deployment policy or account/membership state; reauthenticate when appropriate. Do not move sessions into browser storage or disable CSRF.

**Escalation data:** correlation, safe code, cookie attribute summary, session identifier/hash reference, expiry/status, principal method/AAL, and tenant membership state.

## An authenticated principal receives forbidden

**Discriminating evidence:** normalized principal subject/tenant/method/AAL/scopes, requested permission, object owner/tenant, active membership, and authorization decision code.

**Likely causes:** missing permission/scope, inactive membership, wrong tenant context, ownership mismatch, insufficient AAL, or a service-layer policy denial.

**Safe diagnostic:** compare the requested permission with the exact contract and authoritative membership/object state. Do not infer permission from UI roles, route visibility, or capability metadata.

**Resolution:** correct membership/scope/policy or the request's tenant/object context through authorized administration. Never bypass the service check or grant a broad role to repair one operation.

**Escalation data:** permission identifier, principal/tenant IDs under need-to-know access, method/AAL/scopes, membership status, object tenant/owner, decision code, revision.

## OAuth authorization or token exchange fails

**Discriminating evidence:** safe OAuth error, issuer/client identifier, redirect URI comparison, grant/code state, client authentication method, requested scopes, and server time—excluding tokens, codes, secrets, and signing material.

**Likely causes:** unknown/disabled client, redirect mismatch, invalid/expired/reused code, PKCE/client-auth failure, issuer/audience mismatch, unsupported scope, or secret/signing configuration placeholder.

**Safe diagnostic:** compare protected client registration and grant state with the request metadata. Verify configuration source/provenance without revealing secrets.

**Resolution:** correct client registration/request or rotate/revoke credentials under the approved plan. Do not loosen redirect matching, reuse codes, disclose whether a secret was close, or enable a different grant as a workaround.

**Escalation data:** safe error, client identifier, redirect hash/registered match result, scope set, grant state, timestamps, revision, and configuration provenance.

## Password registration, reset, or verification email does not arrive

**Discriminating evidence:** safe public response, committed account workflow state, bounded delivery-pool warning, mail kind, provider availability, and email configuration presence—never token or address unless strictly authorized.

**Likely causes:** mail configuration/provider failure after commit, bounded delivery pool full, expired/used workflow state, or intentionally uniform response for unknown accounts.

**Safe diagnostic:** confirm durable workflow state and redacted delivery outcome. The API can commit account state before asynchronous mail delivery reports a failure.

**Resolution:** restore provider configuration/capacity and use the authorized restart/reissue policy. Do not expose account existence or manually retrieve token values.

## A JWT is expected but bearer authentication is unavailable

**Discriminating evidence:** concrete reference configuration and mounted authentication mechanisms.

**Likely cause:** JWT module/profile selection was mistaken for enabled reference behavior.

**Resolution:** use the authentication mechanisms actually assembled, or explicitly compose/configure/review JWT in a new application revision. Do not infer it from the catalog.

## Audit history cannot be queried

**Discriminating evidence:** concrete audit sink and mounted operator/API surface.

**Likely cause:** the audit library is implemented but library-only, with no public query surface.

**Resolution:** compose protected storage/query behavior with permissions, tenant scope, retention, redaction, and lifecycle controls. Do not expose raw database tables or telemetry as a substitute.

See [security model](../security/security-model.md), [browser security](../security/browser-security.md), and [incident response](../operations/incident-response.md).