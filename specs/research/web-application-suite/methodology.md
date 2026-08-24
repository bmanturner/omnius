---
spec_id: RSK-WEB-RES-002
title: Web Feature Suite Research Methodology
version: 0.1.0
status: evidence
last_verified: 2026-08-24
---

# Web Feature Suite Research Methodology

## Scope

Research focused on established project documentation, standards, official release information, maintained package metadata, and security advisories for the default web profile.

## Selection method

A technology was favored when it:

- directly fits the architecture rather than requiring broad custom infrastructure.
- is maintained by an established project or standards body.
- has mature TypeScript and browser ergonomics.
- interoperates with generated OpenAPI/AsyncAPI contracts.
- supports strict testing and observable failure behavior.
- has a manageable dependency and security posture.
- can be replaced behind a narrow adapter when the risk is nontrivial.

Popularity alone was not treated as proof of fitness. Exact versions are lock targets subject to package-manager resolution and compatibility experiments.

## Source priority

1. Standards and official project documentation.
2. Official release announcements and package metadata.
3. Maintainer roadmaps.
4. Reviewed security advisories.
5. Secondary commentary only when it exposes a question to verify against primary sources.

## Security treatment

Code generators were reviewed as executable build dependencies. The selection records both features and adverse security history. The presence of patched advisories did not automatically disqualify a tool; it resulted in strict input, pinning, isolation, scanning, and adapter controls.

## Temporal policy

The dependency baseline was verified on August 24, 2026. W0 MUST repeat package resolution and advisory checks because JavaScript packages and security status change quickly.

## Reuse policy

The suite avoids new implementations where mature tools exist:

- Vite rather than custom frontend dev/HMR infrastructure.
- tower-http rather than a custom static server.
- TanStack Query rather than a homegrown server-state cache.
- TanStack Router rather than a homegrown typed router.
- Orval rather than handwritten endpoint clients.
- React Hook Form rather than a bespoke form state engine.
- MSW and Playwright rather than custom network/browser harnesses.
- standards-based OpenAPI, AsyncAPI, JSON Schema, and RFC 9457 contracts.

Custom code remains necessary at the application-specific seams: auth lifecycle, query-effect metadata, uploads, contract assembly, and module composition.
