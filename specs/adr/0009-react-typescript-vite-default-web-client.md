---
spec_id: OMNIUS-ADR-0009
title: Use React, TypeScript, and Vite for the Default Web Client
version: 0.1.0
status: accepted
last_verified: 2026-08-24
---

# Use React, TypeScript, and Vite for the Default Web Client

## Context

The service kit needs a browser implementation with broad ecosystem support, mature testing, straightforward static output, and no required JavaScript production server. The backend architecture must remain usable by other frontend frameworks.

## Decision

The default `web` profile uses React, TypeScript, and Vite.

- React provides the default UI runtime.
- TypeScript is mandatory under strict settings.
- Vite provides development HMR, proxying, and production static output.
- The framework-neutral SDK contains no React dependency.
- Product UI remains application-owned.
- No component library, CSS solution, or design system is selected here.

## Rationale

This combination is well understood, works with a static-production topology, and integrates with mature Router, Query, testing, and accessibility tooling. It does not require Axum to emulate frontend development infrastructure.

## Consequences

- A pinned Node LTS and package manager become build dependencies for web profiles.
- The release process must scan both Rust and Node dependency graphs.
- Alternative web frameworks require adapters and an ADR but can reuse the contracts and client core.
- SSR is not implied.

## Rejected alternatives

- A hand-written DOM client: too much infrastructure and poor ecosystem leverage.
- A mandatory JavaScript SSR server: unnecessary operational complexity for the baseline.
- Leptos as the sole default: attractive for all-Rust deployments but a smaller frontend ecosystem and weaker portability for non-Rust consumers.
- Framework-neutral product UI: tends to produce a lowest-common-denominator abstraction.
