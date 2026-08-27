---
spec_id: OMNIUS-ADR-0032
title: Pin the Last Strict-Type-Compatible TanStack Router Family
version: 0.1.0
status: accepted
last_verified: 2026-08-27
---

# ADR 0032: Pin the Last Strict-Type-Compatible TanStack Router Family

## Context

The web-suite dependency baseline proposed `@tanstack/react-router` 1.170.32 as an initial W0 lock target. Its published manifest requires `@tanstack/router-core` 1.171.27. Under the required TypeScript 6.0.2 strict declaration check, that core release fails in its own `dist/esm/ssr/types.d.ts`: `MakeRouteMatch` does not contain `__beforeLoadContext`.

The same failure occurs with React Router 1.170.31 and Router Core 1.171.26. `skipLibCheck` would hide the incompatibility and is therefore rejected. React Router 1.170.1 and Router Core 1.170.1 compile with `skipLibCheck: false`; the corresponding Router Plugin 1.168.2 accepts React Router `^1.170.1` and also compiles in the pinned Vite 8.2.2 graph.

## Decision

Pin the initial production baseline to:

- `@tanstack/react-router` 1.170.1;
- `@tanstack/router-plugin` 1.168.2;
- the exact transitive `@tanstack/router-core` 1.170.1 selected by that React Router release.

Keep TypeScript declaration checking enabled. Do not override an exact TanStack dependency, patch installed declarations, or suppress library diagnostics. The remainder of the selected React, Query, Router, and Vite architecture is unchanged.

## Alternatives considered

- **Keep 1.170.32 and enable `skipLibCheck`: rejected.** It would make the mandated strict compatibility gate green by hiding a real upstream declaration error.
- **Override Router Core to an older release:** rejected. The newer React Router packages declare exact core dependencies; an override would create an untested runtime pair.
- **Remove TanStack Router or hand-build routing:** rejected. This violates ADR 0009 and the no-reinvention policy.
- **Wait for a future upstream patch:** rejected for the initial implementation because a maintained, advisory-clear compatible pair already exists.

## Security and compatibility evidence

The selected versions are registry releases from the maintained TanStack Router repository. The known 2026 TanStack package-compromise advisory affected different exact versions, including React Router 1.169.5 and Router Plugin 1.167.38; it does not include the selected pair. The lockfile records registry integrity hashes and W0 runs frozen installation plus strict TypeScript 6 and comparison TypeScript 7 checks.

## Consequences

- The dependency baseline and lockfile record a deliberate patch-level downgrade from the initial lock target.
- Router upgrades require strict TypeScript 6 and 7 declaration checks before admission.
- The generator must retain exact pins and must not float the Router family.
- Risk `R-WEB-025` tracks accidental reintroduction of the broken declaration family.

## Migration

No production frontend existed before this decision, so no application migration is required. A generated project on the original unverified target must update both Router packages together, reinstall from the lockfile, regenerate its route tree, and pass strict typecheck plus browser navigation smoke tests.

## Traceability

This amendment preserves `AC-WEB-006`, `AC-WEB-021`, `AC-WEB-074`, `AC-WEB-077`, and `AC-WEB-079`. It changes only the dependency pins used to satisfy those criteria.
