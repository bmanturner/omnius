# W0 frontend dependency admission

Verified 2026-08-27 under Node 24.19.0 and pnpm 11.23.0. This fixture is compatibility evidence, not product UI.

## Decision

Admit the exact lockfile graph for the web-suite baseline. Keep `@msw/source` out of the baseline. Apply ADR 0032's strict-type-compatible TanStack Router pins. TypeScript 7.0.2 is comparison-only; TypeScript 6.0.2 remains authoritative.

## Direct dependency findings

| Capability | Exact pins | Why admitted | License/source and maintenance | Security/build exposure |
|---|---|---|---|---|
| Runtime | `react`/`react-dom` 19.2.8 | Selected rendering runtime; established alternatives would change ADR 0009 | MIT; official React registry releases; current stable | No registry lifecycle scripts |
| Remote and URL state | `@tanstack/react-query` 5.102.2, `@tanstack/react-router` 1.170.1, `@tanstack/router-plugin` 1.168.2 | Avoids hand-built caching/routing and satisfies ADR 0011 | MIT; maintained TanStack registry releases | Router plugin is build-time code generation. Exact pins and reviewed output required. ADR 0032 records why the proposed Router 1.170.32 family was rejected. |
| Forms and schemas | `react-hook-form` 7.86.0, `zod` 4.4.3 | Selected form lifecycle and runtime schema validation | MIT; maintained official registry releases | No registry install hooks; server validation remains authoritative |
| Optional local state | `zustand` 5.0.15 | Only for declared client-local state in profiles that select it | MIT; maintained pmndrs registry release | Must not mirror Query resources, identity, tenant, permissions, or credentials |
| Build | `vite` 8.2.2, `@vitejs/plugin-react` 6.1.0 | Selected development/build infrastructure | MIT; maintained official releases | `esbuild` 0.28.2 is the sole allowed install build. Production source maps are disabled in the fixture. |
| HTTP generation | `orval` 8.26.0 | Maintained OpenAPI Fetch generator; deprecated `openapi-fetch` family remains excluded | MIT; latest official release on 2026-08-23; Node >=22.18 | No Orval lifecycle hook. It includes mock/MCP/Zod generator code transitively, so config fixes `mock: false`, Fetch client only, validation enabled, and external refs `allow: []`. Input is repository-local and generation is secret-free. Published Orval advisory ranges are patched before 8.26.0. |
| Unit/component tests | `vitest` 4.1.11, Testing Library React 16.3.2/DOM 10.4.1/user-event 14.6.6, `jsdom` 30.0.1, `msw` 2.15.0 | Selected behavior-test and browser API mocking tools | MIT; maintained official releases | Vitest 4.1.11 is beyond the 4.1.10 browser-mode advisory fix. MSW's postinstall is explicitly denied; no worker directory is configured. Unhandled MSW requests fail tests. |
| Browser/a11y | Playwright 1.62.1, axe-core and `@axe-core/playwright` 4.13.0 | Selected real-browser and accessibility engines | Apache-2.0 and MPL-2.0; maintained official releases | Browser artifacts and auth state are treated as sensitive later in CI. Current engine downloads: Chromium 151.0.7922.34, Firefox 153.0, WebKit 26.5. |
| Toolchain | TypeScript 6.0.2; comparison alias 7.0.2; pnpm 11.23.0 | Strict compilation and frozen deterministic installs | Apache-2.0 / MIT; official registry releases | TypeScript 7 passes this fixture but is not adopted because its compiler API/tooling migration gate remains open. pnpm permits only the explicit `esbuild` build and denies MSW. |
| Type companions | React/DOM/Node/debug/picomatch exact `@types` pins plus Faker 10.6.0 | Required for `skipLibCheck: false` across application, generator config, tests, and Vite/Playwright declarations | MIT; official registry packages | Faker is present solely because Orval's public declarations reference its types; it is not used to generate runtime fixtures. |

## Resolved graph review

`pnpm-lock.yaml` records registry integrity for 408 resolved packages. Intentional parallel lines are TypeScript 6/7 for the comparison gate and Zod 3 (generator transitive) plus Zod 4 (application runtime). One React 19.2.8 line and one Query Core 5.102.2 line are selected. The admitted TanStack Router pair resolves its declared Router Core 1.170.1 without overrides.

`pnpm audit --audit-level high` reports no known vulnerabilities. `pnpm licenses list --json` reports only MIT, MIT-0, MPL-2.0, Apache-2.0, ISC, Python-2.0, CC-BY-4.0, BSD-2-Clause, BSD-3-Clause, Unlicense, BlueOak-1.0.0, CC0-1.0, and `(MIT OR CC0-1.0)`. These are accepted for this development/tooling graph; no unknown, AGPL, GPL, SSPL, or unreviewed git license/source is present.

The committed lifecycle policy is deny-by-default: `allowBuilds.esbuild: true`, `allowBuilds.msw: false`, and no unrestricted build allowance. Frozen installation succeeds.

## Compatibility evidence

The following pass with the pinned Node and package manager:

- trusted local Orval generation from `contracts/openapi.json` with mocks/external refs disabled;
- TypeScript 6.0.2 full-graph and generated-only checks with `skipLibCheck: false`;
- TypeScript 7.0.2 comparison checks without changing the baseline;
- Vitest/Testing Library/MSW behavior tests;
- Vite React production build without source maps;
- Playwright and axe smoke in Chromium, Firefox, and WebKit;
- frozen pnpm installation, audit, and license inventory.

`@msw/source` 0.6.1 is technically compatible with Node 24 and MSW 2.15.0 but is excluded: it is pre-1.0, has a narrower maintenance base, and adds no value over trusted hand-authored handlers for the baseline. Reconsider it only through a separate trusted-input generation-fidelity gate.

## Primary evidence

- Node release index and schedule: https://nodejs.org/dist/index.json and https://github.com/nodejs/Release
- pnpm 11.23.0 registry metadata and build policy: https://registry.npmjs.org/pnpm/11.23.0 and https://pnpm.io/settings#allowbuilds
- TypeScript releases: https://registry.npmjs.org/typescript/6.0.2 and https://devblogs.microsoft.com/typescript/announcing-typescript-7/
- React/Vite/TanStack metadata: https://registry.npmjs.org/react/19.2.8, https://registry.npmjs.org/vite/8.2.2, https://registry.npmjs.org/@tanstack%2freact-router/1.170.1
- TanStack advisory: https://github.com/advisories/GHSA-g7cv-rxg3-hmpx
- Orval release/security: https://registry.npmjs.org/orval/8.26.0 and https://github.com/orval-labs/orval/security/advisories
- Vitest advisory: https://github.com/advisories/GHSA-p63j-vcc4-9vmv
- Test/a11y metadata: https://registry.npmjs.org/vitest/4.1.11, https://registry.npmjs.org/msw/2.15.0, https://registry.npmjs.org/@playwright%2ftest/1.62.1, https://registry.npmjs.org/@axe-core%2fplaywright/4.13.0
