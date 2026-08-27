---
spec_id: OMNIUS-WEB-RES-001
title: Web Feature Suite Sources
version: 0.1.0
status: evidence
last_verified: 2026-08-24
---

# Web Feature Suite Sources

The following primary or project-maintainer sources informed this feature suite.

| Source ID | Source | URL | Use |
|---|---|---|---|
| `SRC-WEB-REACT-001` | React 19.2 announcement | <https://react.dev/blog/2025/10/01/react-19-2> | React baseline and current feature line. |
| `SRC-WEB-VITE-001` | Vite guide | <https://vite.dev/guide/> | Development and production build model. |
| `SRC-WEB-VITE-002` | Vite backend integration guide | <https://vite.dev/guide/backend-integration.html> | Traditional backend integration and manifest behavior. |
| `SRC-WEB-TANSTACK-QUERY-001` | TanStack Query React overview | <https://tanstack.com/query/latest/docs/framework/react/overview> | Remote/server-state ownership, caching, synchronization, retries, and invalidation. |
| `SRC-WEB-TANSTACK-ROUTER-001` | TanStack Router React overview | <https://tanstack.com/router/latest/docs/framework/react/overview> | Typed routing and URL search parameters. |
| `SRC-WEB-ORVAL-001` | Orval documentation | <https://orval.dev/> | OpenAPI TypeScript client and TanStack Query generation. |
| `SRC-WEB-ORVAL-002` | Orval Fetch guide | <https://orval.dev/docs/guides/fetch> | Native Fetch client generation. |
| `SRC-WEB-ORVAL-003` | Orval custom client guide | <https://orval.dev/docs/guides/custom-client> | Adapter/mutator boundary. |
| `SRC-WEB-ORVAL-004` | Orval v8 upgrade guide | <https://orval.dev/docs/versions/v8> | v8 behavior and migration. |
| `SRC-WEB-ORVAL-SEC-001` | Orval enum-description code-injection advisory | <https://github.com/orval-labs/orval/security/advisories/GHSA-h526-wf6g-67jv> | Evidence for trusted-input and exact-pin controls. |
| `SRC-WEB-ORVAL-SEC-002` | Orval MCP code-injection advisory | <https://github.com/orval-labs/orval/security/advisories/GHSA-mwr6-3gp8-9jmj> | Evidence for disabling unused MCP generation. |
| `SRC-WEB-ORVAL-SEC-003` | Orval mock-generation code-injection advisory | <https://github.com/orval-labs/orval/security/advisories/GHSA-f456-rf33-4626> | Evidence for disabling unused mock generation. |
| `SRC-WEB-OPENAPITS-001` | openapi-typescript 2026 roadmap | <https://github.com/openapi-ts/openapi-typescript/discussions/2559> | Maintainer announcement deprecating openapi-fetch and narrowing project scope. |
| `SRC-WEB-OPENAPITS-002` | openapi-typescript maintainers policy | <https://github.com/openapi-ts/openapi-typescript/blob/main/MAINTAINERS.md> | Records deprecation of non-core projects. |
| `SRC-WEB-ASYNCAPI-001` | AsyncAPI document concepts | <https://www.asyncapi.com/docs/concepts/asyncapi-document> | Asynchronous API document structure. |
| `SRC-WEB-ASYNCAPI-002` | AsyncAPI 3.0 specification | <https://www.asyncapi.com/docs/reference/specification/v3.0.0> | Channel, operation, message, and binding semantics used by 3.x. |
| `SRC-WEB-OPENAPI-001` | OpenAPI 3.1 specification | <https://spec.openapis.org/oas/v3.1.1.html> | HTTP API contract standard. |
| `SRC-WEB-TS-001` | TypeScript 6.0 announcement | <https://devblogs.microsoft.com/typescript/announcing-typescript-6-0/> | Stable bridge release and migration behavior. |
| `SRC-WEB-TS-002` | TypeScript 7.0 announcement | <https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/> | Native compiler release and compatibility claims. |
| `SRC-WEB-NODE-001` | Node.js release schedule | <https://github.com/nodejs/Release> | LTS policy and supported release lines. |
| `SRC-WEB-PNPM-001` | pnpm documentation | <https://pnpm.io/> | Workspace, lockfile, and package manager behavior. |
| `SRC-WEB-RHF-001` | React Hook Form documentation | <https://react-hook-form.com/get-started> | Form state and validation integration. |
| `SRC-WEB-ZOD-001` | Zod documentation | <https://zod.dev/> | TypeScript-first runtime schemas. |
| `SRC-WEB-ZUSTAND-001` | Zustand introduction | <https://zustand.docs.pmnd.rs/getting-started/introduction> | Optional client-local state primitive. |
| `SRC-WEB-VITEST-001` | Vitest guide | <https://vitest.dev/guide/> | Vite-native unit test runner. |
| `SRC-WEB-TESTINGLIB-001` | Testing Library guiding principles | <https://testing-library.com/docs/guiding-principles> | Behavior-focused component testing. |
| `SRC-WEB-MSW-001` | Mock Service Worker documentation | <https://mswjs.io/docs/> | Network-level API mocking. |
| `SRC-WEB-MSW-SOURCE-001` | MSW source repository | <https://github.com/mswjs/source> | Contract-derived handler generation candidate. |
| `SRC-WEB-PLAYWRIGHT-001` | Playwright test documentation | <https://playwright.dev/docs/intro> | Cross-browser E2E testing. |
| `SRC-WEB-TOWERHTTP-001` | tower-http ServeDir documentation | <https://docs.rs/tower-http/0.7.0/tower_http/services/struct.ServeDir.html> | Static file serving and fallback behavior. |
| `SRC-WEB-WCAG-001` | WCAG 2.2 recommendation | <https://www.w3.org/TR/WCAG22/> | Accessibility target. |
| `SRC-WEB-AXE-001` | axe-core repository | <https://github.com/dequelabs/axe-core> | Automated accessibility testing. |
| `SRC-WEB-OWASP-SESSION` | OWASP Session Management Cheat Sheet | <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html> | Cookie/session controls. |
| `SRC-WEB-OWASP-CSRF` | OWASP CSRF Prevention Cheat Sheet | <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> | CSRF defenses. |
| `SRC-WEB-OWASP-WS` | OWASP WebSocket Security Cheat Sheet | <https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html> | WebSocket authentication, origin, message, and lifecycle controls. |
| `SRC-WEB-OWASP-CSP` | OWASP Content Security Policy Cheat Sheet | <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html> | Production CSP policy. |
| `SRC-WEB-OWASP-UPLOAD` | OWASP File Upload Cheat Sheet | <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html> | Upload validation and quarantine. |
| `SRC-WEB-RFC9457` | RFC 9457 Problem Details | <https://www.rfc-editor.org/rfc/rfc9457.html> | HTTP error representation. |
| `SRC-WEB-SSE-001` | HTML Living Standard server-sent events | <https://html.spec.whatwg.org/multipage/server-sent-events.html> | EventSource and resume behavior. |
| `SRC-WEB-WEBSOCKET-001` | WebSockets Standard | <https://websockets.spec.whatwg.org/> | Browser WebSocket API behavior. |
