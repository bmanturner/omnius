---
title: Web accessibility, internationalization, and browser support
description: Current accessibility mechanisms, localization limits, pinned-engine coverage, and required manual review boundaries.
status: experimental
implementation: implemented
profile_availability:
  - web
  - realtime-web
  - saas-web
  - full-reference-web
public_exposure: unassembled
audience:
  - web developers
  - accessibility reviewers
  - release reviewers
topics:
  - accessibility
  - internationalization
  - browser-support
  - testing
capabilities:
  - web-accessibility-and-browser-support
source:
  - web/src/components/app-shell.tsx
  - web/src/router.tsx
  - web/index.html
  - web/browser-support.json
  - release/web-suite-runbook.md
evidence:
  - web/e2e/accessibility.spec.ts
  - web/e2e/browser.spec.ts
  - web/browser-support.json
last_verified: 2026-08-30
---

# Web accessibility, internationalization, and browser support

The checked-in web application has implemented accessibility mechanics and a defined browser-test policy, but the surface is not assembled into the active runtime. Automated checks cover representative fixture routes; they do not certify the whole application, production content, assistive-technology behavior, or release approval.

## Application accessibility baseline

The shared shell provides:

- a skip link targeting the main content;
- named navigation;
- one route-owned document title;
- a main region that can receive programmatic focus;
- focus movement after navigation;
- visible alert presentation for contract mismatch and route failures;
- semantic controls and labels in checked routes.

The main region uses `tabIndex=-1` so route changes can move focus without adding it to ordinary tab order. Route components must preserve that shell ownership rather than independently focusing arbitrary headings or controls.

For a navigation transition, the expected sequence is:

1. route state resolves;
2. the document title reflects the destination;
3. the main region receives focus;
4. a screen-reader user can identify the new page and continue through its content;
5. validation or workflow errors move or announce focus deliberately without trapping it.

If focus is lost, moves behind a dialog, or remains on a removed navigation control, correct the route/view lifecycle. Do not compensate with repeated timers or intrusive focus on every render.

## Keyboard behavior

Representative tests exercise skip navigation and keyboard traversal. Every assembled route still needs route-specific review:

- all actions reachable without a pointer;
- visible focus on interactive elements;
- logical tab order matching the rendered reading order;
- no keyboard trap in dialogs, menus, account actions, consent, file selection, or error recovery;
- native button and link semantics unless a custom interaction fully implements the required pattern;
- destructive and one-time-value actions identified before activation;
- loading states that do not disable the only recovery path.

A route passing an axe scan can still fail these interaction requirements.

## Automated accessibility scope

The checked Playwright accessibility source runs axe rules for WCAG 2.0, 2.1, and 2.2 at levels A and AA on representative routes. It also includes targeted keyboard assertions. This is useful regression evidence, not a declaration of conformance.

Current evidence gaps include:

- authenticated account routes;
- one-time API key disclosure and acknowledgement;
- OAuth authorization consent;
- tenant selection and transition;
- upload progress, quarantine, cancellation, and failure;
- responsive/mobile/touch interaction;
- comprehensive assistive-technology review;
- production content and runtime error states.

The release runbook separates automated results from bound manual accessibility evidence. Ordinary CI is not release-ready evidence until the required manual review is completed and approved for the exact release artifacts.

## Manual review boundary

A release-specific review should bind evidence to the web artifact, API artifact, contract hash, browser engine/version, viewport/input mode, and route state being examined. At minimum, review:

- landmarks, headings, titles, and language;
- route-change focus and skip navigation;
- full keyboard completion of primary journeys;
- form labels, instructions, validation summary, and field association;
- authentication, timeout, and cross-tab state changes;
- conflict and contract-mismatch recovery;
- one-time secret/key presentation without accidental repetition;
- zoom, reflow, text spacing, contrast, reduced motion, and high-contrast behavior where applicable;
- screen-reader announcements for loading, success, denial, and errors;
- touch target and mobile orientation behavior for supported layouts.

Record failures as release blockers according to the runbook. A generic accessibility sign-off from a different artifact or route set is not transferable.

## Current language and locale behavior

`web/index.html` declares English with `lang="en"`. The inspected route source formats dates using `Intl.DateTimeFormat("en-US")` in record, session, and connected-application views. Records are described with UTC-oriented date presentation. No application-wide message catalog, locale negotiation, pluralization framework, or user-selectable locale was identified.

Therefore:

- the current source is English-only in observed strings;
- hard-coded `en-US` date formatting is not locale-aware internationalization;
- browser locale must not be assumed to change the application language;
- future localization needs centralized message and formatting ownership rather than route-by-route string replacement;
- server timestamps and identifiers must remain semantically stable when presentation locale changes.

Do not claim localization or multilingual support from Unicode-capable inputs or `Intl` usage alone.

### Adding localized behavior

Before adding a locale, define:

1. how the locale is selected and validated;
2. which messages and metadata belong to the application catalog;
3. how dates, times, numbers, lists, and plural forms are formatted;
4. which values remain protocol or identifier strings and must not be translated;
5. how directionality and bidirectional text are isolated;
6. how route titles, errors, validation, and asynchronous announcements are covered;
7. fallback behavior for missing translations;
8. browser and accessibility verification for the added locale.

A locale preference may be durable non-secret state, but it must not carry identity authority or leak between tenants where locale is tenant-controlled.

## Browser support policy

`web/browser-support.json` defines support in terms of the Playwright-pinned engines used by the repository, not a broad long-term version promise.

| Engine target | Checked policy scope |
|---|---|
| Chromium Desktop | Full lane: actual Axum functional checks, browser-security negatives, representative accessibility and keyboard checks, and bundle/runtime budgets. |
| Firefox Desktop | Smoke lane: shell/deep links, reserved-route/capability behavior, headers, and representative axe coverage. |
| WebKit Desktop | Smoke lane: shell/deep links, reserved-route/capability behavior, headers, and representative axe coverage. |

This table describes intended test coverage from the checked policy file. It does not report that those checks passed, and it does not promise compatibility with every shipping browser or embedded webview derived from those engines.

When changing browser APIs, syntax targets, CSS, or security policy, evaluate the pinned engines and update policy evidence deliberately. The build targets ES2024, so an assembled deployment must ensure that its stated browser support and build output agree.

## Progressive failure handling

If an API is unavailable in a supported engine:

- preserve the core workflow when a secure, accessible fallback exists;
- make the unavailable enhancement explicit rather than silently failing;
- do not weaken authentication, upload integrity, or browser security to create a fallback;
- keep capability availability separate from browser feature availability;
- record the limitation in compatibility evidence before release.

For example, the auth manager has an in-memory fallback when `BroadcastChannel` is unavailable. That fallback does not provide cross-tab synchronization, so integration and user messaging should not claim cross-tab convergence in that environment.

## Verification checklist

An independent assembled-app review should observe all supported routes in the pinned browser lanes, keyboard completion, route focus, representative axe results, responsive states, localization behavior actually selected, and the required manual accessibility evidence. It must bind results to the exact release artifacts.

No browser, accessibility scanner, build, test, or manual review was run for this page. The checked tests and support policy describe intended coverage only; current release approval remains unverified.
