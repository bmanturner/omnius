The best approach is evidence-driven documentation with centralized integration, not “give every crate to an agent and merge whatever comes
 back.” With 60+ crates and extensive specifications, uncontrolled parallel writing would create duplication, inconsistent terminology, and
 documentation for features that are specified but not actually implemented.

 1. Establish the documentation contract

 Use plain Markdown with portable YAML frontmatter:

 ```yaml
---
title: Configuration
description: Loading, layering, validating, and securing service configuration.
status: stable
audience:
  - application-developer
topics:
  - configuration
  - secrets
source:
  - crates/config/src/lib.rs
  - specs/04-configuration-and-secrets.md
last_verified: 2026-08-26
---
 ```

 Recommended rules:

 - status: experimental, stable, or deprecated
 - Document only implemented behavior as available.
 - Specifications explain architectural intent.
 - Code, tests, schemas, and executable behavior prove what currently works.
 - Every command and example must be exercised.
 - Use relative Markdown links.
 - Do not reproduce exhaustive Rust APIs; leave that to rustdoc.
 - Only one page owns each concept.

 2. Start with a coherent documentation skeleton

 ```text
docs/
├── README.md
├── getting-started/
│   ├── quickstart.md
│   └── project-layout.md
├── concepts/
│   ├── architecture.md
│   ├── modules-and-profiles.md
│   ├── explicit-composition.md
│   └── runtime-lifecycle.md
├── guides/
│   ├── configuration.md
│   ├── http-api.md
│   ├── persistence.md
│   ├── authentication.md
│   ├── authorization.md
│   ├── jobs-and-events.md
│   └── observability.md
├── reference/
│   ├── generator-cli.md
│   ├── profiles.md
│   ├── modules.md
│   ├── configuration.md
│   └── error-model.md
├── operations/
│   ├── deployment.md
│   ├── graceful-shutdown.md
│   ├── health-and-readiness.md
│   ├── security.md
│   └── upgrades.md
├── development/
│   ├── testing.md
│   └── creating-a-module.md
└── glossary.md
 ```

 Organize module documentation around user-facing capabilities, not mechanically around every crate. Several crates often collaborate to provide
 one capability.

 3. Use a wave-based agent swarm

 ### Wave 1: Evidence inventory

 Run 7–8 read-only agents concurrently:

 1. Core, runtime, configuration, and health
 2. HTTP, validation, pagination, and OpenAPI
 3. PostgreSQL, Redis, caching, and rate limiting
 4. Authentication, authorization, tenancy, and audit
 5. Jobs, events, scheduling, outbox, and inbox
 6. Realtime, storage, notifications, and webhooks
 7. Generator, modules, profiles, and upgrades
 8. Operations, testing, deployment, and supply chain

 Each returns a structured brief:

 ```text
Implemented behavior:
Public entry points:
Runnable examples:
Configuration:
Failure modes:
Relevant tests:
Relevant specifications and ADRs:
Claims that could not be verified:
Recommended documentation pages:
 ```

 These agents should not write documentation yet. This prevents the specifications—especially future web and AI work—from being mistaken for
 implemented functionality.

 ### Wave 2: Information architecture

 One integration owner consolidates the briefs and creates:

 - the final page inventory
 - canonical terminology
 - page ownership
 - cross-link map
 - source assignments
 - explicit exclusions for unimplemented features

 This ownership map is the critical orchestration artifact.

 ### Wave 3: Parallel writing

 Assign non-overlapping files or directories to writing agents. For example:

 - Agent A: getting-started/
 - Agent B: foundational concepts/
 - Agent C: HTTP and persistence guides
 - Agent D: identity and security guides
 - Agent E: jobs, realtime, and integration guides
 - Agent F: reference/
 - Agent G: operations/
 - Agent H: development/

 No parallel agent should modify:

 - docs/README.md
 - docs/glossary.md
 - navigation or page manifests
 - shared terminology files

 Those remain owned by the integration agent.

 Each writer must:

 1. Read the evidence brief.
 2. Confirm claims against source and tests.
 3. Run every documented command.
 4. Use the common frontmatter and page template.
 5. Link to related pages rather than duplicating explanations.
 6. Report any source/documentation contradiction.

 ### Wave 4: Independent review

 Use separate reviewers with different mandates:

 - Accuracy reviewer: every claim matches current code.
 - User-journey reviewer: a new Rust developer can complete the quickstart.
 - Consistency reviewer: terminology, links, frontmatter, and conceptual boundaries.
 - Security reviewer: examples do not recommend unsafe production defaults.

 Writers should not approve their own pages.

 ### Wave 5: Integration and verification

 The integration owner:

 - resolves review findings
 - creates docs/README.md
 - creates the glossary
 - adds cross-links
 - removes duplicate explanations
 - runs all documented workflows
 - performs the final link and frontmatter checks

 4. Add a lightweight documentation validator

 I would add a command such as:

 ```bash
cargo xtask docs verify
 ```

 It should check:

 - every Markdown file has valid required frontmatter
 - titles and paths are unique
 - source paths exist
 - internal relative links resolve
 - no page is orphaned
 - statuses use the allowed vocabulary
 - fenced Rust/TOML/JSON examples are syntactically valid where practical
 - no placeholder markers remain

 Later, it can detect stale pages when their recorded source files change after last_verified.

 5. Keep the first pass deliberately small

 The first useful release should be approximately 12–18 strong pages:

 1. Overview
 2. Quickstart
 3. Project layout
 4. Architecture
 5. Modules and profiles
 6. Explicit composition
 7. Runtime lifecycle
 8. Configuration
 9. HTTP API
 10. Persistence
 11. Authentication
 12. Authorization
 13. Jobs and events
 14. Observability
 15. Generator CLI
 16. Operations/deployment
 17. Testing
 18. Upgrades

 That creates a navigable user journey. A swarm producing 60 shallow crate pages would be substantially less useful.

 Recommended orchestration principle

 ▏ Agents gather and write in parallel; one owner controls structure, terminology, navigation, and final truth.
