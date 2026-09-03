# {{project-name}}

Generated Omnius service using the `{{ profile }}` base profile.

## Thin application boundary

This repository is an independent application workspace. Its Rust workspace
starts with only `apps/service` and declares one managed Omnius dependency:
the `service-kit` alias selects `omnius-service-kit` from the canonical HTTPS
Git repository at the exact version and full immutable revision recorded in
`.omnius/service.toml`. Framework source, framework migrations, lifecycle
tooling, specifications, templates, and root `.sqlx` metadata are not copied
into this project.

Application code, assets, contracts, configuration, operations files, and
reserved-range migrations live here. Files recorded as application-owned,
including this README and `apps/service/src/application.rs`, are never
overwritten. Profile-provided web, SDK, and contract application templates are
created only when missing, immediately become application-owned, and survive
module removal, re-add, and profile changes. Managed regions and derived files
remain explicitly identified in strict schema-2 state. `Cargo.lock` is
committed and validated semantically as the shared dependency lock.

Runtime profiles never contain lifecycle, generator, testing, evaluation,
preview, or conformance tooling. The `test-support` kit feature is enabled only
by the generated dev-dependency.

## Lifecycle

Use the separately installed `cargo-service` subcommand, never a project-owned
`xtask`:

```console
cargo service doctor
cargo service diff
cargo service add <MODULE> --dry-run
cargo service profile set <PROFILE> --dry-run
cargo service update --dry-run
```

Remove `--dry-run` only after reviewing the sealed file, package-graph, and
lock diff. Mutating commands require a clean, immutable CLI release matching
the project; `update` is the only identity transition. Add `--offline` to a
mutating command for canonical Cargo-cache-only resolution. It is not a
vendoring mode.

## Run locally

The checked-in base configuration binds only to loopback. The process
automatically loads the selected `config/reference.toml` overlay:

```console
cargo run --locked -p {{project-name}} -- server
```

Override the reference layer with `--environment-config` or the listener with
`OMNIUS__SERVER__LISTEN_ADDRESS`. Persisted profiles require
`OMNIUS__POSTGRES__URL`; it is not written to the overlay. Idempotency does not
require a pagination cursor-signing secret. TOML `${...}` strings are literal
and do not read process variables.

Inspect the resolved profile without starting a listener:

```console
cargo run --locked -p {{project-name}} -- profile-info
```

The public base surface is:

- `GET /live`, `GET /ready`, and `GET /startup` for orchestration probes.
- `GET /version` for build, kit, profile, module, and schema metadata.

Selected advanced modules may still require external endpoint/credential
bindings and named application-owned runtime traits. They fail closed until
supplied; a declared router or task is not a substitute for those contracts.

## Application extension

The generated `application::contributions(ApplicationContributions) ->
ApplicationContributions` entry point starts with an empty application
extension. Add application HTTP behavior explicitly with
`with_application_extension`. The one-shot factory runs after selected runtime
construction and receives `ApplicationRuntime`; `postgres_pool()` and
`idempotency_store()` clone already-selected handles without opening another
connection or performing I/O.

Return `ApplicationExtension::new(router, routes, openapi_document, operations)`
with the custom router, route IDs, optional complete OpenAPI document, and
operation descriptors. HTTP finalization mounts this router exactly once.
Fresh non-SPA output registers neither `/example` nor `/reference-records`, so
both return `404 Not Found` unless application-owned contributions add them.
When `web-static` is selected, its generic SPA fallback may serve the browser
shell at an otherwise unknown path; that does not register an application API
operation. OpenAPI is independent of idempotency, and idempotency contributes
a store rather than pagination, reference routes, or OpenAPI state.

## Schema compatibility and PostgreSQL

Framework migration SQL remains embedded in Omnius. This application may own
forward SQL in the reserved range
`9000000000000000000..=9099999999999999999`; when any such SQL exists it must
also own `migrations/application-compatibility.toml`:

```toml
schema_version = 1
minimum = "9000000000000000000"
maximum = "9000000000000000000"
```

The quoted bounds must be ordered, inside the reserved range, and contain the
application head. Migration preparation combines the optional embedded
application source with the framework source before connecting. Server
startup, `migrate`, `migration-status`, and tests use that same prepared set
and one `_sqlx_migrations` history. Only `migrate` takes SQLx's migration lock;
status and compatibility checks are read-only.

For PostgreSQL profiles, `ops/compose.yaml` provides one local-development
PostgreSQL service and a single one-shot migration service. Production
PostgreSQL is operator-provided. Configure this application for that compatible
external service rather than treating the local Compose container as a
production database.

See `docs/operations.md` for container, locked-build, and release metadata
guidance.
