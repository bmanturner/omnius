# Operations

## Configuration

`config/base.toml` contains only safe process defaults, and the generated process
loads `config/reference.toml` as its selected runtime overlay. Use `--config` or
`--environment-config` to select different files. Hierarchical process variables
override both layers; use `OMNIUS__SERVER__LISTEN_ADDRESS` for the listener.
Persisted profiles require `OMNIUS__POSTGRES__URL`; it is never stored in the
reference overlay. Idempotency has no pagination cursor-signing secret.
Selected external providers may require their own fail-closed endpoint or
credential variables. TOML `${...}` strings are literal and do not read
process variables. Containers run from `/app`, load `/app/config`, and bind
`0.0.0.0:3000`; keep the loopback-published deployment boundary.

## Probes and metadata

Use `/live` for process liveness, `/startup` for startup completion, and
`/ready` for traffic readiness. `/version` and the `profile-info` executable
mode return the same non-secret build and composition fields. Release builds
may set `OMNIUS_GIT_REVISION` to 7–64 hexadecimal characters and `OMNIUS_BUILD_TIME`
to an RFC 3339 timestamp.

## Container

Build from the project root with `ops/Dockerfile`. Its Rust build uses the
committed dependency graph:

```console
cargo build --release --locked --package {{project-name}}
```

Manager-derived `ops/compose.yaml` always publishes only
`127.0.0.1:3000:3000`. The minimal topology contains only `app`. Persisted
profiles add the digest-pinned local `postgres` service and retained
`postgres-data` named volume. Their one-shot `migrate` service is the sole
Compose migration owner; `app` waits for database health and successful
migration, and Compose sets `OMNIUS__MIGRATIONS__RUN_ON_STARTUP=false`. Normal
stop/start retains the named volume and one `_sqlx_migrations` history.

Framework SQL stays embedded in `omnius-service-kit`; only reserved-range
application SQL lives in this project. Migration preparation validates and
combines both sources before database I/O. Direct/operator launches use the
same prepared set for startup compatibility, explicit `migrate`, and
`migration-status`. Only `migrate` acquires SQLx's migration lock; status and
compatibility are read-only.

The image runs as an unprivileged numeric user and uses the executable's
bounded readiness check.

Dependencies without a repository-owned pinned, health-checked topology are
external. Compose uses required `${NAME:?message}` YAML bindings for their exact
endpoint and credential variables and does not generate substitute containers.
This is Compose validation syntax, not TOML interpolation. Application-owned
policy, handler, registry, and provider traits also remain fail-closed
prerequisites; router and task outputs do not satisfy them. See
`docs/module-catalog.md` for the selected dependency requirements.

When `web-static` is selected, pass the public router and asset base at build
time, for example `--build-arg OMNIUS_WEB_BASE_PATH=/console`. The locked
frontend build and the runtime static server use that same value. Do not
override `OMNIUS_WEB_BASE_PATH` at runtime with a path different from the one
baked into the frontend assets.

## Offline and vendored build preparation

`cargo service ... --offline` means canonical Cargo-cache-only lifecycle
resolution. For an explicit build/deployment preparation, an operator may
instead run:

```console
cargo vendor --locked
cargo build --locked --offline
```

Vendoring preserves the committed lock sources, but its source-replacement
configuration makes `cargo service doctor` non-clean and blocks every
lifecycle mutation until that configuration is removed. Do not commit a
vendor tree or treat vendoring as a lifecycle source-selection mechanism.
