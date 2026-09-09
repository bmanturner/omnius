# Reading list

This is an independently runnable generated Omnius workspace with an
application-owned reading-list backend, React browser application, PostgreSQL
schema, email templates, and local Compose topology. Run the commands below
from `examples/reading-list`.

## Ownership and generation provenance

The workspace was generated from the `web` profile and then had `audit`,
`auth-api-key`, and `auth-jwt` removed through the public `cargo service`
lifecycle. The exact Omnius version, immutable Git revision, selected profile,
modules, and schema-2 ownership state are recorded in `.omnius/service.toml`.

Generated or kit-owned files and managed regions must be changed with the
matching immutable `cargo-service` release. Do not hand-edit generated SDK
output. Application-owned files include this README, `compose.yaml`,
`apps/service/src/application.rs`, `config/reading-list.toml`, the email
templates, the reserved-range application migration, the contract sync script,
and the browser application. The generator does not create or own Compose;
lifecycle updates leave independently authored infrastructure files untouched.

The Rust workspace uses the `service-kit` alias for its one managed Omnius Git
dependency. Framework source and framework migrations remain in Omnius rather
than being copied into this workspace. `Cargo.lock` is committed and is the
shared dependency lock.

## Prerequisites

- Docker Engine with Docker Compose v2 (`docker compose`).
- A browser for the application and Mailpit workflows.
- Rust 1.98 or newer and Cargo only when running the workspace or lifecycle
  commands outside Compose.
- Node 24.19.0 and pnpm 11.23.0 only when working on the browser or generated
  SDK outside the image build.

## Local stack

Start the complete stack:

```console
docker compose up --build --wait
```

Compose performs the startup sequence deterministically:

1. PostgreSQL starts and passes `pg_isready`.
2. The one-shot `migrate` service applies the embedded framework migrations and
   the application migration, then exits successfully.
3. The application starts only after PostgreSQL is healthy, migration has
   completed successfully, and Mailpit is ready.

Open the browser application at <http://localhost:3002/> and Mailpit at
<http://localhost:8025/>. Compose publishes the application as
`127.0.0.1:3002:3000` and the Mailpit UI as `127.0.0.1:8025:8025`. PostgreSQL
has no host port. Mailpit SMTP port 1025 is exposed only to services on the
Compose network and is not published to the host.

Both the server and migration commands retain the generated default
`config/reference.toml` environment layer and add the application-owned layer
with:

```text
--environment development --local-config /app/config/reading-list.toml
```

The application container serves the checked web build from `/app/web/dist`.
Server startup migrations are explicitly disabled because the one-shot
migration container owns migration scheduling. The database URL and the
password and invitation-token peppers in `compose.yaml` are synthetic,
local-only values; they are deliberately absent from the checked TOML overlay
and must never be reused outside this example.

Inspect service state and logs with:

```console
docker compose ps
docker compose logs app
docker compose logs migrate
docker compose logs mailpit
```

To rerun migration explicitly after it has completed:

```console
docker compose run --rm migrate
```

To inspect migration status through the same image, configuration layers, and
Compose network:

```console
docker compose run --rm migrate \
  migration-status \
  --environment development \
  --local-config /app/config/reading-list.toml
```

## Account and email workflow

### Register and verify an account

1. Open <http://localhost:3002/register>.
2. Register with an email address and a password of at least 12 bytes. The
   account remains pending and login is denied until verification succeeds.
3. Open <http://localhost:8025/> and select the verification message sent to
   that address.
4. Follow its `http://localhost:3002/verify-email#...` link. The browser reads
   the one-time token from the URL fragment, removes the fragment immediately,
   and submits the verification request without storing the token.
5. Sign in at <http://localhost:3002/login>, add reading-list items, mark them
   finished, or delete them. Reloading the page demonstrates PostgreSQL
   persistence.

### Recover and reset a password

1. Open <http://localhost:3002/forgot-password>, enter the account email, and
   submit the recovery request. The response is intentionally
   enumeration-safe.
2. Open Mailpit at <http://localhost:8025/> and select the password-recovery
   message.
3. Follow its `http://localhost:3002/reset-password#...` link. As with email
   verification, the browser removes the fragment before consuming the token.
4. Set the new password, then sign in at <http://localhost:3002/login>.

Mailpit is an ephemeral development inbox backed by container `/tmp`; restarting
or recreating it may discard captured messages. It must not be used to deliver
production mail.

## Image provenance

Compose uses immutable multi-architecture manifest digests rather than floating
tags. The corresponding upstream tag/digest pairs used to select them are:

- `postgres:17.6-alpine3.22` →
  `postgres@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94`.
  This is the same PostgreSQL digest used by the repository's hardened
  short-link and CI topology.
- `axllent/mailpit:v1.27.11` →
  `axllent/mailpit@sha256:e22dce5b36f93c77082e204a3942fb6b283b7896e057458400a4c88344c3df68`.

The tags document provenance; the Compose runtime references only the immutable
digests.

## Shut down and clean up

Stop containers while retaining the PostgreSQL volume:

```console
docker compose down
```

Remove containers, the network, and all local PostgreSQL data created by this
stack:

```console
docker compose down -v
```

Mailpit messages are ephemeral and require no named-volume cleanup. Do not use
`down -v` if the local database contents need to be retained.

## Lifecycle and workspace checks

Use a separately installed `cargo-service` subcommand whose immutable release
identity matches `.omnius/service.toml`; never substitute a project-owned
`xtask`:

```console
cargo service doctor --project . --json
cargo service diff --project . --json
cargo service add <MODULE> --project . --dry-run
cargo service profile set <PROFILE> --project . --dry-run
cargo service update --project . --dry-run
```

Remove `--dry-run` only after reviewing the sealed file, package-graph, and lock
diff. Mutating commands require a clean CLI release matching the project;
`update` is the only identity transition. Add `--offline` for canonical
Cargo-cache-only resolution, not vendoring.

The service CLI can inspect its compiled profile without connecting to external
services:

```console
cargo run --locked -p reading-list -- profile-info
```

Application contracts and the generated SDK are synchronized through the
application-owned script:

```console
pnpm contracts:check
pnpm contracts:sync
```

Framework migrations are embedded in Omnius. Application SQL lives only in the
reserved range `9000000000000000000..=9099999999999999999` and is accompanied
by `migrations/application-compatibility.toml`. The explicit `migrate` command
combines and applies both sources using one `_sqlx_migrations` history.

## Browser verification

With the Compose stack running, execute the supported browser release gate
against the real application and Mailpit:

```console
OMNIUS_E2E_BASE_URL=http://localhost:3002 \
OMNIUS_E2E_MAILPIT_URL=http://localhost:8025 \
pnpm web:release:gates
```

Chromium runs the complete registration, verification, authenticated
reading-list, persistence, contrast, and logout journey. Firefox and WebKit run
the tagged deep-link smoke coverage. The repository's generated-profile matrix
sets `OMNIUS_E2E_PROFILE_BIN` and `OMNIUS_E2E_PROFILE` instead to exercise the
same pinned browser projects against generated runtimes. `browser-support.json`
is the authoritative declaration of the coverage assigned to each browser
tier.

## Production checklist

The checked Compose topology and `development-smtp` provider are development
fixtures, not a production deployment. Before production:

- Terminate traffic with HTTPS and configure the public application URL and
  trusted origins to use the exact HTTPS origin.
- Use a `__Host-` session cookie name with `secure = true`, `http_only = true`,
  `same_site` appropriate to the deployment, no `Domain` attribute, and path
  `/`; preserve same-origin and CSRF enforcement end to end.
- Replace development SMTP with authenticated implicit TLS or required
  STARTTLS, validate the server identity, and use a production sender domain.
  The plaintext `development-smtp` provider is rejected in production.
- Inject the PostgreSQL URL, password pepper, invitation-token pepper, SMTP
  credentials, and other secrets from an external secret manager. Never bake
  secrets into an image, checked TOML, Compose file, or deployment manifest.
- Use an operator-managed PostgreSQL service with encrypted transport,
  least-privilege credentials, monitored migrations, point-in-time recovery,
  tested backups, and an explicit backup and retention policy.
- Define production health, restart, resource, logging, monitoring, email
  retention, and disaster-recovery policies in the deployment platform rather
  than copying the local Compose defaults.
