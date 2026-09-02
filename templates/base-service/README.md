# {{project-name}}

Generated Omnius service using the `{{ profile }}` base profile.

## Run locally

The checked-in base configuration binds only to loopback. The process automatically
loads the selected `config/reference.toml` overlay:

```console
cargo run -p {{project-name}} -- server
```

Override the reference layer with `--environment-config` or the listener with
`OMNIUS__SERVER__LISTEN_ADDRESS`. Persisted profiles require
`OMNIUS__POSTGRES__URL` and an exact 32-byte
`OMNIUS__PAGINATION__CURSOR_SIGNING_KEY`; neither is written to the overlay.
TOML `${...}` strings are literal and do not read process variables. Inspect the
resolved profile without starting a listener:

```console
cargo run -p {{project-name}} -- profile-info
```

The public base surface is:

- `GET /live`, `GET /ready`, and `GET /startup` for orchestration probes.
- `GET /version` for build, kit, profile, module, and schema metadata.
- `GET /example` for application-owned example behavior.

The exact profile and ordered module versions are recorded in
`.omnius/service.toml`. `apps/service/src/application.rs` and this README are
application-owned; an identical generator pass never overwrites them.

Selected advanced modules may still require external endpoint/credential
bindings and named application-owned runtime traits. They fail closed until
supplied; a declared router or task is not a substitute for those contracts.

See `docs/operations.md` for container and release metadata guidance.
