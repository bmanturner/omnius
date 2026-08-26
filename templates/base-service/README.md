# {{project-name}}

Generated Rust Service Kit service using the `{{ profile }}` base profile.

## Run locally

The checked-in local configuration binds only to loopback by default:

```console
cargo run -p {{project-name}} -- server
```

Override the configuration file with `RSK_CONFIG` or the listener with
`RSK_BIND`. Inspect the resolved profile without starting a listener:

```console
cargo run -p {{project-name}} -- profile-info
```

The public base surface is:

- `GET /live`, `GET /ready`, and `GET /startup` for orchestration probes.
- `GET /version` for build, kit, profile, module, and schema metadata.
- `GET /example` for application-owned example behavior.

The exact profile and ordered module versions are recorded in
`.rsk/service.toml`. `apps/service/src/application.rs` and this README are
application-owned; an identical generator pass never overwrites them.

See `docs/operations.md` for container and release metadata guidance.
