# Operations

## Configuration

`config/local.toml` is safe for a developer machine and binds to
`127.0.0.1:3000`. Set `OMNIUS_CONFIG` to another checked-in configuration path or
`OMNIUS_BIND` to an explicit socket address. Containers set `OMNIUS_BIND` to
`0.0.0.0:3000`; do not expose that listener directly without the deployment
network boundary.

## Probes and metadata

Use `/live` for process liveness, `/startup` for startup completion, and
`/ready` for traffic readiness. `/version` and the `profile-info` executable
mode return the same non-secret build and composition fields. Release builds
may set `OMNIUS_GIT_REVISION` to 7–64 hexadecimal characters and `OMNIUS_BUILD_TIME`
to an RFC 3339 timestamp.

## Container

Build from the project root with `ops/Dockerfile`. `ops/compose.yaml` publishes
the service only on host loopback. The image runs as an unprivileged numeric
user and uses the executable's bounded readiness check.
