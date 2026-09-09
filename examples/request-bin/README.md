# Request bin

A bounded, in-memory HTTP request bin generated from the Omnius `minimal`
profile and then extended with the public `cargo service add` lifecycle. From
the parent repository root, the provenance commands were:

```console
cargo service new request-bin --profile minimal --path examples/request-bin
cargo service add openapi --project examples/request-bin
```

The generating `cargo-service` CLI and this workspace are bound to the full,
immutable Omnius revision
`d6ef2987bc2213bbf07ce44e6993775a93e574dc`. The application has no database,
Redis, mail, or other external service.

## Build and run

Run the binary from this directory using the committed dependency lock:

```console
cargo build --release --locked --package request-bin
cargo run --locked --package request-bin -- server
```

The local binary listens on `127.0.0.1:3000`. Its readiness endpoint is
`http://127.0.0.1:3000/ready`.

Alternatively, build and start the application-only Compose stack:

```console
docker compose build --pull
docker compose up --detach --wait
```

Compose builds `ops/Dockerfile`, publishes container port 3000 only as
`127.0.0.1:3001`, and inherits the image healthcheck, which checks `/ready` on
port 3000. The container runs as an unprivileged user with a read-only root
filesystem, a bounded `/tmp` tmpfs, and `no-new-privileges`.

The examples below use the Compose address. For a directly run binary, set
`BASE_URL=http://127.0.0.1:3000` instead.

## API walkthrough

The walkthrough requires `curl` and `jq`. It keeps the one-time read token in a
mode-0600 temporary curl configuration rather than placing it in shell history
or curl's process arguments. Do not enable shell tracing while handling the
token.

```sh
BASE_URL=http://127.0.0.1:3001
umask 077
CREATE_RESPONSE=$(mktemp)
AUTH_CONFIG=$(mktemp)
trap 'rm -f "$CREATE_RESPONSE" "$AUTH_CONFIG"' EXIT

curl --fail-with-body --silent --show-error \
  --request POST \
  --header 'Content-Type: application/json' \
  --data '{"ttl_seconds":3600}' \
  "$BASE_URL/bins" >"$CREATE_RESPONSE"

CAPTURE_PATH=$(jq -r '.capture_path' "$CREATE_RESPONSE")
INSPECT_PATH=$(jq -r '.inspect_path' "$CREATE_RESPONSE")
READ_TOKEN=$(jq -r '.read_token' "$CREATE_RESPONSE")
printf 'header = "Authorization: Bearer %s"\n' "$READ_TOKEN" >"$AUTH_CONFIG"
unset READ_TOKEN
jq '{bin_id, capture_path, inspect_path, created_at, expires_at, read_token: "[REDACTED]"}' "$CREATE_RESPONSE"

# Capture arbitrary binary bytes, a query string, and headers. Sensitive
# request headers are retained only as the literal value [REDACTED].
printf '\000\001request-bin\377' | curl --fail-with-body --silent --show-error \
  --request POST \
  --header 'Content-Type: application/octet-stream' \
  --header 'X-Example: retained' \
  --header 'Authorization: example-sensitive-value' \
  --data-binary @- \
  "$BASE_URL$CAPTURE_PATH?source=walkthrough"

# Inspect metadata and captures, ordered oldest to newest.
curl --fail-with-body --silent --show-error \
  --config "$AUTH_CONFIG" \
  "$BASE_URL$INSPECT_PATH" | jq .

# Delete the bin. A successful deletion returns 204 with no body.
curl --fail-with-body --silent --show-error \
  --request DELETE \
  --config "$AUTH_CONFIG" \
  "$BASE_URL$INSPECT_PATH"
```

The create response contains `bin_id`, the one-time `read_token`, relative
`capture_path` and `inspect_path`, and creation/expiry timestamps. Treat the
read token as a secret. Inspect and delete require
`Authorization: Bearer <read_token>`; an unknown or expired bin and a missing or
wrong token intentionally produce the same `404 BIN_NOT_FOUND` response.

## Limits and representation

- TTL is fixed at creation: 60 through 86,400 seconds inclusive, default 3,600.
- At most 64 live bins exist per process. Expired bins are purged before the
  capacity check; a live bin is never evicted to create another.
- Each bin retains its newest 25 captures; the oldest capture is dropped when
  the ring is full.
- Each capture permits at most 16 KiB of body and 16 KiB of aggregate request
  header bytes. An over-limit request returns `413` and is not partially stored.
- Capture supports `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`,
  and `TRACE`. `CONNECT` and other unsupported methods return `405`; `HEAD`
  returns `202` without a response body.
- Capture bodies are stored and returned as standard base64 in `body_base64`,
  preserving arbitrary binary bytes.
- `authorization`, `proxy-authorization`, `cookie`, and `set-cookie` header
  values are replaced with `[REDACTED]` before storage.

## Lifecycle checks

Use the separately installed CLI bound to the same revision as the workspace:

```console
cargo service --version
cargo service doctor --project . --json
cargo service diff --project . --json
```

The version output must identify
`d6ef2987bc2213bbf07ce44e6993775a93e574dc`; do not mutate this workspace with
an unbound or differently bound CLI.

## State and teardown

All bins and captures are process-local memory. Restarting or replacing the
process/container permanently loses them. This example is not durable and is
not suitable for multiple application instances: instances neither share nor
replicate state, and a request routed to another instance cannot see the bin.

Stop the Compose stack with:

```console
docker compose down --remove-orphans
```
