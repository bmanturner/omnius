# Short-link service

This is an independent generated Omnius workspace containing a PostgreSQL-backed
short-link API. Run the service commands below from
`examples/short-link-service`.

## Prerequisites

- Docker Engine with Docker Compose v2 (`docker compose`).
- `curl` and `jq` for the API walkthrough.
- Rust 1.98 or newer and Cargo for installing the pinned generator and running checks.

Compose supplies PostgreSQL for local development. In production, configure the
application to use any compatible operator-provided external PostgreSQL service;
the Compose database is not a production dependency.

## Start the service

```console
docker compose -f ops/compose.yaml up --build --wait
```

Compose starts PostgreSQL, runs the one-shot `migrate` service, and exposes the
application only on `http://127.0.0.1:3000`.

```console
BASE_URL=http://127.0.0.1:3000
```

## Exercise the API

### Create a short link

`POST /links` requires exactly one `Idempotency-Key`, an
`application/json` content type, and the strict JSON shape shown below. `url` is
the only accepted field.

```console
CREATE_BODY="$(mktemp)"
curl --silent --show-error \
  --request POST \
  --header 'Content-Type: application/json' \
  --header 'Idempotency-Key: docs-create-1' \
  --data '{"url":"https://example.com/docs?a=1"}' \
  --output "$CREATE_BODY" \
  --write-out 'HTTP %{http_code}\n' \
  "$BASE_URL/links"
jq . "$CREATE_BODY"
CODE="$(jq -r .code "$CREATE_BODY")"
```

The response is `201 Created` with a newly generated 12-character lowercase-hex
code; the exact code varies:

```text
HTTP 201
{
  "code": "<generated-code>",
  "url": "https://example.com/docs?a=1",
  "redirect_path": "/r/<generated-code>"
}
```

### Replay the request

Repeating the same key and JSON returns the exact stored status, content type,
and body. The final command confirms that the bodies are byte-identical.

```console
REPLAY_BODY="$(mktemp)"
curl --silent --show-error \
  --request POST \
  --header 'Content-Type: application/json' \
  --header 'Idempotency-Key: docs-create-1' \
  --data '{"url":"https://example.com/docs?a=1"}' \
  --output "$REPLAY_BODY" \
  --write-out 'HTTP %{http_code}\n' \
  "$BASE_URL/links"
cmp "$CREATE_BODY" "$REPLAY_BODY" && echo 'Replay body is byte-identical'
```

Expected: `HTTP 201` and `Replay body is byte-identical`.

### Reuse the key with a different request

```console
curl --include --silent --show-error \
  --request POST \
  --header 'Content-Type: application/json' \
  --header 'Idempotency-Key: docs-create-1' \
  --data '{"url":"https://example.org/changed"}' \
  "$BASE_URL/links"
```

Expected: `409 Conflict`, content type `application/problem+json`, and a body
like this (the request ID varies):

```json
{
  "type": "https://errors.omnius.invalid/idempotency_conflict",
  "title": "Conflict",
  "status": 409,
  "code": "IDEMPOTENCY_CONFLICT",
  "request_id": "<generated-request-id>",
  "detail": "Idempotency-Key was already used for a different request"
}
```

### List and resolve the link

```console
curl --silent --show-error "$BASE_URL/links" | jq .
curl --include --silent --show-error "$BASE_URL/r/$CODE"
```

`GET /links` returns `200 OK` and includes the live row:

```json
{
  "links": [
    {
      "code": "<generated-code>",
      "url": "https://example.com/docs?a=1",
      "expired": false
    }
  ]
}
```

`GET /r/$CODE` returns `307 Temporary Redirect` with
`Location: https://example.com/docs?a=1`. The command does not follow the
redirect, so its headers remain visible.

### Expire the link twice, then resolve it again

```console
curl --silent --show-error --request DELETE \
  --output /dev/null --write-out 'HTTP %{http_code}\n' \
  "$BASE_URL/links/$CODE"
curl --silent --show-error --request DELETE \
  --output /dev/null --write-out 'HTTP %{http_code}\n' \
  "$BASE_URL/links/$CODE"
curl --include --silent --show-error "$BASE_URL/r/$CODE"
```

Both `DELETE /links/$CODE` requests return `204 No Content`. Resolution after
expiry returns `404 Not Found` with `application/problem+json` and a body like:

```json
{
  "type": "https://errors.omnius.invalid/short_link_not_found",
  "title": "Not Found",
  "status": 404,
  "code": "SHORT_LINK_NOT_FOUND",
  "request_id": "<generated-request-id>",
  "detail": "short link was not found"
}
```

The complete OpenAPI 3 document is available at:

```text
http://127.0.0.1:3000/openapi.json
```

## Migrations

The startup command already runs the generated one-shot `migrate` service. To
run the application CLI's `migrate` and `migration-status` commands explicitly
through the same Compose image, configuration, and PostgreSQL network:

```console
docker compose -f ops/compose.yaml run --rm migrate
docker compose -f ops/compose.yaml run --rm migrate migration-status
```

## Shut down

The `-v` flag also removes the local PostgreSQL volume.

```console
rm -f "$CREATE_BODY" "$REPLAY_BODY"
docker compose -f ops/compose.yaml down -v
```

## Check generator ownership

Install `cargo-service` from the exact `[framework].revision` recorded in
`.omnius/service.toml`, then run the ownership checks from this example
workspace:

```console
cargo install --git https://github.com/bmanturner/omnius.git \
  --rev <framework-revision> omnius-generator --bin cargo-service --locked
cargo service doctor --project . --json
cargo service diff --project . --json
```
