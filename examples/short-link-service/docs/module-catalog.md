# Selected service modules

| Module | Version | Provider slot |
|---|---:|---|
| `config` | `0.1.0` | - |
| `core` | `0.1.0` | - |
| `health` | `0.1.0` | - |
| `http` | `0.1.0` | - |
| `idempotency` | `0.1.0` | - |
| `migrations` | `0.1.0` | - |
| `openapi` | `0.1.0` | - |
| `outbound-http` | `0.1.0` | - |
| `postgres` | `0.1.0` | primary-database |
| `rate-limit-local` | `0.1.0` | rate-limit-provider |
| `runtime` | `0.1.0` | - |
| `telemetry` | `0.1.0` | - |
| `validation` | `0.1.0` | - |

## Runtime dependencies

| Dependency | Resolution | Required environment |
|---|---|---|
| `postgresql` | Compose service `postgres` | development-only bindings managed in `ops/compose.yaml` |
