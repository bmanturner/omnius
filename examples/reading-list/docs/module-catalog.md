# Selected service modules

| Module | Version | Provider slot |
|---|---:|---|
| `auth-core` | `0.1.0` | - |
| `auth-http` | `0.1.0` | - |
| `auth-password` | `0.1.0` | - |
| `auth-session-postgres` | `0.1.0` | session-store |
| `authz-basic` | `0.1.0` | authorization-policy |
| `config` | `0.1.0` | - |
| `core` | `0.1.0` | - |
| `email` | `0.1.0` | email-provider |
| `health` | `0.1.0` | - |
| `http` | `0.1.0` | - |
| `idempotency` | `0.1.0` | - |
| `jobs-core` | `0.1.0` | - |
| `migrations` | `0.1.0` | - |
| `openapi` | `0.1.0` | - |
| `outbound-http` | `0.1.0` | - |
| `postgres` | `0.1.0` | primary-database |
| `rate-limit-local` | `0.1.0` | rate-limit-provider |
| `runtime` | `0.1.0` | - |
| `telemetry` | `0.1.0` | - |
| `validation` | `0.1.0` | - |
| `web-auth` | `0.1.0` | - |
| `web-authorization` | `0.1.0` | - |
| `web-forms` | `0.1.0` | - |
| `web-react` | `0.1.0` | - |
| `web-sdk-core` | `0.1.0` | - |
| `web-static` | `0.1.0` | - |

## Runtime dependencies

| Dependency | Resolution | Required environment |
|---|---|---|
| `postgresql` | External (no generated container) | `OMNIUS__POSTGRES__URL` |
