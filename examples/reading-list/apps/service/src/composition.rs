//! Generator-managed source-level module composition.

include!(concat!(env!("OUT_DIR"), "/profile.rs"));

pub const MANAGED_MODULES: &[&str] = &[
    // omnius:managed-begin id=modules version=1 hash=ace3343ec7a4e8caf76f9a2107298645162c1a849eeb30fe193ad67bf65f947a
    "core",
    "config",
    "telemetry",
    "runtime",
    "http",
    "health",
    "postgres",
    "migrations",
    "validation",
    "openapi",
    "idempotency",
    "outbound-http",
    "rate-limit-local",
    "auth-core",
    "auth-password",
    "auth-session-postgres",
    "authz-basic",
    "jobs-core",
    "email",
    "auth-http",
    "web-sdk-core",
    "web-auth",
    "web-authorization",
    "web-react",
    "web-forms",
    "web-static",
    // omnius:managed-end id=modules
];

pub const fn modules() -> &'static [&'static str] {
    MANAGED_MODULES
}

pub const fn providers() -> &'static [service_kit::ProviderMetadata] {
    PROVIDERS
}

const NO_RUNTIME_DISABLED_MODULES: &[&str] = &[];
const APPLICATION_RATE_LIMIT_DISABLED: &[&str] = &["rate-limit-local"];

pub const fn runtime_disabled_modules(
    application_rate_limit_enabled: bool,
) -> &'static [&'static str] {
    if application_rate_limit_enabled {
        NO_RUNTIME_DISABLED_MODULES
    } else {
        APPLICATION_RATE_LIMIT_DISABLED
    }
}
