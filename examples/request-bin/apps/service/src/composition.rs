//! Generator-managed source-level module composition.

include!(concat!(env!("OUT_DIR"), "/profile.rs"));

pub const MANAGED_MODULES: &[&str] = &[
    // omnius:managed-begin id=modules version=1 hash=54baba3921db3cb390372df3a34074b74aae6643bdef22acc8985feb3d184a84
    "core",
    "config",
    "telemetry",
    "runtime",
    "http",
    "health",
    "validation",
    "openapi",
    "rate-limit-local",
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
