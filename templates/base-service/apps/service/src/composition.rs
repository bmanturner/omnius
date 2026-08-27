//! Generator-managed source-level module composition.

include!(concat!(env!("OUT_DIR"), "/profile.rs"));

pub const MANAGED_MODULES: &[&str] = &[
    // omnius:managed-begin id=modules version=1 hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    // omnius:managed-end id=modules
];

pub const fn modules() -> &'static [&'static str] {
    MODULES
}

pub const fn providers() -> &'static [service_kit::ProviderMetadata] {
    PROVIDERS
}
