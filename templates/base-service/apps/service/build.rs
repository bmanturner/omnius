use std::{collections::BTreeSet, env, error::Error, fs, io, path::PathBuf};

use serde::Deserialize;

#[derive(Deserialize)]
struct ServiceState {
    service: String,
    kit_version: String,
    profile: ProfileState,
    modules: Vec<ModuleState>,
    #[serde(default)]
    providers: Vec<ProviderState>,
}

#[derive(Deserialize)]
struct ProfileState {
    id: String,
}

#[derive(Deserialize)]
struct ModuleState {
    id: String,
}

#[derive(Deserialize)]
struct ProviderState {
    slot: String,
    module: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-changed=../../.omnius/service.toml");
    println!("cargo::rerun-if-env-changed=OMNIUS_GIT_REVISION");
    println!("cargo::rerun-if-env-changed=OMNIUS_BUILD_TIME");

    let source = fs::read_to_string("../../.omnius/service.toml")?;
    let state: ServiceState = toml::from_str(&source)?;
    validate_name("service", &state.service)?;
    validate_name("profile", &state.profile.id)?;
    validate_token("kit_version", &state.kit_version)?;

    let mut unique = BTreeSet::new();
    for module in &state.modules {
        validate_name("module", &module.id)?;
        if !unique.insert(module.id.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("duplicate module in service state: {}", module.id),
            )
            .into());
        }
    }
    let mut provider_slots = BTreeSet::new();
    for provider in &state.providers {
        validate_name("provider slot", &provider.slot)?;
        validate_name("provider module", &provider.module)?;
        if !unique.contains(provider.module.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "provider slot {} selects uninstalled module {}",
                    provider.slot, provider.module
                ),
            )
            .into());
        }
        if !provider_slots.insert(provider.slot.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("duplicate provider slot in service state: {}", provider.slot),
            )
            .into());
        }
    }

    let mut generated = String::new();
    generated.push_str("pub const SERVICE: &str = ");
    generated.push_str(&format!("{:?};\n", state.service));
    generated.push_str("pub const PROFILE: &str = ");
    generated.push_str(&format!("{:?};\n", state.profile.id));
    generated.push_str("pub const KIT_VERSION: &str = ");
    generated.push_str(&format!("{:?};\n", state.kit_version));
    generated.push_str("pub const MODULES: &[&str] = &[\n");
    for module in state.modules {
        generated.push_str("    ");
        generated.push_str(&format!("{:?},\n", module.id));
    }
    generated.push_str("];\n");
    generated.push_str("pub const PROVIDERS: &[service_kit::ProviderMetadata] = &[\n");
    for provider in state.providers {
        generated.push_str("    service_kit::ProviderMetadata { slot: ");
        generated.push_str(&format!("{:?}", provider.slot));
        generated.push_str(", module: ");
        generated.push_str(&format!("{:?}", provider.module));
        generated.push_str(" },\n");
    }
    generated.push_str("];\n");

    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "Cargo did not provide OUT_DIR")
    })?)
    .join("profile.rs");
    let unchanged = fs::read_to_string(&output).is_ok_and(|existing| existing == generated);
    if !unchanged {
        fs::write(output, generated)?;
    }
    println!("cargo::rustc-env=OMNIUS_RUSTC_VERSION=rustc (version not recorded)");
    Ok(())
}

fn validate_name(field: &str, value: &str) -> Result<(), io::Error> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {field} in service state"),
        ));
    }
    Ok(())
}

fn validate_token(field: &str, value: &str) -> Result<(), io::Error> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {field} in service state"),
        ));
    }
    Ok(())
}
