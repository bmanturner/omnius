use std::{
    collections::BTreeSet,
    env,
    error::Error,
    fmt::Write as _,
    fs, io,
    path::{Path, PathBuf},
};

use serde::Deserialize;

const APPLICATION_MIGRATIONS_PATH: &str = "../../migrations";
const APPLICATION_COMPATIBILITY_PATH: &str = "../../migrations/application-compatibility.toml";
const APPLICATION_MIGRATION_MINIMUM: i64 = 9_000_000_000_000_000_000;
const APPLICATION_MIGRATION_MAXIMUM: i64 = 9_099_999_999_999_999_999;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationCompatibility {
    schema_version: u8,
    minimum: String,
    maximum: String,
}

struct SchemaBounds {
    minimum: i64,
    maximum: i64,
}

struct ApplicationMigrationScan {
    head: Option<i64>,
    bounds: Option<SchemaBounds>,
}

#[derive(Deserialize)]
struct ServiceState {
    service: String,
    framework: FrameworkState,
    profile: ProfileState,
    modules: Vec<ModuleState>,
    #[serde(default)]
    providers: Vec<ProviderState>,
}

#[derive(Deserialize)]
struct FrameworkState {
    version: String,
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
    println!("cargo::rerun-if-changed={APPLICATION_MIGRATIONS_PATH}");
    println!("cargo::rerun-if-env-changed=OMNIUS_GIT_REVISION");
    println!("cargo::rerun-if-env-changed=OMNIUS_BUILD_TIME");
    for cfg in [
        "application_migrations",
        "selected_migrations",
        "selected_postgres",
        "selected_idempotency",
        "selected_web_static",
    ] {
        println!("cargo::rustc-check-cfg=cfg({cfg})");
    }

    let source = fs::read_to_string("../../.omnius/service.toml")?;
    let state: ServiceState = toml::from_str(&source)?;
    validate_name("service", &state.service)?;
    validate_name("profile", &state.profile.id)?;
    validate_token("framework version", &state.framework.version)?;

    let mut unique = BTreeSet::new();
    for module in &state.modules {
        validate_name("module", &module.id)?;
        if !unique.insert(module.id.as_str()) {
            return Err(
                invalid_data(format!("duplicate module in service state: {}", module.id)).into(),
            );
        }
    }

    let mut provider_slots = BTreeSet::new();
    for provider in &state.providers {
        validate_name("provider slot", &provider.slot)?;
        validate_name("provider module", &provider.module)?;
        if !unique.contains(provider.module.as_str()) {
            return Err(invalid_data(format!(
                "provider slot {} selects uninstalled module {}",
                provider.slot, provider.module
            ))
            .into());
        }
        if !provider_slots.insert(provider.slot.as_str()) {
            return Err(invalid_data(format!(
                "duplicate provider slot in service state: {}",
                provider.slot
            ))
            .into());
        }
    }

    for (module, cfg) in [
        ("migrations", "selected_migrations"),
        ("postgres", "selected_postgres"),
        ("idempotency", "selected_idempotency"),
        ("web-static", "selected_web_static"),
    ] {
        if unique.contains(module) {
            println!("cargo::rustc-cfg={cfg}");
        }
    }

    let application_migrations = scan_application_migrations()?;
    if let Some(head) = application_migrations.head {
        let bounds = application_migrations
            .bounds
            .ok_or_else(|| invalid_data("application migration bounds were not validated"))?;
        println!("cargo::rustc-cfg=application_migrations");
        println!(
            "cargo::rustc-env=OMNIUS_APPLICATION_SCHEMA_MINIMUM={}",
            bounds.minimum
        );
        println!(
            "cargo::rustc-env=OMNIUS_APPLICATION_SCHEMA_MAXIMUM={}",
            bounds.maximum
        );
        println!("cargo::rustc-env=OMNIUS_APPLICATION_SCHEMA_HEAD={head}");
    }

    let mut generated = String::new();
    generated.push_str("pub const SERVICE: &str = ");
    writeln!(&mut generated, "{:?};", state.service)?;
    generated.push_str("pub const PROFILE: &str = ");
    writeln!(&mut generated, "{:?};", state.profile.id)?;
    generated.push_str("pub const KIT_VERSION: &str = ");
    writeln!(&mut generated, "{:?};", state.framework.version)?;
    generated.push_str("pub const MODULES: &[&str] = &[\n");
    for module in state.modules {
        generated.push_str("    ");
        writeln!(&mut generated, "{:?},", module.id)?;
    }
    generated.push_str("];\n");
    generated.push_str("pub const PROVIDERS: &[service_kit::ProviderMetadata] = &[\n");
    for provider in state.providers {
        generated.push_str("    service_kit::ProviderMetadata { slot: ");
        write!(&mut generated, "{:?}", provider.slot)?;
        generated.push_str(", module: ");
        write!(&mut generated, "{:?}", provider.module)?;
        generated.push_str(" },\n");
    }
    generated.push_str("];\n");

    let output =
        PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| {
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

fn scan_application_migrations() -> Result<ApplicationMigrationScan, Box<dyn Error>> {
    let migration_directory = Path::new(APPLICATION_MIGRATIONS_PATH);
    let directory_metadata = match fs::symlink_metadata(migration_directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ApplicationMigrationScan {
                head: None,
                bounds: None,
            });
        }
        Err(error) => return Err(error.into()),
    };
    if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
        return Err(invalid_data("application migrations path must be a regular directory").into());
    }

    let mut versions = BTreeSet::new();
    for entry in fs::read_dir(migration_directory)? {
        let entry = entry?;
        let filename = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid_data("application migration filename must be valid UTF-8"))?;
        if !filename.ends_with(".sql") {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(invalid_data(format!(
                "application migration must be a regular file: {filename}"
            ))
            .into());
        }
        let version = parse_application_migration_filename(&filename)?;
        if !versions.insert(version) {
            return Err(invalid_data(format!(
                "duplicate application migration version: {version}"
            ))
            .into());
        }
    }

    let Some(head) = versions.last().copied() else {
        if path_exists_without_following(Path::new(APPLICATION_COMPATIBILITY_PATH))? {
            return Err(invalid_data(
                "application compatibility metadata is forbidden without application SQL",
            )
            .into());
        }
        return Ok(ApplicationMigrationScan {
            head: None,
            bounds: None,
        });
    };

    let bounds = load_application_bounds(head)?;
    Ok(ApplicationMigrationScan {
        head: Some(head),
        bounds: Some(bounds),
    })
}

fn parse_application_migration_filename(filename: &str) -> Result<i64, io::Error> {
    if filename.ends_with(".up.sql") || filename.ends_with(".down.sql") {
        return Err(invalid_data(format!(
            "application migrations must be forward-only: {filename}"
        )));
    }
    let stem = filename.strip_suffix(".sql").ok_or_else(|| {
        invalid_data(format!(
            "application migration must end in .sql: {filename}"
        ))
    })?;
    let (version, description) = stem.split_once('_').ok_or_else(|| {
        invalid_data(format!(
            "application migration filename must match <positive-version>_<description>.sql: {filename}"
        ))
    })?;
    if version.is_empty() || !version.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_data(format!(
            "application migration version must be a positive integer: {filename}"
        )));
    }
    if description.is_empty()
        || !description
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(invalid_data(format!(
            "application migration description must use ASCII letters, digits, underscores, or hyphens: {filename}"
        )));
    }
    let version = version.parse::<i64>().map_err(|_| {
        invalid_data(format!(
            "application migration version must fit in a signed 64-bit integer: {filename}"
        ))
    })?;
    if version <= 0 {
        return Err(invalid_data(format!(
            "application migration version must be positive: {filename}"
        )));
    }
    if !(APPLICATION_MIGRATION_MINIMUM..=APPLICATION_MIGRATION_MAXIMUM).contains(&version) {
        return Err(invalid_data(format!(
            "application migration version is outside the reserved application range: {version}"
        )));
    }
    Ok(version)
}

fn load_application_bounds(head: i64) -> Result<SchemaBounds, Box<dyn Error>> {
    let compatibility_path = Path::new(APPLICATION_COMPATIBILITY_PATH);
    let metadata = fs::symlink_metadata(compatibility_path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            invalid_data(
                "application compatibility metadata is required when application SQL exists",
            )
        } else {
            error
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(
            invalid_data("application compatibility metadata must be a regular file").into(),
        );
    }

    let source = fs::read_to_string(compatibility_path)?;
    let compatibility: ApplicationCompatibility = toml::from_str(&source)?;
    if compatibility.schema_version != 1 {
        return Err(invalid_data("application compatibility schema_version must be 1").into());
    }
    let minimum = parse_application_bound("minimum", &compatibility.minimum)?;
    let maximum = parse_application_bound("maximum", &compatibility.maximum)?;
    if maximum < minimum {
        return Err(invalid_data(
            "application compatibility maximum must be greater than or equal to minimum",
        )
        .into());
    }
    if minimum > head || head > maximum {
        return Err(invalid_data(format!(
            "application migration head {head} must be within compatibility range {minimum}..={maximum}"
        ))
        .into());
    }
    Ok(SchemaBounds { minimum, maximum })
}

fn parse_application_bound(field: &str, value: &str) -> Result<i64, io::Error> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_data(format!(
            "application compatibility {field} must be a quoted positive integer string"
        )));
    }
    let bound = value.parse::<i64>().map_err(|_| {
        invalid_data(format!(
            "application compatibility {field} must fit in a signed 64-bit integer"
        ))
    })?;
    if !(APPLICATION_MIGRATION_MINIMUM..=APPLICATION_MIGRATION_MAXIMUM).contains(&bound) {
        return Err(invalid_data(format!(
            "application compatibility {field} must be in the reserved application migration range"
        )));
    }
    Ok(bound)
}

fn path_exists_without_following(path: &Path) -> Result<bool, io::Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn validate_name(field: &str, value: &str) -> Result<(), io::Error> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(invalid_data(format!("invalid {field} in service state")));
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
        return Err(invalid_data(format!("invalid {field} in service state")));
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
