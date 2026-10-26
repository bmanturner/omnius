//! Rebuilds embedded migrations and derives their framework compatibility bounds.

use std::{env, error::Error, fs, path::Path};

fn rust_integer_literal(value: i64) -> String {
    let digits = value.to_string();
    let mut literal = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.bytes().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            literal.push('_');
        }
        literal.push(char::from(digit));
    }
    literal
}

/// Scans the migration directory for the smallest and largest `<version>_*.sql` versions.
fn migration_bounds(migrations: &Path) -> Result<(i64, i64), Box<dyn Error>> {
    let mut bounds: Option<(i64, i64)> = None;
    for entry in fs::read_dir(migrations)
        .map_err(|error| format!("failed to read {}: {error}", migrations.display()))?
    {
        let path = entry
            .map_err(|error| {
                format!(
                    "failed to read an entry below {}: {error}",
                    migrations.display()
                )
            })?
            .path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("sql") {
            continue;
        }
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("migration path is not valid UTF-8: {}", path.display()))?;
        let (version, _) = filename.split_once('_').ok_or_else(|| {
            format!("migration filename must start with `<version>_`: {filename}")
        })?;
        let version = version.parse::<i64>().map_err(|error| {
            format!("migration filename has invalid version `{version}`: {error}")
        })?;
        if version <= 0 {
            return Err(format!("migration filename version must be positive: {filename}").into());
        }
        bounds = Some(bounds.map_or((version, version), |(minimum, head)| {
            (minimum.min(version), head.max(version))
        }));
    }
    bounds.ok_or_else(|| "the embedded migration history must not be empty".into())
}

fn main() -> Result<(), Box<dyn Error>> {
    let migrations = Path::new("../../migrations");
    println!("cargo:rerun-if-changed={}", migrations.display());

    let (minimum, head) = migration_bounds(migrations)?;

    let output_directory = env::var_os("OUT_DIR").ok_or("Cargo must provide OUT_DIR")?;
    let output = Path::new(&output_directory).join("current_schema_version.rs");
    let minimum_literal = rust_integer_literal(minimum);
    let head_literal = rust_integer_literal(head);
    fs::write(
        &output,
        format!(
            "/// Earliest framework migration embedded in [`MIGRATOR`].\n\
             pub const FRAMEWORK_SCHEMA_MINIMUM: i64 = {minimum_literal};\n\
             /// Latest framework migration embedded in [`MIGRATOR`].\n\
             pub const FRAMEWORK_SCHEMA_HEAD: i64 = {head_literal};\n\
             /// Latest forward migration embedded in [`MIGRATOR`].\n\
             pub const CURRENT_SCHEMA_VERSION: i64 = FRAMEWORK_SCHEMA_HEAD;\n\
             /// Returns the framework-only schema compatibility range.\n\
             #[must_use]\n\
             pub const fn framework_schema_compatibility() -> omnius_core::SchemaCompatibility {{\n\
                 omnius_core::SchemaCompatibility {{\n\
                     minimum: \"{minimum}\",\n\
                     maximum: \"{head}\",\n\
                 }}\n\
             }}\n"
        ),
    )
    .map_err(|error| format!("failed to write {}: {error}", output.display()))?;
    Ok(())
}
