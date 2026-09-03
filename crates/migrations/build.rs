//! Rebuilds embedded migrations and derives their framework compatibility bounds.

use std::{env, fs, path::Path};

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

fn main() {
    let migrations = Path::new("../../migrations");
    println!("cargo:rerun-if-changed={}", migrations.display());

    let (minimum, head) = fs::read_dir(migrations)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", migrations.display()))
        .filter_map(|entry| {
            let entry = entry.unwrap_or_else(|error| {
                panic!(
                    "failed to read an entry below {}: {error}",
                    migrations.display()
                )
            });
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("sql") {
                return None;
            }
            let filename = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_else(|| panic!("migration path is not valid UTF-8: {}", path.display()));
            let (version, _) = filename.split_once('_').unwrap_or_else(|| {
                panic!("migration filename must start with `<version>_`: {filename}")
            });
            let version = version.parse::<i64>().unwrap_or_else(|error| {
                panic!("migration filename has invalid version `{version}`: {error}")
            });
            assert!(
                version > 0,
                "migration filename version must be positive: {filename}"
            );
            Some(version)
        })
        .fold(None, |bounds, version| {
            Some(
                bounds.map_or((version, version), |(minimum, head): (i64, i64)| {
                    (minimum.min(version), head.max(version))
                }),
            )
        })
        .unwrap_or_else(|| panic!("the embedded migration history must not be empty"));

    let output_directory =
        env::var_os("OUT_DIR").unwrap_or_else(|| panic!("Cargo must provide OUT_DIR"));
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
    .unwrap_or_else(|error| panic!("failed to write {}: {error}", output.display()));
}
