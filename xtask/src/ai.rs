use std::{collections::BTreeSet, fs, path::Path};

use anyhow::{Context, Result, ensure};
use regex::Regex;
use serde_yaml::Value as YamlValue;
use toml::Value as TomlValue;
use walkdir::WalkDir;

const RIG_CRATES: &[&str] = &["rig-agent", "rig-bedrock", "rig-core", "rig-vertexai"];
const SDK_TOKENS: &[&str] = &[
    "rig_agent::",
    "rig_bedrock::",
    "rig_core::",
    "rig_vertexai::",
    "rmcp::",
];
const FORBIDDEN_MCP_MODULES: &[&str] = &[
    "mcp-http-sse",
    "mcp-initialization",
    "mcp-logging",
    "mcp-roots",
    "mcp-sampling",
    "mcp-sessions",
];

pub(crate) struct AiArchitectureSummary {
    pub(crate) modules: usize,
    pub(crate) rust_files: usize,
}

pub(crate) fn verify(workspace: &Path) -> Result<AiArchitectureSummary> {
    validate_dependency_baseline(workspace)?;
    validate_direct_dependency_ownership(workspace)?;
    let rust_files = validate_source_boundaries(workspace)?;
    let modules = validate_module_lifecycle(workspace)?;
    validate_default_profiles(workspace)?;
    Ok(AiArchitectureSummary {
        modules,
        rust_files,
    })
}

fn validate_dependency_baseline(workspace: &Path) -> Result<()> {
    let manifest = parse_toml(&workspace.join("Cargo.toml"))?;
    let dependencies = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(TomlValue::as_table)
        .context("workspace.dependencies is missing")?;

    for (name, version) in [
        ("rig-agent", "=0.42.0"),
        ("rig-bedrock", "=0.42.0"),
        ("rig-core", "=0.42.0"),
        ("rig-vertexai", "=0.42.0"),
        ("rmcp", "=3.1.4"),
        ("schemars", "=1.2.2"),
        ("jsonschema", "=0.51.0"),
    ] {
        let dependency = dependencies
            .get(name)
            .with_context(|| format!("workspace dependency `{name}` is missing"))?;
        ensure!(
            dependency_version(dependency) == Some(version),
            "workspace dependency `{name}` must use exact version {version}"
        );
        ensure!(
            dependency
                .as_table()
                .and_then(|table| table.get("default-features"))
                .and_then(TomlValue::as_bool)
                == Some(false),
            "workspace dependency `{name}` must disable default features"
        );
    }

    ensure_features(dependencies, "rig-core", &["reqwest", "rustls"])?;
    ensure_features(dependencies, "schemars", &["derive", "std"])?;
    ensure_features(dependencies, "rig-agent", &[])?;
    ensure_features(
        dependencies,
        "rmcp",
        &[
            "elicitation",
            "request-state",
            "server",
            "transport-streamable-http-server",
        ],
    )?;
    Ok(())
}

fn dependency_version(value: &TomlValue) -> Option<&str> {
    value.as_str().or_else(|| {
        value
            .as_table()
            .and_then(|table| table.get("version"))
            .and_then(TomlValue::as_str)
    })
}

fn ensure_features(
    dependencies: &toml::map::Map<String, TomlValue>,
    name: &str,
    expected: &[&str],
) -> Result<()> {
    let features = dependencies
        .get(name)
        .and_then(TomlValue::as_table)
        .and_then(|table| table.get("features"))
        .and_then(TomlValue::as_array)
        .map(|features| {
            features
                .iter()
                .filter_map(TomlValue::as_str)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    ensure!(
        features == expected,
        "workspace dependency `{name}` has an unreviewed feature set"
    );
    Ok(())
}

fn validate_direct_dependency_ownership(workspace: &Path) -> Result<()> {
    for entry in WalkDir::new(workspace)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| entry.file_name() != "target" && entry.file_name() != ".git")
    {
        let entry = entry.context("walk workspace manifests")?;
        if !entry.file_type().is_file() || entry.file_name() != "Cargo.toml" {
            continue;
        }
        let path = entry.path();
        if path == workspace.join("Cargo.toml") {
            continue;
        }
        let relative = path
            .strip_prefix(workspace)
            .context("manifest escaped workspace")?;
        let manifest = parse_toml(path)?;
        let dependencies = direct_dependency_names(&manifest);
        let compatibility_harness = relative == Path::new("compat/phase0/Cargo.toml");
        let rig_adapter = relative.starts_with("crates/llm-provider-rig")
            || relative.starts_with("crates/llm-provider-bedrock")
            || relative.starts_with("crates/llm-provider-vertex");
        let rmcp_adapter = relative
            .components()
            .nth(1)
            .and_then(|component| component.as_os_str().to_str())
            .is_some_and(|name| name.starts_with("mcp-"));

        for dependency in &dependencies {
            if RIG_CRATES.contains(&dependency.as_str()) {
                ensure!(
                    compatibility_harness || rig_adapter,
                    "Rig dependency `{dependency}` is outside an approved adapter: {}",
                    relative.display()
                );
            }
            if dependency == "rmcp" {
                ensure!(
                    compatibility_harness || rmcp_adapter,
                    "RMCP dependency is outside an approved adapter: {}",
                    relative.display()
                );
            }
        }
    }
    Ok(())
}

fn direct_dependency_names(manifest: &TomlValue) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if let Some(manifest) = manifest.as_table() {
        collect_dependency_names(manifest, &mut names);
    }
    if let Some(targets) = manifest.get("target").and_then(TomlValue::as_table) {
        for target in targets.values().filter_map(TomlValue::as_table) {
            collect_dependency_names(target, &mut names);
        }
    }
    names
}

fn collect_dependency_names(
    manifest: &toml::map::Map<String, TomlValue>,
    names: &mut BTreeSet<String>,
) {
    for dependencies in ["dependencies", "dev-dependencies", "build-dependencies"]
        .into_iter()
        .filter_map(|key| manifest.get(key).and_then(TomlValue::as_table))
    {
        names.extend(dependencies.keys().cloned());
    }
}

fn validate_source_boundaries(workspace: &Path) -> Result<usize> {
    let public_sdk = Regex::new(
        r"(?m)^\s*pub(?:\([^)]*\))?\s+(?:use\b[^;\n]*(?:rig_agent|rig_bedrock|rig_core|rig_vertexai|rmcp)(?:::|\b)|(?:(?:(?:async\s+)?fn|trait|struct|enum)\b[^;{\n]*|(?:const|static)\b[^;={\n]*|type\b[^;\n]*)(?:rig_agent|rig_bedrock|rig_core|rig_vertexai|rmcp)::)",
    )?;
    let mut checked = 0;
    for root in [workspace.join("apps"), workspace.join("crates")] {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| entry.file_name() != "target")
        {
            let entry = entry.context("walk Rust sources")?;
            if !entry.file_type().is_file()
                || entry.path().extension().and_then(|value| value.to_str()) != Some("rs")
            {
                continue;
            }
            checked += 1;
            let relative = entry
                .path()
                .strip_prefix(workspace)
                .context("source escaped workspace")?;
            let source = fs::read_to_string(entry.path())
                .with_context(|| format!("read {}", relative.display()))?;
            ensure!(
                !public_sdk.is_match(&source),
                "public API exposes a Rig or RMCP type: {}",
                relative.display()
            );

            let adapter_private = relative.starts_with("crates/llm-provider-rig")
                || relative.starts_with("crates/llm-provider-bedrock")
                || relative.starts_with("crates/llm-provider-vertex")
                || relative
                    .components()
                    .nth(1)
                    .and_then(|component| component.as_os_str().to_str())
                    .is_some_and(|name| name.starts_with("mcp-"));
            if !adapter_private {
                ensure!(
                    !SDK_TOKENS.iter().any(|token| source.contains(token)),
                    "application source imports a Rig or RMCP type outside an adapter: {}",
                    relative.display()
                );
            }
        }
    }
    Ok(checked)
}

fn validate_module_lifecycle(workspace: &Path) -> Result<usize> {
    let catalog: YamlValue = serde_yaml::from_str(&fs::read_to_string(
        workspace.join("specs/machine/extensions/llm-mcp-suite/module-catalog.yaml"),
    )?)?;
    let modules = catalog
        .get("modules")
        .and_then(YamlValue::as_sequence)
        .context("AI module catalog has no modules")?;
    for module in modules {
        let id = module
            .get("id")
            .and_then(YamlValue::as_str)
            .context("AI module has no id")?;
        for key in [
            "acceptance",
            "configuration",
            "criticality",
            "generator_ownership",
            "metrics_prefix",
            "removal_behavior",
            "test_fixtures",
        ] {
            ensure!(
                module.get(key).is_some(),
                "AI module `{id}` omits lifecycle field `{key}`"
            );
        }
    }
    Ok(modules.len())
}

fn validate_default_profiles(workspace: &Path) -> Result<()> {
    let catalog: YamlValue = serde_yaml::from_str(&fs::read_to_string(
        workspace.join("specs/machine/extensions/llm-mcp-suite/profiles.yaml"),
    )?)?;
    let profiles = catalog
        .get("profiles")
        .and_then(YamlValue::as_sequence)
        .context("AI profile catalog has no profiles")?;
    for profile in profiles {
        let id = profile
            .get("id")
            .and_then(YamlValue::as_str)
            .context("AI profile has no id")?;
        let modules = profile
            .get("modules")
            .and_then(YamlValue::as_sequence)
            .context("AI profile has no module list")?;
        for module in modules.iter().filter_map(YamlValue::as_str) {
            ensure!(
                !FORBIDDEN_MCP_MODULES.contains(&module),
                "AI profile `{id}` enables deprecated MCP module `{module}`"
            );
        }
    }
    Ok(())
}

fn parse_toml(path: &Path) -> Result<TomlValue> {
    toml::from_str(&fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_feature_sets_are_exact() -> Result<()> {
        let document: TomlValue = toml::from_str(
            r#"[workspace.dependencies]
rig-core = { version = "=0.42.0", default-features = false, features = ["rustls", "reqwest"] }
"#,
        )?;
        let dependencies = document["workspace"]["dependencies"]
            .as_table()
            .context("missing dependency table")?;
        ensure_features(dependencies, "rig-core", &["reqwest", "rustls"])
    }

    #[test]
    fn dependency_ownership_includes_target_specific_tables() -> Result<()> {
        let document: TomlValue = toml::from_str(
            r"[target.'cfg(unix)'.dependencies]
rmcp = { workspace = true }
",
        )?;

        assert!(direct_dependency_names(&document).contains("rmcp"));
        Ok(())
    }

    #[test]
    fn public_sdk_signature_pattern_rejects_direct_leaks() -> Result<()> {
        let pattern = Regex::new(
            r"(?m)^\s*pub(?:\([^)]*\))?\s+(?:use\b[^;\n]*(?:rig_agent|rig_bedrock|rig_core|rig_vertexai|rmcp)(?:::|\b)|(?:(?:(?:async\s+)?fn|trait|struct|enum)\b[^;{\n]*|(?:const|static)\b[^;={\n]*|type\b[^;\n]*)(?:rig_agent|rig_bedrock|rig_core|rig_vertexai|rmcp)::)",
        )?;
        assert!(pattern.is_match("pub use rmcp::model::CallToolResult;"));
        assert!(pattern.is_match("pub use rmcp;"));
        assert!(pattern.is_match("pub use rig_core as protocol;"));
        assert!(pattern.is_match("pub fn leak() -> rig_core::OneOrMany<()> {"));
        assert!(pattern.is_match("pub async fn leak_async() -> rmcp::model::CallToolResult {"));
        assert!(pattern.is_match("pub type Leak = rmcp::model::CallToolResult;"));
        assert!(pattern.is_match("pub const LEAK: rmcp::model::Role = value;"));
        assert!(!pattern.is_match("pub const SAFE: &str = rmcp::model::TASKS_EXTENSION_ID;"));
        assert!(!pattern.is_match("fn convert(value: rmcp::model::CallToolResult) {}"));
        Ok(())
    }
}
