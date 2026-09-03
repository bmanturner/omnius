use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use toml::Value;

use crate::release::{CANONICAL_REPOSITORY, ReleaseIdentity};

/// One deterministic manifest or Cargo-configuration provenance violation.
#[derive(Clone, Debug)]
pub(crate) struct ProvenanceFinding {
    /// Stable diagnostic code.
    pub(crate) code: &'static str,
    /// Manifest-relative or configuration path.
    pub(crate) path: String,
    /// Actionable violation description.
    pub(crate) message: String,
}

/// Files and findings captured while inspecting Cargo provenance.
#[derive(Debug)]
pub(crate) struct ProvenanceInspection {
    /// UTF-8 Cargo manifests keyed by project-relative path.
    pub(crate) manifest_files: BTreeMap<String, String>,
    /// Sorted provenance violations.
    pub(crate) findings: Vec<ProvenanceFinding>,
}

/// Filesystem failure while inspecting manifests or Cargo configuration.
#[derive(Debug)]
pub(crate) struct ProvenanceError {
    path: PathBuf,
    source: io::Error,
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cannot inspect dependency provenance at {}: {}",
            self.path.display(),
            self.source
        )
    }
}

impl Error for ProvenanceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Discovers workspace manifests and validates immutable framework provenance.
///
/// # Errors
///
/// Returns [`ProvenanceError`] when a candidate manifest or configuration path cannot be
/// inspected as a regular UTF-8 file.
pub(crate) fn inspect_project_provenance(
    project_root: &Path,
    framework: &ReleaseIdentity,
    runtime_features: &[String],
) -> Result<ProvenanceInspection, ProvenanceError> {
    let mut inspection = ProvenanceInspection {
        manifest_files: BTreeMap::new(),
        findings: Vec::new(),
    };
    let root_manifest_path = project_root.join("Cargo.toml");
    let Some(root_source) = read_regular_utf8(&root_manifest_path)? else {
        inspection.findings.push(finding(
            "manifest-missing",
            "Cargo.toml",
            "root Cargo manifest is missing",
        ));
        inspect_cargo_configs(project_root, &mut inspection)?;
        return Ok(inspection);
    };
    inspection
        .manifest_files
        .insert("Cargo.toml".to_owned(), root_source.clone());

    let root_document = match toml::from_str::<Value>(&root_source) {
        Ok(document) => Some(document),
        Err(error) => {
            inspection.findings.push(finding(
                "manifest-invalid",
                "Cargo.toml",
                format!("root Cargo manifest is invalid TOML: {error}"),
            ));
            None
        }
    };

    if let Some(document) = root_document.as_ref() {
        inspect_manifest(
            "Cargo.toml",
            document,
            true,
            framework,
            runtime_features,
            &mut inspection.findings,
        );
        let members = discover_workspace_members(project_root, document, &mut inspection.findings)?;
        if !members.iter().any(|member| member == "apps/service") {
            inspection.findings.push(finding(
                "workspace-member-missing",
                "Cargo.toml",
                "root workspace members must include apps/service",
            ));
        }
        for member in members {
            let manifest = format!("{member}/Cargo.toml");
            let absolute = project_root.join(&manifest);
            let Some(source) = read_regular_utf8(&absolute)? else {
                inspection.findings.push(finding(
                    "workspace-member-missing",
                    &manifest,
                    format!("workspace member `{member}` has no Cargo.toml"),
                ));
                continue;
            };
            let document = match toml::from_str::<Value>(&source) {
                Ok(document) => document,
                Err(error) => {
                    inspection.findings.push(finding(
                        "manifest-invalid",
                        &manifest,
                        format!("workspace member manifest is invalid TOML: {error}"),
                    ));
                    inspection.manifest_files.insert(manifest, source);
                    continue;
                }
            };
            inspect_manifest(
                &manifest,
                &document,
                false,
                framework,
                runtime_features,
                &mut inspection.findings,
            );
            inspection.manifest_files.insert(manifest, source);
        }
    }

    inspect_cargo_configs(project_root, &mut inspection)?;
    inspection.findings.sort_by(|left, right| {
        left.code
            .cmp(right.code)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.message.cmp(&right.message))
    });
    inspection.findings.dedup_by(|left, right| {
        left.code == right.code && left.path == right.path && left.message == right.message
    });
    Ok(inspection)
}

fn discover_workspace_members(
    project_root: &Path,
    document: &Value,
    findings: &mut Vec<ProvenanceFinding>,
) -> Result<Vec<String>, ProvenanceError> {
    let Some(workspace) = document.get("workspace").and_then(Value::as_table) else {
        findings.push(finding(
            "workspace-invalid",
            "Cargo.toml",
            "root Cargo manifest must declare [workspace]",
        ));
        return Ok(Vec::new());
    };
    let Some(member_values) = workspace.get("members").and_then(Value::as_array) else {
        findings.push(finding(
            "workspace-invalid",
            "Cargo.toml",
            "root Cargo workspace must declare a members array",
        ));
        return Ok(Vec::new());
    };
    let exclude_patterns = workspace
        .get("exclude")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut members = BTreeSet::new();
    for value in member_values {
        let Some(pattern) = value.as_str() else {
            findings.push(finding(
                "workspace-member-invalid",
                "Cargo.toml",
                "workspace member entries must be strings",
            ));
            continue;
        };
        if !safe_member_pattern(pattern) {
            findings.push(finding(
                "workspace-member-invalid",
                "Cargo.toml",
                format!("workspace member pattern `{pattern}` is unsafe or unsupported"),
            ));
            continue;
        }
        let expanded = expand_member_pattern(project_root, pattern)?;
        if expanded.is_empty() {
            findings.push(finding(
                "workspace-member-missing",
                "Cargo.toml",
                format!("workspace member pattern `{pattern}` matched no directories"),
            ));
        }
        for member in expanded {
            if member != "."
                && !exclude_patterns
                    .iter()
                    .any(|excluded| member_pattern_matches(excluded, &member))
            {
                members.insert(member);
            }
        }
    }
    Ok(members.into_iter().collect())
}

fn safe_member_pattern(pattern: &str) -> bool {
    !pattern.is_empty()
        && !pattern.contains('\\')
        && !Path::new(pattern).is_absolute()
        && pattern
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, ".."))
        && !pattern.contains('[')
        && !pattern.contains(']')
}

fn expand_member_pattern(
    project_root: &Path,
    pattern: &str,
) -> Result<Vec<String>, ProvenanceError> {
    if pattern == "." {
        return Ok(vec![".".to_owned()]);
    }
    let components = pattern.split('/').collect::<Vec<_>>();
    let mut candidates = vec![(project_root.to_path_buf(), Vec::<String>::new())];
    for component in components {
        let mut next = Vec::new();
        for (absolute, relative) in candidates {
            if component.contains('*') || component.contains('?') {
                let entries = match fs::read_dir(&absolute) {
                    Ok(entries) => entries,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(source) => {
                        return Err(ProvenanceError {
                            path: absolute,
                            source,
                        });
                    }
                };
                for entry in entries {
                    let entry = entry.map_err(|source| ProvenanceError {
                        path: absolute.clone(),
                        source,
                    })?;
                    let name = entry.file_name();
                    let Some(name) = name.to_str() else {
                        continue;
                    };
                    if wildcard_component_matches(component, name) {
                        let metadata = fs::symlink_metadata(entry.path()).map_err(|source| {
                            ProvenanceError {
                                path: entry.path(),
                                source,
                            }
                        })?;
                        if metadata.file_type().is_symlink() {
                            return Err(ProvenanceError {
                                path: entry.path(),
                                source: io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "workspace member path is a symlink",
                                ),
                            });
                        }
                        if metadata.is_dir() {
                            let mut child_relative = relative.clone();
                            child_relative.push(name.to_owned());
                            next.push((entry.path(), child_relative));
                        }
                    }
                }
            } else {
                let child = absolute.join(component);
                let metadata = match fs::symlink_metadata(&child) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(source) => {
                        return Err(ProvenanceError {
                            path: child,
                            source,
                        });
                    }
                };
                if metadata.file_type().is_symlink() {
                    return Err(ProvenanceError {
                        path: child,
                        source: io::Error::new(
                            io::ErrorKind::InvalidData,
                            "workspace member path is a symlink",
                        ),
                    });
                }
                if metadata.is_dir() {
                    let mut child_relative = relative;
                    if component != "." {
                        child_relative.push(component.to_owned());
                    }
                    next.push((child, child_relative));
                }
            }
        }
        candidates = next;
    }
    let mut matches = candidates
        .into_iter()
        .map(|(_, components)| components.join("/"))
        .filter(|relative| !relative.is_empty())
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    Ok(matches)
}

fn member_pattern_matches(pattern: &str, member: &str) -> bool {
    if !safe_member_pattern(pattern) {
        return false;
    }
    let pattern_components = pattern.split('/').collect::<Vec<_>>();
    let member_components = member.split('/').collect::<Vec<_>>();
    pattern_components.len() == member_components.len()
        && pattern_components
            .iter()
            .zip(member_components)
            .all(|(expected, actual)| wildcard_component_matches(expected, actual))
}

fn wildcard_component_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut pattern_index, mut value_index) = (0, 0);
    let (mut star_index, mut star_value_index) = (None, 0);
    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            star_value_index = value_index;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_value_index += 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn inspect_manifest(
    path: &str,
    document: &Value,
    root: bool,
    framework: &ReleaseIdentity,
    runtime_features: &[String],
    findings: &mut Vec<ProvenanceFinding>,
) {
    if document.get("patch").is_some() {
        findings.push(finding(
            "manifest-patch-forbidden",
            path,
            "Cargo [patch] tables are forbidden in managed projects",
        ));
    }
    if document.get("replace").is_some() {
        findings.push(finding(
            "manifest-replace-forbidden",
            path,
            "Cargo [replace] tables are forbidden in managed projects",
        ));
    }
    if document.get("paths").is_some() {
        findings.push(finding(
            "source-override",
            path,
            "Cargo paths substitution is forbidden in managed projects",
        ));
    }

    if root {
        inspect_canonical_workspace_dependency(
            path,
            document,
            framework,
            runtime_features,
            findings,
        );
    }
    if path == "apps/service/Cargo.toml"
        && document
            .get("dependencies")
            .and_then(|dependencies| dependencies.get("service-kit"))
            .is_none()
    {
        findings.push(finding(
            "member-framework-use-missing",
            path,
            "apps/service must inherit service-kit from workspace.dependencies",
        ));
    }

    inspect_dependency_tables(path, document, root, findings);
}

fn inspect_canonical_workspace_dependency(
    path: &str,
    document: &Value,
    framework: &ReleaseIdentity,
    runtime_features: &[String],
    findings: &mut Vec<ProvenanceFinding>,
) {
    let dependency = document
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(|dependencies| dependencies.get("service-kit"));
    let Some(dependency) = dependency else {
        findings.push(finding(
            "framework-dependency-missing",
            path,
            "root workspace must declare workspace.dependencies.service-kit",
        ));
        return;
    };
    let Some(table) = dependency.as_table() else {
        findings.push(finding(
            "framework-dependency-invalid",
            path,
            "workspace.dependencies.service-kit must be a dependency table",
        ));
        return;
    };
    let allowed = [
        "package",
        "version",
        "git",
        "rev",
        "default-features",
        "features",
    ];
    if let Some(key) = table.keys().find(|key| !allowed.contains(&key.as_str())) {
        findings.push(finding(
            "framework-dependency-invalid",
            path,
            format!("workspace.dependencies.service-kit contains forbidden key `{key}`"),
        ));
    }
    require_dependency_string(path, table, "package", "omnius-service-kit", findings);
    require_dependency_string(
        path,
        table,
        "version",
        &format!("={}", framework.version()),
        findings,
    );
    require_dependency_string(path, table, "git", CANONICAL_REPOSITORY, findings);
    require_dependency_string(path, table, "rev", framework.revision(), findings);
    if table.get("default-features").and_then(Value::as_bool) != Some(false) {
        findings.push(finding(
            "framework-dependency-invalid",
            path,
            "workspace.dependencies.service-kit must set default-features = false",
        ));
    }
    let features = table
        .get("features")
        .and_then(Value::as_array)
        .and_then(|values| values.iter().map(Value::as_str).collect::<Option<Vec<_>>>());
    let expected = runtime_features
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if features.as_deref() != Some(expected.as_slice()) {
        findings.push(finding(
            "framework-features-invalid",
            path,
            format!(
                "workspace.dependencies.service-kit features must exactly match [{}]",
                runtime_features.join(", ")
            ),
        ));
    }
}

fn require_dependency_string(
    path: &str,
    table: &toml::Table,
    key: &str,
    expected: &str,
    findings: &mut Vec<ProvenanceFinding>,
) {
    if table.get(key).and_then(Value::as_str) != Some(expected) {
        findings.push(finding(
            "framework-dependency-invalid",
            path,
            format!("workspace.dependencies.service-kit `{key}` must be exactly `{expected}`"),
        ));
    }
}

fn inspect_dependency_tables(
    path: &str,
    document: &Value,
    root: bool,
    findings: &mut Vec<ProvenanceFinding>,
) {
    for (name, dev) in [
        ("dependencies", false),
        ("dev-dependencies", true),
        ("build-dependencies", false),
    ] {
        if let Some(table) = document.get(name).and_then(Value::as_table) {
            inspect_dependency_table(path, name, table, !root, dev, false, findings);
        }
    }
    if let Some(targets) = document.get("target").and_then(Value::as_table) {
        for (target, target_value) in targets {
            let Some(target_table) = target_value.as_table() else {
                continue;
            };
            for (name, dev) in [
                ("dependencies", false),
                ("dev-dependencies", true),
                ("build-dependencies", false),
            ] {
                if let Some(table) = target_table.get(name).and_then(Value::as_table) {
                    inspect_dependency_table(
                        path,
                        &format!("target.{target}.{name}"),
                        table,
                        !root,
                        dev,
                        false,
                        findings,
                    );
                }
            }
        }
    }
    if let Some(workspace_dependencies) = document
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(Value::as_table)
    {
        inspect_dependency_table(
            path,
            "workspace.dependencies",
            workspace_dependencies,
            false,
            false,
            root,
            findings,
        );
    }
}

fn inspect_dependency_table(
    path: &str,
    table_name: &str,
    table: &toml::Table,
    member_use_allowed: bool,
    dev: bool,
    canonical_workspace: bool,
    findings: &mut Vec<ProvenanceFinding>,
) {
    for (key, dependency) in table {
        if canonical_workspace && table_name == "workspace.dependencies" && key == "service-kit" {
            continue;
        }
        let package = dependency
            .as_table()
            .and_then(|value| value.get("package"))
            .and_then(Value::as_str);
        let names_omnius = key.starts_with("omnius-")
            || key == "omnius-generator"
            || package.is_some_and(|package| {
                package.starts_with("omnius-") || package == "omnius-generator"
            });
        if key == "service-kit" {
            if member_use_allowed {
                inspect_member_service_kit(path, table_name, dependency, dev, findings);
            } else {
                findings.push(finding(
                    "framework-dependency-invalid",
                    path,
                    format!(
                        "service-kit may only be declared canonically in workspace.dependencies or inherited by workspace members; found `{table_name}.{key}`"
                    ),
                ));
            }
        } else if names_omnius {
            findings.push(finding(
                "omnius-dependency-forbidden",
                path,
                format!(
                    "direct Omnius dependency `{table_name}.{key}` is forbidden; use service-kit.workspace = true"
                ),
            ));
        }
    }
}

fn inspect_member_service_kit(
    path: &str,
    table_name: &str,
    dependency: &Value,
    dev: bool,
    findings: &mut Vec<ProvenanceFinding>,
) {
    let Some(table) = dependency.as_table() else {
        findings.push(finding(
            "member-framework-use-invalid",
            path,
            format!("`{table_name}.service-kit` must set workspace = true"),
        ));
        return;
    };
    if table.get("workspace").and_then(Value::as_bool) != Some(true)
        || table
            .keys()
            .any(|key| key != "workspace" && !(dev && key == "features"))
    {
        findings.push(finding(
            "member-framework-use-invalid",
            path,
            format!(
                "`{table_name}.service-kit` may only inherit workspace = true{}",
                if dev { " and enable test-support" } else { "" }
            ),
        ));
        return;
    }
    if let Some(features) = table.get("features") {
        let valid = dev
            && features.as_array().is_some_and(|features| {
                features.len() == 1
                    && features.first().and_then(Value::as_str) == Some("test-support")
            });
        if !valid {
            findings.push(finding(
                "member-framework-use-invalid",
                path,
                format!(
                    "`{table_name}.service-kit` may only enable the test-support feature from dev-dependencies"
                ),
            ));
        }
    }
}

fn inspect_cargo_configs(
    project_root: &Path,
    inspection: &mut ProvenanceInspection,
) -> Result<(), ProvenanceError> {
    let mut config_paths = BTreeSet::new();
    for ancestor in project_root.ancestors() {
        config_paths.insert(ancestor.join(".cargo/config"));
        config_paths.insert(ancestor.join(".cargo/config.toml"));
    }
    if let Some(cargo_home) = effective_cargo_home() {
        config_paths.insert(cargo_home.join("config"));
        config_paths.insert(cargo_home.join("config.toml"));
    }
    for path in config_paths {
        let Some(source) = read_regular_utf8(&path)? else {
            continue;
        };
        let display = display_config_path(project_root, &path);
        let document = match toml::from_str::<Value>(&source) {
            Ok(document) => document,
            Err(error) => {
                inspection.findings.push(finding(
                    "cargo-config-invalid",
                    &display,
                    format!("Cargo configuration is invalid TOML: {error}"),
                ));
                continue;
            }
        };
        if document.get("paths").is_some() {
            inspection.findings.push(finding(
                "source-override",
                &display,
                "Cargo paths substitution is forbidden for lifecycle provenance",
            ));
        }
        if let Some(sources) = document.get("source").and_then(Value::as_table) {
            for (name, descriptor) in sources {
                let Some(table) = descriptor.as_table() else {
                    continue;
                };
                if table.get("replace-with").is_none() {
                    continue;
                }
                let git = table.get("git").and_then(Value::as_str);
                if source_names_canonical_omnius(name)
                    || git.is_some_and(source_names_canonical_omnius)
                {
                    inspection.findings.push(finding(
                        "source-override",
                        &display,
                        format!("Cargo source `{name}` replaces the canonical Omnius Git source"),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn source_names_canonical_omnius(value: &str) -> bool {
    value == CANONICAL_REPOSITORY
        || value
            .trim_end_matches(".git")
            .contains("github.com/bmanturner/omnius")
}

fn effective_cargo_home() -> Option<PathBuf> {
    env::var_os("CARGO_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
}

fn display_config_path(project_root: &Path, path: &Path) -> String {
    path.strip_prefix(project_root)
        .ok()
        .and_then(Path::to_str)
        .filter(|relative| !relative.is_empty())
        .map_or_else(|| path.display().to_string(), str::to_owned)
}

fn read_regular_utf8(path: &Path) -> Result<Option<String>, ProvenanceError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ProvenanceError {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(ProvenanceError {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidData, "path is not a regular file"),
        });
    }
    let bytes = fs::read(path).map_err(|source| ProvenanceError {
        path: path.to_path_buf(),
        source,
    })?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| ProvenanceError {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidData, "file is not UTF-8"),
        })
}

fn finding(
    code: &'static str,
    path: impl Into<String>,
    message: impl Into<String>,
) -> ProvenanceFinding {
    ProvenanceFinding {
        code,
        path: path.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matching_should_cover_cargo_member_patterns() {
        assert!(wildcard_component_matches("service-*", "service-api"));
        assert!(!wildcard_component_matches("service-*", "worker-api"));
        assert!(wildcard_component_matches("?pp", "app"));
    }
}
