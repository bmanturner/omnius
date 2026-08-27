use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use csv::Reader;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::{
    extensions::{self, Overlay},
    model::{
        AcceptanceCatalog, Frontmatter, ModuleCatalog, Patterns, Task, TaskCatalog, ensure_unique,
    },
    profiles,
};

const PROHIBITED_MARKERS: &[&str] = &["TODO", "TBD", "FIXME", "???", "unimplemented!()", "todo!()"];

pub(crate) struct SpecSummary {
    pub(crate) modules: usize,
    pub(crate) profiles: usize,
    pub(crate) criteria: usize,
    pub(crate) tasks: usize,
    pub(crate) recommendations: usize,
}
struct BundleCounts {
    modules: usize,
    profiles: usize,
    criteria: usize,
    tasks: usize,
    recommendations: usize,
    sources: usize,
}

#[derive(Debug, Deserialize)]
struct TraceRow {
    #[serde(rename = "recommendation_id")]
    id: String,
    #[serde(rename = "recommendation")]
    text: String,
    specification: String,
    acceptance_id: String,
}

pub(crate) fn verify(root: &Path) -> Result<SpecSummary> {
    let patterns = Patterns::new()?;
    validate_structured_files(root)?;
    let frontmatter = validate_frontmatter(root, &patterns)?;
    let overlay = Overlay::verify(root)?;

    let base_modules: ModuleCatalog =
        profiles::load_yaml(&root.join("machine/module-catalog.yaml"))?;
    let base_acceptance: AcceptanceCatalog =
        profiles::load_yaml(&root.join("machine/acceptance-criteria.yaml"))?;
    let base_tasks: TaskCatalog = profiles::load_yaml(&root.join("machine/tasks.yaml"))?;
    let modules: ModuleCatalog = overlay.yaml(root, "machine/module-catalog.yaml")?;
    let acceptance: AcceptanceCatalog = overlay.yaml(root, "machine/acceptance-criteria.yaml")?;
    let tasks: TaskCatalog = overlay.yaml(root, "machine/tasks.yaml")?;
    modules.validate(&patterns)?;
    acceptance.validate(&patterns)?;
    tasks.validate(&patterns)?;

    let profile_summary = profiles::verify(root)?;
    validate_catalog_schemas(root, &overlay)?;
    validate_frontend_exposure(root, &modules)?;
    validate_references(&frontmatter, &modules, &acceptance, &tasks)?;
    let recommendation_count = validate_recommendations(root, &frontmatter, &acceptance, &overlay)?;
    let source_count = validate_source_references(root)?;
    validate_contract_examples(root)?;
    validate_integrity(
        root,
        &frontmatter,
        &BundleCounts {
            modules: base_modules.modules.len(),
            profiles: base_profile_count(root)?,
            criteria: base_acceptance.criteria.len(),
            tasks: base_tasks.tasks.len(),
            recommendations: csv_record_count(
                root.join("machine/recommendation-traceability.csv"),
            )?,
            sources: source_count,
        },
    )?;
    validate_markers(root)?;

    Ok(SpecSummary {
        modules: profile_summary.modules,
        profiles: profile_summary.profiles,
        criteria: acceptance.criteria.len(),
        tasks: tasks.tasks.len(),
        recommendations: recommendation_count,
    })
}

fn validate_structured_files(root: &Path) -> Result<()> {
    for path in files(root)? {
        let extension = path.extension().and_then(|extension| extension.to_str());
        if !matches!(extension, Some("yaml" | "yml" | "json" | "toml")) {
            continue;
        }
        let contents =
            fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        match extension {
            Some("yaml" | "yml") => {
                serde_yaml::from_str::<serde_yaml::Value>(&contents)
                    .with_context(|| format!("parse {}", path.display()))?;
            }
            Some("json") => {
                serde_json::from_str::<Value>(&contents)
                    .with_context(|| format!("parse {}", path.display()))?;
            }
            Some("toml") => {
                toml::from_str::<toml::Value>(&contents)
                    .with_context(|| format!("parse {}", path.display()))?;
            }
            _ => unreachable!("structured extensions were filtered above"),
        }
    }
    Ok(())
}

fn validate_frontmatter(root: &Path, patterns: &Patterns) -> Result<HashMap<String, Document>> {
    let mut by_id = HashMap::new();
    for path in files(root)?
        .into_iter()
        .filter(|path| path.extension().is_some_and(|extension| extension == "md"))
    {
        let contents =
            fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let relative_path = relative(root, &path)?;
        let yaml = contents
            .strip_prefix("---\n")
            .and_then(|rest| rest.split_once("\n---\n").map(|(header, _)| header))
            .with_context(|| format!("{relative_path} has invalid YAML frontmatter"))?;
        let metadata: Frontmatter = serde_yaml::from_str(yaml)
            .with_context(|| format!("parse frontmatter for {relative_path}"))?;
        metadata.validate(patterns)?;
        let id = metadata.spec_id.clone();
        let document = Document {
            path: relative_path,
            metadata,
        };
        ensure!(
            by_id.insert(id.clone(), document).is_none(),
            "duplicate spec_id {id}"
        );
    }
    Ok(by_id)
}

struct Document {
    path: String,
    metadata: Frontmatter,
}

fn validate_catalog_schemas(root: &Path, overlay: &Overlay) -> Result<()> {
    for (catalog_name, key, schema_name) in [
        (
            "module-catalog.yaml",
            "modules",
            "module-manifest.schema.json",
        ),
        ("profiles.yaml", "profiles", "profile.schema.json"),
    ] {
        let target = format!("machine/{catalog_name}");
        let catalog = extensions::json_value(overlay.yaml_value(root, &target)?)?;
        let schema: Value =
            serde_json::from_str(&fs::read_to_string(root.join("machine").join(schema_name))?)?;
        let validator = jsonschema::validator_for(&schema)
            .with_context(|| format!("compile machine/{schema_name}"))?;
        let entries = catalog
            .get(key)
            .and_then(Value::as_array)
            .with_context(|| format!("{target} missing {key}"))?;
        for entry in entries {
            let errors: Vec<String> = validator
                .iter_errors(entry)
                .map(|error| error.to_string())
                .collect();
            ensure!(
                errors.is_empty(),
                "{target} schema failure: {}",
                errors.join("; ")
            );
        }
    }
    Ok(())
}

fn validate_frontend_exposure(root: &Path, modules: &ModuleCatalog) -> Result<()> {
    let extension = root.join("machine/extensions/web-application-suite");
    let capability_document: Value = extensions::json_value(serde_yaml::from_str(
        &fs::read_to_string(extension.join("frontend-capabilities.yaml"))?,
    )?)?;
    let records = capability_document
        .get("capabilities")
        .and_then(Value::as_array)
        .context("frontend-capabilities.yaml is missing capabilities")?;
    let schema: Value = serde_json::from_str(&fs::read_to_string(
        extension.join("schemas/frontend-capability.schema.json"),
    )?)?;
    let validator =
        jsonschema::validator_for(&schema).context("compile frontend capability schema")?;
    let module_ids = modules
        .modules
        .iter()
        .map(|module| module.id.as_str())
        .collect::<HashSet<_>>();
    let mut exposed = HashSet::new();
    for record in records {
        let id = record
            .get("module_id")
            .and_then(Value::as_str)
            .context("frontend capability has no module_id")?;
        ensure!(
            exposed.insert(id),
            "duplicate frontend capability declaration for module {id}"
        );
        ensure!(
            module_ids.contains(id),
            "frontend capability references unknown module {id}"
        );
        let errors = validator
            .iter_errors(record)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        ensure!(
            errors.is_empty(),
            "frontend capability {id} schema failure: {}",
            errors.join("; ")
        );
        if record.get("exposure").and_then(Value::as_str) == Some("none") {
            for (section, fields) in [
                (
                    "contracts",
                    &["openapi_tags", "asyncapi_events", "runtime_capabilities"][..],
                ),
                (
                    "provides",
                    &[
                        "core_exports",
                        "react_exports",
                        "route_requirements",
                        "query_effects",
                        "testing",
                    ][..],
                ),
            ] {
                let values = record
                    .get(section)
                    .and_then(Value::as_object)
                    .context("frontend capability section is not an object")?;
                ensure!(
                    fields.iter().all(|field| {
                        values
                            .get(*field)
                            .and_then(Value::as_array)
                            .is_none_or(Vec::is_empty)
                    }),
                    "headless module {id} declares frontend contracts or exports"
                );
            }
        }
    }
    let mut missing = module_ids.difference(&exposed).copied().collect::<Vec<_>>();
    missing.sort_unstable();
    ensure!(
        missing.is_empty(),
        "modules missing frontend exposure declarations: {}",
        missing.join(", ")
    );
    Ok(())
}

fn validate_references(
    documents: &HashMap<String, Document>,
    modules: &ModuleCatalog,
    acceptance: &AcceptanceCatalog,
    tasks: &TaskCatalog,
) -> Result<()> {
    let spec_ids: HashSet<&str> = documents.keys().map(String::as_str).collect();
    let acceptance_by_id: HashMap<&str, _> = acceptance
        .criteria
        .iter()
        .map(|criterion| (criterion.id.as_str(), criterion))
        .collect();
    let task_by_id: HashMap<&str, &Task> = tasks
        .tasks
        .iter()
        .map(|task| (task.id.as_str(), task))
        .collect();

    for criterion in &acceptance.criteria {
        ensure!(
            spec_ids.contains(criterion.spec.as_str()),
            "acceptance {} references unknown spec {}",
            criterion.id,
            criterion.spec
        );
    }
    for module in &modules.modules {
        ensure!(
            spec_ids.contains(module.spec.as_str()),
            "module {} references unknown spec {}",
            module.id,
            module.spec
        );
        for criterion in &module.acceptance {
            ensure!(
                acceptance_by_id.contains_key(criterion.as_str()),
                "module {} references unknown acceptance {criterion}",
                module.id
            );
        }
    }
    for task in &tasks.tasks {
        let phase = phase_rank(&task.phase)?;
        for dependency in &task.depends_on {
            let dependency_task = task_by_id.get(dependency.as_str()).with_context(|| {
                format!(
                    "task {} references unknown dependency {dependency}",
                    task.id
                )
            })?;
            ensure!(
                phase_rank(&dependency_task.phase)? <= phase,
                "task {} depends on later-phase task {dependency}",
                task.id
            );
        }
        for criterion_id in &task.acceptance {
            let criterion = acceptance_by_id
                .get(criterion_id.as_str())
                .with_context(|| {
                    format!(
                        "task {} references unknown acceptance {criterion_id}",
                        task.id
                    )
                })?;
            if task.phase == "0" {
                ensure!(
                    ["build", "compile", "dependency"].contains(&criterion.verification.as_str()),
                    "phase 0 task {} maps behavioral acceptance {criterion_id}",
                    task.id
                );
            }
        }
    }
    validate_task_dag(&task_by_id)
}

fn validate_task_dag(tasks: &HashMap<&str, &Task>) -> Result<()> {
    fn visit<'a>(
        id: &'a str,
        tasks: &HashMap<&'a str, &'a Task>,
        visiting: &mut HashSet<&'a str>,
        complete: &mut HashSet<&'a str>,
    ) -> Result<()> {
        if complete.contains(id) {
            return Ok(());
        }
        ensure!(visiting.insert(id), "task dependency cycle at {id}");
        let task = tasks
            .get(id)
            .with_context(|| format!("unknown task {id}"))?;
        for dependency in &task.depends_on {
            visit(dependency, tasks, visiting, complete)?;
        }
        visiting.remove(id);
        complete.insert(id);
        Ok(())
    }

    let mut visiting = HashSet::new();
    let mut complete = HashSet::new();
    for id in tasks.keys() {
        visit(id, tasks, &mut visiting, &mut complete)?;
    }
    Ok(())
}

fn validate_recommendations(
    root: &Path,
    documents: &HashMap<String, Document>,
    acceptance: &AcceptanceCatalog,
    overlay: &Overlay,
) -> Result<usize> {
    let mut recommendations = Vec::new();
    for source in overlay.csv_sources("machine/recommendation-traceability.csv")? {
        let mut reader = Reader::from_path(root.join(source))?;
        recommendations.extend(reader.deserialize().collect::<Result<Vec<TraceRow>, _>>()?);
    }
    ensure_unique(
        recommendations.iter().map(|item| item.id.as_str()),
        "recommendation IDs",
    )?;
    let acceptance_ids: HashSet<&str> = acceptance
        .criteria
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    for item in &recommendations {
        ensure!(
            !item.text.trim().is_empty(),
            "recommendation {} is empty",
            item.id
        );
        for spec in split_references(&item.specification) {
            ensure!(
                documents.contains_key(spec),
                "recommendation {} references unknown spec {spec}",
                item.id
            );
        }
        for criterion in split_references(&item.acceptance_id) {
            ensure!(
                acceptance_ids.contains(criterion),
                "recommendation {} references unknown acceptance {criterion}",
                item.id
            );
        }
    }
    Ok(recommendations.len())
}

fn phase_rank(phase: &str) -> Result<u16> {
    if let Some(web_phase) = phase.strip_prefix('W') {
        return Ok(100 + web_phase.parse::<u16>()?);
    }
    Ok(phase.parse::<u16>()?)
}

fn base_profile_count(root: &Path) -> Result<usize> {
    let document: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(root.join("machine/profiles.yaml"))?)?;
    document
        .get("profiles")
        .and_then(serde_yaml::Value::as_sequence)
        .map(Vec::len)
        .context("machine/profiles.yaml is missing profiles")
}

fn csv_record_count(path: PathBuf) -> Result<usize> {
    let mut reader = Reader::from_path(path)?;
    Ok(reader.records().collect::<Result<Vec<_>, _>>()?.len())
}

fn split_references(value: &str) -> impl Iterator<Item = &str> {
    value
        .split([';', ','])
        .map(str::trim)
        .filter(|part| !part.is_empty())
}

fn validate_source_references(root: &Path) -> Result<usize> {
    let pattern = Regex::new(r"SRC-[A-Z0-9-]+")?;
    let source_text = fs::read_to_string(root.join("research/sources.md"))?;
    let sources: HashSet<&str> = pattern
        .find_iter(&source_text)
        .map(|item| item.as_str())
        .collect();
    for relative_path in [
        "21-crate-selection-matrix.md",
        "research/compatibility-findings.md",
    ] {
        let contents = fs::read_to_string(root.join(relative_path))?;
        for source in pattern.find_iter(&contents).map(|item| item.as_str()) {
            ensure!(
                sources.contains(source),
                "{relative_path} references unknown source {source}"
            );
        }
    }
    Ok(sources.len())
}

fn validate_contract_examples(root: &Path) -> Result<()> {
    for (schema_name, example_name) in [
        ("problem-details.schema.json", "problem-details.json"),
        ("event-envelope.schema.json", "event-envelope.json"),
        ("job-envelope.schema.json", "job-envelope.json"),
    ] {
        let schema: Value =
            serde_json::from_str(&fs::read_to_string(root.join("machine").join(schema_name))?)?;
        let example: Value = serde_json::from_str(&fs::read_to_string(
            root.join("examples").join(example_name),
        )?)?;
        let validator = jsonschema::validator_for(&schema)
            .with_context(|| format!("compile machine/{schema_name}"))?;
        let errors: Vec<String> = validator
            .iter_errors(&example)
            .map(|error| error.to_string())
            .collect();
        ensure!(
            errors.is_empty(),
            "examples/{example_name} schema failure: {}",
            errors.join("; ")
        );
    }
    Ok(())
}

fn validate_integrity(
    root: &Path,
    documents: &HashMap<String, Document>,
    bundle_counts: &BundleCounts,
) -> Result<()> {
    let manifest: Value = serde_json::from_str(&fs::read_to_string(root.join("MANIFEST.json"))?)?;
    let manifest_files = manifest
        .get("files")
        .and_then(Value::as_array)
        .context("MANIFEST.json missing files")?;
    let mut declared = HashSet::new();
    for entry in manifest_files {
        let path = json_string(entry, "path")?;
        ensure!(
            declared.insert(path),
            "MANIFEST.json contains duplicate path {path}"
        );
        validate_digest_entry(root, path, entry)?;
    }
    let extension_files = validate_extension_integrity(root, &declared)?;
    let actual: HashSet<String> = files(root)?
        .into_iter()
        .map(|path| relative(root, &path))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|path| {
            path != "MANIFEST.json" && path != "SHA256SUMS" && !extension_files.contains(path)
        })
        .collect();
    ensure!(
        declared == actual.iter().map(String::as_str).collect(),
        "MANIFEST.json file inventory differs from the bundle"
    );

    let counts = manifest
        .get("counts")
        .and_then(Value::as_object)
        .context("MANIFEST.json missing counts")?;
    let markdown_count = actual
        .iter()
        .filter(|path| has_extension(path, "md"))
        .count();
    let numbered_count = actual
        .iter()
        .filter(|path| {
            path.len() >= 6
                && path.as_bytes()[0].is_ascii_digit()
                && path.as_bytes()[1].is_ascii_digit()
                && path.as_bytes()[2] == b'-'
                && has_extension(path, "md")
        })
        .count();
    let adr_count = actual
        .iter()
        .filter(|path| path.starts_with("adr/") && has_extension(path, "md"))
        .count();
    for (key, expected) in [
        ("files_excluding_manifest_and_checksums", actual.len()),
        ("markdown_documents", markdown_count),
        ("numbered_specs", numbered_count),
        ("adrs", adr_count),
        ("modules", bundle_counts.modules),
        ("profiles", bundle_counts.profiles),
        ("acceptance_criteria", bundle_counts.criteria),
        ("tasks", bundle_counts.tasks),
        ("recommendations", bundle_counts.recommendations),
        ("research_sources", bundle_counts.sources),
    ] {
        ensure!(
            counts.get(key).and_then(Value::as_u64) == Some(expected as u64),
            "MANIFEST.json count {key} is stale"
        );
    }

    validate_spec_manifest(root, documents)?;
    validate_checksum_file(root, &actual)?;
    Ok(())
}

fn extension_bundle_paths(root: &Path) -> Result<HashSet<String>> {
    let mut paths = HashSet::new();
    for manifest_path in files(root)? {
        if manifest_path.parent() != Some(root) {
            continue;
        }
        let manifest_name = relative(root, &manifest_path)?;
        if !manifest_name.ends_with("_FEATURE_SUITE_MANIFEST.json") {
            continue;
        }
        let manifest: Value = serde_json::from_str(&fs::read_to_string(&manifest_path)?)?;
        let entries = manifest
            .get("files")
            .and_then(Value::as_array)
            .with_context(|| format!("{manifest_name} missing files"))?;
        paths.insert(manifest_name.clone());
        for entry in entries {
            paths.insert(json_string(entry, "path")?.to_owned());
        }
        let checksum_name = manifest_name.replace("MANIFEST.json", "SHA256SUMS");
        if root.join(&checksum_name).is_file() {
            paths.insert(checksum_name);
        }
    }
    Ok(paths)
}

fn validate_spec_manifest(root: &Path, documents: &HashMap<String, Document>) -> Result<()> {
    let manifest: Value = serde_json::from_str(&fs::read_to_string(
        root.join("machine/spec-manifest.json"),
    )?)?;
    ensure!(
        manifest.get("schema_version").and_then(Value::as_u64) == Some(1),
        "spec manifest schema_version must be 1"
    );
    let entries = manifest
        .get("documents")
        .and_then(Value::as_array)
        .context("spec manifest missing documents")?;
    let extension_paths = extension_bundle_paths(root)?;
    let base_document_count = documents
        .values()
        .filter(|document| !extension_paths.contains(&document.path))
        .count();
    ensure!(
        entries.len() == base_document_count,
        "spec manifest document count is stale"
    );
    let mut seen = HashSet::new();
    for entry in entries {
        let id = json_string(entry, "spec_id")?;
        ensure!(
            seen.insert(id),
            "spec manifest contains duplicate spec_id {id}"
        );
        let document = documents
            .get(id)
            .with_context(|| format!("spec manifest references unknown spec_id {id}"))?;
        ensure!(
            json_string(entry, "path")? == document.path,
            "spec manifest path mismatch for {id}"
        );
        ensure!(
            json_string(entry, "title")? == document.metadata.title,
            "spec manifest title mismatch for {id}"
        );
        ensure!(
            json_string(entry, "version")? == document.metadata.version,
            "spec manifest version mismatch for {id}"
        );
        ensure!(
            json_string(entry, "status")? == document.metadata.status,
            "spec manifest status mismatch for {id}"
        );
        ensure!(
            json_string(entry, "last_verified")? == document.metadata.last_verified,
            "spec manifest last_verified mismatch for {id}"
        );
        validate_digest_entry(root, &document.path, entry)?;
    }
    Ok(())
}

fn validate_extension_integrity(
    root: &Path,
    base_paths: &HashSet<&str>,
) -> Result<HashSet<String>> {
    let mut extension_files = HashSet::new();
    for (manifest_name, checksums_name) in [
        (
            "WEB_FEATURE_SUITE_MANIFEST.json",
            "WEB_FEATURE_SUITE_SHA256SUMS",
        ),
        (
            "LLM_MCP_FEATURE_SUITE_MANIFEST.json",
            "LLM_MCP_FEATURE_SUITE_SHA256SUMS",
        ),
    ] {
        let extension_manifest: Value =
            serde_json::from_str(&fs::read_to_string(root.join(manifest_name))?)?;
        let files = extension_manifest
            .get("files")
            .and_then(Value::as_array)
            .with_context(|| format!("{manifest_name} missing files"))?;
        for own_path in [manifest_name, checksums_name] {
            ensure!(
                !base_paths.contains(own_path),
                "extension control path {own_path} collides with the base manifest"
            );
            ensure!(
                extension_files.insert(own_path.to_owned()),
                "extension control path collision at {own_path}"
            );
        }
        let mut extension_declared = HashSet::new();
        for entry in files {
            let path = json_string(entry, "path")?;
            ensure!(
                !base_paths.contains(path),
                "extension path {path} collides with the base manifest"
            );
            ensure!(
                extension_declared.insert(path),
                "{manifest_name} contains duplicate path {path}"
            );
            ensure!(
                extension_files.insert(path.to_owned()),
                "extension path collision at {path}"
            );
            validate_digest_entry(root, path, entry)?;
        }
        validate_extension_checksum_file(root, checksums_name, manifest_name, &extension_declared)?;
    }
    Ok(extension_files)
}

fn validate_extension_checksum_file(
    root: &Path,
    checksum_name: &str,
    manifest_name: &str,
    declared: &HashSet<&str>,
) -> Result<()> {
    let contents = fs::read_to_string(root.join(checksum_name))?;
    let mut checksums = HashMap::new();
    for line in contents.lines() {
        let (digest, path) = line
            .split_once("  ")
            .with_context(|| format!("invalid {checksum_name} line"))?;
        ensure!(
            checksums.insert(path, digest).is_none(),
            "duplicate {checksum_name} path {path}"
        );
    }
    let mut expected = declared.clone();
    expected.insert(manifest_name);
    ensure!(
        checksums.keys().copied().collect::<HashSet<_>>() == expected,
        "{checksum_name} inventory differs from {manifest_name}"
    );
    for (path, expected_digest) in checksums {
        let bytes = fs::read(root.join(path))?;
        ensure!(
            sha256(&bytes) == expected_digest,
            "{checksum_name} digest mismatch for {path}"
        );
    }
    Ok(())
}

fn validate_checksum_file(root: &Path, actual: &HashSet<String>) -> Result<()> {
    let contents = fs::read_to_string(root.join("SHA256SUMS"))?;
    let mut checksums = HashMap::new();
    for line in contents.lines() {
        let (digest, path) = line.split_once("  ").context("invalid SHA256SUMS line")?;
        ensure!(
            checksums.insert(path, digest).is_none(),
            "duplicate SHA256SUMS path {path}"
        );
    }
    let mut expected = actual.clone();
    expected.insert("MANIFEST.json".into());
    ensure!(
        checksums.keys().copied().collect::<HashSet<_>>()
            == expected.iter().map(String::as_str).collect(),
        "SHA256SUMS inventory differs from MANIFEST.json"
    );
    for (path, expected_digest) in checksums {
        let bytes = fs::read(root.join(path))?;
        ensure!(
            sha256(&bytes) == expected_digest,
            "SHA256SUMS digest mismatch for {path}"
        );
    }
    Ok(())
}

fn validate_digest_entry(root: &Path, path: &str, entry: &Value) -> Result<()> {
    let bytes = fs::read(root.join(path)).with_context(|| format!("read manifest path {path}"))?;
    ensure!(
        entry.get("bytes").and_then(Value::as_u64) == Some(bytes.len() as u64),
        "manifest byte count mismatch for {path}"
    );
    ensure!(
        json_string(entry, "sha256")? == sha256(&bytes),
        "manifest digest mismatch for {path}"
    );
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn json_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string field {key}"))
}

fn validate_markers(root: &Path) -> Result<()> {
    for path in files(root)? {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if !["md", "yaml", "yml", "toml", "json", "csv"].contains(&extension) {
            continue;
        }
        let contents = fs::read_to_string(&path)?;
        for marker in PROHIBITED_MARKERS {
            ensure!(
                !contents.contains(marker),
                "{} contains prohibited marker {marker}",
                relative(root, &path)?
            );
        }
    }
    Ok(())
}

fn files(root: &Path) -> Result<Vec<PathBuf>> {
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .map(|entry| entry.context("walk specification bundle"))
        .filter_map(|entry| match entry {
            Ok(entry) if entry.file_type().is_file() => {
                let hidden = entry.path().strip_prefix(root).is_ok_and(|relative| {
                    relative
                        .components()
                        .any(|component| component.as_os_str().to_string_lossy().starts_with('.'))
                });
                (!hidden).then(|| Ok(entry.into_path()))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}
fn has_extension(path: &str, extension: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case(extension))
}

fn relative(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)
        .with_context(|| format!("{} is outside {}", path.display(), root.display()))?
        .to_string_lossy()
        .replace('\\', "/"))
}
