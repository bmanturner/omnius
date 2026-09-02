use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};

const EXTENSIONS_DIRECTORY: &str = "machine/extensions";
const BASE_EXTENSION_ID: &str = "omnius-specs";

#[derive(Debug)]
struct MergePlan {
    extension: Extension,
    requires: Vec<Requirement>,
    strategy: Strategy,
    catalogs: Vec<CatalogRule>,
    csv_catalogs: Vec<CsvRule>,
    independent_catalogs: Vec<String>,
}

#[derive(Debug)]
struct Extension {
    id: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct LegacyMergePlan {
    schema_version: String,
    extension: LegacyExtension,
    strategy: Strategy,
    catalogs: Vec<CatalogRule>,
    csv_catalogs: Vec<CsvRule>,
    #[serde(default)]
    independent_catalogs: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LegacyExtension {
    id: String,
    version: String,
    requires_bundle: String,
}

#[derive(Debug, Deserialize)]
struct AppendMergePlan {
    schema_version: String,
    extension: String,
    version: String,
    requires: Vec<Requirement>,
    operations: Vec<AppendOperation>,
    #[serde(default)]
    independent_catalogs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct Requirement {
    id: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct AppendOperation {
    source: String,
    target: String,
    collection: Option<String>,
    unique_key: String,
}

#[derive(Debug, Deserialize)]
struct Strategy {
    preferred: String,
    idempotency_key: String,
    collision_policy: String,
    preserve_existing_order: bool,
    sort_new_entries_by_id: bool,
}

#[derive(Debug, Deserialize)]
struct CatalogRule {
    source: String,
    source_key: String,
    target: String,
    target_key: String,
    unique_key: String,
}

#[derive(Debug, Deserialize)]
struct CsvRule {
    source: String,
    target: String,
    unique_key: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct AppliedMarker {
    schema_version: u32,
    extension: String,
    version: String,
    idempotency_key: String,
    strategy: String,
    catalogs: Vec<AppliedCatalog>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct AppliedCatalog {
    source: String,
    target: String,
    source_sha256: String,
    entry_ids: Vec<String>,
}

struct ExtensionOverlay {
    plan: MergePlan,
    marker: AppliedMarker,
}

pub(crate) struct Overlay {
    extensions: Vec<ExtensionOverlay>,
}

impl Overlay {
    pub(crate) fn load(root: &Path) -> Result<Self> {
        let extensions = load_plans(root)?
            .into_iter()
            .map(|plan| {
                let marker = expected_marker(root, &plan)?;
                Ok(ExtensionOverlay { plan, marker })
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !extensions.is_empty(),
            "no specification extension merge plans were found"
        );
        Ok(Self { extensions })
    }

    pub(crate) fn verify(root: &Path) -> Result<Self> {
        let overlay = Self::load(root)?;
        let yaml_targets = overlay
            .extensions
            .iter()
            .flat_map(|extension| {
                extension
                    .plan
                    .catalogs
                    .iter()
                    .map(|rule| rule.target.as_str())
            })
            .collect::<BTreeSet<_>>();
        for target in yaml_targets {
            let first = compose_yaml_target(root, &overlay.extensions, target)?;
            let second = compose_yaml_target(root, &overlay.extensions, target)?;
            ensure!(first == second, "overlay for {target} is not idempotent");
        }

        let csv_targets = overlay
            .extensions
            .iter()
            .flat_map(|extension| {
                extension
                    .plan
                    .csv_catalogs
                    .iter()
                    .map(|rule| rule.target.as_str())
            })
            .collect::<BTreeSet<_>>();
        for target in csv_targets {
            verify_csv_target(root, &overlay.extensions, target)?;
        }

        for extension in &overlay.extensions {
            for source in &extension.plan.independent_catalogs {
                ensure!(
                    root.join(source).is_file(),
                    "independent extension catalog {source} does not exist"
                );
            }
            let marker_path = marker_path(root, &extension.plan);
            let actual: AppliedMarker =
                serde_json::from_str(&fs::read_to_string(&marker_path).with_context(|| {
                    format!("read applied extension marker {}", marker_path.display())
                })?)
                .with_context(|| {
                    format!("parse applied extension marker {}", marker_path.display())
                })?;
            ensure!(
                actual == extension.marker,
                "applied extension marker for {} is stale; run `cargo xtask specs extensions record`",
                extension.plan.extension.id
            );
        }
        Ok(overlay)
    }

    pub(crate) fn yaml<T>(&self, root: &Path, target: &str) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        serde_yaml::from_value(compose_yaml_target(root, &self.extensions, target)?)
            .with_context(|| format!("decode composed {target}"))
    }

    pub(crate) fn yaml_value(&self, root: &Path, target: &str) -> Result<Value> {
        compose_yaml_target(root, &self.extensions, target)
    }

    pub(crate) fn csv_sources<'a>(&'a self, target: &str) -> Result<Vec<&'a str>> {
        let mut target_source = None;
        let mut sources = Vec::new();
        for extension in &self.extensions {
            for rule in extension
                .plan
                .csv_catalogs
                .iter()
                .filter(|rule| rule.target == target)
            {
                if let Some(existing) = target_source {
                    ensure!(
                        existing == rule.target,
                        "extension CSV plans disagree on target {target}"
                    );
                } else {
                    target_source = Some(rule.target.as_str());
                    sources.push(rule.target.as_str());
                }
                sources.push(rule.source.as_str());
            }
        }
        ensure!(
            target_source.is_some(),
            "merge plans do not declare {target}"
        );
        Ok(sources)
    }

    pub(crate) fn independent_sources<'a>(&'a self, file_name: &str) -> Vec<&'a str> {
        self.extensions
            .iter()
            .flat_map(|extension| extension.plan.independent_catalogs.iter())
            .filter(|source| {
                Path::new(source)
                    .file_name()
                    .is_some_and(|name| name == file_name)
            })
            .map(String::as_str)
            .collect()
    }

    pub(crate) fn record(root: &Path) -> Result<Vec<PathBuf>> {
        let overlay = Self::load(root)?;
        for target in overlay
            .extensions
            .iter()
            .flat_map(|extension| extension.plan.catalogs.iter())
            .map(|rule| rule.target.as_str())
            .collect::<BTreeSet<_>>()
        {
            compose_yaml_target(root, &overlay.extensions, target)?;
        }
        for target in overlay
            .extensions
            .iter()
            .flat_map(|extension| extension.plan.csv_catalogs.iter())
            .map(|rule| rule.target.as_str())
            .collect::<BTreeSet<_>>()
        {
            verify_csv_target(root, &overlay.extensions, target)?;
        }

        let mut paths = Vec::with_capacity(overlay.extensions.len());
        for extension in &overlay.extensions {
            let path = marker_path(root, &extension.plan);
            let parent = path.parent().context("extension marker has no parent")?;
            fs::create_dir_all(parent)?;
            let mut bytes = serde_json::to_vec_pretty(&extension.marker)?;
            bytes.push(b'\n');
            fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
            paths.push(path);
        }
        Ok(paths)
    }
}

fn load_plans(root: &Path) -> Result<Vec<MergePlan>> {
    let extension_root = root.join(EXTENSIONS_DIRECTORY);
    let mut pending = BTreeMap::new();
    for entry in fs::read_dir(&extension_root)
        .with_context(|| format!("read {}", extension_root.display()))?
    {
        let entry = entry.with_context(|| format!("read {}", extension_root.display()))?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path().join("merge-plan.yaml");
        if !path.is_file() {
            continue;
        }
        let plan = parse_merge_plan(&path)?;
        let id = plan.extension.id.clone();
        ensure!(
            pending.insert(id.clone(), plan).is_none(),
            "duplicate extension merge plan for {id}"
        );
    }

    let base_manifest: JsonValue =
        serde_json::from_str(&fs::read_to_string(root.join("MANIFEST.json"))?)?;
    let base_version = base_manifest
        .get("bundle")
        .and_then(|bundle| bundle.get("version"))
        .and_then(JsonValue::as_str)
        .context("MANIFEST.json is missing bundle.version")?;
    let mut available = BTreeMap::from([(BASE_EXTENSION_ID.to_owned(), base_version.to_owned())]);
    let mut ordered = Vec::with_capacity(pending.len());
    while !pending.is_empty() {
        for plan in pending.values() {
            for requirement in &plan.requires {
                if let Some(version) = available.get(&requirement.id) {
                    ensure!(
                        version == &requirement.version,
                        "extension {} requires {} {}, found {}",
                        plan.extension.id,
                        requirement.id,
                        requirement.version,
                        version
                    );
                }
            }
        }
        let next = pending.iter().find_map(|(id, plan)| {
            plan.requires
                .iter()
                .all(|requirement| available.contains_key(&requirement.id))
                .then_some(id.clone())
        });
        let Some(id) = next else {
            let unresolved = pending.keys().cloned().collect::<Vec<_>>().join(", ");
            bail!("extension dependency cycle or unknown requirement among: {unresolved}");
        };
        let plan = pending
            .remove(&id)
            .context("selected extension merge plan disappeared")?;
        available.insert(plan.extension.id.clone(), plan.extension.version.clone());
        ordered.push(plan);
    }
    Ok(ordered)
}

fn parse_merge_plan(path: &Path) -> Result<MergePlan> {
    let source = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let document: Value =
        serde_yaml::from_str(&source).with_context(|| format!("parse {}", path.display()))?;
    let extension = document
        .get("extension")
        .context("extension merge plan is missing extension")?;
    let plan = if extension.is_mapping() {
        let legacy: LegacyMergePlan = serde_yaml::from_value(document)
            .with_context(|| format!("decode {}", path.display()))?;
        ensure!(
            legacy.schema_version == "1.0.0",
            "unsupported legacy extension merge-plan schema {}",
            legacy.schema_version
        );
        MergePlan {
            requires: vec![Requirement {
                id: BASE_EXTENSION_ID.to_owned(),
                version: legacy.extension.requires_bundle,
            }],
            extension: Extension {
                id: legacy.extension.id,
                version: legacy.extension.version,
            },
            strategy: legacy.strategy,
            catalogs: legacy.catalogs,
            csv_catalogs: legacy.csv_catalogs,
            independent_catalogs: legacy.independent_catalogs,
        }
    } else {
        let append: AppendMergePlan = serde_yaml::from_value(document)
            .with_context(|| format!("decode {}", path.display()))?;
        ensure!(
            append.schema_version == "1.0.0",
            "unsupported append extension merge-plan schema {}",
            append.schema_version
        );
        let mut catalogs = Vec::new();
        let mut csv_catalogs = Vec::new();
        for operation in append.operations {
            if let Some(collection) = operation.collection {
                catalogs.push(CatalogRule {
                    source: operation.source,
                    source_key: collection.clone(),
                    target: operation.target,
                    target_key: collection,
                    unique_key: operation.unique_key,
                });
            } else {
                csv_catalogs.push(CsvRule {
                    source: operation.source,
                    target: operation.target,
                    unique_key: operation.unique_key,
                });
            }
        }
        let idempotency_key = format!("{}@{}", append.extension, append.version);
        MergePlan {
            extension: Extension {
                id: append.extension,
                version: append.version,
            },
            requires: append.requires,
            strategy: Strategy {
                preferred: "overlay".to_owned(),
                idempotency_key,
                collision_policy: "fail".to_owned(),
                preserve_existing_order: true,
                sort_new_entries_by_id: true,
            },
            catalogs,
            csv_catalogs,
            independent_catalogs: append.independent_catalogs,
        }
    };
    validate_plan(&plan)?;
    Ok(plan)
}

fn validate_plan(plan: &MergePlan) -> Result<()> {
    ensure!(
        !plan.extension.id.is_empty() && !plan.extension.version.is_empty(),
        "extension identity and version must be non-empty"
    );
    ensure!(
        plan.strategy.preferred == "overlay",
        "{} extension strategy must be overlay",
        plan.extension.id
    );
    ensure!(
        plan.strategy.collision_policy == "fail",
        "{} extension collision policy must be fail",
        plan.extension.id
    );
    ensure!(
        plan.strategy.preserve_existing_order,
        "{} extension must preserve prior catalog order",
        plan.extension.id
    );
    ensure!(
        plan.strategy.sort_new_entries_by_id,
        "{} extension entries must be sorted by ID",
        plan.extension.id
    );
    ensure!(
        plan.strategy.idempotency_key
            == format!("{}@{}", plan.extension.id, plan.extension.version),
        "{} extension idempotency key does not match its identity",
        plan.extension.id
    );
    Ok(())
}

fn compose_yaml_target(
    root: &Path,
    extensions: &[ExtensionOverlay],
    target_name: &str,
) -> Result<Value> {
    let plans = extensions
        .iter()
        .map(|extension| &extension.plan)
        .collect::<Vec<_>>();
    compose_yaml_target_for_plans(root, &plans, target_name)
}

fn compose_yaml_target_for_plans(
    root: &Path,
    plans: &[&MergePlan],
    target_name: &str,
) -> Result<Value> {
    let mut target: Option<Value> = None;
    for plan in plans {
        for rule in plan
            .catalogs
            .iter()
            .filter(|rule| rule.target == target_name)
        {
            ensure!(
                rule.unique_key == "id",
                "unsupported unique key {}",
                rule.unique_key
            );
            if target.is_none() {
                let target_path = root.join(&rule.target);
                target = Some(
                    serde_yaml::from_str(&fs::read_to_string(&target_path)?)
                        .with_context(|| format!("parse {}", target_path.display()))?,
                );
            }

            let source_path = root.join(&rule.source);
            let source: Value = serde_yaml::from_str(&fs::read_to_string(&source_path)?)
                .with_context(|| format!("parse {}", source_path.display()))?;
            let target_document = target
                .as_mut()
                .context("target catalog was not initialized")?;
            let target_mapping = target_document
                .as_mapping_mut()
                .with_context(|| format!("{} is not a mapping", rule.target))?;
            let source_mapping = source
                .as_mapping()
                .with_context(|| format!("{} is not a mapping", rule.source))?;
            let target_entries = sequence_mut(target_mapping, &rule.target_key, &rule.target)?;
            let source_entries = sequence(source_mapping, &rule.source_key, &rule.source)?;
            merge_entries(
                target_entries,
                source_entries,
                &rule.unique_key,
                &rule.target,
                &rule.source,
            )?;
        }
    }
    target.with_context(|| format!("merge plans do not declare {target_name}"))
}

fn merge_entries(
    target: &mut Vec<Value>,
    source: &[Value],
    unique_key: &str,
    target_name: &str,
    source_name: &str,
) -> Result<()> {
    let mut seen = HashSet::new();
    for entry in target.iter() {
        let id = entry_id(entry, unique_key, target_name)?;
        ensure!(
            seen.insert(id.to_owned()),
            "duplicate ID `{id}` in {target_name}"
        );
    }
    let mut additions = source.to_vec();
    additions.sort_by(|left, right| {
        let left = entry_id(left, unique_key, source_name).unwrap_or_default();
        let right = entry_id(right, unique_key, source_name).unwrap_or_default();
        left.cmp(right)
    });
    for entry in &additions {
        let id = entry_id(entry, unique_key, source_name)?;
        ensure!(
            seen.insert(id.to_owned()),
            "extension ID `{id}` collides with {target_name}"
        );
    }
    target.extend(additions);
    Ok(())
}

fn entry_id<'a>(entry: &'a Value, key: &str, source: &str) -> Result<&'a str> {
    entry
        .as_mapping()
        .and_then(|mapping| mapping.get(Value::String(key.to_owned())))
        .and_then(Value::as_str)
        .with_context(|| format!("entry in {source} is missing string `{key}`"))
}

fn sequence_mut<'a>(
    mapping: &'a mut Mapping,
    key: &str,
    source: &str,
) -> Result<&'a mut Vec<Value>> {
    mapping
        .get_mut(Value::String(key.to_owned()))
        .and_then(Value::as_sequence_mut)
        .with_context(|| format!("{source} is missing sequence `{key}`"))
}

fn sequence<'a>(mapping: &'a Mapping, key: &str, source: &str) -> Result<&'a Vec<Value>> {
    mapping
        .get(Value::String(key.to_owned()))
        .and_then(Value::as_sequence)
        .with_context(|| format!("{source} is missing sequence `{key}`"))
}

fn verify_csv_target(
    root: &Path,
    extensions: &[ExtensionOverlay],
    target_name: &str,
) -> Result<()> {
    let plans = extensions
        .iter()
        .map(|extension| &extension.plan)
        .collect::<Vec<_>>();
    verify_csv_rules(root, &plans, target_name)
}

fn verify_csv_rules(root: &Path, plans: &[&MergePlan], target_name: &str) -> Result<()> {
    let rules = plans
        .iter()
        .flat_map(|plan| plan.csv_catalogs.iter())
        .filter(|rule| rule.target == target_name)
        .collect::<Vec<_>>();
    let first = rules
        .first()
        .with_context(|| format!("merge plans do not declare {target_name}"))?;
    for rule in &rules {
        ensure!(
            rule.unique_key == first.unique_key,
            "extension CSV plans disagree on unique key for {target_name}"
        );
    }

    let mut seen = HashSet::new();
    for relative in
        std::iter::once(first.target.as_str()).chain(rules.iter().map(|rule| rule.source.as_str()))
    {
        let mut reader = csv::Reader::from_path(root.join(relative))?;
        let headers = reader.headers()?.clone();
        let key_index = headers
            .iter()
            .position(|header| header == first.unique_key)
            .with_context(|| format!("{relative} is missing CSV key {}", first.unique_key))?;
        for record in reader.records() {
            let record = record?;
            let id = record
                .get(key_index)
                .context("CSV record is missing its unique key")?;
            ensure!(
                seen.insert(id.to_owned()),
                "extension CSV ID `{id}` collides in {target_name}"
            );
        }
    }
    Ok(())
}

fn expected_marker(root: &Path, plan: &MergePlan) -> Result<AppliedMarker> {
    let mut catalogs = Vec::with_capacity(plan.catalogs.len() + plan.csv_catalogs.len());
    for rule in &plan.catalogs {
        let source_path = root.join(&rule.source);
        let bytes = fs::read(&source_path)?;
        let document: Value = serde_yaml::from_slice(&bytes)?;
        let mapping = document
            .as_mapping()
            .context("extension catalog is not a mapping")?;
        let mut entry_ids = sequence(mapping, &rule.source_key, &rule.source)?
            .iter()
            .map(|entry| entry_id(entry, &rule.unique_key, &rule.source).map(str::to_owned))
            .collect::<Result<Vec<_>>>()?;
        entry_ids.sort();
        catalogs.push(AppliedCatalog {
            source: rule.source.clone(),
            target: rule.target.clone(),
            source_sha256: hex_digest(&bytes),
            entry_ids,
        });
    }
    for rule in &plan.csv_catalogs {
        let source_path = root.join(&rule.source);
        let bytes = fs::read(&source_path)?;
        let mut reader = csv::Reader::from_reader(bytes.as_slice());
        let headers = reader.headers()?.clone();
        let key_index = headers
            .iter()
            .position(|header| header == rule.unique_key)
            .context("extension CSV is missing its unique key")?;
        let mut entry_ids = reader
            .records()
            .map(|record| {
                let record = record?;
                Ok(record
                    .get(key_index)
                    .context("CSV record is missing its unique key")?
                    .to_owned())
            })
            .collect::<Result<Vec<String>>>()?;
        entry_ids.sort();
        catalogs.push(AppliedCatalog {
            source: rule.source.clone(),
            target: rule.target.clone(),
            source_sha256: hex_digest(&bytes),
            entry_ids,
        });
    }
    Ok(AppliedMarker {
        schema_version: 1,
        extension: plan.extension.id.clone(),
        version: plan.extension.version.clone(),
        idempotency_key: plan.strategy.idempotency_key.clone(),
        strategy: plan.strategy.preferred.clone(),
        catalogs,
    })
}

fn marker_path(root: &Path, plan: &MergePlan) -> PathBuf {
    root.join("machine/applied-extensions").join(format!(
        "{}-{}.json",
        plan.extension.id, plan.extension.version
    ))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(crate) fn json_value(value: Value) -> Result<JsonValue> {
    serde_json::to_value(value).context("convert YAML catalog to JSON value")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str) -> Value {
        let mut mapping = Mapping::new();
        mapping.insert(Value::String("id".into()), Value::String(id.into()));
        Value::Mapping(mapping)
    }

    #[test]
    fn overlay_preserves_base_order_and_sorts_extension_entries() -> Result<()> {
        let mut target = vec![entry("base-b"), entry("base-a")];
        merge_entries(
            &mut target,
            &[entry("web-z"), entry("web-a")],
            "id",
            "base",
            "extension",
        )?;
        let ids = target
            .iter()
            .map(|value| entry_id(value, "id", "fixture"))
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(ids, ["base-b", "base-a", "web-a", "web-z"]);
        Ok(())
    }

    #[test]
    fn overlay_rejects_duplicate_extension_ids() {
        let mut target = vec![entry("base")];
        let result = merge_entries(
            &mut target,
            &[entry("web"), entry("web")],
            "id",
            "base",
            "extension",
        );
        assert!(matches!(result, Err(error) if error.to_string().contains("collides")));
    }

    #[test]
    fn overlay_rejects_base_extension_collisions() {
        let mut target = vec![entry("shared")];
        let result = merge_entries(&mut target, &[entry("shared")], "id", "base", "extension");
        assert!(matches!(result, Err(error) if error.to_string().contains("collides")));
    }
}
