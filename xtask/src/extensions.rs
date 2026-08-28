use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};

const MERGE_PLAN: &str = "machine/extensions/web-application-suite/merge-plan.yaml";

#[derive(Debug, Deserialize)]
struct MergePlan {
    extension: Extension,
    strategy: Strategy,
    catalogs: Vec<CatalogRule>,
    csv_catalogs: Vec<CsvRule>,
}

#[derive(Debug, Deserialize)]
struct Extension {
    id: String,
    version: String,
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

pub(crate) struct Overlay {
    plan: MergePlan,
    marker: AppliedMarker,
}

impl Overlay {
    pub(crate) fn load(root: &Path) -> Result<Self> {
        let plan_path = root.join(MERGE_PLAN);
        let plan: MergePlan = serde_yaml::from_str(
            &fs::read_to_string(&plan_path)
                .with_context(|| format!("read {}", plan_path.display()))?,
        )
        .with_context(|| format!("parse {}", plan_path.display()))?;
        ensure!(
            plan.strategy.preferred == "overlay",
            "web extension strategy must be overlay"
        );
        ensure!(
            plan.strategy.collision_policy == "fail",
            "web extension collision policy must be fail"
        );
        ensure!(
            plan.strategy.preserve_existing_order,
            "web extension must preserve base catalog order"
        );
        ensure!(
            plan.strategy.sort_new_entries_by_id,
            "web extension entries must be sorted by ID"
        );
        ensure!(
            plan.strategy.idempotency_key
                == format!("{}@{}", plan.extension.id, plan.extension.version),
            "web extension idempotency key does not match its identity"
        );

        let marker = expected_marker(root, &plan)?;
        Ok(Self { plan, marker })
    }

    pub(crate) fn verify(root: &Path) -> Result<Self> {
        let overlay = Self::load(root)?;
        for rule in &overlay.plan.catalogs {
            let first = compose_yaml_rule(root, rule)?;
            let second = compose_yaml_rule(root, rule)?;
            ensure!(
                first == second,
                "overlay for {} is not idempotent",
                rule.target
            );
        }
        for rule in &overlay.plan.csv_catalogs {
            verify_csv_rule(root, rule)?;
        }
        let marker_path = marker_path(root, &overlay.plan);
        let actual: AppliedMarker =
            serde_json::from_str(&fs::read_to_string(&marker_path).with_context(|| {
                format!("read applied extension marker {}", marker_path.display())
            })?)
            .with_context(|| format!("parse applied extension marker {}", marker_path.display()))?;
        ensure!(
            actual == overlay.marker,
            "applied extension marker is stale; run `cargo xtask specs extensions record`"
        );
        Ok(overlay)
    }

    pub(crate) fn yaml<T>(&self, root: &Path, target: &str) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let rule = self
            .plan
            .catalogs
            .iter()
            .find(|rule| rule.target == target)
            .with_context(|| format!("merge plan does not declare {target}"))?;
        serde_yaml::from_value(compose_yaml_rule(root, rule)?)
            .with_context(|| format!("decode composed {target}"))
    }

    pub(crate) fn yaml_value(&self, root: &Path, target: &str) -> Result<Value> {
        let rule = self
            .plan
            .catalogs
            .iter()
            .find(|rule| rule.target == target)
            .with_context(|| format!("merge plan does not declare {target}"))?;
        compose_yaml_rule(root, rule)
    }

    pub(crate) fn csv_sources<'a>(&'a self, target: &str) -> Result<[&'a str; 2]> {
        let rule = self
            .plan
            .csv_catalogs
            .iter()
            .find(|rule| rule.target == target)
            .with_context(|| format!("merge plan does not declare {target}"))?;
        Ok([rule.target.as_str(), rule.source.as_str()])
    }

    pub(crate) fn record(root: &Path) -> Result<PathBuf> {
        let overlay = Self::load(root)?;
        for rule in &overlay.plan.catalogs {
            compose_yaml_rule(root, rule)?;
        }
        for rule in &overlay.plan.csv_catalogs {
            verify_csv_rule(root, rule)?;
        }
        let path = marker_path(root, &overlay.plan);
        let parent = path.parent().context("extension marker has no parent")?;
        fs::create_dir_all(parent)?;
        let mut bytes = serde_json::to_vec_pretty(&overlay.marker)?;
        bytes.push(b'\n');
        fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
        Ok(path)
    }
}

fn compose_yaml_rule(root: &Path, rule: &CatalogRule) -> Result<Value> {
    ensure!(
        rule.unique_key == "id",
        "unsupported unique key {}",
        rule.unique_key
    );
    let target_path = root.join(&rule.target);
    let source_path = root.join(&rule.source);
    let mut target: Value = serde_yaml::from_str(&fs::read_to_string(&target_path)?)
        .with_context(|| format!("parse {}", target_path.display()))?;
    let source: Value = serde_yaml::from_str(&fs::read_to_string(&source_path)?)
        .with_context(|| format!("parse {}", source_path.display()))?;
    let target_mapping = target
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
    Ok(target)
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

fn verify_csv_rule(root: &Path, rule: &CsvRule) -> Result<()> {
    let mut seen = HashSet::new();
    for relative in [&rule.target, &rule.source] {
        let mut reader = csv::Reader::from_path(root.join(relative))?;
        let headers = reader.headers()?.clone();
        let key_index = headers
            .iter()
            .position(|header| header == rule.unique_key)
            .with_context(|| format!("{relative} is missing CSV key {}", rule.unique_key))?;
        for record in reader.records() {
            let record = record?;
            let id = record
                .get(key_index)
                .context("CSV record is missing its unique key")?;
            ensure!(
                seen.insert(id.to_owned()),
                "extension CSV ID `{id}` collides in {}",
                rule.target
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
