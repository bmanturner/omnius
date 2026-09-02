use std::{collections::HashSet, fs, path::Path};

use anyhow::{Context, Result, ensure};
use csv::Reader;
use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const BASE_COMPLETE_HEADER: &str = r"---
spec_id: OMNIUS-COMPLETE
title: Complete Omnius Specification
version: 0.1.0
status: generated
last_verified: 2026-08-24
---

# Complete Omnius Specification

This is a generated single-file rendering of the human-readable specifications.
Machine-readable catalogs, schemas, examples, and validation tools remain separate
files in the bundle and are authoritative where referenced.
";

const WEB_COMPLETE_HEADER: &str = r"---
spec_id: OMNIUS-WEB-COMPLETE
title: Complete Web Application Feature Suite
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Complete Web Application Feature Suite

This document combines the normative web feature-suite specifications, accepted ADRs, integration guidance, autonomous-agent handoff, and recommendation traceability. Individual files remain authoritative for stable paths and machine references.
";

const LLM_COMPLETE_HEADER: &str = r#"---
spec_id: OMNIUS-AI-SUITE-COMPLETE
title: "Complete LLM and MCP Feature Suite"
version: 0.1.0
status: reference
last_verified: 2026-09-01
---

# Complete LLM and MCP Feature Suite

This document concatenates the LLM/MCP extension specifications, ADRs, handoff, integration instructions, and research summaries. Machine-readable files remain authoritative for IDs and graph validation.
"#;

const BASE_PREFIX_SOURCES: &[&str] = &[
    "README.md",
    "AGENTS.md",
    "AUTONOMOUS_AGENT_HANDOFF.md",
    "SPEC_INDEX.md",
];
const BASE_SUFFIX_SOURCES: &[&str] = &["VALIDATION_REPORT.md"];
const WEB_SUFFIX_SOURCES: &[&str] = &[
    "WEB_FEATURE_SUITE_INTEGRATION.md",
    "WEB_FEATURE_SUITE_AGENT_HANDOFF.md",
    "WEB_FEATURE_SUITE_TRACEABILITY.md",
];
const LLM_SUFFIX_SOURCES: &[&str] = &[
    "LLM_MCP_FEATURE_SUITE_AGENT_HANDOFF.md",
    "LLM_MCP_FEATURE_SUITE_INTEGRATION.md",
    "research/llm-mcp-suite/crate-evaluation.md",
    "research/llm-mcp-suite/mcp-2026-07-28-findings.md",
    "research/llm-mcp-suite/mcp-roadmap-forward-design.md",
    "research/llm-mcp-suite/provider-output-findings.md",
];

#[derive(Debug, Deserialize)]
struct ArchiveManifest {
    files: Vec<ArchivePath>,
}

#[derive(Debug, Deserialize)]
struct ArchivePath {
    path: String,
}

#[derive(Debug, Deserialize)]
struct Frontmatter {
    spec_id: String,
    title: String,
    version: String,
    status: String,
    last_verified: String,
}

struct ArtifactRecord {
    path: String,
    bytes: usize,
    sha256: String,
}

struct DocumentRecord {
    metadata: Frontmatter,
    artifact: ArtifactRecord,
}

pub(crate) fn generate(root: &Path) -> Result<()> {
    let base_paths = archive_paths(root, "MANIFEST.json")?;
    let web_paths = archive_paths(root, "WEB_FEATURE_SUITE_MANIFEST.json")?;
    let llm_paths = archive_paths(root, "LLM_MCP_FEATURE_SUITE_MANIFEST.json")?;

    render_base_complete(root, &base_paths)?;
    render_web_complete(root, &web_paths)?;
    render_llm_complete(root, &llm_paths)?;

    let web_paths = refresh_archive_manifest(root, "WEB_FEATURE_SUITE_MANIFEST.json")?;
    let llm_paths = refresh_archive_manifest(root, "LLM_MCP_FEATURE_SUITE_MANIFEST.json")?;
    write_checksums(
        root,
        "WEB_FEATURE_SUITE_SHA256SUMS",
        "WEB_FEATURE_SUITE_MANIFEST.json",
        &web_paths,
    )?;
    write_checksums(
        root,
        "LLM_MCP_FEATURE_SUITE_SHA256SUMS",
        "LLM_MCP_FEATURE_SUITE_MANIFEST.json",
        &llm_paths,
    )?;

    refresh_document_manifest(root, &base_paths)?;
    let base_paths = refresh_archive_manifest(root, "MANIFEST.json")?;
    write_checksums(root, "SHA256SUMS", "MANIFEST.json", &base_paths)?;
    Ok(())
}

fn archive_paths(root: &Path, manifest_name: &str) -> Result<HashSet<String>> {
    let contents = fs::read_to_string(root.join(manifest_name))
        .with_context(|| format!("read {manifest_name}"))?;
    let manifest: ArchiveManifest =
        serde_json::from_str(&contents).with_context(|| format!("parse {manifest_name}"))?;
    let entry_count = manifest.files.len();
    let paths: HashSet<String> = manifest.files.into_iter().map(|entry| entry.path).collect();
    ensure!(
        paths.len() == entry_count,
        "{manifest_name} contains duplicate paths"
    );
    Ok(paths)
}

fn render_base_complete(root: &Path, owned: &HashSet<String>) -> Result<()> {
    let mut sources = required_sources(owned, BASE_PREFIX_SOURCES, "base bundle")?;
    sources.extend(sorted_sources(owned, is_numbered_spec));
    sources.extend(sorted_sources(owned, |path| {
        path.starts_with("adr/") && has_extension(path, "md")
    }));
    sources.extend(sorted_sources(owned, |path| {
        path.starts_with("research/")
            && has_extension(path, "md")
            && Path::new(path).parent() == Some(Path::new("research"))
    }));
    sources.extend(required_sources(owned, BASE_SUFFIX_SOURCES, "base bundle")?);

    let mut output = String::from(BASE_COMPLETE_HEADER);
    for source in sources {
        let contents = read_source(root, &source)?;
        let body = strip_frontmatter(&contents, &source)?;
        output.push_str("\n---\n\n<!-- BEGIN ");
        output.push_str(&source);
        output.push_str(" -->\n\n");
        output.push_str(body.trim_matches('\n'));
        output.push_str("\n\n<!-- END ");
        output.push_str(&source);
        output.push_str(" -->\n");
    }
    write_if_changed(&root.join("COMPLETE_SPEC.md"), output.as_bytes())
}

fn render_web_complete(root: &Path, owned: &HashSet<String>) -> Result<()> {
    let mut primary = sorted_sources(owned, is_numbered_spec);
    primary.extend(sorted_sources(owned, |path| {
        path.starts_with("adr/") && has_extension(path, "md")
    }));
    ensure!(
        !primary.is_empty(),
        "web complete specification has no sources"
    );

    let mut output = String::from(WEB_COMPLETE_HEADER);
    output.push_str("\n## Contents\n");
    for source in &primary {
        let contents = read_source(root, source)?;
        let metadata = parse_frontmatter(&contents, source)?;
        output.push_str("- `");
        output.push_str(&metadata.spec_id);
        output.push_str("` — ");
        output.push_str(&metadata.title);
        output.push('\n');
    }

    primary.extend(required_sources(owned, WEB_SUFFIX_SOURCES, "web suite")?);
    for source in primary {
        let contents = read_source(root, &source)?;
        let body = strip_frontmatter(&contents, &source)?;
        output.push_str("\n---\n\n");
        output.push_str(body.trim_matches('\n'));
        output.push('\n');
    }
    write_if_changed(
        &root.join("WEB_FEATURE_SUITE_COMPLETE_SPEC.md"),
        output.as_bytes(),
    )
}

fn render_llm_complete(root: &Path, owned: &HashSet<String>) -> Result<()> {
    let mut sources = sorted_sources(owned, is_numbered_spec);
    sources.extend(sorted_sources(owned, |path| {
        path.starts_with("adr/") && has_extension(path, "md")
    }));
    sources.extend(required_sources(
        owned,
        LLM_SUFFIX_SOURCES,
        "LLM/MCP suite",
    )?);
    ensure!(
        !sources.is_empty(),
        "LLM/MCP complete specification has no sources"
    );

    let mut output = String::from(LLM_COMPLETE_HEADER);
    for source in sources {
        let contents = read_source(root, &source)?;
        output.push_str("\n---\n\n");
        output.push_str(contents.trim_matches('\n'));
        output.push('\n');
    }
    write_if_changed(
        &root.join("LLM_MCP_FEATURE_SUITE_COMPLETE_SPEC.md"),
        output.as_bytes(),
    )
}

fn required_sources(
    owned: &HashSet<String>,
    required: &[&str],
    bundle: &str,
) -> Result<Vec<String>> {
    required
        .iter()
        .map(|path| {
            ensure!(
                owned.contains(*path),
                "{bundle} does not own required source {path}"
            );
            Ok((*path).to_owned())
        })
        .collect()
}

fn sorted_sources(owned: &HashSet<String>, predicate: impl Fn(&str) -> bool) -> Vec<String> {
    let mut sources: Vec<String> = owned
        .iter()
        .filter(|path| predicate(path))
        .cloned()
        .collect();
    sources.sort();
    sources
}

fn is_numbered_spec(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 6
        && bytes[0].is_ascii_digit()
        && bytes[1].is_ascii_digit()
        && bytes[2] == b'-'
        && has_extension(path, "md")
        && !path.contains('/')
}

fn has_extension(path: &str, extension: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case(extension))
}

fn read_source(root: &Path, path: &str) -> Result<String> {
    fs::read_to_string(root.join(path)).with_context(|| format!("read complete-spec source {path}"))
}

fn strip_frontmatter<'a>(contents: &'a str, path: &str) -> Result<&'a str> {
    contents
        .strip_prefix("---\n")
        .and_then(|rest| rest.split_once("\n---\n").map(|(_, body)| body))
        .with_context(|| format!("{path} has invalid YAML frontmatter"))
}

fn parse_frontmatter(contents: &str, path: &str) -> Result<Frontmatter> {
    let yaml = contents
        .strip_prefix("---\n")
        .and_then(|rest| rest.split_once("\n---\n").map(|(header, _)| header))
        .with_context(|| format!("{path} has invalid YAML frontmatter"))?;
    serde_yaml::from_str(yaml).with_context(|| format!("parse frontmatter for {path}"))
}

fn refresh_archive_manifest(root: &Path, manifest_name: &str) -> Result<Vec<String>> {
    let path = root.join(manifest_name);
    let contents = fs::read_to_string(&path).with_context(|| format!("read {manifest_name}"))?;
    let manifest: ArchiveManifest =
        serde_json::from_str(&contents).with_context(|| format!("parse {manifest_name}"))?;
    let mut records = Vec::with_capacity(manifest.files.len());
    for entry in manifest.files {
        records.push(artifact_record(root, entry.path)?);
    }

    let mut updated = replace_json_array(&contents, "files", &render_artifact_records(&records))?;
    replace_json_count(
        &mut updated,
        "files_excluding_manifest_and_checksums",
        records.len(),
    )?;
    replace_json_count(
        &mut updated,
        "markdown_documents",
        records
            .iter()
            .filter(|record| has_extension(&record.path, "md"))
            .count(),
    )?;
    replace_json_count(
        &mut updated,
        "numbered_specs",
        records
            .iter()
            .filter(|record| is_numbered_spec(&record.path))
            .count(),
    )?;
    replace_json_count(
        &mut updated,
        "adrs",
        records
            .iter()
            .filter(|record| record.path.starts_with("adr/") && has_extension(&record.path, "md"))
            .count(),
    )?;
    if manifest_name == "MANIFEST.json" {
        refresh_base_counts(root, &mut updated)?;
    }
    write_if_changed(&path, updated.as_bytes())?;
    Ok(records.into_iter().map(|record| record.path).collect())
}

fn refresh_base_counts(root: &Path, manifest: &mut String) -> Result<()> {
    for (key, path, sequence) in [
        ("modules", "machine/module-catalog.yaml", "modules"),
        ("profiles", "machine/profiles.yaml", "profiles"),
        (
            "acceptance_criteria",
            "machine/acceptance-criteria.yaml",
            "criteria",
        ),
        ("tasks", "machine/tasks.yaml", "tasks"),
    ] {
        replace_json_count(manifest, key, yaml_sequence_len(root, path, sequence)?)?;
    }

    let mut recommendations =
        Reader::from_path(root.join("machine/recommendation-traceability.csv"))?;
    replace_json_count(
        manifest,
        "recommendations",
        recommendations
            .records()
            .collect::<Result<Vec<_>, _>>()?
            .len(),
    )?;

    let sources = fs::read_to_string(root.join("research/sources.md"))?;
    let source_pattern = Regex::new(r"SRC-[A-Z0-9-]+")?;
    let source_count = source_pattern
        .find_iter(&sources)
        .map(|source| source.as_str())
        .collect::<HashSet<_>>()
        .len();
    replace_json_count(manifest, "research_sources", source_count)
}

fn yaml_sequence_len(root: &Path, path: &str, sequence: &str) -> Result<usize> {
    let document: serde_yaml::Value = serde_yaml::from_str(&fs::read_to_string(root.join(path))?)?;
    document
        .get(sequence)
        .and_then(serde_yaml::Value::as_sequence)
        .map(Vec::len)
        .with_context(|| format!("{path} is missing {sequence}"))
}

fn refresh_document_manifest(root: &Path, base_paths: &HashSet<String>) -> Result<()> {
    let path = root.join("machine/spec-manifest.json");
    let contents = fs::read_to_string(&path).context("read machine/spec-manifest.json")?;
    let mut records = Vec::new();
    for source in base_paths.iter().filter(|path| has_extension(path, "md")) {
        let contents = read_source(root, source)?;
        records.push(DocumentRecord {
            metadata: parse_frontmatter(&contents, source)?,
            artifact: artifact_record(root, source.clone())?,
        });
    }
    records.sort_by(|left, right| left.metadata.spec_id.cmp(&right.metadata.spec_id));
    let updated = replace_json_array(&contents, "documents", &render_document_records(&records))?;
    write_if_changed(&path, updated.as_bytes())
}

fn artifact_record(root: &Path, path: String) -> Result<ArtifactRecord> {
    let bytes = fs::read(root.join(&path)).with_context(|| format!("read archive path {path}"))?;
    Ok(ArtifactRecord {
        path,
        bytes: bytes.len(),
        sha256: sha256(&bytes),
    })
}

fn render_artifact_records(records: &[ArtifactRecord]) -> String {
    let mut output = String::from("[\n");
    for (index, record) in records.iter().enumerate() {
        if index > 0 {
            output.push_str(",\n");
        }
        output.push_str("    {\n      \"path\": ");
        output.push_str(&json_string(&record.path));
        output.push_str(",\n      \"bytes\": ");
        output.push_str(&record.bytes.to_string());
        output.push_str(",\n      \"sha256\": ");
        output.push_str(&json_string(&record.sha256));
        output.push_str("\n    }");
    }
    output.push_str("\n  ]");
    output
}

fn render_document_records(records: &[DocumentRecord]) -> String {
    let mut output = String::from("[\n");
    for (index, record) in records.iter().enumerate() {
        if index > 0 {
            output.push_str(",\n");
        }
        output.push_str("    {\n      \"spec_id\": ");
        output.push_str(&json_string(&record.metadata.spec_id));
        output.push_str(",\n      \"title\": ");
        output.push_str(&json_string(&record.metadata.title));
        output.push_str(",\n      \"version\": ");
        output.push_str(&json_string(&record.metadata.version));
        output.push_str(",\n      \"status\": ");
        output.push_str(&json_string(&record.metadata.status));
        output.push_str(",\n      \"last_verified\": ");
        output.push_str(&json_string(&record.metadata.last_verified));
        output.push_str(",\n      \"path\": ");
        output.push_str(&json_string(&record.artifact.path));
        output.push_str(",\n      \"bytes\": ");
        output.push_str(&record.artifact.bytes.to_string());
        output.push_str(",\n      \"sha256\": ");
        output.push_str(&json_string(&record.artifact.sha256));
        output.push_str("\n    }");
    }
    output.push_str("\n  ]");
    output
}

fn replace_json_array(contents: &str, key: &str, replacement: &str) -> Result<String> {
    let marker = format!("\"{key}\": [");
    let marker_start = contents
        .find(&marker)
        .with_context(|| format!("JSON document missing {key} array"))?;
    let array_start = marker_start + marker.len() - 1;
    let array_end = matching_array_end(contents, array_start)
        .with_context(|| format!("JSON document has unterminated {key} array"))?;
    let mut updated = String::with_capacity(contents.len() + replacement.len());
    updated.push_str(&contents[..array_start]);
    updated.push_str(replacement);
    updated.push_str(&contents[array_end + 1..]);
    Ok(updated)
}

fn matching_array_end(contents: &str, start: usize) -> Option<usize> {
    let mut depth = 0_u32;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, byte) in contents.as_bytes()[start..].iter().copied().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' => depth += 1,
            b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(start + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn replace_json_count(contents: &mut String, key: &str, value: usize) -> Result<()> {
    let marker = format!("\"{key}\": ");
    let value_start = contents
        .find(&marker)
        .with_context(|| format!("JSON document missing count {key}"))?
        + marker.len();
    let value_end = contents[value_start..]
        .find(|character: char| !character.is_ascii_digit())
        .map_or(contents.len(), |offset| value_start + offset);
    ensure!(value_end > value_start, "JSON count {key} is not numeric");
    contents.replace_range(value_start..value_end, &value.to_string());
    Ok(())
}

fn write_checksums(
    root: &Path,
    checksum_name: &str,
    manifest_name: &str,
    paths: &[String],
) -> Result<()> {
    let mut paths = paths.to_vec();
    paths.push(manifest_name.to_owned());
    paths.sort();
    let mut output = String::new();
    for path in paths {
        let bytes =
            fs::read(root.join(&path)).with_context(|| format!("read checksum path {path}"))?;
        output.push_str(&sha256(&bytes));
        output.push_str("  ");
        output.push_str(&path);
        output.push('\n');
    }
    write_if_changed(&root.join(checksum_name), output.as_bytes())
}

fn json_string(value: &str) -> String {
    serde_json::Value::String(value.to_owned()).to_string()
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

fn write_if_changed(path: &Path, contents: &[u8]) -> Result<()> {
    if fs::read(path).is_ok_and(|existing| existing == contents) {
        return Ok(());
    }
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};

    use super::{matching_array_end, replace_json_array, strip_frontmatter};

    #[test]
    fn strips_yaml_frontmatter() -> Result<()> {
        let document = "---\nspec_id: EXAMPLE\n---\n\n# Body\n";
        assert_eq!(strip_frontmatter(document, "example.md")?, "\n# Body\n");
        Ok(())
    }

    #[test]
    fn replaces_array_without_treating_string_brackets_as_structure() -> Result<()> {
        let document = "{\n  \"files\": [\"name]with-bracket\", [1]]\n}\n";
        let start = document.find('[').context("test array must be present")?;
        assert_eq!(matching_array_end(document, start), document.rfind(']'));
        assert_eq!(
            replace_json_array(document, "files", "[\n    2\n  ]")?,
            "{\n  \"files\": [\n    2\n  ]\n}\n"
        );
        Ok(())
    }
}
