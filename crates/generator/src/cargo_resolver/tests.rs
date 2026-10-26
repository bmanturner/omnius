use std::{
    ffi::OsString,
    fs,
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::{Value, json};

use super::{
    CargoGraph, CargoGraphError, CargoMetadataError, cargo_update_args, read_regular_lockfile,
};
use crate::release::{CANONICAL_REPOSITORY, ReleaseIdentity};

const OLD_REVISION: &str = "1111111111111111111111111111111111111111";
const NEW_REVISION: &str = "2222222222222222222222222222222222222222";

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn framework_validation_accepts_canonical_alias_and_reachable_packages() {
    let release = release(OLD_REVISION);
    let graph = parse_graph(&metadata(
        OLD_REVISION,
        "service_kit",
        "registry-one",
        false,
    ));

    let framework = graph.validate_framework(&release);

    assert_eq!(framework, Ok(kit_id(OLD_REVISION)));
}

#[test]
fn framework_validation_accepts_multiple_canonical_workspace_aliases() {
    let release = release(OLD_REVISION);
    let mut document = metadata(OLD_REVISION, "service_kit", "registry-one", false);
    let kit = kit_id(OLD_REVISION);
    let Some(packages) = document["packages"].as_array_mut() else {
        panic!("packages must be an array");
    };
    packages.push(json!({
        "id": "worker",
        "name": "example-worker",
        "version": "0.1.0",
        "source": null
    }));
    let Some(workspace_members) = document["workspace_members"].as_array_mut() else {
        panic!("workspace members must be an array");
    };
    workspace_members.push(json!("worker"));
    let Some(resolve_nodes) = document["resolve"]["nodes"].as_array_mut() else {
        panic!("resolve nodes must be an array");
    };
    resolve_nodes.push(json!({
        "id": "worker",
        "deps": [
            {
                "name": "service_kit",
                "pkg": kit,
                "dep_kinds": [{ "kind": null, "target": null }]
            }
        ],
        "features": []
    }));

    assert_eq!(
        parse_graph(&document).validate_framework(&release),
        Ok(kit_id(OLD_REVISION))
    );
}

#[test]
fn framework_validation_rejects_noncanonical_reachable_omnius_source() {
    let release = release(OLD_REVISION);
    let mut document = metadata(OLD_REVISION, "service_kit", "registry-one", false);
    document["packages"][2]["source"] = Value::Null;
    let graph = parse_graph(&document);

    let error = graph.validate_framework(&release);

    assert!(matches!(
        error,
        Err(CargoGraphError::OmniusSourceMismatch { package, actual: None, .. })
            if package == runtime_id(OLD_REVISION)
    ));
}

#[test]
fn framework_validation_rejects_wrong_resolved_revision() {
    let release = release(OLD_REVISION);
    let mut document = metadata(OLD_REVISION, "service_kit", "registry-one", false);
    document["packages"][1]["source"] = json!(source(NEW_REVISION));
    let graph = parse_graph(&document);

    let error = graph.validate_framework(&release);

    assert!(matches!(
        error,
        Err(CargoGraphError::OmniusSourceMismatch { package, .. })
            if package == kit_id(OLD_REVISION)
    ));
}

#[test]
fn framework_validation_rejects_wrong_root_alias() {
    let release = release(OLD_REVISION);
    let graph = parse_graph(&metadata(OLD_REVISION, "framework", "registry-one", false));

    let error = graph.validate_framework(&release);

    assert!(matches!(
        error,
        Err(CargoGraphError::RootAliasMismatch { actual, .. }) if actual == "framework"
    ));
}

#[test]
fn bounded_difference_allows_changes_inside_old_and_new_framework_closures() {
    let before_release = release(OLD_REVISION);
    let after_release = release(NEW_REVISION);
    let before = parse_graph(&metadata(
        OLD_REVISION,
        "service_kit",
        "registry-one",
        false,
    ));
    let after = parse_graph(&metadata(
        NEW_REVISION,
        "service_kit",
        "registry-one",
        false,
    ));
    assert!(before.validate_framework(&before_release).is_ok());
    assert!(after.validate_framework(&after_release).is_ok());

    let difference = before.bounded_framework_difference(&after);

    assert!(matches!(
        difference,
        Ok(difference)
            if difference.added_packages.contains(&kit_id(NEW_REVISION))
                && difference.removed_packages.contains(&kit_id(OLD_REVISION))
    ));
}

#[test]
fn legacy_cutover_allows_direct_framework_edges_to_collapse_behind_service_kit() {
    let mut before_document = metadata(OLD_REVISION, "service_kit", "registry-one", false);
    before_document["resolve"]["nodes"][0]["deps"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("application dependencies must be an array"))
        .push(json!({
            "name": "omnius_runtime",
            "pkg": runtime_id(OLD_REVISION),
            "dep_kinds": [{ "kind": null, "target": null }]
        }));
    let before = parse_graph(&before_document);
    let after = parse_graph(&thin_metadata(NEW_REVISION, "registry-one"));

    let difference = before.bounded_difference_from_roots(
        &after,
        &kit_id(OLD_REVISION),
        &kit_id(NEW_REVISION),
        true,
    );

    assert!(difference.is_ok());
}

#[test]
fn legacy_short_link_fixture_allows_obsolete_toml_normal_kind_removal() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/legacy-short-link-resolver-graphs.json"
    ))
    .unwrap_or_else(|error| panic!("legacy resolver fixture must be valid JSON: {error}"));
    let before = parse_graph(&fixture["before"]);
    let after = parse_graph(&fixture["after"]);

    let difference = before.bounded_difference_from_roots(&after, "legacy-kit", "git-kit", true);

    assert!(difference.is_ok());
}

#[test]
fn legacy_cutover_rejects_application_external_edge_changes() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/legacy-short-link-resolver-graphs.json"
    ))
    .unwrap_or_else(|error| panic!("legacy resolver fixture must be valid JSON: {error}"));
    let before = parse_graph(&fixture["before"]);
    let mut after_document = fixture["after"].clone();
    after_document["resolve"]["nodes"][0]["deps"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("application dependencies must be an array"))
        .retain(|dependency| dependency["name"] != "serde");
    let after = parse_graph(&after_document);

    let error = before.bounded_difference_from_roots(&after, "legacy-kit", "git-kit", true);

    assert!(matches!(
        error,
        Err(CargoGraphError::OutOfScopeNodeChange { package }) if package == "app"
    ));
}

#[test]
fn legacy_cutover_still_rejects_unrelated_workspace_edge_changes() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/legacy-short-link-resolver-graphs.json"
    ))
    .unwrap_or_else(|error| panic!("legacy resolver fixture must be valid JSON: {error}"));
    let before = parse_graph(&fixture["before"]);
    let mut after_document = fixture["after"].clone();
    after_document["resolve"]["nodes"][1]["deps"] = json!([]);
    let after = parse_graph(&after_document);

    let error = before.bounded_difference_from_roots(&after, "legacy-kit", "git-kit", true);

    assert!(matches!(
        error,
        Err(CargoGraphError::OutOfScopeNodeChange { package }) if package == "helper"
    ));
}

#[test]
fn legacy_cutover_rejects_candidate_direct_omnius_edges() {
    let before = parse_graph(&metadata(
        OLD_REVISION,
        "service_kit",
        "registry-one",
        false,
    ));
    let mut after_document = thin_metadata(NEW_REVISION, "registry-one");
    after_document["resolve"]["nodes"][0]["deps"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("application dependencies must be an array"))
        .push(json!({
            "name": "omnius_runtime",
            "pkg": runtime_id(NEW_REVISION),
            "dep_kinds": [{ "kind": null, "target": null }]
        }));
    let after = parse_graph(&after_document);

    let error = before.bounded_difference_from_roots(
        &after,
        &kit_id(OLD_REVISION),
        &kit_id(NEW_REVISION),
        true,
    );

    assert!(matches!(
        error,
        Err(CargoGraphError::OutOfScopeNodeChange { package }) if package == "app"
    ));
}

#[test]
fn legacy_cutover_requires_the_canonical_service_kit_replacement_edge() {
    let before = parse_graph(&metadata(
        OLD_REVISION,
        "service_kit",
        "registry-one",
        false,
    ));
    for replacement in [
        json!([{
            "name": "registry_dependency",
            "pkg": "registry-one",
            "dep_kinds": [{ "kind": null, "target": null }]
        }]),
        json!([
            {
                "name": "framework",
                "pkg": kit_id(NEW_REVISION),
                "dep_kinds": [
                    { "kind": null, "target": null },
                    { "kind": "dev", "target": null }
                ]
            },
            {
                "name": "registry_dependency",
                "pkg": "registry-one",
                "dep_kinds": [{ "kind": null, "target": null }]
            }
        ]),
    ] {
        let mut after_document = thin_metadata(NEW_REVISION, "registry-one");
        after_document["resolve"]["nodes"][0]["deps"] = replacement;
        let after = parse_graph(&after_document);

        let error = before.bounded_difference_from_roots(
            &after,
            &kit_id(OLD_REVISION),
            &kit_id(NEW_REVISION),
            true,
        );

        assert!(matches!(
            error,
            Err(CargoGraphError::OutOfScopeNodeChange { package }) if package == "app"
        ));
    }
}

#[test]
fn bounded_difference_normalizes_workspace_packages_across_stage_paths() {
    let before = parse_graph(&relocated_metadata(
        OLD_REVISION,
        "/tmp/current-service-project",
    ));
    let after = parse_graph(&relocated_metadata(
        NEW_REVISION,
        "/tmp/candidate-service-project",
    ));

    let difference = before.bounded_framework_difference(&after);

    assert!(difference.is_ok());
}

#[test]
fn bounded_difference_rejects_framework_boundary_kind_change() {
    let before = parse_graph(&metadata(
        OLD_REVISION,
        "service_kit",
        "registry-one",
        false,
    ));
    let mut document = metadata(NEW_REVISION, "service_kit", "registry-one", false);
    document["resolve"]["nodes"][0]["deps"][0]["dep_kinds"][0]["kind"] = json!("dev");
    let after = parse_graph(&document);

    let error = before.bounded_framework_difference(&after);

    assert!(matches!(
        error,
        Err(CargoGraphError::OutOfScopeNodeChange { package }) if package == "app"
    ));
}

#[test]
fn bounded_difference_normalizes_external_local_packages_across_stage_paths() {
    let before = parse_graph(&external_local_metadata(
        OLD_REVISION,
        "/tmp/current/service",
        "/tmp/current/shared",
    ));
    let after = parse_graph(&external_local_metadata(
        NEW_REVISION,
        "/tmp/candidate/service",
        "/tmp/candidate/shared",
    ));

    let difference = before.bounded_framework_difference(&after);

    assert!(difference.is_ok());
}

#[test]
fn bounded_difference_rejects_unrelated_package_identity_change() {
    let before = parse_graph(&metadata(
        OLD_REVISION,
        "service_kit",
        "registry-one",
        false,
    ));
    let after = parse_graph(&metadata(NEW_REVISION, "service_kit", "registry-one", true));

    let error = before.bounded_framework_difference(&after);

    assert!(matches!(
        error,
        Err(CargoGraphError::OutOfScopePackageChange { package })
            if package == "registry-one"
    ));
}

#[test]
fn bounded_difference_rejects_unrelated_edge_change() {
    let before = parse_graph(&metadata(
        OLD_REVISION,
        "service_kit",
        "registry-one",
        false,
    ));
    let mut document = metadata(NEW_REVISION, "service_kit", "registry-one", false);
    document["resolve"]["nodes"][0]["deps"] = json!([]);
    let after = parse_graph(&document);

    let error = before.bounded_framework_difference(&after);

    assert!(matches!(
        error,
        Err(CargoGraphError::OutOfScopeNodeChange { package }) if package == "app"
    ));
}

#[test]
fn metadata_projection_rejects_dependency_to_unknown_package() {
    let mut document = metadata(OLD_REVISION, "service_kit", "registry-one", false);
    document["resolve"]["nodes"][1]["deps"][0]["pkg"] = json!("missing");

    let error = CargoGraph::from_metadata_json(document.to_string().as_bytes());

    assert!(matches!(
        error,
        Err(CargoMetadataError::Graph(
            CargoGraphError::DependencyTargetMissing { target, .. }
        )) if target == "missing"
    ));
}

#[test]
fn precise_offline_update_selects_the_locked_framework_version() {
    let arguments = cargo_update_args("0.2.0", Some(NEW_REVISION), true);

    assert_eq!(
        arguments,
        vec![
            OsString::from("update"),
            OsString::from("-p"),
            OsString::from("omnius-service-kit@0.2.0"),
            OsString::from("--precise"),
            OsString::from(NEW_REVISION),
            OsString::from("--offline"),
        ]
    );
}

#[test]
fn lockfile_reader_preserves_exact_binary_bytes() {
    let unique = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let project = std::env::temp_dir().join(format!(
        "omnius-cargo-resolver-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&project)
        .unwrap_or_else(|error| panic!("test directory must be creatable: {error}"));
    let expected = b"version = 4\n\xff\x00lock-bytes\n";
    fs::write(project.join("Cargo.lock"), expected)
        .unwrap_or_else(|error| panic!("test lockfile must be writable: {error}"));

    let actual = read_regular_lockfile(&project);
    let _ = fs::remove_dir_all(project);
    match actual {
        Ok(bytes) => assert_eq!(bytes, expected),
        Err(error) => panic!("test lockfile must be readable: {error}"),
    }
}

fn release(revision: &str) -> ReleaseIdentity {
    ReleaseIdentity::new("0.3.0", CANONICAL_REPOSITORY, revision)
        .unwrap_or_else(|error| panic!("test release identity must be valid: {error}"))
}

fn parse_graph(document: &Value) -> CargoGraph {
    CargoGraph::from_metadata_json(document.to_string().as_bytes())
        .unwrap_or_else(|error| panic!("test metadata must be valid: {error}"))
}

fn source(revision: &str) -> String {
    format!("git+{CANONICAL_REPOSITORY}?rev={revision}#{revision}")
}

fn kit_id(revision: &str) -> String {
    format!("git-kit-{revision}")
}

fn runtime_id(revision: &str) -> String {
    format!("git-runtime-{revision}")
}

fn external_local_metadata(revision: &str, root: &str, shared: &str) -> Value {
    let mut document = relocated_metadata(revision, root);
    let dependency_id = format!("file://{shared}#registry-dependency@1.0.0");
    document["packages"][3]["id"] = json!(dependency_id.clone());
    document["packages"][3]["source"] = Value::Null;
    document["packages"][3]["manifest_path"] = json!(format!("{shared}/Cargo.toml"));
    document["resolve"]["nodes"][0]["deps"][1]["pkg"] = json!(dependency_id.clone());
    document["resolve"]["nodes"][3]["id"] = json!(dependency_id);
    document
}

fn thin_metadata(revision: &str, registry_id: &str) -> Value {
    let mut document = metadata(revision, "service_kit", registry_id, false);
    document["resolve"]["nodes"][0]["deps"][0]["dep_kinds"] = json!([
        { "kind": null, "target": null },
        { "kind": "dev", "target": null }
    ]);
    document
}

fn relocated_metadata(revision: &str, root: &str) -> Value {
    let mut document = metadata(revision, "service_kit", "registry-one", false);
    let application_id = format!("file://{root}#example-service@0.1.0");
    document["workspace_root"] = json!(root);
    document["packages"][0]["id"] = json!(application_id.clone());
    document["packages"][0]["manifest_path"] = json!(format!("{root}/Cargo.toml"));
    document["workspace_members"][0] = json!(application_id.clone());
    document["resolve"]["nodes"][0]["id"] = json!(application_id);
    document
}

fn metadata(
    revision: &str,
    alias: &str,
    registry_id: &str,
    changed_registry_identity: bool,
) -> Value {
    let kit = kit_id(revision);
    let runtime = runtime_id(revision);
    let registry_version = if changed_registry_identity {
        "2.0.0"
    } else {
        "1.0.0"
    };
    json!({
        "packages": [
            { "id": "app", "name": "example-service", "version": "0.1.0", "source": null },
            { "id": kit.clone(), "name": "omnius-service-kit", "version": "0.3.0", "source": source(revision) },
            { "id": runtime.clone(), "name": "omnius-runtime", "version": "0.3.0", "source": source(revision) },
            { "id": registry_id, "name": "registry-dependency", "version": registry_version, "source": "registry+https://github.com/rust-lang/crates.io-index" }
        ],
        "workspace_members": ["app"],
        "resolve": {
            "nodes": [
                {
                    "id": "app",
                    "deps": [
                        { "name": alias, "pkg": kit.clone(), "dep_kinds": [{ "kind": null, "target": null }] },
                        { "name": "registry_dependency", "pkg": registry_id, "dep_kinds": [{ "kind": null, "target": null }] }
                    ],
                    "features": []
                },
                {
                    "id": kit,
                    "deps": [
                        { "name": "omnius_runtime", "pkg": runtime.clone(), "dep_kinds": [{ "kind": null, "target": null }] }
                    ],
                    "features": ["http"]
                },
                {
                    "id": runtime,
                    "deps": [],
                    "features": []
                },
                {
                    "id": registry_id,
                    "deps": [],
                    "features": []
                }
            ]
        }
    })
}
