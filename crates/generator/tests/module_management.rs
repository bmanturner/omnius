//! Catalog-driven module planning and managed-ownership integration contracts.

use std::{collections::BTreeSet, error::Error, fmt::Write as _, fs, path::Path, sync::LazyLock};

use omnius_generator::{
    ApplyOutcome, CANONICAL_REPOSITORY, CargoGraph, CargoResolverError, CargoResolverRequest,
    CargoResolverResult, KIT_VERSION, LockfileResolver, MANAGED_MARKER_VERSION,
    ManagedRegionRecord, ModuleCatalog, OwnershipKind, OwnershipRecord, PlanOperation,
    ProjectManager, ProjectState, ReleaseIdentity, RenderError, RenderOutcome, RenderRequest,
    parse_managed_regions, preserves_historical_path, reconcile_managed_region,
    render_project_with_resolver,
};
use omnius_test_support::CleanDirectory;
use sha2::{Digest, Sha256};

const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
static TEST_RELEASE_IDENTITY: LazyLock<ReleaseIdentity> = LazyLock::new(|| {
    ReleaseIdentity::new(
        KIT_VERSION,
        CANONICAL_REPOSITORY,
        "0000000000000000000000000000000000000001",
    )
    .unwrap_or_else(|error| panic!("valid test release identity: {error}"))
});

fn test_release_identity() -> &'static ReleaseIdentity {
    &TEST_RELEASE_IDENTITY
}

struct TestLockfileResolver;

impl LockfileResolver for TestLockfileResolver {
    fn resolve(
        &self,
        request: &CargoResolverRequest,
    ) -> Result<CargoResolverResult, CargoResolverError> {
        let manifest =
            fs::read(request.candidate_project().join("Cargo.toml")).map_err(|error| {
                CargoResolverError::InvalidRequest(format!(
                    "test resolver cannot read staged manifest: {error}"
                ))
            })?;
        let lockfile = format!(
            "version = 4\n\n# deterministic test lock: {}\n",
            sha256_bytes(&manifest)
        )
        .into_bytes();
        Ok(CargoResolverResult::from_parts(
            lockfile,
            request.current_project().map(|_| CargoGraph::default()),
            CargoGraph::default(),
            None,
        ))
    }
}

fn render_test_project(request: RenderRequest<'_>) -> Result<RenderOutcome, RenderError> {
    if request.destination.is_dir()
        && fs::read_dir(request.destination)
            .unwrap_or_else(|error| panic!("test destination must be readable: {error}"))
            .next()
            .is_none()
    {
        fs::remove_dir(request.destination)
            .unwrap_or_else(|error| panic!("empty test destination must be removable: {error}"));
    }
    render_project_with_resolver(request, false, &TestLockfileResolver)
}

fn apply_add(manager: &ProjectManager<'_>, module: &str) -> Result<ApplyOutcome, Box<dyn Error>> {
    let sealed = manager.seal_add_with(module, false, &TestLockfileResolver)?;
    Ok(manager.apply(&sealed)?)
}

fn apply_remove(
    manager: &ProjectManager<'_>,
    module: &str,
) -> Result<ApplyOutcome, Box<dyn Error>> {
    let sealed = manager.seal_remove_with(module, false, &TestLockfileResolver)?;
    Ok(manager.apply(&sealed)?)
}

fn assert_error<T, E>(result: Result<T, E>) -> E {
    let Err(error) = result else {
        panic!("expected operation to fail");
    };
    error
}
fn corrupt_first_managed_hash(source: &str) -> String {
    let Some(hash_offset) = source.find(" hash=") else {
        panic!("expected a managed marker hash");
    };
    let hash_start = hash_offset + " hash=".len();
    let hash_end = hash_start + 64;
    assert!(source.is_char_boundary(hash_end));
    let mut corrupted = source.to_owned();
    corrupted.replace_range(hash_start..hash_end, &"0".repeat(64));
    corrupted
}

#[test]
fn add_resolution_includes_transitive_dependency_closure() -> TestResult {
    let catalog = ModuleCatalog::bundled()?;
    let selected = catalog.resolve_add(&BTreeSet::new(), "auth-session-redis")?;

    assert!(
        [
            "auth-session-redis",
            "auth-core",
            "redis-core",
            "http",
            "config",
            "core"
        ]
        .iter()
        .all(|id| selected.contains(*id)),
        "resolved selection was {selected:?}"
    );
    Ok(())
}

#[test]
fn explicit_conflicts_are_checked_in_both_declaration_directions() -> TestResult {
    let catalog = ModuleCatalog::bundled()?;
    let selected = catalog.resolve_add(&BTreeSet::new(), "authz-basic")?;
    let error = assert_error(catalog.resolve_add(&selected, "authz-cedar"));

    assert!(error.to_string().contains("module conflict"));
    Ok(())
}

#[test]
fn provider_slots_reject_multiple_selected_providers() -> TestResult {
    let catalog = ModuleCatalog::bundled()?;
    let selected = catalog.resolve_add(&BTreeSet::new(), "rate-limit-local")?;
    let error = assert_error(catalog.resolve_add(&selected, "rate-limit-redis"));

    assert!(
        error
            .to_string()
            .contains("provider slot `rate-limit-provider`")
    );
    Ok(())
}

#[test]
fn removal_is_blocked_by_transitive_reverse_dependents() -> TestResult {
    let catalog = ModuleCatalog::bundled()?;
    let selected = catalog.resolve_add(&BTreeSet::new(), "feature-flags")?;
    let error = assert_error(catalog.resolve_remove(&selected, "core"));

    assert!(error.to_string().contains("selected dependents"));
    Ok(())
}

#[test]
fn managed_region_reconciliation_preserves_every_outside_byte() -> TestResult {
    let source = format!(
        "prefix\r\n# omnius:managed-begin id=workspace-members version=1 hash={EMPTY_HASH}\r\n# omnius:managed-end id=workspace-members\r\nsuffix\n"
    );
    let record = ManagedRegionRecord {
        id: "workspace-members".to_owned(),
        path: "Cargo.toml".to_owned(),
        marker_version: MANAGED_MARKER_VERSION,
        content_hash: EMPTY_HASH.to_owned(),
    };
    let reconciled = reconcile_managed_region(&source, &record, "  \"crates/example\",\r\n")?;

    assert!(
        reconciled.starts_with("prefix\r\n# omnius:managed-begin")
            && reconciled.ends_with("# omnius:managed-end id=workspace-members\r\nsuffix\n")
    );
    Ok(())
}

#[test]
fn managed_region_parser_rejects_nested_markers() {
    let source = format!(
        "# omnius:managed-begin id=outer version=1 hash={EMPTY_HASH}\n# omnius:managed-begin id=inner version=1 hash={EMPTY_HASH}\n# omnius:managed-end id=inner\n# omnius:managed-end id=outer\n"
    );
    let error = assert_error(parse_managed_regions(&source));

    assert!(error.to_string().contains("nested"));
}

#[test]
fn managed_region_parser_rejects_duplicate_ids() {
    let source = format!(
        "# omnius:managed-begin id=region version=1 hash={EMPTY_HASH}\n# omnius:managed-end id=region\n# omnius:managed-begin id=region version=1 hash={EMPTY_HASH}\n# omnius:managed-end id=region\n"
    );
    let error = assert_error(parse_managed_regions(&source));

    assert!(error.to_string().contains("duplicate"));
}

#[test]
fn managed_region_parser_rejects_missing_end_markers() {
    let source = format!("# omnius:managed-begin id=region version=1 hash={EMPTY_HASH}\nmanaged\n");
    let error = assert_error(parse_managed_regions(&source));

    assert!(error.to_string().contains("missing its end marker"));
}

#[test]
fn managed_region_parser_rejects_unapproved_content_edits() {
    let source = format!(
        "# omnius:managed-begin id=region version=1 hash={EMPTY_HASH}\nedited\n# omnius:managed-end id=region\n"
    );
    let error = assert_error(parse_managed_regions(&source));

    assert!(error.to_string().contains("edited outside the generator"));
}

#[test]
fn project_state_serde_rejects_unknown_fields() {
    let source = "schema_version = 2\nservice = \"example\"\nunknown = true\nmodules = []\nownership = []\nmanaged_regions = []\n\n[framework]\nversion = \"0.3.0\"\nrepository = \"https://github.com/bmanturner/omnius.git\"\nrevision = \"0000000000000000000000000000000000000001\"\n\n[profile]\nid = \"minimal\"\nversion = \"0.3.0\"\nadditions = []\nremovals = []\n";
    let error = assert_error(ProjectState::parse(source));

    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn project_state_serde_rejects_unsupported_versions() {
    let source = "schema_version = 3\nservice = \"example\"\nmodules = []\nownership = []\nmanaged_regions = []\n\n[framework]\nversion = \"0.3.0\"\nrepository = \"https://github.com/bmanturner/omnius.git\"\nrevision = \"0000000000000000000000000000000000000001\"\n\n[profile]\nid = \"minimal\"\nversion = \"0.3.0\"\nadditions = []\nremovals = []\n";
    let error = assert_error(ProjectState::parse(source));

    assert!(
        error
            .to_string()
            .contains("unsupported project state schema version")
    );
}

#[test]
fn generated_project_add_remove_is_idempotent_journaled_and_healthy() -> TestResult {
    let directory = generated_minimal("module-manager-roundtrip")?;
    let catalog = ModuleCatalog::bundled()?;

    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    let add = manager.plan_add("localization")?;
    assert_eq!(manager.plan_add("localization")?, add);
    assert!(add.added_modules.contains(&"localization".to_owned()));
    let applied = apply_add(&manager, "localization")?;
    assert!(applied.changed_files > 0);
    assert!(!directory.path().join("crates").exists());
    let added_manifest = fs::read_to_string(directory.path().join("Cargo.toml"))?;
    assert!(added_manifest.contains("\"localization\""));
    assert!(!added_manifest.contains("chrono = "));
    assert!(manager.plan_add("localization")?.is_empty());
    assert!(manager.doctor()?.healthy);
    assert!(manager.diff()?.is_empty());

    apply_remove(&manager, "localization")?;
    assert!(!fs::read_to_string(directory.path().join("Cargo.toml"))?.contains("\"localization\""));
    assert!(manager.plan_remove("localization")?.is_empty());
    assert!(manager.doctor()?.healthy);
    assert!(manager.diff()?.is_empty());
    Ok(())
}

#[test]
fn compose_topology_reconciles_and_retains_postgres_volume_on_removal() -> TestResult {
    let directory = generated_minimal("compose-manager-roundtrip")?;
    let catalog = ModuleCatalog::bundled()?;

    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    let add = manager.plan_add("migrations")?;
    assert!(add.operations.iter().any(|operation| {
        matches!(
            operation,
            PlanOperation::RegenerateDerived { path, .. } if path == "ops/compose.yaml"
        )
    }));
    apply_add(&manager, "migrations")?;
    let persisted = fs::read_to_string(directory.path().join("ops/compose.yaml"))?;
    assert!(persisted.contains("\n  postgres:\n"));
    assert!(persisted.contains("condition: service_healthy"));
    assert!(persisted.contains("condition: service_completed_successfully"));
    assert_eq!(persisted.matches("command: [\"migrate\"]").count(), 1);
    assert!(persisted.contains("OMNIUS__MIGRATIONS__RUN_ON_STARTUP: \"false\""));
    assert!(manager.doctor()?.healthy);
    assert!(manager.diff()?.is_empty());

    apply_remove(&manager, "migrations")?;
    let startup_owned = fs::read_to_string(directory.path().join("ops/compose.yaml"))?;
    assert!(!startup_owned.contains("command: [\"migrate\"]"));
    assert!(!startup_owned.contains("OMNIUS__MIGRATIONS__RUN_ON_STARTUP"));
    apply_remove(&manager, "postgres")?;
    let removed = fs::read_to_string(directory.path().join("ops/compose.yaml"))?;
    assert!(!removed.contains("\n  postgres:\n"));
    assert!(removed.contains("volumes:\n  postgres-data:\n"));
    let state = ProjectState::parse(&fs::read_to_string(
        directory.path().join(".omnius/service.toml"),
    )?)?;
    assert_eq!(state.retained_compose_volumes, ["postgres-data"]);
    assert!(manager.doctor()?.healthy);
    assert!(manager.diff()?.is_empty());
    Ok(())
}
#[test]
fn application_templates_are_create_once_and_survive_remove_readd() -> TestResult {
    let directory = generated_minimal("web-module-manager-roundtrip")?;
    let catalog = ModuleCatalog::bundled()?;
    let existing = directory.path().join("web/package.json");
    fs::create_dir_all(existing.parent().ok_or("web package has no parent")?)?;
    fs::write(&existing, "{\"application\":\"owned\"}\n")?;
    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    let add = manager.plan_add("web")?;
    assert!(add.added_modules.contains(&"web-react".to_owned()));
    apply_add(&manager, "web")?;
    assert_eq!(
        fs::read_to_string(&existing)?,
        "{\"application\":\"owned\"}\n"
    );
    let created = directory.path().join("packages/web-sdk/package.json");
    let created_bytes = fs::read(&created)?;
    let browser_created = directory.path().join("web/playwright.config.ts");
    let browser_created_bytes = fs::read(&browser_created)?;
    let state = ProjectState::parse(&fs::read_to_string(
        directory.path().join(".omnius/service.toml"),
    )?)?;
    for path in [
        "web/package.json",
        "web/playwright.config.ts",
        "packages/web-sdk/package.json",
    ] {
        assert_eq!(
            state.ownership_of(path),
            Some(OwnershipKind::ApplicationOwned)
        );
    }

    apply_remove(&manager, "web")?;
    assert_eq!(
        fs::read_to_string(&existing)?,
        "{\"application\":\"owned\"}\n"
    );
    assert_eq!(fs::read(&created)?, created_bytes);
    assert_eq!(fs::read(&browser_created)?, browser_created_bytes);

    apply_add(&manager, "web")?;
    assert_eq!(
        fs::read_to_string(&existing)?,
        "{\"application\":\"owned\"}\n"
    );
    assert_eq!(fs::read(&created)?, created_bytes);
    assert_eq!(fs::read(&browser_created)?, browser_created_bytes);
    assert!(manager.doctor()?.healthy);
    assert!(manager.diff()?.is_empty());
    Ok(())
}

#[test]
fn existing_destination_rejection_preserves_application_history() -> TestResult {
    let directory = generated_minimal("canonical-application-history-rerender")?;
    let owned = [
        ("data/history.json", "{\"preserved\":true}\n"),
        (
            "migrations/9000000000000000000_application.sql",
            "-- application history\n",
        ),
    ];
    for (path, contents) in owned {
        let absolute = directory.path().join(path);
        fs::create_dir_all(absolute.parent().ok_or("application file has no parent")?)?;
        fs::write(absolute, contents)?;
    }
    record_application_owned(directory.path(), &owned.map(|(path, _)| path))?;
    let state_before = fs::read(directory.path().join(".omnius/service.toml"))?;
    let result = render_test_project(RenderRequest {
        service_name: "managed-service",
        profile: "minimal",
        destination: directory.path(),
        release_identity: test_release_identity(),
    });
    assert!(matches!(result, Err(RenderError::DestinationExists(_))));
    assert_eq!(
        fs::read(directory.path().join(".omnius/service.toml"))?,
        state_before
    );
    for (path, contents) in owned {
        assert_eq!(
            ProjectState::parse(std::str::from_utf8(&state_before)?)?.ownership_of(path),
            Some(OwnershipKind::ApplicationOwned)
        );
        assert_eq!(fs::read_to_string(directory.path().join(path))?, contents);
    }

    let catalog = ModuleCatalog::bundled()?;

    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);
    assert!(manager.doctor()?.healthy);
    assert!(manager.diff()?.is_empty());
    Ok(())
}

#[test]
fn ai_profile_lifecycle_is_thin_idempotent_and_preserves_application_bytes() -> TestResult {
    let directory = generated_profile("ai-module-manager-roundtrip", "llm-runtime")?;
    for forbidden in ["crates", "migrations", "specs", "templates", ".sqlx"] {
        assert!(
            !directory.path().join(forbidden).exists(),
            "generated AI profile copied forbidden `{forbidden}`"
        );
    }
    let application = directory.path().join("apps/service/src/application.rs");
    fs::write(
        &application,
        "pub async fn example() -> &'static str { \"application-owned-ai\" }\n",
    )?;
    let application_before = fs::read(&application)?;
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    let add = manager.plan_add("llm-budgeting")?;
    assert_eq!(manager.plan_add("llm-budgeting")?, add);
    apply_add(&manager, "llm-budgeting")?;
    assert!(manager.plan_add("llm-budgeting")?.is_empty());
    assert!(!directory.path().join("crates").exists());
    assert_eq!(fs::read(&application)?, application_before);

    let remove = manager.plan_remove("llm-budgeting")?;
    assert_eq!(manager.plan_remove("llm-budgeting")?, remove);
    apply_remove(&manager, "llm-budgeting")?;
    assert!(manager.plan_remove("llm-budgeting")?.is_empty());
    assert!(!directory.path().join("crates").exists());
    assert_eq!(fs::read(&application)?, application_before);
    assert!(manager.doctor()?.healthy);
    assert!(manager.diff()?.is_empty());
    Ok(())
}

#[test]
fn nonregular_web_template_target_blocks_add_without_mutation() -> TestResult {
    let directory = generated_minimal("web-module-manager-conflict")?;
    let target = directory.path().join("web/package.json");
    fs::create_dir_all(&target)?;
    let state_path = directory.path().join(".omnius/service.toml");
    let state_before = fs::read(&state_path)?;
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    let error = assert_error(manager.plan_add("web"));

    assert!(error.to_string().contains("not a regular file"));
    assert_eq!(fs::read(state_path)?, state_before);
    assert!(target.is_dir());
    assert!(!directory.path().join(".node-version").exists());
    Ok(())
}

#[test]
fn kit_owned_drift_blocks_removal_without_any_mutation() -> TestResult {
    let directory = generated_minimal("module-manager-drift")?;
    let catalog = ModuleCatalog::bundled()?;

    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);
    apply_add(&manager, "localization")?;
    let state_path = directory.path().join(".omnius/service.toml");
    let state_before = fs::read(&state_path)?;
    fs::write(
        directory.path().join(".dockerignore"),
        "# application edit\n",
    )?;

    let error = assert_error(manager.plan_remove("localization"));

    assert!(error.to_string().contains("kit-owned-drift"));
    assert_eq!(fs::read(state_path)?, state_before);
    Ok(())
}

#[test]
fn provider_conflict_fails_before_any_project_mutation() -> TestResult {
    let directory = generated_minimal("module-manager-provider-conflict")?;
    let state_path = directory.path().join(".omnius/service.toml");
    let state_before = fs::read(&state_path)?;
    let catalog = ModuleCatalog::bundled()?;

    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    let error = assert_error(manager.plan_add("rate-limit-redis"));

    assert!(
        error
            .to_string()
            .contains("provider slot `rate-limit-provider`")
    );
    assert_eq!(fs::read(state_path)?, state_before);
    assert!(!directory.path().join("crates/rate-limit-redis").exists());
    Ok(())
}

#[test]
fn outside_region_application_manifest_edit_survives_add() -> TestResult {
    let directory = generated_minimal("module-manager-outside-edit")?;
    let manifest = directory.path().join("Cargo.toml");
    let mut edited = fs::read_to_string(&manifest)?;
    edited.push_str("\n[workspace.metadata.application-edit]\n");
    fs::write(&manifest, &edited)?;
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    apply_add(&manager, "feature-flags")?;

    let updated = fs::read_to_string(&manifest)?;
    assert!(updated.contains("[workspace.metadata.application-edit]"));
    assert!(updated.contains("\"feature-flags\""));
    assert!(!directory.path().join("crates").exists());
    assert!(manager.doctor()?.healthy);
    assert!(manager.diff()?.is_empty());
    Ok(())
}

#[test]
fn corrupt_marker_blocks_add_without_any_mutation() -> TestResult {
    let directory = generated_minimal("module-manager-corrupt")?;
    let manifest = directory.path().join("Cargo.toml");
    let corrupted = corrupt_first_managed_hash(&fs::read_to_string(&manifest)?);
    fs::write(&manifest, corrupted)?;
    let state_path = directory.path().join(".omnius/service.toml");
    let state_before = fs::read(&state_path)?;
    let catalog = ModuleCatalog::bundled()?;

    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    let error = assert_error(manager.plan_add("feature-flags"));

    assert!(error.to_string().contains("managed-region-corrupt"));
    assert_eq!(fs::read(state_path)?, state_before);
    assert!(!directory.path().join("crates/feature-flags").exists());
    Ok(())
}

#[test]
fn doctor_reports_unrecorded_marker_added_to_kit_owned_file() -> TestResult {
    let directory = generated_minimal("module-manager-untracked-marker")?;
    let source_path = directory.path().join(".dockerignore");
    let mut source = fs::read_to_string(&source_path)?;
    write!(
        source,
        "\n// omnius:managed-begin id=unexpected version=1 hash={EMPTY_HASH}\n// omnius:managed-end id=unexpected\n"
    )?;
    fs::write(&source_path, source)?;
    let catalog = ModuleCatalog::bundled()?;

    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    let report = manager.doctor()?;

    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "managed-region-untracked"
            && diagnostic.path.as_deref() == Some(".dockerignore")
    }));
    Ok(())
}

#[test]
fn target_specific_omnius_dependency_blocks_mutation() -> TestResult {
    let directory = generated_minimal("module-manager-target-omnius-dependency")?;
    let manifest_path = directory.path().join("apps/service/Cargo.toml");
    let mut manifest = fs::read_to_string(&manifest_path)?;
    manifest.push_str(
        "\n[target.'cfg(unix)'.dependencies]\nrogue-http = { package = \"omnius-http\", version = \"=0.3.0\" }\nrogue-generator = { package = \"omnius-generator\", version = \"=0.3.0\" }\n",
    );
    fs::write(&manifest_path, manifest)?;
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    let report = manager.doctor()?;
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "omnius-dependency-forbidden"
            && diagnostic.path.as_deref() == Some("apps/service/Cargo.toml")
    }));
    let error = assert_error(manager.plan_add("feature-flags"));
    assert!(error.to_string().contains("omnius-dependency-forbidden"));
    Ok(())
}

#[test]
fn canonical_framework_dependency_rejects_mutable_or_alternate_sources() -> TestResult {
    let directory = generated_minimal("module-manager-canonical-framework-source")?;
    let manifest_path = directory.path().join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)?
        .replace(
            "git = \"https://github.com/bmanturner/omnius.git\"",
            "git = \"ssh://git@github.com/bmanturner/omnius.git\"\nbranch = \"main\"\npath = \"../omnius\"\nregistry = \"private\"",
        );
    fs::write(manifest_path, manifest)?;
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    let report = manager.doctor()?;

    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "framework-dependency-invalid"
            && diagnostic.path.as_deref() == Some("Cargo.toml")
    }));
    assert!(
        assert_error(manager.plan_add("localization"))
            .to_string()
            .contains("framework-dependency-invalid")
    );
    Ok(())
}

#[test]
fn application_workspace_member_and_dependencies_survive_lifecycle_changes() -> TestResult {
    let directory = generated_minimal("module-manager-extra-workspace-member")?;
    let root_manifest_path = directory.path().join("Cargo.toml");
    let root_manifest = fs::read_to_string(&root_manifest_path)?
        .replace("members = [\"apps/service\"]", "members = [\"apps/*\"]");
    fs::write(&root_manifest_path, root_manifest)?;
    let member_manifest_path = directory.path().join("apps/worker/Cargo.toml");
    fs::create_dir_all(
        member_manifest_path
            .parent()
            .ok_or("worker manifest has no parent")?,
    )?;
    let member_manifest = "[package]\nname = \"application-worker\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n[dependencies]\nserde.workspace = true\nservice-kit.workspace = true\n";
    fs::write(&member_manifest_path, member_manifest)?;
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    assert!(manager.doctor()?.healthy);
    apply_add(&manager, "localization")?;

    assert_eq!(fs::read_to_string(member_manifest_path)?, member_manifest);
    assert!(fs::read_to_string(root_manifest_path)?.contains("members = [\"apps/*\"]"));
    assert!(manager.doctor()?.healthy);
    Ok(())
}

#[test]
fn mutable_member_framework_source_is_rejected() -> TestResult {
    let directory = generated_minimal("module-manager-member-framework-source")?;
    let manifest_path = directory.path().join("apps/service/Cargo.toml");
    let mut manifest = fs::read_to_string(&manifest_path)?;
    manifest.push_str(
        "\n[target.'cfg(target_os = \"linux\")'.build-dependencies]\nservice-kit = { git = \"https://github.com/bmanturner/omnius.git\", branch = \"main\" }\n",
    );
    fs::write(manifest_path, manifest)?;
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    let report = manager.doctor()?;

    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "member-framework-use-invalid"
            && diagnostic.message.contains("workspace = true")
    }));
    Ok(())
}

#[test]
fn manifest_patch_and_replace_tables_block_mutation() -> TestResult {
    let directory = generated_minimal("module-manager-manifest-overrides")?;
    let manifest_path = directory.path().join("Cargo.toml");
    let mut manifest = fs::read_to_string(&manifest_path)?;
    manifest.push_str(
        "\n[patch.crates-io]\nitoa = { path = \"vendor/itoa\" }\n\n[replace]\n\"itoa:1.0.0\" = { path = \"vendor/itoa\" }\n",
    );
    fs::write(manifest_path, manifest)?;
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    let report = manager.doctor()?;
    assert!(
        ["manifest-patch-forbidden", "manifest-replace-forbidden"]
            .iter()
            .all(|code| report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == *code))
    );
    let error = assert_error(manager.plan_add("localization"));
    assert!(error.to_string().contains("manifest-patch-forbidden"));
    Ok(())
}

#[test]
fn ancestor_cargo_paths_and_source_replacement_block_mutation() -> TestResult {
    let directory = CleanDirectory::new("module-manager-ancestor-cargo-config")?;
    let destination = directory.path().join("nested/service");
    fs::create_dir_all(destination.parent().ok_or("nested service has no parent")?)?;
    render_test_project(RenderRequest {
        service_name: "managed-service",
        profile: "minimal",
        destination: &destination,
        release_identity: test_release_identity(),
    })?;
    let cargo_directory = directory.path().join(".cargo");
    fs::create_dir_all(&cargo_directory)?;
    fs::write(
        cargo_directory.join("config.toml"),
        "paths = [\"vendor\"]\n\n[source.\"git+https://github.com/bmanturner/omnius.git\"]\nreplace-with = \"vendored\"\n\n[source.vendored]\ndirectory = \"vendor\"\n",
    )?;
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(&destination, test_release_identity(), &catalog);

    let report = manager.doctor()?;
    assert!(
        report
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "source-override")
            .count()
            >= 2
    );
    let error = assert_error(manager.plan_add("localization"));
    assert!(error.to_string().contains("source-override"));
    Ok(())
}

#[test]
fn approved_derived_hash_drift_blocks_mutation() -> TestResult {
    let directory = generated_minimal("module-manager-derived-approved-hash")?;
    fs::write(
        directory.path().join("ops/compose.yaml"),
        "application edit\n",
    )?;
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    let report = manager.doctor()?;
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "approved-hash-mismatch"
            && diagnostic.path.as_deref() == Some("ops/compose.yaml")
    }));
    let error = assert_error(manager.plan_add("localization"));
    assert!(error.to_string().contains("approved-hash-mismatch"));
    Ok(())
}

#[test]
fn older_identity_inspection_uses_recorded_hashes_without_reconstruction() -> TestResult {
    let directory = generated_minimal("module-manager-older-identity")?;
    let older_identity = ReleaseIdentity::new(
        KIT_VERSION,
        CANONICAL_REPOSITORY,
        "0000000000000000000000000000000000000002",
    )?;
    let state_path = directory.path().join(".omnius/service.toml");
    let mut state = ProjectState::parse(&fs::read_to_string(&state_path)?)?;
    let manifest_path = directory.path().join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)?;
    let framework_record = state
        .managed_region("Cargo.toml", "framework-dependency")
        .ok_or("framework region state is missing")?
        .clone();
    let current_region = parse_managed_regions(&manifest)?
        .into_iter()
        .find(|region| region.id == "framework-dependency")
        .ok_or("framework region is missing")?;
    let historical_region = current_region.content.replace(
        test_release_identity().revision(),
        older_identity.revision(),
    );
    let historical_manifest =
        reconcile_managed_region(&manifest, &framework_record, &historical_region)?;
    let historical_region_hash = parse_managed_regions(&historical_manifest)?
        .into_iter()
        .find(|region| region.id == "framework-dependency")
        .ok_or("historical framework region is missing")?
        .content_hash
        .to_owned();
    state.framework = older_identity;
    state
        .managed_regions
        .iter_mut()
        .find(|record| record.path == "Cargo.toml" && record.id == "framework-dependency")
        .ok_or("framework state record disappeared")?
        .content_hash = historical_region_hash;
    let historical_derived = "historical generator output\n";
    fs::write(
        directory.path().join("ops/compose.yaml"),
        historical_derived,
    )?;
    state
        .ownership
        .iter_mut()
        .find(|record| record.path == "ops/compose.yaml")
        .ok_or("Compose ownership is missing")?
        .approved_sha256 = Some(sha256(historical_derived));
    fs::write(manifest_path, historical_manifest)?;
    fs::write(&state_path, state.to_toml()?)?;
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    let report = manager.doctor()?;
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "release-mismatch")
    );
    assert!(!report.diagnostics.iter().any(|diagnostic| {
        matches!(
            diagnostic.code.as_str(),
            "approved-hash-mismatch" | "derived-drift" | "framework-dependency-invalid"
        )
    }));
    assert!(manager.diff()?.is_empty());
    assert!(
        assert_error(manager.plan_add("localization"))
            .to_string()
            .contains("release-mismatch")
    );
    fs::write(
        directory.path().join("ops/compose.yaml"),
        "tampered historical output\n",
    )?;
    assert!(
        assert_error(manager.diff())
            .to_string()
            .contains("approved-hash-mismatch")
    );
    Ok(())
}

#[test]
fn removal_preserves_released_migrations_but_not_framework_crate_sources() {
    assert!(
        [
            "migrations/0001.sql",
            "crates/example/migrations/0001.sql",
            "data/history.json",
        ]
        .iter()
        .all(|path| preserves_historical_path(path))
    );
    assert!(!preserves_historical_path("crates/migrations/Cargo.toml"));
}

#[test]
fn schema_one_projects_reject_every_non_update_lifecycle_command_with_guidance() -> TestResult {
    let directory = generated_minimal("schema-one-update-guidance")?;
    let state_path = directory.path().join(".omnius/service.toml");
    let mut state: toml::Value = toml::from_str(&fs::read_to_string(&state_path)?)?;
    state["schema_version"] = toml::Value::Integer(1);
    fs::write(&state_path, toml::to_string_pretty(&state)?)?;
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), test_release_identity(), &catalog);

    for message in [
        assert_error(manager.doctor()).to_string(),
        assert_error(manager.diff()).to_string(),
        assert_error(manager.plan_add("localization")).to_string(),
        assert_error(manager.plan_remove("config")).to_string(),
        assert_error(manager.plan_profile_set("api")).to_string(),
        assert_error(manager.seal_add_with("localization", false, &TestLockfileResolver))
            .to_string(),
    ] {
        assert_eq!(
            message,
            "legacy schema-1 project; run `cargo service update`"
        );
    }
    Ok(())
}

fn generated_minimal(label: &str) -> TestResult<CleanDirectory> {
    generated_profile(label, "minimal")
}

fn generated_profile(label: &str, profile: &str) -> TestResult<CleanDirectory> {
    let directory = CleanDirectory::new(label)?;
    render_test_project(RenderRequest {
        service_name: "managed-service",
        profile,
        destination: directory.path(),
        release_identity: test_release_identity(),
    })?;
    Ok(directory)
}

fn sha256(source: &str) -> String {
    sha256_bytes(source.as_bytes())
}

fn sha256_bytes(source: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(source);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn record_application_owned(root: &Path, paths: &[&str]) -> TestResult {
    let state_path = root.join(".omnius/service.toml");
    let mut state = ProjectState::parse(&fs::read_to_string(&state_path)?)?;
    for path in paths {
        state.ownership.push(OwnershipRecord {
            path: (*path).to_owned(),
            kind: OwnershipKind::ApplicationOwned,
            approved_sha256: None,
        });
    }
    state.ownership.sort();
    fs::write(state_path, state.to_toml()?)?;
    Ok(())
}

#[test]
fn generated_state_records_current_framework_identity() -> TestResult {
    let directory = generated_minimal("module-manager-state-version")?;
    let state = ProjectState::parse(&fs::read_to_string(
        directory.path().join(".omnius/service.toml"),
    )?)?;

    assert_eq!(&state.framework, test_release_identity());
    Ok(())
}
