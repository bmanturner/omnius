//! Catalog-driven module planning and managed-ownership integration contracts.

use std::{collections::BTreeSet, error::Error, fmt::Write as _, fs, path::Path};

use omnius_generator::{
    KIT_VERSION, MANAGED_MARKER_VERSION, ManagedRegionRecord, ModuleCatalog, OwnershipKind,
    OwnershipRecord, ProjectManager, ProjectState, RenderRequest, parse_managed_regions,
    preserves_historical_path, reconcile_managed_region, render_project,
};
use omnius_test_support::CleanDirectory;
use sha2::{Digest, Sha256};

const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const PRIOR_DERIVED_FIXTURES: &[(&str, &str)] = &[
    (
        "contracts/openapi.json",
        include_str!("fixtures/prior-0.0.0/contracts/openapi.json"),
    ),
    (
        "contracts/permissions.json",
        include_str!("fixtures/prior-0.0.0/contracts/permissions.json"),
    ),
    (
        "contracts/capabilities.json",
        include_str!("fixtures/prior-0.0.0/contracts/capabilities.json"),
    ),
    (
        "contracts/contract-manifest.json",
        include_str!("fixtures/prior-0.0.0/contracts/contract-manifest.json"),
    ),
    (
        "contracts/asyncapi.json",
        include_str!("fixtures/prior-0.0.0/contracts/asyncapi.json"),
    ),
    (
        "packages/web-sdk/src/internal/generated/http/core.ts",
        include_str!("fixtures/prior-0.0.0/packages/web-sdk/src/internal/generated/http/core.ts"),
    ),
    (
        "packages/web-sdk/src/internal/generated/http/react-query.ts",
        include_str!(
            "fixtures/prior-0.0.0/packages/web-sdk/src/internal/generated/http/react-query.ts"
        ),
    ),
    (
        "packages/web-sdk/src/internal/generated/realtime.ts",
        include_str!("fixtures/prior-0.0.0/packages/web-sdk/src/internal/generated/realtime.ts"),
    ),
];

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

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
    let source = "schema_version = 1\nkit_version = \"0.1.0\"\nservice = \"example\"\nunknown = true\nmodules = []\nownership = []\nmanaged_regions = []\n\n[profile]\nid = \"minimal\"\nversion = \"0.1.0\"\nadditions = []\nremovals = []\n";
    let error = assert_error(ProjectState::parse(source));

    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn project_state_serde_rejects_unsupported_versions() {
    let source = "schema_version = 2\nkit_version = \"0.1.0\"\nservice = \"example\"\nmodules = []\nownership = []\nmanaged_regions = []\n\n[profile]\nid = \"minimal\"\nversion = \"0.1.0\"\nadditions = []\nremovals = []\n";
    let error = assert_error(ProjectState::parse(source));

    assert!(
        error
            .to_string()
            .contains("unsupported project state schema version")
    );
}

#[test]
fn generated_project_add_remove_is_idempotent_backed_up_and_healthy() -> TestResult {
    let directory = generated_minimal("module-manager-roundtrip")?;
    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);

    let add = manager.plan_add("localization")?;
    assert_eq!(manager.plan_add("localization")?, add);
    assert!(add.added_modules.contains(&"localization".to_owned()));
    let applied = manager.apply(&add)?;
    assert!(directory.path().join(&applied.backup_artifact).is_file());
    assert!(
        directory
            .path()
            .join("crates/localization/src/lib.rs")
            .is_file()
    );
    assert!(fs::read_to_string(directory.path().join("Cargo.toml"))?.contains("chrono = "));
    assert!(manager.plan_add("localization")?.is_empty());
    assert!(manager.doctor()?.healthy);
    assert!(manager.diff()?.is_empty());

    let remove = manager.plan_remove("localization")?;
    manager.apply(&remove)?;
    assert!(!directory.path().join("crates/localization").exists());
    assert!(manager.plan_remove("localization")?.is_empty());
    assert!(manager.doctor()?.healthy);
    assert!(manager.diff()?.is_empty());
    Ok(())
}
#[test]
fn web_support_add_remove_is_idempotent_and_preserves_application_owned_files() -> TestResult {
    let directory = generated_minimal("web-module-manager-roundtrip")?;
    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);

    let add = manager.plan_add("web")?;
    assert_eq!(manager.plan_add("web")?, add);
    assert!(add.added_modules.contains(&"web-react".to_owned()));
    manager.apply(&add)?;
    let second_add = manager.plan_add("web")?;
    assert!(second_add.is_empty());
    assert_eq!(manager.apply(&second_add)?.changed_files, 0);
    assert!(directory.path().join("web/package.json").is_file());
    let web_dockerfile = fs::read_to_string(directory.path().join("ops/Dockerfile"))?;
    assert!(web_dockerfile.contains("FROM node:24.19.0-bookworm-slim AS web-build"));
    assert!(web_dockerfile.contains("pnpm install --frozen-lockfile"));
    assert!(web_dockerfile.contains("COPY --from=web-build /workspace/web/dist /app/web/dist"));
    let state = ProjectState::parse(&fs::read_to_string(
        directory.path().join(".omnius/service.toml"),
    )?)?;
    assert_eq!(
        state.ownership_of("contracts/openapi.json"),
        Some(OwnershipKind::Derived)
    );

    let owned = [
        (
            "web/src/routes/product-route.tsx",
            "export const productRoute = 'application-owned';\n",
        ),
        (
            "web/src/components/product-card.tsx",
            "export const ProductCard = () => null;\n",
        ),
        ("data/history.json", "{\"preserved\":true}\n"),
        (
            "migrations/9999_application.sql",
            "-- application history\n",
        ),
    ];
    for (path, contents) in owned {
        let absolute = directory.path().join(path);
        fs::create_dir_all(absolute.parent().ok_or("application file has no parent")?)?;
        fs::write(absolute, contents)?;
    }
    record_application_owned(directory.path(), &owned.map(|(path, _)| path))?;
    let application = directory.path().join("apps/service/src/application.rs");
    fs::write(
        &application,
        "pub fn application_owned() -> bool { true }\n",
    )?;
    let application_before = fs::read(&application)?;

    let remove = manager.plan_remove("web")?;
    for (path, _) in owned.iter().skip(2) {
        assert!(remove.preserved_paths.contains(&(*path).to_owned()));
    }
    manager.apply(&remove)?;

    assert!(!directory.path().join("web/package.json").exists());
    assert!(
        !directory
            .path()
            .join("packages/web-sdk/package.json")
            .exists()
    );
    assert!(!directory.path().join("contracts/openapi.json").exists());
    let lean_dockerfile = fs::read_to_string(directory.path().join("ops/Dockerfile"))?;
    assert!(!lean_dockerfile.contains("node:"));
    assert!(!lean_dockerfile.contains("pnpm"));
    assert!(!lean_dockerfile.contains("web/dist"));
    for (path, contents) in owned {
        assert_eq!(fs::read_to_string(directory.path().join(path))?, contents);
    }
    assert_eq!(fs::read(application)?, application_before);
    assert!(manager.plan_remove("web")?.is_empty());
    assert!(manager.doctor()?.healthy);
    assert!(manager.diff()?.is_empty());
    Ok(())
}

#[test]
fn existing_unowned_web_target_blocks_add_without_mutation() -> TestResult {
    let directory = generated_minimal("web-module-manager-conflict")?;
    let target = directory.path().join("web/package.json");
    fs::create_dir_all(target.parent().ok_or("web target has no parent")?)?;
    fs::write(&target, "{\"application\":true}\n")?;
    let state_path = directory.path().join(".omnius/service.toml");
    let state_before = fs::read(&state_path)?;
    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);

    let error = assert_error(manager.plan_add("web"));

    assert!(error.to_string().contains("unowned module target"));
    assert_eq!(fs::read(state_path)?, state_before);
    assert_eq!(fs::read_to_string(target)?, "{\"application\":true}\n");
    assert!(!directory.path().join(".node-version").exists());
    Ok(())
}

#[test]
fn kit_owned_drift_blocks_removal_without_any_mutation() -> TestResult {
    let directory = generated_minimal("module-manager-drift")?;
    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);
    let add = manager.plan_add("localization")?;
    manager.apply(&add)?;
    let state_path = directory.path().join(".omnius/service.toml");
    let state_before = fs::read(&state_path)?;
    fs::write(
        directory.path().join("crates/localization/Cargo.toml"),
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
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);

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
fn outside_region_edit_in_kit_owned_manifest_blocks_add() -> TestResult {
    let directory = generated_minimal("module-manager-outside-drift")?;
    let manifest = directory.path().join("Cargo.toml");
    let mut edited = fs::read_to_string(&manifest)?;
    edited.push_str("\n[workspace.metadata.application-edit]\n");
    fs::write(&manifest, edited)?;
    let state_path = directory.path().join(".omnius/service.toml");
    let state_before = fs::read(&state_path)?;
    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);

    let error = assert_error(manager.plan_add("feature-flags"));

    assert!(error.to_string().contains("kit-owned-drift"));
    assert_eq!(fs::read(state_path)?, state_before);
    assert!(!directory.path().join("crates/feature-flags").exists());
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
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);

    let error = assert_error(manager.plan_add("feature-flags"));

    assert!(error.to_string().contains("managed-region-corrupt"));
    assert_eq!(fs::read(state_path)?, state_before);
    assert!(!directory.path().join("crates/feature-flags").exists());
    Ok(())
}

#[test]
fn doctor_reports_unrecorded_marker_added_to_kit_owned_file() -> TestResult {
    let directory = generated_minimal("module-manager-untracked-marker")?;
    let source_path = directory.path().join("crates/core/src/lib.rs");
    let mut source = fs::read_to_string(&source_path)?;
    write!(
        source,
        "\n// omnius:managed-begin id=unexpected version=1 hash={EMPTY_HASH}\n// omnius:managed-end id=unexpected\n"
    )?;
    fs::write(&source_path, source)?;
    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);

    let report = manager.doctor()?;

    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "managed-region-untracked"
            && diagnostic.path.as_deref() == Some("crates/core/src/lib.rs")
    }));
    Ok(())
}

#[test]
fn application_owned_managed_target_fails_closed() -> TestResult {
    let directory = generated_minimal("module-manager-application-owned")?;
    let state_path = directory.path().join(".omnius/service.toml");
    let source = fs::read_to_string(&state_path)?;
    let changed = source.replace(
        "path = \"Cargo.toml\"\nkind = \"kit-owned\"",
        "path = \"Cargo.toml\"\nkind = \"application-owned\"",
    );
    fs::write(&state_path, &changed)?;
    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);

    let error = assert_error(manager.plan_add("feature-flags"));

    assert!(error.to_string().contains("application-owned"));
    assert_eq!(fs::read_to_string(state_path)?, changed);
    assert!(!directory.path().join("crates/feature-flags").exists());
    Ok(())
}

#[test]
fn removal_never_classifies_migrations_or_data_history_as_deletable() {
    assert!(
        [
            "migrations/0001.sql",
            "crates/example/migrations/0001.sql",
            "data/history.json",
        ]
        .iter()
        .all(|path| preserves_historical_path(path))
    );
}

#[test]
fn omnius_0_0_0_upgrade_applies_preserves_app_bytes_and_repeats_as_noop() -> TestResult {
    let directory = generated_minimal("upgrade-untouched-app-edited")?;
    let application = directory.path().join("apps/service/src/application.rs");
    fs::write(
        &application,
        "pub async fn example() -> &'static str { \"edited\" }\n",
    )?;
    let application_before = fs::read(&application)?;
    downgrade_project(directory.path())?;
    assert_prior_fixture_is_omnius_source(directory.path())?;
    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);

    let plan = manager.plan_upgrade(KIT_VERSION)?;
    assert_eq!(manager.plan_upgrade(KIT_VERSION)?, plan);
    let outcome = manager.apply(&plan)?;

    assert!(directory.path().join(outcome.backup_artifact).is_file());
    assert_eq!(fs::read(application)?, application_before);
    assert!(
        fs::read_to_string(directory.path().join("Cargo.lock"))?.contains("version = \"0.1.0\"")
    );
    assert!(manager.plan_upgrade(KIT_VERSION)?.is_empty());
    assert!(manager.doctor()?.healthy);
    Ok(())
}

#[test]
fn prior_web_profiles_upgrade_untouched_and_repeat_as_noop() -> TestResult {
    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    for profile in ["web", "web-sdk-only", "saas-web"] {
        let directory = generated_profile(&format!("upgrade-{profile}"), profile)?;
        downgrade_project(directory.path())?;
        assert_prior_fixture_is_omnius_source(directory.path())?;
        let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);

        let plan = manager.plan_upgrade(KIT_VERSION)?;
        assert_eq!(manager.plan_upgrade(KIT_VERSION)?, plan);
        manager.apply(&plan)?;

        assert!(manager.plan_upgrade(KIT_VERSION)?.is_empty());
        assert!(manager.doctor()?.healthy);
        assert!(manager.diff()?.is_empty());
    }
    Ok(())
}

#[test]
fn prior_conditional_sdk_artifacts_migrate_from_derived_ownership() -> TestResult {
    let directory = generated_profile("upgrade-web-derived-entries", "web")?;
    downgrade_project(directory.path())?;
    let state_path = directory.path().join(".omnius/service.toml");
    let mut state = ProjectState::parse(&fs::read_to_string(&state_path)?)?;
    for path in [
        "packages/web-sdk/src/internal/generated/contract-metadata.ts",
        "packages/web-sdk/src/react/index.ts",
        "packages/web-sdk/src/testing/index.ts",
    ] {
        let record = state
            .ownership
            .iter_mut()
            .find(|record| record.path == path)
            .ok_or("missing conditional SDK ownership record")?;
        record.kind = OwnershipKind::Derived;
    }
    fs::write(&state_path, state.to_toml()?)?;

    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);
    let plan = manager.plan_upgrade(KIT_VERSION)?;
    manager.apply(&plan)?;

    let upgraded = ProjectState::parse(&fs::read_to_string(&state_path)?)?;
    for path in [
        "packages/web-sdk/src/internal/generated/contract-metadata.ts",
        "packages/web-sdk/src/react/index.ts",
        "packages/web-sdk/src/testing/index.ts",
    ] {
        assert_eq!(upgraded.ownership_of(path), Some(OwnershipKind::KitOwned));
    }
    assert!(manager.doctor()?.healthy);
    Ok(())
}

#[test]
fn prior_application_owned_conditional_sdk_entry_is_preserved() -> TestResult {
    let directory = generated_profile("upgrade-web-owned-entry", "web")?;
    downgrade_project(directory.path())?;
    let entry_path = "packages/web-sdk/src/testing/index.ts";
    let entry = directory.path().join(entry_path);
    let application_source = "export const applicationOwnedTestingEntry = true;\n";
    fs::write(&entry, application_source)?;
    let state_path = directory.path().join(".omnius/service.toml");
    let mut state = ProjectState::parse(&fs::read_to_string(&state_path)?)?;
    let record = state
        .ownership
        .iter_mut()
        .find(|record| record.path == entry_path)
        .ok_or("missing testing entry ownership record")?;
    record.kind = OwnershipKind::ApplicationOwned;
    fs::write(&state_path, state.to_toml()?)?;

    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);
    let plan = manager.plan_upgrade(KIT_VERSION)?;
    manager.apply(&plan)?;

    assert_eq!(fs::read_to_string(entry)?, application_source);
    let upgraded = ProjectState::parse(&fs::read_to_string(state_path)?)?;
    assert_eq!(
        upgraded.ownership_of(entry_path),
        Some(OwnershipKind::ApplicationOwned)
    );
    Ok(())
}
#[test]
fn prior_web_upgrade_preserves_application_routes_components_and_node_lock() -> TestResult {
    let directory = generated_profile("upgrade-web-application-owned", "web")?;
    let owned = [
        (
            "web/src/routes/billing-route.tsx",
            "export const billingRoute = 'preserved';\n",
        ),
        (
            "web/src/components/account-card.tsx",
            "export const AccountCard = () => null;\n",
        ),
    ];
    for (path, contents) in owned {
        let absolute = directory.path().join(path);
        fs::create_dir_all(
            absolute
                .parent()
                .ok_or("web application file has no parent")?,
        )?;
        fs::write(absolute, contents)?;
    }
    record_application_owned(directory.path(), &owned.map(|(path, _)| path))?;
    let pnpm_lock = fs::read(directory.path().join("pnpm-lock.yaml"))?;
    downgrade_project(directory.path())?;
    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);

    let plan = manager.plan_upgrade(KIT_VERSION)?;
    manager.apply(&plan)?;

    for (path, contents) in owned {
        assert_eq!(fs::read_to_string(directory.path().join(path))?, contents);
    }
    assert_eq!(
        fs::read(directory.path().join("pnpm-lock.yaml"))?,
        pnpm_lock
    );
    assert!(
        fs::read_to_string(directory.path().join("package.json"))?
            .contains("\"version\": \"0.1.0\"")
    );
    assert!(manager.plan_upgrade(KIT_VERSION)?.is_empty());
    assert!(manager.doctor()?.healthy);
    Ok(())
}

#[test]
fn prior_upgrade_preserves_approved_managed_module_content() -> TestResult {
    let directory = generated_profile("upgrade-approved-managed", "web")?;
    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let current = ProjectManager::new(directory.path(), &kit_root, &catalog);
    let add = current.plan_add("localization")?;
    current.apply(&add)?;
    downgrade_project(directory.path())?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);

    let plan = manager.plan_upgrade(KIT_VERSION)?;
    manager.apply(&plan)?;
    let manifest = fs::read_to_string(directory.path().join("Cargo.toml"))?;
    let composition = fs::read_to_string(directory.path().join("apps/service/src/composition.rs"))?;

    assert!(manifest.contains("\"crates/localization\""));
    assert!(composition.contains("\"localization\""));
    assert!(manager.plan_upgrade(KIT_VERSION)?.is_empty());
    Ok(())
}

#[test]
fn dependency_override_conflict_blocks_upgrade_without_mutation() -> TestResult {
    let directory = generated_profile("upgrade-dependency-conflict", "web-sdk-only")?;
    downgrade_project(directory.path())?;
    approve_dependency_override(directory.path(), "serde = \"=0.0.1\"\n")?;
    let before = upgrade_mutation_snapshot(directory.path())?;
    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);

    let error = assert_error(manager.plan_upgrade(KIT_VERSION));

    assert!(error.to_string().contains("dependency override conflict"));
    assert_eq!(upgrade_mutation_snapshot(directory.path())?, before);
    Ok(())
}

#[test]
fn stale_prior_contract_blocks_upgrade_without_mutation() -> TestResult {
    let directory = generated_profile("upgrade-stale-contract", "web-sdk-only")?;
    downgrade_project(directory.path())?;
    let contract = directory.path().join("contracts/contract-manifest.json");
    fs::write(&contract, "{\"stale\":true}\n")?;
    let contract_before = fs::read(&contract)?;
    let state_before = fs::read(directory.path().join(".omnius/service.toml"))?;
    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);

    let error = assert_error(manager.plan_upgrade(KIT_VERSION));

    assert!(error.to_string().contains("derived source baseline drift"));
    assert_eq!(fs::read(contract)?, contract_before);
    assert_eq!(
        fs::read(directory.path().join(".omnius/service.toml"))?,
        state_before
    );
    Ok(())
}

#[test]
fn corrupted_prior_region_blocks_upgrade_without_mutation() -> TestResult {
    let directory = generated_minimal("upgrade-corrupt-region")?;
    downgrade_project(directory.path())?;
    let manifest = directory.path().join("Cargo.toml");
    let corrupted = corrupt_first_managed_hash(&fs::read_to_string(&manifest)?);
    fs::write(&manifest, corrupted)?;
    let before = upgrade_mutation_snapshot(directory.path())?;
    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(directory.path(), &kit_root, &catalog);

    let error = assert_error(manager.plan_upgrade(KIT_VERSION));

    assert!(error.to_string().contains("managed region"));
    assert_eq!(upgrade_mutation_snapshot(directory.path())?, before);
    Ok(())
}

#[test]
fn unsupported_and_stale_prior_upgrades_are_nonmutating() -> TestResult {
    let unsupported = generated_minimal("upgrade-unsupported")?;
    downgrade_project(unsupported.path())?;
    let before = upgrade_mutation_snapshot(unsupported.path())?;
    let catalog = ModuleCatalog::bundled()?;
    let kit_root = kit_root()?;
    let manager = ProjectManager::new(unsupported.path(), &kit_root, &catalog);
    let error = assert_error(manager.plan_upgrade("9.0.0"));
    assert!(error.to_string().contains("unsupported"));
    assert_eq!(upgrade_mutation_snapshot(unsupported.path())?, before);

    let unsupported_source = generated_minimal("upgrade-unsupported-source")?;
    downgrade_project(unsupported_source.path())?;
    let source_state_path = unsupported_source.path().join(".omnius/service.toml");
    let mut source_state = ProjectState::parse(&fs::read_to_string(&source_state_path)?)?;
    source_state.kit_version = "0.0.1".to_owned();
    fs::write(&source_state_path, source_state.to_toml()?)?;
    let source_before = upgrade_mutation_snapshot(unsupported_source.path())?;
    let source_manager = ProjectManager::new(unsupported_source.path(), &kit_root, &catalog);
    let error = assert_error(source_manager.plan_upgrade(KIT_VERSION));
    assert!(error.to_string().contains("unsupported"));
    assert_eq!(
        upgrade_mutation_snapshot(unsupported_source.path())?,
        source_before
    );

    let stale = generated_minimal("upgrade-stale")?;
    downgrade_state_only(stale.path())?;
    let stale_before = upgrade_mutation_snapshot(stale.path())?;
    let stale_manager = ProjectManager::new(stale.path(), &kit_root, &catalog);
    let error = assert_error(stale_manager.plan_upgrade(KIT_VERSION));
    assert!(error.to_string().contains("baseline drift"));
    assert_eq!(upgrade_mutation_snapshot(stale.path())?, stale_before);
    Ok(())
}

fn assert_prior_fixture_is_omnius_source(root: &Path) -> TestResult {
    let state_path = root.join(".omnius/service.toml");
    let state = ProjectState::parse(&fs::read_to_string(&state_path)?)?;
    assert_eq!(state.kit_version, "0.0.0");
    assert_eq!(state.profile.version, "0.0.0");
    assert!(state.modules.iter().all(|module| module.version == "0.0.0"));

    let manifest = fs::read_to_string(root.join("Cargo.toml"))?;
    let fixture_manifest = include_str!("fixtures/prior-0.0.0/Cargo.toml");
    assert!(manifest.contains("omnius:managed-begin"));
    assert!(manifest.contains("omnius:managed-end"));
    assert!(fixture_manifest.contains("omnius:managed-begin"));
    assert!(fixture_manifest.contains("omnius:managed-end"));

    let dockerfile = fs::read_to_string(root.join("ops/Dockerfile"))?;
    let expected_dockerfile =
        include_str!("fixtures/prior-0.0.0/Dockerfile").replace("{{project-name}}", &state.service);
    assert_eq!(dockerfile, expected_dockerfile);
    assert!(dockerfile.contains("ENV OMNIUS_BIND="));
    let package = root.join("package.json");
    if package.is_file() {
        assert_eq!(
            fs::read_to_string(package)?,
            include_str!("fixtures/prior-0.0.0/package.json")
        );
    }
    for (path, source) in PRIOR_DERIVED_FIXTURES {
        let artifact = root.join(path);
        if artifact.is_file() {
            assert_eq!(
                fs::read_to_string(artifact)?,
                source.replace(KIT_VERSION, "0.0.0")
            );
        }
    }

    let legacy_stem = ["r", "s", "k"].concat();
    assert!(!root.join(format!(".{legacy_stem}")).exists());
    assert!(!manifest.contains(&format!("{legacy_stem}:managed-")));
    assert!(!fixture_manifest.contains(&format!("{legacy_stem}:managed-")));
    assert!(!dockerfile.contains(&format!("{}_", legacy_stem.to_ascii_uppercase())));
    Ok(())
}

fn downgrade_project(root: &Path) -> TestResult {
    let manifest_path = root.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)?
        .replace(
            "version = \"0.1.0\"\nedition",
            "version = \"0.0.0\"\nedition",
        )
        .replace("rust-version = \"1.98.0\"", "rust-version = \"1.97.0\"");
    fs::write(manifest_path, manifest)?;
    let state = ProjectState::parse(&fs::read_to_string(root.join(".omnius/service.toml"))?)?;
    let docker =
        include_str!("fixtures/prior-0.0.0/Dockerfile").replace("{{project-name}}", &state.service);
    fs::write(root.join("ops/Dockerfile"), docker)?;
    let package = root.join("package.json");
    if package.is_file() {
        fs::write(package, include_str!("fixtures/prior-0.0.0/package.json"))?;
    }
    for derived in ["docs/module-catalog.md", "config/reference.toml"] {
        let path = root.join(derived);
        if path.is_file() {
            let source = fs::read_to_string(&path)?.replace(KIT_VERSION, "0.0.0");
            fs::write(path, source)?;
        }
    }
    for (relative, source) in PRIOR_DERIVED_FIXTURES {
        let path = root.join(relative);
        if path.is_file() {
            fs::write(path, source.replace(KIT_VERSION, "0.0.0"))?;
        }
    }
    fs::write(
        root.join("Cargo.lock"),
        include_str!("fixtures/prior-0.0.0/Cargo.lock"),
    )?;
    downgrade_state_only(root)
}

fn downgrade_state_only(root: &Path) -> TestResult {
    let path = root.join(".omnius/service.toml");
    let mut state = ProjectState::parse(&fs::read_to_string(&path)?)?;
    "0.0.0".clone_into(&mut state.kit_version);
    "0.0.0".clone_into(&mut state.profile.version);
    for module in &mut state.modules {
        "0.0.0".clone_into(&mut module.version);
    }
    fs::write(path, state.to_toml()?)?;
    Ok(())
}

fn approve_dependency_override(root: &Path, content: &str) -> TestResult {
    let state_path = root.join(".omnius/service.toml");
    let mut state = ProjectState::parse(&fs::read_to_string(&state_path)?)?;
    let record = state
        .managed_region("Cargo.toml", "workspace-dependencies")
        .cloned()
        .ok_or("missing workspace-dependencies region")?;
    let manifest_path = root.join("Cargo.toml");
    let manifest =
        reconcile_managed_region(&fs::read_to_string(&manifest_path)?, &record, content)?;
    fs::write(manifest_path, manifest)?;
    let updated = state
        .managed_regions
        .iter_mut()
        .find(|region| region.id == "workspace-dependencies")
        .ok_or("missing mutable workspace-dependencies region")?;
    updated.content_hash.clear();
    for byte in Sha256::digest(content.as_bytes()) {
        write!(updated.content_hash, "{byte:02x}")?;
    }
    fs::write(state_path, state.to_toml()?)?;
    Ok(())
}

fn upgrade_mutation_snapshot(root: &Path) -> TestResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let lock = match fs::read(root.join("Cargo.lock")) {
        Ok(lock) => lock,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    Ok((
        fs::read(root.join(".omnius/service.toml"))?,
        fs::read(root.join("Cargo.toml"))?,
        lock,
    ))
}

fn generated_minimal(label: &str) -> TestResult<CleanDirectory> {
    generated_profile(label, "minimal")
}

fn generated_profile(label: &str, profile: &str) -> TestResult<CleanDirectory> {
    let directory = CleanDirectory::new(label)?;
    render_project(RenderRequest {
        service_name: "managed-service",
        profile,
        destination: directory.path(),
    })?;
    Ok(directory)
}

fn record_application_owned(root: &Path, paths: &[&str]) -> TestResult {
    let state_path = root.join(".omnius/service.toml");
    let mut state = ProjectState::parse(&fs::read_to_string(&state_path)?)?;
    for path in paths {
        state.ownership.push(OwnershipRecord {
            path: (*path).to_owned(),
            kind: OwnershipKind::ApplicationOwned,
        });
    }
    state.ownership.sort();
    fs::write(state_path, state.to_toml()?)?;
    Ok(())
}

fn kit_root() -> TestResult<std::path::PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "generator crate has no workspace root".into())
}

#[test]
fn generated_state_records_current_kit_version() -> TestResult {
    let directory = generated_minimal("module-manager-state-version")?;
    let state = ProjectState::parse(&fs::read_to_string(
        directory.path().join(".omnius/service.toml"),
    )?)?;

    assert_eq!(state.kit_version, KIT_VERSION);
    Ok(())
}
