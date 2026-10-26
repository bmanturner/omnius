use super::*;
use crate::{
    CargoGraph, CargoResolverMode, CargoResolverResult, KIT_VERSION,
    cargo_resolver::CargoResolverError,
    release::CANONICAL_REPOSITORY,
    upgrade::{TEST_LEGACY_VERSION, test_legacy_files},
};
use omnius_test_support::CleanDirectory;

struct LegacyCutoverResolver;

impl LockfileResolver for LegacyCutoverResolver {
    fn resolve(
        &self,
        request: &CargoResolverRequest,
    ) -> Result<CargoResolverResult, CargoResolverError> {
        if request.mode() != &CargoResolverMode::LegacyCutover {
            return Err(CargoResolverError::InvalidRequest(
                "schema-1 update did not request legacy cutover resolution".to_owned(),
            ));
        }
        for forbidden in [".sqlx", "specs", "templates", "xtask", "crates"] {
            if request.candidate_project().join(forbidden).exists() {
                return Err(CargoResolverError::InvalidRequest(format!(
                    "staged legacy cutover retained `{forbidden}`"
                )));
            }
        }
        Ok(CargoResolverResult::from_parts(
            b"version = 4\n\n# sealed legacy cutover lock\n".to_vec(),
            Some(CargoGraph::default()),
            CargoGraph::default(),
            None,
        ))
    }
}

fn materialize_legacy_project(root: &Path) -> Result<(), Box<dyn Error>> {
    for (relative, contents) in test_legacy_files() {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)?;
    }
    Ok(())
}

fn test_release_identity() -> Result<ReleaseIdentity, Box<dyn Error>> {
    Ok(ReleaseIdentity::new(
        KIT_VERSION,
        CANONICAL_REPOSITORY,
        "0000000000000000000000000000000000000001",
    )?)
}

#[test]
fn schema_one_fixture_updates_only_through_a_sealed_cutover() -> Result<(), Box<dyn Error>> {
    let directory = CleanDirectory::new("minimal-schema-one-cutover")?;
    materialize_legacy_project(directory.path())?;
    let application_path = directory.path().join("apps/service/src/application.rs");
    let migration_path = directory
        .path()
        .join("migrations/9000000000000000000_fixture.sql");
    let application_before = fs::read(&application_path)?;
    let migration_before = fs::read(&migration_path)?;
    let legacy_lock = fs::read(directory.path().join("Cargo.lock"))?;
    let catalog = ModuleCatalog::bundled()?;
    let identity = test_release_identity()?;
    let manager = ProjectManager::new(directory.path(), &identity, &catalog);

    let sealed = manager.seal_update_with(false, &LegacyCutoverResolver)?;
    assert_eq!(sealed.plan().action, PlanAction::Upgrade);
    assert!(sealed.resolution().is_some());
    let lock_index = sealed
        .plan()
        .operations
        .iter()
        .position(|operation| matches!(operation, PlanOperation::WriteResolvedLock { .. }))
        .ok_or("sealed cutover omitted resolved lock bytes")?;
    assert!(lock_index + 1 < sealed.plan().operations.len());
    assert!(matches!(
        sealed.plan().operations.last(),
        Some(PlanOperation::WriteState { .. })
    ));
    manager.apply(&sealed)?;

    assert_ne!(fs::read(directory.path().join("Cargo.lock"))?, legacy_lock);
    assert_eq!(fs::read(&application_path)?, application_before);
    assert_eq!(fs::read(&migration_path)?, migration_before);
    for forbidden in [".sqlx", "specs", "templates", "xtask", "crates"] {
        assert!(!directory.path().join(forbidden).exists(), "{forbidden}");
    }
    let state_source = fs::read_to_string(directory.path().join(PROJECT_STATE_PATH))?;
    let state = ProjectState::parse(&state_source)?;
    assert_eq!(state.framework, identity);
    assert_ne!(state.framework.version(), TEST_LEGACY_VERSION);
    assert!(!state_source.contains("retained_compose_volumes"));
    assert!(!directory.path().join("compose.yaml").exists());
    assert!(!directory.path().join("ops/compose.yaml").exists());
    assert!(
        state
            .ownership
            .iter()
            .all(|record| record.path != "compose.yaml" && record.path != "ops/compose.yaml")
    );

    let repeated = manager.seal_update_with(false, &LegacyCutoverResolver)?;
    assert!(repeated.is_empty());
    assert!(repeated.resolution().is_none());
    assert!(manager.doctor()?.healthy);
    Ok(())
}

#[test]
fn schema_one_fixture_leaves_existing_root_compose_untracked() -> Result<(), Box<dyn Error>> {
    let directory = CleanDirectory::new("schema-one-root-compose-preservation")?;
    materialize_legacy_project(directory.path())?;
    let compose_path = directory.path().join("compose.yaml");
    let compose_before = "# application-owned legacy topology\nservices: {}\n";
    fs::write(&compose_path, compose_before)?;
    let catalog = ModuleCatalog::bundled()?;
    let identity = test_release_identity()?;
    let manager = ProjectManager::new(directory.path(), &identity, &catalog);

    let sealed = manager.seal_update_with(false, &LegacyCutoverResolver)?;
    manager.apply(&sealed)?;

    assert_eq!(fs::read_to_string(&compose_path)?, compose_before);
    assert!(!directory.path().join("ops/compose.yaml").exists());
    let state = ProjectState::parse(&fs::read_to_string(
        directory.path().join(PROJECT_STATE_PATH),
    )?)?;
    assert!(
        state
            .ownership
            .iter()
            .all(|record| record.path != "compose.yaml" && record.path != "ops/compose.yaml")
    );
    assert!(manager.doctor()?.healthy);
    Ok(())
}

#[test]
fn schema_one_rejects_unknown_empty_forbidden_roots() -> Result<(), Box<dyn Error>> {
    let directory = CleanDirectory::new("schema-one-empty-forbidden-root")?;
    materialize_legacy_project(directory.path())?;
    fs::create_dir_all(directory.path().join("xtask"))?;
    let catalog = ModuleCatalog::bundled()?;
    let identity = test_release_identity()?;
    let manager = ProjectManager::new(directory.path(), &identity, &catalog);

    let error = manager
        .seal_update_with(false, &LegacyCutoverResolver)
        .err()
        .ok_or("unknown empty legacy directory must be rejected")?;

    assert!(error.to_string().contains("unknown directory `xtask`"));
    assert_eq!(
        toml::from_str::<toml::Value>(&fs::read_to_string(
            directory.path().join(PROJECT_STATE_PATH),
        )?)?["schema_version"]
            .as_integer(),
        Some(1),
    );
    Ok(())
}

#[test]
fn sdk_barrels_export_only_selected_adapters() -> Result<(), Box<dyn Error>> {
    let catalog = ModuleCatalog::bundled()?;
    let mut selected = ["web-auth", "web-llm", "web-react", "web-tenancy"]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();

    assert!(
        selected_derived_paths(&catalog, &selected)?
            .contains("packages/web-sdk/src/react/index.ts")
    );
    assert_eq!(
        render_react_index(&selected),
        concat!(
            "export * from \"./core.js\";\n",
            "export * from \"./auth.js\";\n",
            "export * from \"./capabilities.js\";\n",
            "export * from \"./tenant.js\";\n",
            "export * from \"./llm.js\";\n",
        )
    );

    selected.remove("web-tenancy");
    assert!(!render_react_index(&selected).contains("./tenant.js"));
    selected.remove("web-llm");
    assert!(!render_react_index(&selected).contains("./llm.js"));
    assert!(
        selected_derived_paths(&catalog, &selected)?
            .contains("packages/web-sdk/src/testing/index.ts")
    );
    assert_eq!(
        render_testing_index(&selected),
        "export * from \"./core.js\";\n"
    );
    selected.insert("web-realtime".to_owned());
    assert_eq!(
        render_testing_index(&selected),
        concat!(
            "export * from \"./core.js\";\n",
            "export * from \"./realtime.js\";\n",
        )
    );
    let realtime_only = ["web-realtime"]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert!(
        selected_derived_paths(&catalog, &realtime_only)?
            .contains("packages/web-sdk/src/testing/index.ts")
    );
    assert_eq!(
        render_testing_index(&realtime_only),
        "export * from \"./realtime.js\";\n"
    );
    Ok(())
}

#[test]
fn thin_candidate_rejects_untracked_omnius_crate_without_manifest() -> Result<(), Box<dyn Error>> {
    let directory = CleanDirectory::new("thin-unknown-omnius-crate")?;
    let source = directory.path().join("crates/omnius-extra/src/lib.rs");
    fs::create_dir_all(source.parent().ok_or("source path has no parent")?)?;
    fs::write(source, "pub const EXTRA: bool = true;\n")?;

    let Err(error) = ensure_thin_candidate_tree(directory.path()) else {
        return Err("untracked Omnius crate must be rejected".into());
    };
    assert!(error.to_string().contains("omnius-extra"));
    Ok(())
}
