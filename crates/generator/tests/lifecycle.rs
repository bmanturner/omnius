//! Sealed schema-2 lifecycle contracts driven by a deterministic Cargo resolver.

use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use omnius_generator::{
    CANONICAL_REPOSITORY, CargoGraph, CargoResolverError, CargoResolverMode, CargoResolverRequest,
    CargoResolverResult, KIT_VERSION, LockfileResolver, ModuleCatalog, OwnershipKind,
    PlanOperation, ProjectManager, ProjectState, ReleaseIdentity, RenderError, RenderRequest,
    render_project_with_resolver,
};
use omnius_test_support::CleanDirectory;
use sha2::{Digest, Sha256};

const FIRST_LOCK: &[u8] = b"version = 4\r\n\r\n# exact first lock\r\n";
const SECOND_LOCK: &[u8] = b"version = 4\n\n# exact second lock\n";

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
fn test_error<T, E>(result: Result<T, E>, message: &str) -> E {
    let Err(error) = result else {
        panic!("{message}");
    };
    error
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

#[derive(Clone, Debug)]
struct Observation {
    mode: CargoResolverMode,
    offline: bool,
    current: Option<PathBuf>,
    candidate: PathBuf,
    current_lock: Option<Vec<u8>>,
    candidate_lock: Option<Vec<u8>>,
    candidate_has_state: bool,
}

struct RecordingResolver {
    calls: AtomicUsize,
    lockfile: Vec<u8>,
    failure: Option<String>,
    observations: Mutex<Vec<Observation>>,
}

impl RecordingResolver {
    fn succeeds_with(lockfile: &[u8]) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            lockfile: lockfile.to_vec(),
            failure: None,
            observations: Mutex::new(Vec::new()),
        }
    }

    fn fails(message: &str) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            lockfile: Vec::new(),
            failure: Some(message.to_owned()),
            observations: Mutex::new(Vec::new()),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn observations(&self) -> Vec<Observation> {
        self.observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl LockfileResolver for RecordingResolver {
    fn resolve(
        &self,
        request: &CargoResolverRequest,
    ) -> Result<CargoResolverResult, CargoResolverError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let current_lock = request
            .current_project()
            .map(|root| fs::read(root.join("Cargo.lock")))
            .transpose()
            .map_err(|error| CargoResolverError::InvalidRequest(error.to_string()))?;
        let candidate_lock = fs::read(request.candidate_project().join("Cargo.lock")).ok();
        self.observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Observation {
                mode: request.mode().clone(),
                offline: request.offline(),
                current: request.current_project().map(Path::to_path_buf),
                candidate: request.candidate_project().to_path_buf(),
                current_lock,
                candidate_lock,
                candidate_has_state: request
                    .candidate_project()
                    .join(".omnius/service.toml")
                    .is_file(),
            });
        if let Some(message) = &self.failure {
            return Err(CargoResolverError::InvalidRequest(message.clone()));
        }
        Ok(CargoResolverResult::from_parts(
            self.lockfile.clone(),
            request.current_project().map(|_| CargoGraph::default()),
            CargoGraph::default(),
            None,
        ))
    }
}

fn identity() -> ReleaseIdentity {
    ReleaseIdentity::new(
        KIT_VERSION,
        CANONICAL_REPOSITORY,
        "0000000000000000000000000000000000000001",
    )
    .unwrap_or_else(|error| panic!("valid test release: {error}"))
}

fn nonexistent_destination(label: &str) -> TestResult<CleanDirectory> {
    let directory = CleanDirectory::new(label)?;
    fs::remove_dir(directory.path())?;
    Ok(directory)
}

fn render_minimal(label: &str, resolver: &RecordingResolver) -> TestResult<CleanDirectory> {
    let directory = nonexistent_destination(label)?;
    let release = identity();
    render_project_with_resolver(
        RenderRequest {
            service_name: "sealed-service",
            profile: "minimal",
            destination: directory.path(),
            release_identity: &release,
        },
        false,
        resolver,
    )?;
    Ok(directory)
}

fn lifecycle_stage_names(destination: &Path) -> TestResult<Vec<String>> {
    let parent = destination.parent().ok_or("destination has no parent")?;
    let destination_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("destination has no UTF-8 name")?;
    let prefix = format!(".{destination_name}.omnius-");
    let mut names = fs::read_dir(parent)?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with(&prefix))
        .collect::<Vec<_>>();
    names.sort();
    Ok(names)
}

#[test]
fn new_resolves_once_in_a_sibling_then_publishes_exact_lock_and_state_last() -> TestResult {
    let directory = nonexistent_destination("sealed-new")?;
    let release = identity();
    let resolver = RecordingResolver::succeeds_with(FIRST_LOCK);

    render_project_with_resolver(
        RenderRequest {
            service_name: "sealed-service",
            profile: "minimal",
            destination: directory.path(),
            release_identity: &release,
        },
        true,
        &resolver,
    )?;

    assert_eq!(resolver.call_count(), 1);
    let observations = resolver.observations();
    let observation = observations.first().ok_or("missing resolver observation")?;
    assert_eq!(observation.mode, CargoResolverMode::New);
    assert!(observation.current.is_none());
    assert!(observation.offline);
    assert!(observation.candidate_lock.is_none());
    assert_ne!(observation.candidate, directory.path());
    assert!(!observation.candidate_has_state);
    assert_eq!(fs::read(directory.path().join("Cargo.lock"))?, FIRST_LOCK);
    let state = ProjectState::parse(&fs::read_to_string(
        directory.path().join(".omnius/service.toml"),
    )?)?;
    assert_eq!(state.framework, release);
    let manifest = fs::read_to_string(directory.path().join("Cargo.toml"))?;
    assert!(manifest.contains(release.version()));
    assert!(manifest.contains(release.revision()));
    assert_eq!(
        state.ownership_of("Cargo.lock"),
        Some(OwnershipKind::DependencyLock)
    );
    assert_eq!(
        lifecycle_stage_names(directory.path())?,
        Vec::<String>::new()
    );
    Ok(())
}

#[test]
fn new_rejects_effective_cargo_source_overrides_before_resolution() -> TestResult {
    let parent = CleanDirectory::new("sealed-new-source-override")?;
    fs::create_dir(parent.path().join(".cargo"))?;
    fs::write(
        parent.path().join(".cargo/config.toml"),
        "paths = [\"vendor\"]\n",
    )?;
    let destination = parent.path().join("project");
    let release = identity();
    let resolver = RecordingResolver::fails("resolver must not run");

    let error = test_error(
        render_project_with_resolver(
            RenderRequest {
                service_name: "sealed-service",
                profile: "minimal",
                destination: &destination,
                release_identity: &release,
            },
            false,
            &resolver,
        ),
        "effective Cargo source overrides must block publication",
    );

    assert!(matches!(error, RenderError::Provenance(_)));
    assert_eq!(resolver.call_count(), 0);
    assert!(!destination.exists());
    assert_eq!(lifecycle_stage_names(&destination)?, Vec::<String>::new());
    Ok(())
}

#[test]
fn sealed_add_resolves_once_without_destination_writes_then_apply_is_journal_only() -> TestResult {
    let initial = RecordingResolver::succeeds_with(FIRST_LOCK);
    let directory = render_minimal("sealed-add", &initial)?;
    let release = identity();
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), &release, &catalog);
    let manifest_before = fs::read(directory.path().join("Cargo.toml"))?;
    let state_before = fs::read(directory.path().join(".omnius/service.toml"))?;
    let resolver = RecordingResolver::succeeds_with(SECOND_LOCK);

    let sealed = manager.seal_add_with("localization", true, &resolver)?;

    assert_eq!(resolver.call_count(), 1);
    assert_eq!(
        fs::read(directory.path().join("Cargo.toml"))?,
        manifest_before
    );
    assert_eq!(fs::read(directory.path().join("Cargo.lock"))?, FIRST_LOCK);
    assert_eq!(
        fs::read(directory.path().join(".omnius/service.toml"))?,
        state_before
    );
    let observation = resolver
        .observations()
        .into_iter()
        .next()
        .ok_or("missing resolver observation")?;
    assert_eq!(observation.mode, CargoResolverMode::UpdateLocked);
    assert!(observation.offline);
    assert_ne!(observation.current.as_deref(), Some(directory.path()));
    assert_ne!(observation.candidate, directory.path());
    assert_ne!(observation.current.as_ref(), Some(&observation.candidate));
    assert_eq!(observation.current_lock.as_deref(), Some(FIRST_LOCK));
    assert_eq!(observation.candidate_lock.as_deref(), Some(FIRST_LOCK));
    assert!(observation.candidate_has_state);
    let paths = sealed
        .plan()
        .operations
        .iter()
        .map(|operation| match operation {
            PlanOperation::CreateFile { path, .. }
            | PlanOperation::ReplaceKitFile { path, .. }
            | PlanOperation::ReconcileRegions { path, .. }
            | PlanOperation::RegenerateDerived { path, .. }
            | PlanOperation::RemoveFile { path, .. }
            | PlanOperation::WriteLock { path, .. }
            | PlanOperation::WriteResolvedLock { path, .. }
            | PlanOperation::WriteState { path, .. } => path.as_str(),
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.last().copied(), Some(".omnius/service.toml"));
    assert_eq!(paths.get(paths.len() - 2).copied(), Some("Cargo.lock"));

    let outcome = manager.apply(&sealed)?;
    assert_eq!(outcome.plan_id, sealed.plan().plan_id);
    assert_eq!(fs::read(directory.path().join("Cargo.lock"))?, SECOND_LOCK);
    let state = ProjectState::parse(&fs::read_to_string(
        directory.path().join(".omnius/service.toml"),
    )?)?;
    assert!(
        state
            .modules
            .iter()
            .any(|module| module.id == "localization")
    );
    assert!(!directory.path().join(".omnius/transaction.json").exists());

    let no_op_resolver = RecordingResolver::fails("must not resolve an idempotent plan");
    let no_op = manager.seal_add_with("localization", false, &no_op_resolver)?;
    assert!(no_op.is_empty());
    assert_eq!(no_op_resolver.call_count(), 0);
    manager.apply(&no_op)?;
    assert_eq!(fs::read(directory.path().join("Cargo.lock"))?, SECOND_LOCK);
    Ok(())
}

#[test]
fn sealed_remove_resolves_once_and_commits_lock_before_state() -> TestResult {
    let initial = RecordingResolver::succeeds_with(FIRST_LOCK);
    let directory = render_minimal("sealed-remove", &initial)?;
    let release = identity();
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), &release, &catalog);
    let add_resolver = RecordingResolver::succeeds_with(SECOND_LOCK);
    let add = manager.seal_add_with("localization", false, &add_resolver)?;
    manager.apply(&add)?;
    let remove_resolver = RecordingResolver::succeeds_with(FIRST_LOCK);

    let remove = manager.seal_remove_with("localization", false, &remove_resolver)?;

    assert_eq!(remove_resolver.call_count(), 1);
    let paths = remove
        .plan()
        .operations
        .iter()
        .map(|operation| match operation {
            PlanOperation::CreateFile { path, .. }
            | PlanOperation::ReplaceKitFile { path, .. }
            | PlanOperation::ReconcileRegions { path, .. }
            | PlanOperation::RegenerateDerived { path, .. }
            | PlanOperation::RemoveFile { path, .. }
            | PlanOperation::WriteLock { path, .. }
            | PlanOperation::WriteResolvedLock { path, .. }
            | PlanOperation::WriteState { path, .. } => path.as_str(),
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.last().copied(), Some(".omnius/service.toml"));
    assert_eq!(paths.get(paths.len() - 2).copied(), Some("Cargo.lock"));
    manager.apply(&remove)?;
    assert_eq!(fs::read(directory.path().join("Cargo.lock"))?, FIRST_LOCK);
    let state = ProjectState::parse(&fs::read_to_string(
        directory.path().join(".omnius/service.toml"),
    )?)?;
    assert!(
        !state
            .modules
            .iter()
            .any(|module| module.id == "localization")
    );
    Ok(())
}

#[test]
fn profile_set_replaces_selection_and_clears_explicit_changes() -> TestResult {
    let initial = RecordingResolver::succeeds_with(FIRST_LOCK);
    let directory = render_minimal("sealed-profile-set", &initial)?;
    let release = identity();
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), &release, &catalog);
    let resolver = RecordingResolver::succeeds_with(SECOND_LOCK);

    let sealed = manager.seal_profile_set_with("api", false, &resolver)?;
    assert_eq!(resolver.call_count(), 1);
    assert_eq!(
        sealed.plan().action,
        omnius_generator::PlanAction::ProfileSet
    );
    assert!(!sealed.plan().added_modules.is_empty());
    manager.apply(&sealed)?;

    let state = ProjectState::parse(&fs::read_to_string(
        directory.path().join(".omnius/service.toml"),
    )?)?;
    assert_eq!(state.profile.id, "api");
    assert!(state.profile.additions.is_empty());
    assert!(state.profile.removals.is_empty());
    assert_eq!(fs::read(directory.path().join("Cargo.lock"))?, SECOND_LOCK);
    Ok(())
}

#[test]
fn schema_two_update_refreshes_kit_owned_files_and_uses_precise_resolution() -> TestResult {
    let initial = RecordingResolver::succeeds_with(FIRST_LOCK);
    let directory = render_minimal("sealed-identity-update", &initial)?;
    let build_script_path = directory.path().join("apps/service/build.rs");
    let target_build_script = fs::read_to_string(&build_script_path)?;
    let historical_build_script =
        format!("{target_build_script}// historical release formatting\n");
    fs::write(&build_script_path, &historical_build_script)?;
    let state_path = directory.path().join(".omnius/service.toml");
    let mut historical_state = ProjectState::parse(&fs::read_to_string(&state_path)?)?;
    historical_state
        .ownership
        .iter_mut()
        .find(|record| record.path == "apps/service/build.rs")
        .ok_or("rendered state does not own apps/service/build.rs")?
        .approved_sha256 = Some(sha256(historical_build_script.as_bytes()));
    fs::write(&state_path, historical_state.to_toml()?)?;

    let target = ReleaseIdentity::new(
        KIT_VERSION,
        CANONICAL_REPOSITORY,
        "0000000000000000000000000000000000000002",
    )?;
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), &target, &catalog);
    let resolver = RecordingResolver::succeeds_with(SECOND_LOCK);

    let sealed = manager.seal_update_with(false, &resolver)?;
    assert_eq!(resolver.call_count(), 1);
    assert!(matches!(
        resolver.observations()[0].mode,
        CargoResolverMode::RevisionPrecise { .. }
    ));
    let replacement = sealed.plan().operations.iter().find_map(|operation| {
        let PlanOperation::ReplaceKitFile {
            path,
            expected_hash,
            content_hash,
            content,
        } = operation
        else {
            return None;
        };
        (path == "apps/service/build.rs").then_some((expected_hash, content_hash, content))
    });
    let Some((expected_hash, content_hash, content)) = replacement else {
        panic!(
            "revision update did not replace apps/service/build.rs: {:#?}",
            sealed.plan().operations
        );
    };
    assert_eq!(expected_hash, &sha256(historical_build_script.as_bytes()));
    assert_eq!(content_hash, &sha256(target_build_script.as_bytes()));
    assert_eq!(content, &target_build_script);
    assert!(
        !sealed
            .plan()
            .operations
            .iter()
            .any(|operation| matches!(operation, PlanOperation::RemoveFile { .. })),
        "same-version revision update removed current kit files: {:#?}",
        sealed.plan().operations
    );
    manager.apply(&sealed)?;

    let state = ProjectState::parse(&fs::read_to_string(&state_path)?)?;
    assert_eq!(state.framework, target);
    let manifest = fs::read_to_string(directory.path().join("Cargo.toml"))?;
    assert!(manifest.contains(target.revision()));
    assert_eq!(fs::read_to_string(build_script_path)?, target_build_script);
    assert_eq!(
        state
            .ownership
            .iter()
            .find(|record| record.path == "apps/service/build.rs")
            .and_then(|record| record.approved_sha256.as_deref()),
        Some(sha256(target_build_script.as_bytes()).as_str())
    );
    assert_eq!(fs::read(directory.path().join("Cargo.lock"))?, SECOND_LOCK);
    assert!(manager.doctor()?.healthy);
    assert!(manager.diff()?.is_empty());
    Ok(())
}

#[test]
fn schema_two_update_migrates_exact_legacy_sdk_barrels_to_derived_ownership() -> TestResult {
    const REACT_INDEX_PATH: &str = "packages/web-sdk/src/react/index.ts";
    const LEGACY_REACT_INDEX: &str = concat!(
        "export * from \"./core.js\";\n",
        "export * from \"./auth.js\";\n",
        "export * from \"./capabilities.js\";\n",
    );
    const TESTING_INDEX_PATH: &str = "packages/web-sdk/src/testing/index.ts";
    const LEGACY_TESTING_INDEX: &str = "export * from \"./core.js\";\n";

    let directory = nonexistent_destination("sealed-react-index-ownership-update")?;
    let source = identity();
    let initial = RecordingResolver::succeeds_with(FIRST_LOCK);
    render_project_with_resolver(
        RenderRequest {
            service_name: "sealed-web-service",
            profile: "full-reference-web",
            destination: directory.path(),
            release_identity: &source,
        },
        false,
        &initial,
    )?;
    let state_path = directory.path().join(".omnius/service.toml");
    let mut historical_state = ProjectState::parse(&fs::read_to_string(&state_path)?)?;
    for (path, content) in [
        (REACT_INDEX_PATH, LEGACY_REACT_INDEX),
        (TESTING_INDEX_PATH, LEGACY_TESTING_INDEX),
    ] {
        fs::write(directory.path().join(path), content)?;
        let ownership = historical_state
            .ownership
            .iter_mut()
            .find(|record| record.path == path)
            .ok_or("rendered state does not own an SDK barrel")?;
        ownership.kind = OwnershipKind::ApplicationOwned;
        ownership.approved_sha256 = None;
    }
    fs::write(&state_path, historical_state.to_toml()?)?;

    let target = ReleaseIdentity::new(
        KIT_VERSION,
        CANONICAL_REPOSITORY,
        "0000000000000000000000000000000000000002",
    )?;
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), &target, &catalog);
    let resolver = RecordingResolver::succeeds_with(SECOND_LOCK);
    let sealed = manager.seal_update_with(false, &resolver)?;
    assert!(sealed.plan().operations.iter().any(|operation| {
        matches!(
            operation,
            PlanOperation::RegenerateDerived { path, content, .. }
                if path == REACT_INDEX_PATH && content.contains("./tenant.js")
        )
    }));
    assert!(sealed.plan().operations.iter().any(|operation| {
        matches!(
            operation,
            PlanOperation::RegenerateDerived { path, content, .. }
                if path == TESTING_INDEX_PATH && content.contains("./realtime.js")
        )
    }));

    manager.apply(&sealed)?;
    let state = ProjectState::parse(&fs::read_to_string(&state_path)?)?;
    for path in [REACT_INDEX_PATH, TESTING_INDEX_PATH] {
        assert_eq!(state.ownership_of(path), Some(OwnershipKind::Derived));
    }
    assert!(fs::read_to_string(directory.path().join(REACT_INDEX_PATH))?.contains("./tenant.js"));
    assert!(
        fs::read_to_string(directory.path().join(TESTING_INDEX_PATH))?.contains("./realtime.js")
    );
    assert!(manager.doctor()?.healthy);
    assert!(manager.diff()?.is_empty());
    Ok(())
}
#[test]
fn schema_two_update_preserves_edited_application_owned_testing_barrel() -> TestResult {
    const TESTING_INDEX_PATH: &str = "packages/web-sdk/src/testing/index.ts";

    let directory = nonexistent_destination("edited-testing-index-ownership-update")?;
    let source = identity();
    render_project_with_resolver(
        RenderRequest {
            service_name: "sealed-web-service",
            profile: "full-reference-web",
            destination: directory.path(),
            release_identity: &source,
        },
        false,
        &RecordingResolver::succeeds_with(FIRST_LOCK),
    )?;
    fs::write(
        directory.path().join(TESTING_INDEX_PATH),
        concat!(
            "export * from \"./core.js\";\n",
            "export const applicationOwned = true;\n",
        ),
    )?;
    let state_path = directory.path().join(".omnius/service.toml");
    let mut state = ProjectState::parse(&fs::read_to_string(&state_path)?)?;
    let testing_ownership = state
        .ownership
        .iter_mut()
        .find(|record| record.path == TESTING_INDEX_PATH)
        .ok_or("rendered state does not own the testing barrel")?;
    testing_ownership.kind = OwnershipKind::ApplicationOwned;
    testing_ownership.approved_sha256 = None;
    fs::write(&state_path, state.to_toml()?)?;

    let target = ReleaseIdentity::new(
        KIT_VERSION,
        CANONICAL_REPOSITORY,
        "0000000000000000000000000000000000000002",
    )?;
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), &target, &catalog);
    let error = test_error(
        manager.seal_update_with(false, &RecordingResolver::succeeds_with(SECOND_LOCK)),
        "edited application-owned testing barrel unexpectedly migrated",
    );
    assert!(
        error.to_string().contains("derived-ownership-invalid"),
        "unexpected update error: {error}"
    );
    Ok(())
}

#[test]
fn web_static_add_and_remove_regenerate_the_derived_dockerfile() -> TestResult {
    let initial = RecordingResolver::succeeds_with(FIRST_LOCK);
    let directory = render_minimal("sealed-web-static-dockerfile", &initial)?;
    let release = identity();
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), &release, &catalog);
    let dockerfile_path = directory.path().join("ops/Dockerfile");
    let minimal_dockerfile = fs::read_to_string(&dockerfile_path)?;
    assert!(!minimal_dockerfile.contains("FROM node:"));

    let add_resolver = RecordingResolver::succeeds_with(SECOND_LOCK);
    let add = manager.seal_add_with("web-static", false, &add_resolver)?;
    assert!(add.plan().operations.iter().any(|operation| {
        matches!(
            operation,
            PlanOperation::RegenerateDerived { path, .. } if path == "ops/Dockerfile"
        )
    }));
    manager.apply(&add)?;
    assert!(fs::read_to_string(&dockerfile_path)?.contains("FROM node:"));
    let state = ProjectState::parse(&fs::read_to_string(
        directory.path().join(".omnius/service.toml"),
    )?)?;
    assert_eq!(
        state.ownership_of("ops/Dockerfile"),
        Some(OwnershipKind::Derived)
    );

    let remove_resolver = RecordingResolver::succeeds_with(FIRST_LOCK);
    let remove = manager.seal_remove_with("web-static", false, &remove_resolver)?;
    manager.apply(&remove)?;
    assert_eq!(fs::read_to_string(dockerfile_path)?, minimal_dockerfile);
    Ok(())
}

#[test]
fn seal_is_the_dry_run_and_leaves_destination_bytes_untouched() -> TestResult {
    let initial = RecordingResolver::succeeds_with(FIRST_LOCK);
    let directory = render_minimal("sealed-dry-run", &initial)?;
    let release = identity();
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), &release, &catalog);
    let manifest_before = fs::read(directory.path().join("Cargo.toml"))?;
    let lock_before = fs::read(directory.path().join("Cargo.lock"))?;
    let state_before = fs::read(directory.path().join(".omnius/service.toml"))?;
    let resolver = RecordingResolver::succeeds_with(SECOND_LOCK);

    let sealed = manager.seal_add_with("localization", false, &resolver)?;

    assert!(!sealed.is_empty());
    assert_eq!(resolver.call_count(), 1);
    assert_eq!(
        fs::read(directory.path().join("Cargo.toml"))?,
        manifest_before
    );
    assert_eq!(fs::read(directory.path().join("Cargo.lock"))?, lock_before);
    assert_eq!(
        fs::read(directory.path().join(".omnius/service.toml"))?,
        state_before
    );
    assert_eq!(
        lifecycle_stage_names(directory.path())?,
        Vec::<String>::new()
    );
    Ok(())
}

#[test]
fn stale_sealed_plan_fails_before_any_owned_write() -> TestResult {
    let initial = RecordingResolver::succeeds_with(FIRST_LOCK);
    let directory = render_minimal("sealed-stale", &initial)?;
    let release = identity();
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), &release, &catalog);
    let resolver = RecordingResolver::succeeds_with(SECOND_LOCK);
    let sealed = manager.seal_add_with("localization", false, &resolver)?;
    let manifest_before = fs::read(directory.path().join("Cargo.toml"))?;
    let lock_before = fs::read(directory.path().join("Cargo.lock"))?;
    let state_before = fs::read(directory.path().join(".omnius/service.toml"))?;
    fs::write(
        directory.path().join("README.md"),
        "stale application edit\n",
    )?;

    let error = test_error(manager.apply(&sealed), "stale plan must fail");

    assert!(error.to_string().contains("changed before apply"));
    assert_eq!(
        fs::read(directory.path().join("Cargo.toml"))?,
        manifest_before
    );
    assert_eq!(fs::read(directory.path().join("Cargo.lock"))?, lock_before);
    assert_eq!(
        fs::read(directory.path().join(".omnius/service.toml"))?,
        state_before
    );
    assert!(!directory.path().join(".omnius/transaction.json").exists());
    Ok(())
}

#[test]
fn resolver_failure_preserves_destination_and_cleans_owned_stages() -> TestResult {
    let initial = RecordingResolver::succeeds_with(FIRST_LOCK);
    let directory = render_minimal("sealed-resolver-failure", &initial)?;
    let release = identity();
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), &release, &catalog);
    let manifest_before = fs::read(directory.path().join("Cargo.toml"))?;
    let lock_before = fs::read(directory.path().join("Cargo.lock"))?;
    let state_before = fs::read(directory.path().join(".omnius/service.toml"))?;
    let resolver = RecordingResolver::fails("injected resolver failure");

    let error = test_error(
        manager.seal_add_with("localization", false, &resolver),
        "resolver failure must abort sealing",
    );

    assert!(error.to_string().contains("injected resolver failure"));
    assert_eq!(resolver.call_count(), 1);
    assert_eq!(
        fs::read(directory.path().join("Cargo.toml"))?,
        manifest_before
    );
    assert_eq!(fs::read(directory.path().join("Cargo.lock"))?, lock_before);
    assert_eq!(
        fs::read(directory.path().join(".omnius/service.toml"))?,
        state_before
    );
    assert_eq!(
        lifecycle_stage_names(directory.path())?,
        Vec::<String>::new()
    );
    Ok(())
}

#[test]
fn new_failure_and_existing_destinations_never_publish_or_call_cargo_unnecessarily() -> TestResult {
    let release = identity();
    let failed_destination = nonexistent_destination("sealed-new-failure")?;
    let failing = RecordingResolver::fails("new resolution failed");
    let error = test_error(
        render_project_with_resolver(
            RenderRequest {
                service_name: "sealed-service",
                profile: "minimal",
                destination: failed_destination.path(),
                release_identity: &release,
            },
            false,
            &failing,
        ),
        "new resolver failure must abort publication",
    );
    assert!(error.to_string().contains("new resolution failed"));
    assert_eq!(failing.call_count(), 1);
    assert!(!failed_destination.path().exists());
    assert_eq!(
        lifecycle_stage_names(failed_destination.path())?,
        Vec::<String>::new()
    );

    let empty = CleanDirectory::new("sealed-existing-empty")?;
    let never = RecordingResolver::fails("must not be called");
    let result = render_project_with_resolver(
        RenderRequest {
            service_name: "sealed-service",
            profile: "minimal",
            destination: empty.path(),
            release_identity: &release,
        },
        false,
        &never,
    );
    assert!(matches!(result, Err(RenderError::DestinationExists(_))));
    assert_eq!(never.call_count(), 0);

    fs::write(empty.path().join("application.txt"), "preserve\n")?;
    let result = render_project_with_resolver(
        RenderRequest {
            service_name: "sealed-service",
            profile: "minimal",
            destination: empty.path(),
            release_identity: &release,
        },
        false,
        &never,
    );
    assert!(matches!(result, Err(RenderError::DestinationExists(_))));
    assert_eq!(
        fs::read_to_string(empty.path().join("application.txt"))?,
        "preserve\n"
    );
    assert_eq!(never.call_count(), 0);
    Ok(())
}

#[test]
fn existing_schema_two_mutation_requires_a_committed_dependency_lock() -> TestResult {
    let initial = RecordingResolver::succeeds_with(FIRST_LOCK);
    let directory = render_minimal("sealed-missing-lock", &initial)?;
    fs::remove_file(directory.path().join("Cargo.lock"))?;
    let release = identity();
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), &release, &catalog);
    let resolver = RecordingResolver::fails("must not resolve without a committed lock");

    let error = test_error(
        manager.seal_add_with("localization", false, &resolver),
        "missing committed lock must block mutation",
    );

    assert!(
        error
            .to_string()
            .contains("requires a committed Cargo.lock")
    );
    assert_eq!(resolver.call_count(), 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn existing_project_staging_rejects_symlinks_without_mutation() -> TestResult {
    use std::os::unix::fs::symlink;

    let initial = RecordingResolver::succeeds_with(FIRST_LOCK);
    let directory = render_minimal("sealed-symlink", &initial)?;
    symlink("README.md", directory.path().join("application-link"))?;
    let release = identity();
    let catalog = ModuleCatalog::bundled()?;
    let manager = ProjectManager::new(directory.path(), &release, &catalog);
    let lock_before = fs::read(directory.path().join("Cargo.lock"))?;
    let resolver = RecordingResolver::fails("must not resolve a symlinked project");

    let error = test_error(
        manager.seal_add_with("localization", false, &resolver),
        "symlink must block byte-copy staging",
    );

    assert!(error.to_string().contains("refuses symlink"));
    assert_eq!(resolver.call_count(), 0);
    assert_eq!(fs::read(directory.path().join("Cargo.lock"))?, lock_before);
    assert_eq!(
        lifecycle_stage_names(directory.path())?,
        Vec::<String>::new()
    );
    Ok(())
}
