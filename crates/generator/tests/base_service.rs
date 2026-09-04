//! Base profile catalog, deterministic rendering, and generated-service contracts.

use std::{
    collections::BTreeSet,
    error::Error,
    ffi::OsString,
    fs,
    io::{self, Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::LazyLock,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use omnius_generator::{
    ApplicationRequirement, CANONICAL_REPOSITORY, CargoGraph, CargoResolverError,
    CargoResolverRequest, CargoResolverResult, KIT_VERSION, LockfileResolver, ModuleCatalog,
    OwnershipKind, OwnershipRecord, PROJECT_STATE_PATH, PROJECT_STATE_SCHEMA_VERSION,
    ProfileCatalog, ProfileDefinition, ProjectManager, ProjectState, ReleaseBuildStatus,
    ReleaseIdentity, RenderError, RenderOutcome, RenderRequest, bundled_profile_catalog,
    render_project_with_resolver, resolve_profile,
};
use omnius_test_support::{ProfileCommand, ProfileGenerationHarness};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PROFILE_SOURCE: &str = include_str!("../../../specs/machine/profiles.yaml");
const WEB_PROFILE_SOURCE: &str =
    include_str!("../../../specs/machine/extensions/web-application-suite/profiles.yaml");
const AI_PROFILE_SOURCE: &str =
    include_str!("../../../specs/machine/extensions/llm-mcp-suite/profiles.yaml");
const MODULE_SOURCE: &str = include_str!("../../../specs/machine/module-catalog.yaml");
const WEB_MODULE_SOURCE: &str =
    include_str!("../../../specs/machine/extensions/web-application-suite/module-catalog.yaml");
const AI_MODULE_SOURCE: &str =
    include_str!("../../../specs/machine/extensions/llm-mcp-suite/module-catalog.yaml");
const MODULE_SCHEMA_SOURCE: &str =
    include_str!("../../../specs/machine/module-manifest.schema.json");
const MINIMAL_SNAPSHOT: &str = include_str!("snapshots/minimal-profile-info.json");
const AUTHENTICATED_SNAPSHOT: &str = include_str!("snapshots/authenticated-api-profile-info.json");

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
static TEST_RELEASE_IDENTITY: LazyLock<ReleaseIdentity> = LazyLock::new(|| {
    let status = ReleaseBuildStatus::current()
        .unwrap_or_else(|error| panic!("valid test release binding: {error}"));
    let revision = status
        .revision()
        .unwrap_or("0000000000000000000000000000000000000001");
    ReleaseIdentity::new(KIT_VERSION, CANONICAL_REPOSITORY, revision)
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
            sha256_hex(&manifest)
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

#[derive(Deserialize)]
struct CatalogDocument {
    bundle_version: String,
    profiles: Vec<CatalogProfile>,
}

#[derive(Deserialize)]
struct ExtensionCatalogDocument {
    extension_version: String,
    base_bundle_version: String,
    #[serde(default)]
    web_extension_version: Option<String>,
    profiles: Vec<CatalogProfile>,
}

fn assert_error<T, E>(result: Result<T, E>) -> E {
    let Err(error) = result else {
        panic!("expected operation to fail");
    };
    error
}

#[derive(Deserialize)]
struct CatalogProfile {
    id: String,
    description: String,
    extends: Option<String>,
    modules: Vec<String>,
}

#[derive(Deserialize)]
struct ModuleCatalogDocument {
    modules: Vec<CatalogModule>,
}

#[derive(Deserialize)]
struct CatalogModule {
    id: String,
    composition: CatalogComposition,
}

#[derive(Deserialize)]
struct CatalogComposition {
    crates: Vec<CatalogCompositionCrate>,
    registrar: bool,
    application_requirements: Vec<ApplicationRequirement>,
}

#[derive(Deserialize)]
struct CatalogCompositionCrate {
    dependency: String,
    features: Vec<String>,
}

#[derive(Deserialize)]
struct ServiceState {
    service: String,
    framework: ReleaseIdentity,
    profile: ProfileState,
    modules: Vec<ModuleState>,
}

#[derive(Deserialize)]
struct ProfileState {
    id: String,
}

#[derive(Deserialize)]
struct ModuleState {
    id: String,
    version: String,
}

#[derive(Serialize)]
struct ProfileInfoSnapshot<'a> {
    service: &'a str,
    framework_version: &'a str,
    profile: &'a str,
    modules: Vec<&'a str>,
}

#[test]
fn typed_profile_manifest_matches_authoritative_catalogs() -> TestResult {
    let source: CatalogDocument = serde_yaml::from_str(PROFILE_SOURCE)?;
    let mut web: ExtensionCatalogDocument = serde_yaml::from_str(WEB_PROFILE_SOURCE)?;
    let mut ai: ExtensionCatalogDocument = serde_yaml::from_str(AI_PROFILE_SOURCE)?;
    web.profiles.sort_by(|left, right| left.id.cmp(&right.id));
    ai.profiles.sort_by(|left, right| left.id.cmp(&right.id));
    let catalog = bundled_profile_catalog()?;
    assert_eq!(source.bundle_version, KIT_VERSION);
    assert_eq!(web.base_bundle_version, KIT_VERSION);
    assert_eq!(ai.base_bundle_version, KIT_VERSION);
    assert_eq!(
        ai.web_extension_version.as_deref(),
        Some(web.extension_version.as_str())
    );
    assert_eq!(source.profiles.len(), 10);
    assert_eq!(web.profiles.len(), 5);
    assert_eq!(ai.profiles.len(), 8);
    let expected = source
        .profiles
        .iter()
        .chain(&web.profiles)
        .chain(&ai.profiles);
    for (source, typed) in expected.zip(catalog.profiles()) {
        assert_eq!(source.id, typed.id);
        assert_eq!(source.description, typed.description);
        assert_eq!(source.extends, typed.extends);
        assert_eq!(source.modules, typed.modules);
    }
    assert_eq!(catalog.profiles().len(), 23);
    Ok(())
}

#[test]
fn typed_module_manifest_matches_authoritative_catalogs() -> TestResult {
    let source: ModuleCatalogDocument = serde_yaml::from_str(MODULE_SOURCE)?;
    let mut web: ModuleCatalogDocument = serde_yaml::from_str(WEB_MODULE_SOURCE)?;
    let mut ai: ModuleCatalogDocument = serde_yaml::from_str(AI_MODULE_SOURCE)?;
    web.modules.sort_by(|left, right| left.id.cmp(&right.id));
    ai.modules.sort_by(|left, right| left.id.cmp(&right.id));
    let catalog = ModuleCatalog::bundled()?;
    let expected_count = source.modules.len() + web.modules.len() + ai.modules.len();
    let expected = source.modules.iter().chain(&web.modules).chain(&ai.modules);
    for (source, typed) in expected.zip(&catalog.modules) {
        assert_eq!(source.id, typed.id);
        assert_eq!(source.composition.registrar, typed.composition.registrar);
        assert_eq!(
            source.composition.application_requirements,
            typed.composition.application_requirements
        );
        assert_eq!(
            source
                .composition
                .crates
                .iter()
                .map(|value| (value.dependency.as_str(), value.features.as_slice()))
                .collect::<Vec<_>>(),
            typed
                .composition
                .crates
                .iter()
                .map(|value| (value.dependency.as_str(), value.features.as_slice()))
                .collect::<Vec<_>>()
        );
    }
    assert_eq!(catalog.modules.len(), expected_count);
    Ok(())
}
#[test]
fn module_schema_requirements_match_the_runtime_enum() -> TestResult {
    let schema: serde_json::Value = serde_json::from_str(MODULE_SCHEMA_SOURCE)?;
    let schema_values = schema
        .pointer("/properties/composition/properties/application_requirements/items/enum")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| io::Error::other("application requirement schema enum is missing"))?;
    let schema_ids = schema_values
        .iter()
        .map(|value| {
            value.as_str().ok_or_else(|| {
                io::Error::other("application requirement schema ID is not a string")
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let runtime_ids = ApplicationRequirement::ALL
        .iter()
        .map(ApplicationRequirement::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(schema_ids.len(), schema_values.len());

    assert_eq!(schema_ids, runtime_ids);
    Ok(())
}

#[test]
fn all_profiles_resolve_unique_modules_in_catalog_order() -> TestResult {
    let catalog = bundled_profile_catalog()?;
    assert_eq!(catalog.profiles().len(), 23);
    for definition in catalog.profiles() {
        let resolved = resolve_profile(&definition.id)?;
        assert_eq!(resolved.definition(), definition);
        for (index, module) in resolved.modules().iter().enumerate() {
            assert!(!resolved.modules()[..index].contains(module));
        }
    }
    assert_eq!(resolve_profile("minimal")?.modules().len(), 7);
    assert_eq!(resolve_profile("full-reference")?.modules().len(), 50);
    Ok(())
}

fn assert_manager_clean(root: &Path, profile_id: &str, modules: &ModuleCatalog) -> TestResult {
    let manager = ProjectManager::new(root, test_release_identity(), modules);
    let doctor = manager.doctor()?;
    assert!(
        doctor.healthy,
        "{profile_id} doctor diagnostics: {:?}",
        doctor.diagnostics
    );
    let diff = manager.diff()?;
    assert!(
        diff.is_empty(),
        "{profile_id} fresh diff operations: {:?}",
        diff.operations
    );
    Ok(())
}

fn assert_fresh_schema_two_state(root: &Path) -> TestResult {
    let state_source = fs::read_to_string(root.join(PROJECT_STATE_PATH))?;
    let state = ProjectState::parse(&state_source)?;
    assert_eq!(PROJECT_STATE_SCHEMA_VERSION, 2);
    assert_eq!(state.schema_version, 2);
    assert_eq!(state.to_toml()?, state_source);
    assert_eq!(&state.framework, test_release_identity());
    assert!(
        state
            .ownership
            .iter()
            .all(|record| record.path != PROJECT_STATE_PATH)
    );
    assert_eq!(
        state.ownership_of("Cargo.lock"),
        Some(OwnershipKind::DependencyLock)
    );
    assert!(
        state
            .ownership
            .iter()
            .find(|record| record.path == "Cargo.lock")
            .is_some_and(|record| record.approved_sha256.is_none())
    );
    assert_eq!(
        state
            .managed_regions
            .iter()
            .map(|record| format!("{}#{}", record.path, record.id))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "Cargo.toml#framework-dependency".to_owned(),
            "apps/service/src/composition.rs#modules".to_owned(),
        ])
    );
    assert!(root.join("Cargo.lock").is_file());
    for record in &state.ownership {
        let path = root.join(&record.path);
        assert!(
            fs::symlink_metadata(&path)?.file_type().is_file(),
            "owned path is not a regular file: {}",
            record.path
        );
        match record.kind {
            OwnershipKind::KitOwned | OwnershipKind::Derived => {
                assert_eq!(
                    record.approved_sha256.as_deref(),
                    Some(sha256_hex(&fs::read(path)?).as_str()),
                    "approved hash differs for {}",
                    record.path
                );
            }
            OwnershipKind::ApplicationOwned | OwnershipKind::DependencyLock => {
                assert_eq!(
                    record.approved_sha256, None,
                    "non-generator-owned path has an approved hash: {}",
                    record.path
                );
            }
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
fn assert_web_profile_templates(
    root: &Path,
    profile_id: &str,
    selected: &BTreeSet<String>,
) -> TestResult {
    let react_index_path = root.join("packages/web-sdk/src/react/index.ts");
    if selected.contains("web-react") {
        let react_index = fs::read_to_string(&react_index_path)?;
        for (module, export) in [
            ("web-react", "core"),
            ("web-auth", "auth"),
            ("web-realtime", "realtime"),
            ("web-forms", "forms"),
            ("web-local-state", "local-state"),
            ("web-react", "capabilities"),
            ("web-tenancy", "tenant"),
            ("web-uploads", "uploads"),
            ("web-llm", "llm"),
        ] {
            assert_eq!(
                react_index.contains(&format!("export * from \"./{export}.js\";")),
                selected.contains(module),
                "fresh {profile_id} profile emitted the wrong React `{export}` export"
            );
        }
    } else {
        assert!(
            !react_index_path.exists(),
            "fresh {profile_id} profile emitted an inactive React barrel"
        );
    }
    for path in [
        "packages/web-sdk/src/llm/index.ts",
        "packages/web-sdk/src/llm/stream.ts",
        "packages/web-sdk/src/llm/types.ts",
        "packages/web-sdk/src/react/llm.ts",
        "packages/web-sdk/test/llm-stream.test.ts",
    ] {
        assert_eq!(
            root.join(path).exists(),
            selected.contains("web-llm"),
            "fresh {profile_id} profile emitted the wrong web-llm template inventory at `{path}`"
        );
    }
    Ok(())
}

fn assert_fresh_profile_render(
    definition: &ProfileDefinition,
    modules: &ModuleCatalog,
) -> TestResult {
    let harness = ProfileGenerationHarness::new(&definition.id)?;
    let service_name = format!("clean-{}", definition.id);
    render_test_project(RenderRequest {
        service_name: &service_name,
        profile: &definition.id,
        destination: harness.root(),
        release_identity: test_release_identity(),
    })?;
    let root_manifest: toml::Value =
        toml::from_str(&fs::read_to_string(harness.root().join("Cargo.toml"))?)?;
    assert_eq!(
        root_manifest["workspace"]["members"],
        toml::Value::Array(vec![toml::Value::String("apps/service".to_owned())])
    );
    let dependency = &root_manifest["workspace"]["dependencies"]["service-kit"];
    let expected_version = format!("={KIT_VERSION}");
    assert_eq!(dependency["package"].as_str(), Some("omnius-service-kit"));
    assert_eq!(
        dependency["version"].as_str(),
        Some(expected_version.as_str())
    );
    assert_eq!(
        dependency["git"].as_str(),
        Some(test_release_identity().repository())
    );
    assert_eq!(
        dependency["rev"].as_str(),
        Some(test_release_identity().revision())
    );
    let selected = resolve_profile(&definition.id)?
        .modules()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_features = modules
        .composition_order(&selected)?
        .into_iter()
        .map(|module| toml::Value::String(module.id.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        dependency["features"],
        toml::Value::Array(expected_features)
    );
    let app_manifest = fs::read_to_string(harness.root().join("apps/service/Cargo.toml"))?;
    assert!(app_manifest.contains("service-kit.workspace = true"));
    assert!(app_manifest.contains("features = [\"test-support\"]"));
    assert_web_profile_templates(harness.root(), &definition.id, &selected)?;
    for relative_path in ["config/profile.toml", "ops/profile.toml"] {
        let profile = fs::read(harness.root().join(relative_path))?;
        assert!(
            profile.ends_with(b"\n") && !profile.ends_with(b"\n\n"),
            "fresh {} profile rendered trailing blank line in {relative_path}",
            definition.id
        );
    }
    for forbidden in ["crates", ".sqlx", "specs", "templates"] {
        assert!(
            !harness.root().join(forbidden).exists(),
            "fresh {} profile copied forbidden `{forbidden}`",
            definition.id
        );
    }
    assert_fresh_schema_two_state(harness.root())?;
    assert_manager_clean(harness.root(), &definition.id, modules)
}

#[test]
fn fresh_profiles_are_thin_and_manager_clean() -> TestResult {
    let modules = ModuleCatalog::bundled()?;
    for definition in bundled_profile_catalog()?.profiles() {
        assert_fresh_profile_render(definition, &modules)?;
    }
    Ok(())
}

#[test]
fn profile_selection_changes_only_service_kit_features() -> TestResult {
    let minimal = ProfileGenerationHarness::new("minimal-artifacts")?;
    let api = ProfileGenerationHarness::new("api-artifacts")?;
    for (root, service, profile) in [
        (minimal.root(), "minimal-artifacts", "minimal"),
        (api.root(), "api-artifacts", "api"),
    ] {
        render_test_project(RenderRequest {
            service_name: service,
            profile,
            destination: root,
            release_identity: test_release_identity(),
        })?;
        assert!(!root.join("crates").exists());
    }
    assert_ne!(
        fs::read_to_string(minimal.root().join("Cargo.toml"))?,
        fs::read_to_string(api.root().join("Cargo.toml"))?
    );
    Ok(())
}

#[test]
fn rejects_invalid_base_inheritance() -> TestResult {
    let modules = ModuleCatalog::from_yaml(MODULE_SOURCE)?;
    let broken = PROFILE_SOURCE.replacen("  extends: minimal", "  extends: absent-profile", 1);
    let error = assert_error(ProfileCatalog::from_yaml(&broken, &modules));
    assert!(error.to_string().contains("extends unknown profile"));
    Ok(())
}

#[test]
fn rejects_missing_explicit_provider_slot() {
    let broken = MODULE_SOURCE.replacen("  provider_slot: null\n", "", 1);
    let error = assert_error(ModuleCatalog::from_yaml(&broken));
    assert!(
        error
            .to_string()
            .contains("explicitly declare provider_slot")
    );
}

#[test]
fn rejects_invalid_service_names_and_unknown_profiles() -> TestResult {
    let harness = ProfileGenerationHarness::new("minimal")?;
    let invalid_name = render_test_project(RenderRequest {
        service_name: "Not Canonical",
        profile: "minimal",
        destination: harness.root(),
        release_identity: test_release_identity(),
    });
    assert!(matches!(invalid_name, Err(RenderError::InvalidServiceName)));

    let unknown = render_test_project(RenderRequest {
        service_name: "unknown-profile-service",
        profile: "unknown",
        destination: harness.root(),
        release_identity: test_release_identity(),
    });
    assert!(matches!(unknown, Err(RenderError::Profile(_))));
    Ok(())
}

#[test]
fn minimal_render_publishes_once_and_refuses_an_existing_destination() -> TestResult {
    let harness = ProfileGenerationHarness::new("minimal")?;
    let outcome = render_test_project(RenderRequest {
        service_name: "minimal-service",
        profile: "minimal",
        destination: harness.root(),
        release_identity: test_release_identity(),
    })?;
    assert!(outcome.files > 1);
    fs::write(
        harness.root().join("apps/service/src/application.rs"),
        "// application-owned edit\n",
    )?;
    fs::write(harness.root().join("notes.txt"), "application data\n")?;

    let rerender = render_test_project(RenderRequest {
        service_name: "minimal-service",
        profile: "minimal",
        destination: harness.root(),
        release_identity: test_release_identity(),
    });
    assert!(matches!(rerender, Err(RenderError::DestinationExists(_))));
    assert_eq!(
        fs::read_to_string(harness.root().join("apps/service/src/application.rs"))?,
        "// application-owned edit\n"
    );
    assert_omnius_generated_contract(harness.root())?;
    assert_eq!(state_snapshot(harness.root())?, MINIMAL_SNAPSHOT);
    Ok(())
}

#[test]
fn existing_destination_preserves_recorded_application_owned_files_and_state() -> TestResult {
    let harness = ProfileGenerationHarness::new("application-owned-rerender")?;
    let created = render_test_project(RenderRequest {
        service_name: "application-owned-service",
        profile: "api",
        destination: harness.root(),
        release_identity: test_release_identity(),
    })?;
    assert!(created.files > 1);
    let state_path = harness.root().join(".omnius/service.toml");
    let canonical = ProjectState::parse(&fs::read_to_string(&state_path)?)?;
    let application_files = [
        (
            "migrations/9000000000000000000_application.sql",
            "-- application migration\n",
        ),
        (
            "migrations/application-compatibility.toml",
            "schema_version = 1\nminimum = \"9000000000000000000\"\nmaximum = \"9000000000000000000\"\n",
        ),
    ];
    for (path, contents) in application_files {
        let absolute = harness.root().join(path);
        fs::create_dir_all(absolute.parent().ok_or("application file has no parent")?)?;
        fs::write(absolute, contents)?;
    }
    let mut expected = canonical;
    expected
        .ownership
        .extend(application_files.map(|(path, _)| OwnershipRecord {
            path: path.to_owned(),
            kind: OwnershipKind::ApplicationOwned,
            approved_sha256: None,
        }));
    expected.ownership.sort();
    fs::write(&state_path, expected.to_toml()?)?;

    let outcome = render_test_project(RenderRequest {
        service_name: "application-owned-service",
        profile: "api",
        destination: harness.root(),
        release_identity: test_release_identity(),
    });
    assert!(matches!(outcome, Err(RenderError::DestinationExists(_))));
    assert_eq!(
        ProjectState::parse(&fs::read_to_string(state_path)?)?,
        expected
    );
    for (path, contents) in application_files {
        assert_eq!(fs::read_to_string(harness.root().join(path))?, contents);
    }
    Ok(())
}

#[test]
fn authenticated_api_render_matches_resolved_profile_snapshot() -> TestResult {
    let harness = ProfileGenerationHarness::new("authenticated-api")?;
    render_test_project(RenderRequest {
        service_name: "authenticated-service",
        profile: "authenticated-api",
        destination: harness.root(),
        release_identity: test_release_identity(),
    })?;
    assert_eq!(state_snapshot(harness.root())?, AUTHENTICATED_SNAPSHOT);
    Ok(())
}

fn assert_generated_base_configuration(root: &Path) -> TestResult {
    let base_source = fs::read_to_string(root.join("config/base.toml"))?;
    let base: toml::Value = toml::from_str(&base_source)?;
    let base_tables = base
        .as_table()
        .ok_or_else(|| io::Error::other("base configuration must be a TOML table"))?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        base_tables,
        BTreeSet::from(["application_rate_limit", "health", "http", "server"])
    );
    Ok(())
}

fn assert_generated_reference_configuration(
    root: &Path,
    service_name: &str,
    persisted: bool,
) -> TestResult {
    let reference_source = fs::read_to_string(root.join("config/reference.toml"))?;
    assert!(!reference_source.contains("${"));
    assert!(!reference_source.contains("{{"));
    assert!(!reference_source.contains("postgres://"));
    assert!(!reference_source.contains("cursor_signing_key ="));
    let reference: toml::Value = toml::from_str(&reference_source)?;
    assert_eq!(
        reference["telemetry"]["service"].as_str(),
        Some(service_name)
    );
    assert_eq!(
        reference["telemetry"]["environment"].as_str(),
        Some("development")
    );
    assert_eq!(reference.get("postgres").is_some(), persisted);
    assert!(reference.get("pagination").is_none());
    if persisted {
        assert!(reference["postgres"].get("url").is_none());
        assert_eq!(
            reference["postgres"]["max_connections"].as_integer(),
            Some(16)
        );
        assert_eq!(
            reference["migrations"]["run_on_startup"].as_bool(),
            Some(true)
        );
        assert_eq!(reference["postgres"]["health_timeout"].as_str(), Some("5s"));
        assert_eq!(
            reference["postgres"]["health_timeout"],
            reference["postgres"]["acquire_timeout"]
        );
        assert_eq!(reference["idempotency"]["ttl"].as_str(), Some("24h"));
        assert_eq!(
            reference["openapi"]["max_document_bytes"].as_integer(),
            Some(4_194_304)
        );
        assert_eq!(
            reference["outbound_http"]["url_policy"]["allowed_https_ports"]
                .as_array()
                .and_then(|ports| ports.first())
                .and_then(toml::Value::as_integer),
            Some(443)
        );
    }
    Ok(())
}

fn assert_generated_source_contracts(root: &Path) -> TestResult {
    let main = fs::read_to_string(root.join("apps/service/src/main.rs"))?;
    assert!(main.contains(r#"default_value = "config/reference.toml""#));
    assert!(main.contains("persisted_reference_overlay_enforces_and_redacts_database_secret"));
    assert!(main.contains("cfg(not(selected_postgres))"));
    assert!(main.contains("cfg(selected_migrations)"));
    assert_eq!(main.matches("service::schema_compatibility()").count(), 2);
    let build = fs::read_to_string(root.join("apps/service/build.rs"))?;
    assert!(build.contains(r#"("postgres", "selected_postgres")"#));
    assert!(build.contains(r#"("idempotency", "selected_idempotency")"#));
    assert!(build.contains("cargo::rustc-check-cfg=cfg({cfg})"));
    assert!(build.contains("cargo::rustc-cfg={cfg}"));
    assert!(build.contains("cargo::rerun-if-changed={APPLICATION_MIGRATIONS_PATH}"));
    assert!(build.contains("cargo::rustc-env=OMNIUS_APPLICATION_SCHEMA_MINIMUM="));
    assert!(build.contains("cargo::rustc-env=OMNIUS_APPLICATION_SCHEMA_MAXIMUM="));
    let library = fs::read_to_string(root.join("apps/service/src/lib.rs"))?;
    assert!(library.contains("pub const fn application_migrations()"));
    assert!(library.contains("pub async fn prepared_migrations()"));
    assert!(!root.join("crates").exists());
    Ok(())
}

fn assert_generated_container_contracts(root: &Path) -> TestResult {
    let dockerfile = fs::read_to_string(root.join("ops/Dockerfile"))?;
    for required in [
        "WORKDIR /app",
        "apt-get install --yes --no-install-recommends libssl3",
        "COPY --from=build /workspace/config /app/config",
        "ENV OMNIUS__SERVER__LISTEN_ADDRESS=0.0.0.0:3000",
        r#"["service", "healthcheck", "--address", "127.0.0.1:3000"]"#,
    ] {
        assert!(dockerfile.contains(required));
    }
    Ok(())
}

fn assert_generated_compose_contracts(root: &Path, persisted: bool) -> TestResult {
    let compose = fs::read_to_string(root.join("ops/compose.yaml"))?;
    let topology: serde_yaml::Value = serde_yaml::from_str(&compose)?;
    let services = topology["services"]
        .as_mapping()
        .ok_or_else(|| io::Error::other("Compose services must be a mapping"))?;
    assert_eq!(services.len(), if persisted { 3 } else { 1 });
    assert!(services.contains_key(serde_yaml::Value::String("app".to_owned())));
    assert_eq!(
        topology["services"]["app"]["ports"][0].as_str(),
        Some("127.0.0.1:3000:3000")
    );
    assert_eq!(
        topology["services"]["app"]["environment"]["OMNIUS__SERVER__LISTEN_ADDRESS"].as_str(),
        Some("0.0.0.0:3000")
    );
    assert!(!compose.contains("OMNIUS_BIND"));
    assert!(!compose.contains("OMNIUS_HEALTH_ADDRESS"));
    if persisted {
        assert_eq!(
            topology["services"]["app"]["environment"]["OMNIUS__MIGRATIONS__RUN_ON_STARTUP"]
                .as_str(),
            Some("false")
        );
        assert_eq!(
            topology["services"]["app"]["depends_on"]["postgres"]["condition"].as_str(),
            Some("service_healthy")
        );
        assert_eq!(
            topology["services"]["app"]["depends_on"]["migrate"]["condition"].as_str(),
            Some("service_completed_successfully")
        );
        assert_eq!(
            topology["services"]["migrate"]["command"][0].as_str(),
            Some("migrate")
        );
        assert_eq!(
            topology["services"]["migrate"]["depends_on"]["postgres"]["condition"].as_str(),
            Some("service_healthy")
        );
        assert_eq!(
            topology["services"]["postgres"]["image"].as_str(),
            Some(
                "postgres@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94"
            )
        );
        assert_eq!(
            topology["services"]["app"]["environment"]["OMNIUS__POSTGRES__URL"].as_str(),
            Some("postgres://omnius:omnius-development-only@postgres:5432/omnius")
        );
        assert!(
            topology["services"]["app"]["environment"]
                .get("OMNIUS__PAGINATION__CURSOR_SIGNING_KEY")
                .is_none()
        );
        assert!(topology["volumes"].get("postgres-data").is_some());
        assert_eq!(compose.matches("command: [\"migrate\"]").count(), 1);
    } else {
        assert!(topology.get("volumes").is_none());
        assert!(!compose.contains("postgres:"));
        assert!(!compose.contains("migrate:"));
    }
    Ok(())
}

fn assert_catalog_environment_bindings(catalog: &ModuleCatalog) {
    let postgres_url = catalog
        .module("postgres")
        .and_then(|module| {
            module
                .configuration
                .fields
                .iter()
                .find(|field| field.path == "postgres.url")
        })
        .and_then(|field| field.environment.as_deref());
    assert_eq!(postgres_url, Some("OMNIUS__POSTGRES__URL"));
    let Some(idempotency) = catalog.module("idempotency") else {
        panic!("bundled catalog must include idempotency");
    };
    assert!(
        idempotency
            .configuration
            .fields
            .iter()
            .all(|field| field.path != "pagination.cursor_signing_key")
    );
}

#[test]
fn generated_reference_configuration_and_container_contracts_are_executable() -> TestResult {
    let catalog = ModuleCatalog::bundled()?;
    for (profile, service_name, persisted) in [
        ("minimal", "config-minimal", false),
        ("api", "config-persisted", true),
    ] {
        let harness = ProfileGenerationHarness::new(profile)?;
        render_test_project(RenderRequest {
            service_name,
            profile,
            destination: harness.root(),
            release_identity: test_release_identity(),
        })?;

        assert_generated_base_configuration(harness.root())?;
        assert_generated_reference_configuration(harness.root(), service_name, persisted)?;
        assert_generated_source_contracts(harness.root())?;
        assert_generated_container_contracts(harness.root())?;
        assert_generated_compose_contracts(harness.root(), persisted)?;
    }
    assert_catalog_environment_bindings(&catalog);
    Ok(())
}

#[test]
fn advanced_runtime_dependencies_fail_closed_without_substitute_services() -> TestResult {
    let harness = ProfileGenerationHarness::new("realtime-durable")?;
    render_test_project(RenderRequest {
        service_name: "external-runtime",
        profile: "realtime-durable",
        destination: harness.root(),
        release_identity: test_release_identity(),
    })?;
    let compose = fs::read_to_string(harness.root().join("ops/compose.yaml"))?;
    let topology: serde_yaml::Value = serde_yaml::from_str(&compose)?;
    let services = topology["services"]
        .as_mapping()
        .ok_or_else(|| io::Error::other("Compose services must be a mapping"))?;
    assert_eq!(services.len(), 3);
    assert!(services.contains_key(serde_yaml::Value::String("app".to_owned())));
    assert!(services.contains_key(serde_yaml::Value::String("migrate".to_owned())));
    assert!(services.contains_key(serde_yaml::Value::String("postgres".to_owned())));
    assert!(!services.contains_key(serde_yaml::Value::String("nats".to_owned())));
    assert_eq!(
        topology["services"]["app"]["environment"]["OMNIUS__NATS__URL"].as_str(),
        Some("${OMNIUS__NATS__URL:?set the NATS JetStream endpoint}")
    );
    assert_eq!(
        topology["services"]["app"]["environment"]["OMNIUS__NATS__CREDENTIALS"].as_str(),
        Some("${OMNIUS__NATS__CREDENTIALS:?set the NATS credentials}")
    );
    let module_docs = fs::read_to_string(harness.root().join("docs/module-catalog.md"))?;
    assert!(module_docs.contains("External (no generated container)"));
    assert!(module_docs.contains("`OMNIUS__NATS__URL`"));
    Ok(())
}

struct ComposeSmokeGuard {
    root: PathBuf,
    project: String,
    armed: bool,
}

impl ComposeSmokeGuard {
    fn new(root: &Path) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self {
            root: root.to_path_buf(),
            project: format!("omnius-generator-smoke-{}-{nonce}", std::process::id()),
            armed: true,
        }
    }

    fn output(&self, arguments: &[&str]) -> io::Result<Output> {
        let mut command = Command::new("docker");
        command
            .args([
                "compose",
                "--project-name",
                &self.project,
                "-f",
                "ops/compose.yaml",
            ])
            .args(arguments)
            .current_dir(&self.root);
        command.output()
    }

    fn run(&self, operation: &str, arguments: &[&str]) -> TestResult<Output> {
        let output = self.output(arguments)?;
        require_success(operation, &output)?;
        Ok(output)
    }
    fn run_up(&self, operation: &str, arguments: &[&str]) -> TestResult<Output> {
        let output = self.output(arguments)?;
        if output.status.success() {
            return Ok(output);
        }
        let logs = self.output(&["logs", "--no-color"])?;
        let message = format!(
            "{operation} failed\nstdout tail:\n{}\nstderr tail:\n{}\nservice logs stdout tail:\n{}\nservice logs stderr tail:\n{}",
            output_tail(&output.stdout),
            output_tail(&output.stderr),
            output_tail(&logs.stdout),
            output_tail(&logs.stderr)
        );
        eprintln!("{message}");
        Err(io::Error::other(message).into())
    }

    fn remove(&mut self) -> TestResult {
        self.run(
            "docker compose down with volumes and local images",
            &["down", "--volumes", "--rmi", "local", "--remove-orphans"],
        )?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for ComposeSmokeGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.output(&["down", "--volumes", "--rmi", "local", "--remove-orphans"]);
        }
    }
}

struct SmokeHttpResponse {
    status: u16,
    body: String,
}

fn smoke_http_request(
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> TestResult<SmokeHttpResponse> {
    let address: SocketAddr = "127.0.0.1:3000".parse()?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:3000\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes())?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes)?;
    let boundary = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("HTTP response has no header boundary"))?;
    let header_bytes = &bytes[..boundary];
    let header = std::str::from_utf8(header_bytes)?;
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| io::Error::other("HTTP response has no status"))?
        .parse()?;
    let raw_body = &bytes[boundary + 4..];
    let decoded;
    let body_bytes = if header
        .lines()
        .any(|line| line.eq_ignore_ascii_case("transfer-encoding: chunked"))
    {
        decoded = decode_chunked_body(raw_body)?;
        decoded.as_slice()
    } else {
        raw_body
    };
    Ok(SmokeHttpResponse {
        status,
        body: String::from_utf8(body_bytes.to_vec())?,
    })
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>, io::Error> {
    let mut cursor = 0;
    let mut decoded = Vec::new();
    loop {
        let line_end = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|offset| cursor + offset)
            .ok_or_else(|| io::Error::other("chunked response has no size terminator"))?;
        let size_text = std::str::from_utf8(&body[cursor..line_end])
            .map_err(io::Error::other)?
            .split(';')
            .next()
            .unwrap_or_default();
        let size = usize::from_str_radix(size_text, 16).map_err(io::Error::other)?;
        cursor = line_end + 2;
        if size == 0 {
            return Ok(decoded);
        }
        let data_end = cursor
            .checked_add(size)
            .ok_or_else(|| io::Error::other("chunk size overflow"))?;
        if body.get(data_end..data_end + 2) != Some(b"\r\n") {
            return Err(io::Error::other("chunked response is truncated"));
        }
        decoded.extend_from_slice(&body[cursor..data_end]);
        cursor = data_end + 2;
    }
}

fn wait_for_generated_ready(timeout: Duration) -> TestResult {
    let deadline = Instant::now() + timeout;
    let mut last_failure = String::from("no request attempted");
    while Instant::now() < deadline {
        match smoke_http_request("GET", "/ready", &[], "") {
            Ok(response) if response.status == 200 => return Ok(()),
            Ok(response) => last_failure = format!("HTTP {}", response.status),
            Err(error) => last_failure = error.to_string(),
        }
        thread::sleep(Duration::from_millis(250));
    }
    Err(io::Error::other(format!(
        "generated service did not become ready before timeout: {last_failure}"
    ))
    .into())
}

fn compose_migration_status(compose: &ComposeSmokeGuard) -> TestResult<serde_json::Value> {
    let output = compose.run(
        "docker compose migration-status",
        &["run", "--rm", "--no-deps", "app", "migration-status"],
    )?;
    let stdout = String::from_utf8(output.stdout)?;
    let document = stdout
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .ok_or_else(|| io::Error::other("migration-status emitted no JSON document"))?;
    Ok(serde_json::from_str(document)?)
}

#[test]
#[ignore = "requires a Docker daemon and the opt-in generated-runtime smoke environment"]
fn generated_route_less_compose_survives_restart_with_stable_migrations() -> TestResult {
    let harness = ProfileGenerationHarness::new("docker-compose-smoke")?;
    render_test_project(RenderRequest {
        service_name: "docker-compose-smoke",
        profile: "api",
        destination: harness.root(),
        release_identity: test_release_identity(),
    })?;
    let mut compose = ComposeSmokeGuard::new(harness.root());

    compose.run("docker compose config", &["config"])?;
    compose.run_up("docker compose up --build", &["up", "--build", "--detach"])?;
    wait_for_generated_ready(Duration::from_secs(120))?;

    for path in ["/example", "/reference-records"] {
        let response = smoke_http_request("GET", path, &[], "")?;
        assert_eq!(
            response.status, 404,
            "fresh generated application unexpectedly exposed {path}: {}",
            response.body
        );
    }

    let migration_before = compose_migration_status(&compose)?;
    assert_eq!(
        migration_before["current_version"],
        migration_before["target_version"]
    );
    for clean_field in [
        "pending_versions",
        "unknown_versions",
        "checksum_mismatches",
        "history_gaps",
    ] {
        assert_eq!(migration_before[clean_field], serde_json::json!([]));
    }
    assert!(migration_before["dirty_version"].is_null());

    compose.run(
        "docker compose down retaining volumes",
        &["down", "--remove-orphans"],
    )?;
    compose.run_up("docker compose restart", &["up", "--detach"])?;
    wait_for_generated_ready(Duration::from_secs(120))?;

    for path in ["/example", "/reference-records"] {
        let response = smoke_http_request("GET", path, &[], "")?;
        assert_eq!(
            response.status, 404,
            "restarted generated application unexpectedly exposed {path}: {}",
            response.body
        );
    }
    let migration_after = compose_migration_status(&compose)?;
    assert_eq!(migration_after, migration_before);

    compose.remove()?;
    Ok(())
}

#[test]
fn refuses_nonempty_unmanaged_destinations_and_preserves_application_manifest() -> TestResult {
    let unmanaged = ProfileGenerationHarness::new("minimal")?;
    fs::write(unmanaged.root().join("owned.txt"), "keep\n")?;
    let result = render_test_project(RenderRequest {
        service_name: "safe-service",
        profile: "minimal",
        destination: unmanaged.root(),
        release_identity: test_release_identity(),
    });
    assert!(matches!(result, Err(RenderError::DestinationExists(_))));
    assert_eq!(
        fs::read_to_string(unmanaged.root().join("owned.txt"))?,
        "keep\n"
    );

    let managed = ProfileGenerationHarness::new("minimal")?;
    render_test_project(RenderRequest {
        service_name: "safe-service",
        profile: "minimal",
        destination: managed.root(),
        release_identity: test_release_identity(),
    })?;
    fs::write(managed.root().join("Cargo.toml"), "application edit\n")?;
    let result = render_test_project(RenderRequest {
        service_name: "safe-service",
        profile: "minimal",
        destination: managed.root(),
        release_identity: test_release_identity(),
    });
    assert!(matches!(result, Err(RenderError::DestinationExists(_))));
    assert_eq!(
        fs::read_to_string(managed.root().join("Cargo.toml"))?,
        "application edit\n"
    );
    Ok(())
}

#[test]
fn state_parser_rejects_duplicate_and_unsafe_application_ownership_records() -> TestResult {
    let harness = ProfileGenerationHarness::new("invalid-application-ownership")?;
    render_test_project(RenderRequest {
        service_name: "safe-service",
        profile: "minimal",
        destination: harness.root(),
        release_identity: test_release_identity(),
    })?;
    let canonical = fs::read_to_string(harness.root().join(".omnius/service.toml"))?;
    let duplicate = format!(
        "{canonical}\n[[ownership]]\npath = \"Cargo.toml\"\nkind = \"kit-owned\"\napproved_sha256 = \"{}\"\n",
        "0".repeat(64)
    );
    assert!(ProjectState::parse(&duplicate).is_err());
    let unsafe_path = format!(
        "{canonical}\n[[ownership]]\npath = \"../outside.sql\"\nkind = \"application-owned\"\n"
    );
    assert!(ProjectState::parse(&unsafe_path).is_err());
    Ok(())
}

#[test]
fn schema_two_rejects_invalid_ownership_hashes_self_ownership_and_unknown_fields() -> TestResult {
    let harness = ProfileGenerationHarness::new("invalid-schema-two-state")?;
    render_test_project(RenderRequest {
        service_name: "safe-service",
        profile: "minimal",
        destination: harness.root(),
        release_identity: test_release_identity(),
    })?;
    let state_source = fs::read_to_string(harness.root().join(PROJECT_STATE_PATH))?;
    let canonical = ProjectState::parse(&state_source)?;

    let mut missing_generator_hash = canonical.clone();
    missing_generator_hash
        .ownership
        .iter_mut()
        .find(|record| record.kind == OwnershipKind::KitOwned)
        .ok_or("fresh state has no kit-owned record")?
        .approved_sha256 = None;
    assert!(missing_generator_hash.to_toml().is_err());

    let mut malformed_generator_hash = canonical.clone();
    malformed_generator_hash
        .ownership
        .iter_mut()
        .find(|record| record.kind == OwnershipKind::Derived)
        .ok_or("fresh state has no derived record")?
        .approved_sha256 = Some("g".repeat(64));
    assert!(malformed_generator_hash.to_toml().is_err());

    let mut application_hash = canonical.clone();
    application_hash
        .ownership
        .iter_mut()
        .find(|record| record.kind == OwnershipKind::ApplicationOwned)
        .ok_or("fresh state has no application-owned record")?
        .approved_sha256 = Some("0".repeat(64));
    assert!(application_hash.to_toml().is_err());

    let mut dependency_lock_hash = canonical.clone();
    dependency_lock_hash
        .ownership
        .iter_mut()
        .find(|record| record.kind == OwnershipKind::DependencyLock)
        .ok_or("fresh state has no dependency-lock record")?
        .approved_sha256 = Some("0".repeat(64));
    assert!(dependency_lock_hash.to_toml().is_err());

    let mut self_owned = canonical;
    self_owned.ownership.push(OwnershipRecord {
        path: PROJECT_STATE_PATH.to_owned(),
        kind: OwnershipKind::ApplicationOwned,
        approved_sha256: None,
    });
    assert!(self_owned.to_toml().is_err());

    let unknown_framework_field =
        state_source.replacen("[framework]\n", "[framework]\nunknown = true\n", 1);
    let Err(error) = ProjectState::parse(&unknown_framework_field) else {
        panic!("unknown framework identity field must be rejected");
    };
    assert!(error.to_string().contains("unknown field"));
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One generated build lifecycle covers the strict input matrix.
async fn application_schema_compatibility_build_input_is_strict() -> TestResult {
    const SERVICE: &str = "compatibility-service";
    const APPLICATION_MINIMUM: &str = "9000000000000000000";
    const APPLICATION_MAXIMUM: &str = "9099999999999999999";

    let canonical = ProfileGenerationHarness::new("application-schema-compatibility")?;
    render_test_project(RenderRequest {
        service_name: SERVICE,
        profile: "api",
        destination: canonical.root(),
        release_identity: test_release_identity(),
    })?;
    assert_manager_clean(canonical.root(), "api", &ModuleCatalog::bundled()?)?;
    let harness = clone_generated_project(canonical.root(), "application-schema-compile")?;
    patch_service_kit_for_compile(harness.root())?;
    let output = cargo_command(&harness)
        .arg("generate-lockfile")
        .timeout(Duration::from_secs(600))
        .output()
        .await?;
    require_success("cargo generate-lockfile", &output)?;
    let compatibility_path = harness
        .root()
        .join("migrations/application-compatibility.toml");

    let output = cargo_command(&harness)
        .arg("run")
        .arg("--locked")
        .arg("--quiet")
        .arg("--package")
        .arg(SERVICE)
        .arg("--")
        .arg("profile-info")
        .timeout(Duration::from_secs(600))
        .output()
        .await?;
    require_success("profile-info without application compatibility", &output)?;
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"]["minimum"], "2026082301");
    assert_eq!(document["schema"]["maximum"], "2026082809");

    fs::create_dir_all(
        compatibility_path
            .parent()
            .ok_or("application compatibility path must have a parent")?,
    )?;
    let migration_path = harness
        .root()
        .join("migrations/9000000000000000000_application.sql");
    fs::write(&migration_path, "-- application migration\n")?;
    fs::write(
        &compatibility_path,
        format!(
            "schema_version = 1\nminimum = \"{APPLICATION_MINIMUM}\"\nmaximum = \"{APPLICATION_MAXIMUM}\"\n"
        ),
    )?;
    let output = cargo_command(&harness)
        .arg("run")
        .arg("--locked")
        .arg("--quiet")
        .arg("--package")
        .arg(SERVICE)
        .arg("--")
        .arg("profile-info")
        .timeout(Duration::from_secs(600))
        .output()
        .await?;
    require_success("profile-info with application compatibility", &output)?;
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"]["minimum"], APPLICATION_MINIMUM);
    assert_eq!(document["schema"]["maximum"], APPLICATION_MAXIMUM);

    for (case, source, expected_error) in [
        (
            "unsupported schema version",
            "schema_version = 2\nminimum = \"9000000000000000000\"\nmaximum = \"9000000000000000000\"\n",
            "schema_version must be 1",
        ),
        (
            "unquoted integer",
            "schema_version = 1\nminimum = 9000000000000000000\nmaximum = \"9000000000000000000\"\n",
            "minimum",
        ),
        (
            "noninteger string",
            "schema_version = 1\nminimum = \"version-one\"\nmaximum = \"9000000000000000000\"\n",
            "quoted positive integer string",
        ),
        (
            "nonpositive version",
            "schema_version = 1\nminimum = \"0\"\nmaximum = \"9000000000000000000\"\n",
            "reserved application migration range",
        ),
        (
            "reversed range",
            "schema_version = 1\nminimum = \"9000000000000000001\"\nmaximum = \"9000000000000000000\"\n",
            "maximum must be greater than or equal to minimum",
        ),
        (
            "version below reserved range",
            "schema_version = 1\nminimum = \"8999999999999999999\"\nmaximum = \"9000000000000000000\"\n",
            "reserved application migration range",
        ),
        (
            "version above reserved range",
            "schema_version = 1\nminimum = \"9000000000000000000\"\nmaximum = \"9100000000000000000\"\n",
            "reserved application migration range",
        ),
        (
            "unknown field",
            "schema_version = 1\nminimum = \"9000000000000000000\"\nmaximum = \"9000000000000000000\"\nextra = true\n",
            "unknown field",
        ),
        (
            "missing field",
            "schema_version = 1\nminimum = \"9000000000000000000\"\n",
            "missing field",
        ),
    ] {
        fs::write(&compatibility_path, source)?;
        let output = cargo_command(&harness)
            .arg("check")
            .arg("--locked")
            .arg("--package")
            .arg(SERVICE)
            .timeout(Duration::from_secs(600))
            .output()
            .await?;
        assert!(
            !output.status.success(),
            "{case} unexpectedly passed generated build validation"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected_error),
            "{case} did not report {expected_error:?}\nstderr tail:\n{}",
            output_tail(&output.stderr)
        );
    }

    fs::remove_file(&compatibility_path)?;
    fs::remove_file(&migration_path)?;
    let output = cargo_command(&harness)
        .arg("run")
        .arg("--locked")
        .arg("--quiet")
        .arg("--package")
        .arg(SERVICE)
        .arg("--")
        .arg("profile-info")
        .timeout(Duration::from_secs(600))
        .output()
        .await?;
    require_success(
        "profile-info after removing application compatibility",
        &output,
    )?;
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"]["minimum"], "2026082301");
    assert_eq!(document["schema"]["maximum"], "2026082809");
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Compile and metadata checks share one generated-root lifecycle.
async fn generated_reference_roots_compile_and_report_selected_profiles() -> TestResult {
    for (profile, service_name) in [
        ("minimal", "compile-minimal"),
        ("api", "compile-api"),
        ("authenticated-api", "compile-authenticated"),
        ("oauth-provider", "compile-oauth-provider"),
        ("web", "compile-web"),
    ] {
        let canonical = ProfileGenerationHarness::new(profile)?;
        render_test_project(RenderRequest {
            service_name,
            profile,
            destination: canonical.root(),
            release_identity: test_release_identity(),
        })?;
        if profile == "web" {
            assert_no_reference_scaffold(canonical.root())?;
        }
        assert_manager_clean(canonical.root(), profile, &ModuleCatalog::bundled()?)?;
        let harness = clone_generated_project(canonical.root(), &format!("{profile}-compile"))?;
        patch_service_kit_for_compile(harness.root())?;
        let output = cargo_command(&harness)
            .arg("generate-lockfile")
            .timeout(Duration::from_secs(600))
            .output()
            .await?;
        require_success("cargo generate-lockfile", &output)?;

        let output = cargo_command(&harness)
            .arg("check")
            .arg("--locked")
            .arg("--workspace")
            .arg("--all-targets")
            .timeout(Duration::from_secs(600))
            .output()
            .await?;
        require_success("cargo check --workspace --all-targets", &output)?;

        if matches!(profile, "minimal" | "api") {
            let output = cargo_command(&harness)
                .arg("nextest")
                .arg("run")
                .arg("--locked")
                .arg("--package")
                .arg(service_name)
                .timeout(Duration::from_secs(600))
                .output()
                .await?;
            require_success("cargo nextest run", &output)?;
        }

        let output = cargo_command(&harness)
            .arg("test")
            .arg("--locked")
            .arg("--doc")
            .arg("--workspace")
            .timeout(Duration::from_secs(600))
            .output()
            .await?;
        require_success("cargo test --doc", &output)?;

        let output = cargo_command(&harness)
            .arg("run")
            .arg("--locked")
            .arg("--quiet")
            .arg("--package")
            .arg(service_name)
            .arg("--")
            .arg("profile-info")
            .timeout(Duration::from_secs(600))
            .output()
            .await?;
        require_success("profile-info", &output)?;
        let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let expected = resolve_profile(profile)?;
        assert_eq!(document["service"], service_name);
        assert_eq!(document["profile"], profile);
        assert_eq!(document["modules"], serde_json::json!(expected.modules()));
        assert_eq!(
            document["providers"],
            serde_json::json!(expected.providers())
        );
        let schema = if expected
            .modules()
            .iter()
            .any(|module| module == "migrations")
        {
            serde_json::json!({
                "minimum": "2026082301",
                "maximum": "2026082809",
            })
        } else {
            serde_json::json!({
                "minimum": "none",
                "maximum": "none",
            })
        };
        assert_eq!(document["schema"], schema);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = vec![0_u8; 1024];
            let _ = stream.read(&mut request).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await?;
            Ok::<_, io::Error>(())
        });
        let output = cargo_command(&harness)
            .arg("run")
            .arg("--locked")
            .arg("--quiet")
            .arg("--package")
            .arg(service_name)
            .arg("--")
            .arg("healthcheck")
            .arg("--address")
            .arg(address.to_string())
            .timeout(Duration::from_secs(600))
            .output()
            .await?;
        require_success("healthcheck", &output)?;
        responder.await??;

        if profile == "minimal" {
            let output = cargo_command(&harness)
                .arg("run")
                .arg("--locked")
                .arg("--quiet")
                .arg("--package")
                .arg(service_name)
                .arg("--")
                .arg("migrate")
                .timeout(Duration::from_secs(600))
                .output()
                .await?;
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains(&format!(
                "command `migrate` is unavailable for profile `{profile}`"
            )));
        }
    }
    Ok(())
}

fn state_snapshot(root: &Path) -> TestResult<String> {
    let state = read_service_state(root)?;
    assert_eq!(&state.framework, test_release_identity());
    assert!(
        state
            .modules
            .iter()
            .all(|module| !module.version.is_empty())
    );
    let snapshot = ProfileInfoSnapshot {
        service: &state.service,
        framework_version: state.framework.version(),
        profile: &state.profile.id,
        modules: state
            .modules
            .iter()
            .map(|module| module.id.as_str())
            .collect(),
    };
    Ok(format!("{}\n", serde_json::to_string_pretty(&snapshot)?))
}

fn read_service_state(root: &Path) -> TestResult<ServiceState> {
    Ok(toml::from_str(&fs::read_to_string(
        root.join(".omnius/service.toml"),
    )?)?)
}

fn assert_omnius_generated_contract(root: &Path) -> TestResult {
    let state_path = root.join(".omnius/service.toml");
    assert!(state_path.is_file(), "missing {}", state_path.display());

    let legacy_stem = ["r", "s", "k"].concat();
    let legacy_path = format!(".{legacy_stem}");
    assert!(
        !root.join(&legacy_path).exists(),
        "fresh tree contains legacy state directory"
    );

    let mut pending = vec![root.to_path_buf()];
    let mut legacy_bind_paths = Vec::new();
    let mut tree = String::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
            continue;
        }
        let relative = path.strip_prefix(root)?;
        let contents = fs::read_to_string(&path)?;
        if contents.contains("OMNIUS_BIND") && !relative.starts_with("crates/generator/tests") {
            legacy_bind_paths.push(relative.to_path_buf());
        }
        tree.push_str(&relative.to_string_lossy());
        tree.push('\n');
        tree.push_str(&contents);
        tree.push('\n');
    }

    assert!(!tree.contains("path = \".omnius/service.toml\""));
    assert!(tree.contains("omnius:managed-begin"));
    assert!(tree.contains("omnius:managed-end"));
    assert!(tree.contains("OMNIUS__SERVER__LISTEN_ADDRESS"));
    assert!(
        legacy_bind_paths.is_empty(),
        "fresh tree contains OMNIUS_BIND in {legacy_bind_paths:?}"
    );
    assert!(
        !tree.contains(&legacy_path),
        "fresh tree names a legacy path"
    );
    assert!(
        !tree.contains(&format!("{legacy_stem}:managed-")),
        "fresh tree contains legacy managed markers"
    );
    assert!(
        !tree.contains(&format!("{}_", legacy_stem.to_ascii_uppercase())),
        "fresh tree contains a legacy runtime environment variable"
    );
    Ok(())
}
fn assert_no_reference_scaffold(root: &Path) -> TestResult {
    let mut pending = ["contracts", "packages/web-sdk", "web"]
        .into_iter()
        .map(|path| root.join(path))
        .collect::<Vec<_>>();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        for forbidden in [
            "/reference-records",
            "ReferenceRecord",
            "reference-records-route",
        ] {
            assert!(
                !contents.contains(forbidden),
                "fresh web scaffold contains `{forbidden}` in {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn clone_generated_project(source: &Path, profile: &str) -> TestResult<ProfileGenerationHarness> {
    let clone = ProfileGenerationHarness::new(profile)?;
    copy_generated_tree(source, clone.root())?;
    Ok(clone)
}

fn copy_generated_tree(source: &Path, destination: &Path) -> TestResult {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.is_dir() {
            fs::create_dir(&destination_path)?;
            copy_generated_tree(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &destination_path)?;
        } else {
            return Err(io::Error::other(format!(
                "generated compile clone refuses non-file path {}",
                source_path.display()
            ))
            .into());
        }
    }
    Ok(())
}

fn patch_service_kit_for_compile(root: &Path) -> TestResult {
    let service_kit = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../service-kit")
        .canonicalize()?;
    let path = service_kit
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let manifest_path = root.join("Cargo.toml");
    let mut manifest = fs::OpenOptions::new().append(true).open(&manifest_path)?;
    writeln!(
        manifest,
        "\n[patch.\"{CANONICAL_REPOSITORY}\"]\nomnius-service-kit = {{ path = \"{path}\" }}"
    )?;
    Ok(())
}

fn cargo_command(harness: &ProfileGenerationHarness) -> ProfileCommand<'_> {
    let mut command = harness.command(env!("CARGO"));
    for key in [
        "PATH",
        "HOME",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "SSL_CERT_FILE",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "CARGO_NET_OFFLINE",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command = command.env(key, value);
        }
    }
    let target = std::env::temp_dir().join("omnius-generated-profile-tests");
    command
        .env("CARGO_TARGET_DIR", target.as_os_str())
        .env("CARGO_TERM_COLOR", "never")
}

fn output_tail(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.lines().rev().take(80).collect::<Vec<_>>();
    lines.reverse();
    lines.join("\n")
}

fn require_success(operation: &str, output: &std::process::Output) -> Result<(), io::Error> {
    if output.status.success() {
        return Ok(());
    }
    let mut message = OsString::from(operation);
    message.push(" failed\nstdout tail:\n");
    message.push(output_tail(&output.stdout));
    message.push("\nstderr tail:\n");
    message.push(output_tail(&output.stderr));
    let message = message.to_string_lossy().into_owned();
    eprintln!("{message}");
    Err(io::Error::other(message))
}
