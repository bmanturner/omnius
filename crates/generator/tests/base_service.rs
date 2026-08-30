//! Base profile catalog, deterministic rendering, and generated-service contracts.

use std::{
    collections::BTreeSet,
    error::Error,
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};

use omnius_generator::{
    KIT_VERSION, ModuleCatalog, ProfileCatalog, ProfileDefinition, ProjectManager, RenderError,
    RenderOutcome, RenderRequest, bundled_profile_catalog, render_project, resolve_profile,
};
use omnius_test_support::{ProfileCommand, ProfileGenerationHarness};
use serde::{Deserialize, Serialize};

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
const TEMPLATE_CONFIG: &str = include_str!("../../../templates/base-service/cargo-generate.toml");
const MINIMAL_SNAPSHOT: &str = include_str!("snapshots/minimal-profile-info.json");
const AUTHENTICATED_SNAPSHOT: &str = include_str!("snapshots/authenticated-api-profile-info.json");

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

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
}

#[derive(Deserialize)]
struct ServiceState {
    service: String,
    kit_version: String,
    profile: ProfileState,
    modules: Vec<ModuleState>,
    providers: Vec<ProviderState>,
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

#[derive(Deserialize)]
struct ProviderState {
    slot: String,
    module: String,
}
fn ai_profile_ids() -> TestResult<BTreeSet<String>> {
    let ai: ExtensionCatalogDocument = serde_yaml::from_str(AI_PROFILE_SOURCE)?;
    Ok(ai.profiles.into_iter().map(|profile| profile.id).collect())
}

#[derive(Serialize)]
struct ProfileInfoSnapshot<'a> {
    service: &'a str,
    kit_version: &'a str,
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
    assert_eq!(ai.profiles.len(), 9);
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
    assert_eq!(catalog.profiles().len(), 24);
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
    }
    assert_eq!(catalog.modules.len(), expected_count);
    Ok(())
}

#[test]
fn all_profiles_resolve_unique_modules_in_catalog_order() -> TestResult {
    let catalog = bundled_profile_catalog()?;
    assert_eq!(catalog.profiles().len(), 24);
    for definition in catalog.profiles() {
        let resolved = resolve_profile(&definition.id)?;
        assert_eq!(resolved.definition(), definition);
        for (index, module) in resolved.modules().iter().enumerate() {
            assert!(!resolved.modules()[..index].contains(module));
        }
    }
    assert_eq!(resolve_profile("minimal")?.modules().len(), 9);
    assert_eq!(resolve_profile("full-reference")?.modules().len(), 52);
    Ok(())
}

#[test]
fn cargo_generate_profile_choices_match_typed_catalog() -> TestResult {
    let config: toml::Value = toml::from_str(TEMPLATE_CONFIG)?;
    let choices = config
        .get("placeholders")
        .and_then(|placeholders| placeholders.get("profile"))
        .and_then(|profile| profile.get("choices"))
        .and_then(toml::Value::as_array)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing profile choices"))?;
    let choices = choices
        .iter()
        .map(|choice| {
            choice.as_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "profile choice is not a string")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let catalog = bundled_profile_catalog()?;
    assert_eq!(
        choices,
        catalog
            .profiles()
            .iter()
            .map(|definition| definition.id.as_str())
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn every_template_profile_renders_with_exact_resolved_modules() -> TestResult {
    let ai_profiles = ai_profile_ids()?;
    assert_eq!(ai_profiles.len(), 9);
    for definition in bundled_profile_catalog()?.profiles() {
        assert!(
            !ai_profiles.contains(&definition.id) || definition.id != "full-reference",
            "AI extension must not reuse the base full-reference identifier"
        );
        let harness = ProfileGenerationHarness::new(&definition.id)?;
        let service_name = format!("render-{}", definition.id);
        render_project(RenderRequest {
            service_name: &service_name,
            profile: &definition.id,
            destination: harness.root(),
        })?;
        let state = read_service_state(harness.root())?;
        let rendered = state
            .modules
            .iter()
            .map(|module| module.id.as_str())
            .collect::<Vec<_>>();
        let expected = resolve_profile(&definition.id)?;
        assert_eq!(rendered, expected.modules());
        let actual_providers = state
            .providers
            .iter()
            .map(|provider| (provider.slot.as_str(), provider.module.as_str()))
            .collect::<Vec<_>>();
        let expected_providers = expected
            .providers()
            .iter()
            .map(|provider| (provider.slot.as_str(), provider.module.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(actual_providers, expected_providers);
    }
    Ok(())
}

fn assert_sdk_module_surface(
    root: &Path,
    profile_id: &str,
    selected: &BTreeSet<String>,
) -> TestResult {
    let sdk_package_path = root.join("packages/web-sdk/package.json");
    if sdk_package_path.is_file() {
        let sdk_package: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&sdk_package_path)?)?;
        for (subpath, module) in [
            ("./auth", "web-auth"),
            ("./authorization", "web-authorization"),
            ("./realtime", "web-realtime"),
            ("./llm", "web-llm"),
            ("./uploads", "web-uploads"),
            ("./react", "web-react"),
            ("./testing", "web-testing"),
        ] {
            assert_eq!(
                sdk_package["exports"].get(subpath).is_some(),
                selected.contains(module),
                "{profile_id} SDK export {subpath} does not match module {module}"
            );
        }
    }
    for (path, module) in [
        ("packages/web-sdk/src/auth", "web-auth"),
        ("packages/web-sdk/src/authorization", "web-authorization"),
        ("packages/web-sdk/src/realtime", "web-realtime"),
        ("packages/web-sdk/src/llm", "web-llm"),
        ("packages/web-sdk/src/uploads", "web-uploads"),
        ("packages/web-sdk/src/react/core.ts", "web-react"),
        ("packages/web-sdk/src/testing/core.ts", "web-testing"),
        (
            "packages/web-sdk/src/internal/generated/http/react-query.ts",
            "web-react",
        ),
        (
            "packages/web-sdk/src/internal/generated/realtime.ts",
            "web-realtime",
        ),
    ] {
        assert_eq!(
            root.join(path).exists(),
            selected.contains(module),
            "{profile_id} source {path} does not match module {module}"
        );
    }
    let has_oauth_web = selected.contains("auth-oauth-server") && selected.contains("web-react");
    for path in [
        "web/src/routes/account-connected-apps-route.tsx",
        "web/src/routes/authorize-route.tsx",
    ] {
        assert_eq!(
            root.join(path).is_file(),
            has_oauth_web,
            "{profile_id} OAuth web route {path} does not match the combined module selection"
        );
    }
    Ok(())
}

fn assert_web_static_surface(
    root: &Path,
    profile_id: &str,
    selected: &BTreeSet<String>,
) -> TestResult {
    let has_web_static = selected.contains("web-static");
    let dockerfile = fs::read_to_string(root.join("ops/Dockerfile"))?;
    for required in [
        "FROM node:24.19.0-bookworm-slim AS web-build",
        "npm install --global pnpm@11.23.0",
        "pnpm install --frozen-lockfile",
        "pnpm --filter @omnius/web build",
        "COPY --from=web-build /workspace/web/dist /app/web/dist",
        "ARG OMNIUS_WEB_BASE_PATH=/",
        "WORKDIR /app",
    ] {
        assert_eq!(
            dockerfile.contains(required),
            has_web_static,
            "{profile_id} container fragment `{required}` does not match web-static selection"
        );
    }
    if has_web_static {
        let server = fs::read_to_string(root.join("apps/service/src/lib.rs"))?;
        assert!(server.contains(r#"var_os("OMNIUS_WEB_BASE_PATH")"#));
        assert!(server.contains("config.base_path = base_path.into_string()"));
    } else {
        assert!(!dockerfile.contains("node:"));
        assert!(!dockerfile.contains("pnpm"));
        assert!(!dockerfile.contains("web/dist"));
    }
    assert_sdk_module_surface(root, profile_id, selected)
}

fn assert_issuer_contract_surface(
    profile_id: &str,
    selected: &BTreeSet<String>,
    capabilities: &serde_json::Value,
    openapi: &serde_json::Value,
) -> TestResult {
    let issuer_selected = selected.contains("auth-oauth-server");
    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/.well-known/openid-configuration",
        "/oauth/token",
        "/oauth/userinfo",
    ] {
        assert_eq!(
            openapi["paths"].get(path).is_some(),
            issuer_selected,
            "{profile_id} OpenAPI issuer path `{path}` does not match auth-oauth-server selection"
        );
    }
    for (path, module) in [
        ("/whoami", "auth-core"),
        ("/auth/register", "auth-password"),
        ("/auth/login", "auth-session-postgres"),
        ("/auth/service-accounts", "auth-api-key"),
        ("/tenants", "tenancy"),
    ] {
        assert_eq!(
            openapi["paths"].get(path).is_some(),
            selected.contains(module),
            "{profile_id} OpenAPI path `{path}` does not match `{module}` selection"
        );
    }
    let capability_entries = capabilities["capabilities"]
        .as_array()
        .ok_or("capability contract has no capability inventory")?;
    let oauth_issuer = capability_entries
        .iter()
        .find(|entry| entry["id"] == "auth-oauth-server")
        .ok_or("capability contract omits auth-oauth-server")?;
    assert_eq!(
        oauth_issuer["compiled"], issuer_selected,
        "{profile_id} issuer capability compilation does not match module selection"
    );
    assert_eq!(
        oauth_issuer["runtime_available"], issuer_selected,
        "{profile_id} issuer capability runtime does not match module selection"
    );
    let issuer_roles = oauth_issuer["auth_roles"]
        .as_array()
        .ok_or("issuer capability has no auth_roles")?;
    for role in [
        "openid-provider",
        "oauth-authorization-server",
        "oauth-resource-server",
    ] {
        assert_eq!(
            issuer_roles.iter().any(|value| value == role),
            issuer_selected,
            "{profile_id} issuer capability role `{role}` does not match module selection"
        );
    }
    let web_auth = capability_entries
        .iter()
        .find(|entry| entry["id"] == "web-auth")
        .ok_or("capability contract omits web-auth")?;
    let web_auth_roles = web_auth["auth_roles"]
        .as_array()
        .ok_or("web-auth capability has no auth_roles")?;
    assert!(
        !web_auth_roles.iter().any(|value| {
            matches!(
                value.as_str(),
                Some("openid-provider" | "oauth-authorization-server")
            )
        }),
        "{profile_id} web-auth capability claims issuer roles"
    );
    Ok(())
}

fn assert_profile_contract_surface(
    root: &Path,
    profile_id: &str,
    selected: &BTreeSet<String>,
) -> TestResult {
    let manifest_path = root.join("contracts/contract-manifest.json");
    if !manifest_path.is_file() {
        return Ok(());
    }
    let manifest: serde_json::Value = serde_json::from_str(&fs::read_to_string(&manifest_path)?)?;
    let capabilities: serde_json::Value = serde_json::from_str(&fs::read_to_string(
        root.join("contracts/capabilities.json"),
    )?)?;
    let openapi: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(root.join("contracts/openapi.json"))?)?;
    assert_eq!(manifest["profile"], profile_id);
    assert_eq!(capabilities["profile"], profile_id);
    assert_eq!(manifest["modules"], serde_json::to_value(selected)?);
    assert_issuer_contract_surface(profile_id, selected, &capabilities, &openapi)?;
    assert_eq!(
        capabilities["contract_hash"],
        format!(
            "sha256:{}",
            manifest["aggregate_sha256"]
                .as_str()
                .ok_or("contract manifest omits aggregate_sha256")?
        ),
        "{profile_id} capability contract hash is stale"
    );
    Ok(())
}

fn assert_manager_clean(
    root: &Path,
    profile_id: &str,
    kit_root: &Path,
    modules: &ModuleCatalog,
) -> TestResult {
    let manager = ProjectManager::new(root, kit_root, modules);
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

fn assert_fresh_profile_render(
    definition: &ProfileDefinition,
    kit_root: &Path,
    modules: &ModuleCatalog,
) -> TestResult {
    let harness = ProfileGenerationHarness::new(&definition.id)?;
    let service_name = format!("clean-{}", definition.id);
    render_project(RenderRequest {
        service_name: &service_name,
        profile: &definition.id,
        destination: harness.root(),
    })?;
    let selected = resolve_profile(&definition.id)?
        .modules()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_web_static_surface(harness.root(), &definition.id, &selected)?;
    assert_profile_contract_surface(harness.root(), &definition.id, &selected)?;
    assert_omnius_generated_contract(harness.root())?;
    assert_manager_clean(harness.root(), &definition.id, kit_root, modules)
}

#[test]
fn fresh_profile_renders_use_only_omnius_contract_and_are_manager_clean() -> TestResult {
    let kit_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let modules = ModuleCatalog::bundled()?;
    let ai_profiles = ai_profile_ids()?;
    assert_eq!(ai_profiles.len(), 9);
    for definition in bundled_profile_catalog()?.profiles() {
        assert_fresh_profile_render(definition, &kit_root, &modules)?;
    }
    Ok(())
}
#[test]
fn materially_different_profiles_install_distinct_real_crate_trees() -> TestResult {
    let minimal = ProfileGenerationHarness::new("minimal-artifacts")?;
    let api = ProfileGenerationHarness::new("api-artifacts")?;
    render_project(RenderRequest {
        service_name: "minimal-artifacts",
        profile: "minimal",
        destination: minimal.root(),
    })?;
    render_project(RenderRequest {
        service_name: "api-artifacts",
        profile: "api",
        destination: api.root(),
    })?;
    assert!(!minimal.root().join("crates/postgres/Cargo.toml").exists());
    assert!(api.root().join("crates/postgres/Cargo.toml").is_file());
    assert_ne!(
        fs::read_to_string(minimal.root().join("Cargo.toml"))?,
        fs::read_to_string(api.root().join("Cargo.toml"))?
    );
    let catalog = ModuleCatalog::bundled()?;
    for profile in ["minimal", "api"] {
        let root = if profile == "minimal" {
            minimal.root()
        } else {
            api.root()
        };
        for id in resolve_profile(profile)?.modules() {
            let module = catalog
                .module(id)
                .ok_or_else(|| io::Error::other(format!("missing catalog module {id}")))?;
            for path in &module.generator_ownership.kit_owned {
                assert!(
                    root.join(path).exists(),
                    "{profile} did not install `{id}` artifact `{path}`"
                );
            }
        }
    }
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
    let invalid_name = render_project(RenderRequest {
        service_name: "Not Canonical",
        profile: "minimal",
        destination: harness.root(),
    });
    assert!(matches!(invalid_name, Err(RenderError::InvalidServiceName)));

    let unknown = render_project(RenderRequest {
        service_name: "unknown-profile-service",
        profile: "unknown",
        destination: harness.root(),
    });
    assert!(matches!(unknown, Err(RenderError::Profile(_))));
    Ok(())
}

#[test]
fn minimal_render_is_idempotent_and_preserves_application_owned_files() -> TestResult {
    let harness = ProfileGenerationHarness::new("minimal")?;
    let mut pass = 0_u8;
    harness.generate_idempotently(|root| {
        let outcome = render_project(RenderRequest {
            service_name: "minimal-service",
            profile: "minimal",
            destination: root,
        })?;
        if pass == 0 {
            assert!(matches!(outcome, RenderOutcome::Created { .. }));
            fs::write(
                root.join("apps/service/src/application.rs"),
                "// application-owned edit\n",
            )
            .map_err(RenderError::Filesystem)?;
            fs::write(root.join("notes.txt"), "application data\n")
                .map_err(RenderError::Filesystem)?;
        } else {
            assert!(matches!(outcome, RenderOutcome::Unchanged { .. }));
            let application = fs::read_to_string(root.join("apps/service/src/application.rs"))
                .map_err(RenderError::Filesystem)?;
            assert_eq!(application, "// application-owned edit\n");
        }
        pass += 1;
        Ok::<_, RenderError>(())
    })?;
    assert_omnius_generated_contract(harness.root())?;
    assert_eq!(state_snapshot(harness.root())?, MINIMAL_SNAPSHOT);
    Ok(())
}

#[test]
fn authenticated_api_render_matches_resolved_profile_snapshot() -> TestResult {
    let harness = ProfileGenerationHarness::new("authenticated-api")?;
    harness.generate_idempotently(|root| {
        render_project(RenderRequest {
            service_name: "authenticated-service",
            profile: "authenticated-api",
            destination: root,
        })?;
        Ok::<_, RenderError>(())
    })?;
    assert_eq!(state_snapshot(harness.root())?, AUTHENTICATED_SNAPSHOT);
    Ok(())
}

#[test]
fn refuses_nonempty_unmanaged_destinations_and_changed_kit_files() -> TestResult {
    let unmanaged = ProfileGenerationHarness::new("minimal")?;
    fs::write(unmanaged.root().join("owned.txt"), "keep\n")?;
    let result = render_project(RenderRequest {
        service_name: "safe-service",
        profile: "minimal",
        destination: unmanaged.root(),
    });
    assert!(matches!(result, Err(RenderError::DestinationNotEmpty)));
    assert_eq!(
        fs::read_to_string(unmanaged.root().join("owned.txt"))?,
        "keep\n"
    );

    let managed = ProfileGenerationHarness::new("minimal")?;
    render_project(RenderRequest {
        service_name: "safe-service",
        profile: "minimal",
        destination: managed.root(),
    })?;
    fs::write(managed.root().join("Cargo.toml"), "application edit\n")?;
    let result = render_project(RenderRequest {
        service_name: "safe-service",
        profile: "minimal",
        destination: managed.root(),
    });
    assert!(
        matches!(result, Err(RenderError::GeneratedFileConflict(path)) if path == Path::new("Cargo.toml"))
    );
    assert_eq!(
        fs::read_to_string(managed.root().join("Cargo.toml"))?,
        "application edit\n"
    );
    Ok(())
}

#[tokio::test]
async fn generated_minimal_and_authenticated_projects_run_contracts_and_report_profiles()
-> TestResult {
    for (profile, service_name) in [
        ("minimal", "compile-minimal"),
        ("authenticated-api", "compile-authenticated"),
    ] {
        let harness = ProfileGenerationHarness::new(profile)?;
        render_project(RenderRequest {
            service_name,
            profile,
            destination: harness.root(),
        })?;

        let output = cargo_command(&harness)
            .arg("nextest")
            .arg("run")
            .arg("--workspace")
            .arg("--exclude")
            .arg("omnius-generator")
            .arg("-E")
            .arg("not group(/^(postgres|redis|nats|minio)-integration$/)")
            .timeout(Duration::from_secs(600))
            .output()
            .await?;
        require_success("cargo nextest run", &output)?;

        let output = cargo_command(&harness)
            .arg("test")
            .arg("--doc")
            .arg("--workspace")
            .arg("--exclude")
            .arg("omnius-generator")
            .timeout(Duration::from_secs(600))
            .output()
            .await?;
        require_success("cargo test --doc", &output)?;

        let output = cargo_command(&harness)
            .arg("run")
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
    }
    Ok(())
}

fn state_snapshot(root: &Path) -> TestResult<String> {
    let state = read_service_state(root)?;
    assert!(
        state
            .modules
            .iter()
            .all(|module| module.version == KIT_VERSION)
    );
    let snapshot = ProfileInfoSnapshot {
        service: &state.service,
        kit_version: &state.kit_version,
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
    let mut tree = String::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
            continue;
        }
        tree.push_str(&path.strip_prefix(root)?.to_string_lossy());
        tree.push('\n');
        tree.push_str(&fs::read_to_string(path)?);
        tree.push('\n');
    }

    assert!(tree.contains("path = \".omnius/service.toml\""));
    assert!(tree.contains("omnius:managed-begin"));
    assert!(tree.contains("omnius:managed-end"));
    assert!(tree.contains("OMNIUS_BIND"));
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
    ] {
        if let Some(value) = std::env::var_os(key) {
            command = command.env(key, value);
        }
    }
    let target =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/generated-profile-tests");
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
