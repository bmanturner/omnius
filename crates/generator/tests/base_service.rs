//! Base profile catalog, deterministic rendering, and generated-service contracts.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::OsString,
    fs,
    io::{self, Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use omnius_generator::{
    ApplicationRequirement, KIT_VERSION, ModuleCatalog, ProfileCatalog, ProfileDefinition,
    ProjectManager, RenderError, RenderOutcome, RenderRequest, bundled_profile_catalog,
    render_project, resolve_profile,
};
use omnius_test_support::{ProfileCommand, ProfileGenerationHarness};
use serde::{Deserialize, Serialize};
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
#[allow(clippy::too_many_lines)] // One table-driven test proves every bundled profile contract.
fn every_template_profile_renders_with_exact_resolved_modules() -> TestResult {
    let ai_profiles = ai_profile_ids()?;
    assert_eq!(ai_profiles.len(), 8);
    let module_catalog = ModuleCatalog::bundled()?;
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
        let selected = expected.modules().iter().cloned().collect::<BTreeSet<_>>();
        let ordered = module_catalog.composition_order(&selected)?;
        let manifest: toml::Value = toml::from_str(&fs::read_to_string(
            harness.root().join("crates/service-kit/Cargo.toml"),
        )?)?;
        let features = manifest
            .get("features")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| io::Error::other("service-kit features table is missing"))?;
        let defaults = features
            .get("default")
            .and_then(toml::Value::as_array)
            .ok_or_else(|| io::Error::other("service-kit default features are missing"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| io::Error::other("default feature is not a string"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            defaults,
            ordered
                .iter()
                .map(|module| module.id.as_str())
                .collect::<Vec<_>>()
        );
        for module in &module_catalog.modules {
            let actual = features
                .get(&module.id)
                .and_then(toml::Value::as_array)
                .ok_or_else(|| io::Error::other("module feature is missing"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| io::Error::other("module feature member is not a string"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let expected_dependencies = if selected.contains(&module.id) {
                module
                    .composition
                    .crates
                    .iter()
                    .map(|value| format!("dep:{}", value.dependency))
                    .collect::<BTreeSet<_>>()
            } else {
                BTreeSet::new()
            };
            assert_eq!(
                actual,
                expected_dependencies
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
            );
        }
        let dependencies = manifest
            .get("dependencies")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| io::Error::other("service-kit dependencies table is missing"))?;
        let actual_optional = dependencies
            .iter()
            .filter_map(|(name, value)| {
                value
                    .get("optional")
                    .and_then(toml::Value::as_bool)
                    .is_some_and(|optional| optional)
                    .then_some(name.as_str())
            })
            .collect::<BTreeSet<_>>();
        let expected_optional = ordered
            .iter()
            .flat_map(|module| &module.composition.crates)
            .map(|value| value.dependency.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(actual_optional, expected_optional);
        let mut expected_dependency_features = BTreeMap::<&str, BTreeSet<&str>>::new();
        for module in &ordered {
            for composition_crate in &module.composition.crates {
                expected_dependency_features
                    .entry(&composition_crate.dependency)
                    .or_default()
                    .extend(composition_crate.features.iter().map(String::as_str));
            }
        }
        for (dependency, expected_features) in expected_dependency_features {
            let actual_features = dependencies
                .get(dependency)
                .and_then(|value| value.get("features"))
                .and_then(toml::Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .map(|value| {
                            value.as_str().ok_or_else(|| {
                                io::Error::other("dependency feature is not a string")
                            })
                        })
                        .collect::<Result<BTreeSet<_>, _>>()
                })
                .transpose()?
                .unwrap_or_default();
            assert_eq!(actual_features, expected_features);
        }
        let selected_source =
            fs::read_to_string(harness.root().join("crates/service-kit/src/selected.rs"))?;
        assert_eq!(
            selected_source
                .matches("crate::SelectedModuleContract {")
                .count(),
            ordered.len()
        );
        assert!(selected_source.contains("pub enum ApplicationRequirement {"));
        assert!(selected_source.contains("pub const ALL: &[Self]"));
        for requirement in ApplicationRequirement::ALL {
            assert!(selected_source.contains(&format!("    {requirement:?},")));
            assert!(selected_source.contains(&format!(
                "Self::{requirement:?} => {:?}",
                requirement.as_str()
            )));
        }
        assert!(selected_source.contains("pub const fn as_str(&self) -> &'static str"));
        assert!(!selected_source.contains("application_requirements: &[\""));
        for requirement in ordered
            .iter()
            .flat_map(|module| &module.composition.application_requirements)
        {
            assert!(selected_source.contains(&format!("ApplicationRequirement::{requirement:?}")));
        }
        let registrar_offsets = ordered
            .iter()
            .filter(|module| module.composition.registrar)
            .map(|module| {
                let call = format!(
                    "crate::modules::{}::register(builder).await?;",
                    module.id.replace('-', "_")
                );
                selected_source
                    .find(&call)
                    .ok_or_else(|| io::Error::other("selected registrar call is missing"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert!(registrar_offsets.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(matches!(
            render_project(RenderRequest {
                service_name: &service_name,
                profile: &definition.id,
                destination: harness.root(),
            })?,
            RenderOutcome::Unchanged { .. }
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // SDK surface assertions cover one cross-file public contract.
fn assert_sdk_module_surface(
    root: &Path,
    profile_id: &str,
    selected: &BTreeSet<String>,
) -> TestResult {
    let sdk_package_path = root.join("packages/web-sdk/package.json");
    if sdk_package_path.is_file() {
        let sdk_package: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&sdk_package_path)?)?;
        for (subpath, expected) in [
            ("./auth", selected.contains("web-auth")),
            ("./authorization", selected.contains("web-authorization")),
            ("./realtime", selected.contains("web-realtime")),
            ("./llm", selected.contains("web-llm")),
            ("./uploads", selected.contains("web-uploads")),
            ("./react", selected.contains("web-react")),
            ("./testing", selected.contains("web-testing")),
        ] {
            assert_eq!(
                sdk_package["exports"].get(subpath).is_some(),
                expected,
                "{profile_id} SDK export {subpath} does not match its selected support surface"
            );
        }
    }
    for (path, expected) in [
        ("packages/web-sdk/src/auth", selected.contains("web-auth")),
        (
            "packages/web-sdk/src/authorization",
            selected.contains("web-authorization"),
        ),
        (
            "packages/web-sdk/src/realtime",
            selected.contains("web-realtime"),
        ),
        ("packages/web-sdk/src/llm", selected.contains("web-llm")),
        (
            "packages/web-sdk/src/uploads",
            selected.contains("web-uploads"),
        ),
        (
            "packages/web-sdk/src/react/realtime.ts",
            selected.contains("web-realtime"),
        ),
        (
            "packages/web-sdk/src/react/uploads.ts",
            selected.contains("web-uploads"),
        ),
        (
            "packages/web-sdk/src/react/tenant.ts",
            selected.contains("web-tenancy"),
        ),
        (
            "packages/web-sdk/src/react/capabilities.ts",
            selected.contains("web-react"),
        ),
        (
            "packages/web-sdk/src/react/local-state.ts",
            selected.contains("web-local-state"),
        ),
        (
            "web/src/components/tenant-switcher.tsx",
            selected.contains("web-tenancy"),
        ),
        (
            "web/src/components/upload-panel.tsx",
            selected.contains("web-uploads"),
        ),
        (
            "web/src/runtime-composition.tsx",
            selected.contains("web-react"),
        ),
        (
            "packages/web-sdk/src/react/core.ts",
            selected.contains("web-react"),
        ),
        (
            "packages/web-sdk/src/testing/core.ts",
            selected.contains("web-testing"),
        ),
        (
            "packages/web-sdk/src/internal/generated/http/react-query.ts",
            selected.contains("web-react"),
        ),
        (
            "packages/web-sdk/src/internal/generated/realtime.ts",
            selected.contains("web-realtime"),
        ),
        ("contracts/openapi.json", selected.contains("openapi")),
    ] {
        assert_eq!(
            root.join(path).exists(),
            expected,
            "{profile_id} source {path} does not match its selected support surface"
        );
    }
    let app_path = root.join("web/src/app.tsx");
    if app_path.is_file() {
        let app = fs::read_to_string(app_path)?;
        assert_eq!(
            app.contains("createRealtimeManager"),
            selected.contains("web-realtime"),
            "{profile_id} application realtime wiring does not match module selection"
        );
        assert_eq!(
            app.contains("<WebRuntimeCompositionProvider"),
            selected.contains("web-tenancy") || selected.contains("web-uploads"),
            "{profile_id} optional runtime provider does not match module selection"
        );
        assert_eq!(
            app.contains("readonly contributions?:"),
            selected.contains("web-uploads"),
            "{profile_id} upload contribution input does not match module selection"
        );
    }
    let account_path = root.join("web/src/routes/account-route.tsx");
    if account_path.is_file() {
        let account = fs::read_to_string(account_path)?;
        assert_eq!(
            account.contains("function TenantControls"),
            selected.contains("web-tenancy"),
            "{profile_id} account tenancy controls do not match module selection"
        );
        assert_eq!(
            account.contains("function OptionalUploadControls"),
            selected.contains("web-uploads"),
            "{profile_id} account upload controls do not match module selection"
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
    ] {
        assert_eq!(
            dockerfile.contains(required),
            has_web_static,
            "{profile_id} container fragment `{required}` does not match web-static selection"
        );
    }
    assert!(dockerfile.contains("WORKDIR /app"));
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
    let capability_entries = capabilities["capabilities"]
        .as_array()
        .ok_or("capability contract has no inventory")?;
    for id in [
        "web-feature-flags",
        "web-llm",
        "web-local-state",
        "web-realtime",
        "web-tenancy",
        "web-uploads",
    ] {
        let descriptor = capability_entries.iter().find(|entry| entry["id"] == id);
        assert_eq!(
            descriptor.is_some(),
            selected.contains(id),
            "{profile_id} capability descriptor `{id}` does not match module selection"
        );
        if let Some(descriptor) = descriptor {
            assert_eq!(descriptor["compiled"], true);
            assert_eq!(descriptor["runtime_available"], true);
        }
    }
    assert_eq!(
        capabilities["transports"]
            .get("sse")
            .and_then(serde_json::Value::as_str),
        selected
            .contains("web-realtime")
            .then_some("/realtime/events")
    );
    assert_eq!(
        capabilities["transports"]
            .get("websocket")
            .and_then(serde_json::Value::as_str),
        selected.contains("web-realtime").then_some("/realtime/ws")
    );
    assert_eq!(manifest["profile"], profile_id);
    assert_eq!(capabilities["profile"], profile_id);
    assert_eq!(manifest["modules"], serde_json::to_value(selected)?);
    let asyncapi_selected = selected.contains("asyncapi-contracts");
    let asyncapi_path = root.join("contracts/asyncapi.json");
    assert_eq!(
        asyncapi_path.is_file(),
        asyncapi_selected,
        "{profile_id} AsyncAPI artifact does not match module selection"
    );
    let manifest_contracts = manifest["contracts"]
        .as_array()
        .ok_or("contract manifest has no contract inventory")?;
    assert_eq!(
        manifest_contracts
            .iter()
            .any(|entry| entry["path"] == "contracts/asyncapi.json"),
        asyncapi_selected,
        "{profile_id} AsyncAPI manifest entry does not match module selection"
    );
    assert_eq!(
        manifest["generators"].get("asyncapi").is_some(),
        asyncapi_selected,
        "{profile_id} AsyncAPI generator ownership does not match module selection"
    );
    if asyncapi_selected {
        let _: serde_json::Value = serde_json::from_str(&fs::read_to_string(asyncapi_path)?)?;
    }
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
    assert_eq!(ai_profiles.len(), 8);
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
        BTreeSet::from(["health", "http", "rate_limit_local", "server"])
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
    assert_eq!(reference.get("pagination").is_some(), persisted);
    if persisted {
        assert!(reference["postgres"].get("url").is_none());
        assert!(reference["pagination"].get("cursor_signing_key").is_none());
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
    assert!(main.contains("persisted_reference_overlay_enforces_and_redacts_environment_secrets"));
    assert!(main.contains("cfg(not(selected_postgres))"));
    assert!(main.contains("cfg(selected_idempotency)"));
    let build = fs::read_to_string(root.join("apps/service/build.rs"))?;
    assert!(build.contains(r#"("postgres", "selected_postgres")"#));
    assert!(build.contains(r#"("idempotency", "selected_idempotency")"#));
    assert!(build.contains("cargo::rustc-check-cfg=cfg({cfg})"));
    assert!(build.contains("cargo::rustc-cfg={cfg}"));
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
        assert_eq!(
            topology["services"]["app"]["environment"]["OMNIUS__PAGINATION__CURSOR_SIGNING_KEY"]
                .as_str(),
            Some("omnius-compose-development-key!!")
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
    let cursor_key = catalog
        .module("idempotency")
        .and_then(|module| {
            module
                .configuration
                .fields
                .iter()
                .find(|field| field.path == "pagination.cursor_signing_key")
        })
        .and_then(|field| field.environment.as_deref());
    assert_eq!(cursor_key, Some("OMNIUS__PAGINATION__CURSOR_SIGNING_KEY"));
}

#[test]
fn generated_reference_configuration_and_container_contracts_are_executable() -> TestResult {
    let catalog = ModuleCatalog::bundled()?;
    for (profile, service_name, persisted) in [
        ("minimal", "config-minimal", false),
        ("api", "config-persisted", true),
    ] {
        let harness = ProfileGenerationHarness::new(profile)?;
        render_project(RenderRequest {
            service_name,
            profile,
            destination: harness.root(),
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
    render_project(RenderRequest {
        service_name: "external-runtime",
        profile: "realtime-durable",
        destination: harness.root(),
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
fn generated_persisted_compose_survives_restart_with_stable_migrations() -> TestResult {
    let harness = ProfileGenerationHarness::new("docker-compose-smoke")?;
    render_project(RenderRequest {
        service_name: "docker-compose-smoke",
        profile: "api",
        destination: harness.root(),
    })?;
    let mut compose = ComposeSmokeGuard::new(harness.root());

    compose.run("docker compose config", &["config"])?;
    compose.run_up("docker compose up --build", &["up", "--build", "--detach"])?;
    wait_for_generated_ready(Duration::from_secs(120))?;

    let record_name = "persisted compose smoke";
    let create = smoke_http_request(
        "POST",
        "/reference-records",
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "generated-compose-smoke-create"),
        ],
        r#"{"name":"persisted compose smoke"}"#,
    )?;
    assert_eq!(create.status, 201, "create response: {}", create.body);
    let created: serde_json::Value = serde_json::from_str(&create.body)?;
    assert_eq!(created["name"].as_str(), Some(record_name));
    let record_id = created["id"]
        .as_str()
        .ok_or_else(|| io::Error::other("create response has no record ID"))?
        .to_owned();

    let first_list = smoke_http_request("GET", "/reference-records?limit=100", &[], "")?;
    assert_eq!(first_list.status, 200, "list response: {}", first_list.body);
    let first_page: serde_json::Value = serde_json::from_str(&first_list.body)?;
    assert!(first_page["items"].as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item["id"].as_str() == Some(record_id.as_str())
                && item["name"].as_str() == Some(record_name)
        })
    }));

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

    let restarted_list = smoke_http_request("GET", "/reference-records?limit=100", &[], "")?;
    assert_eq!(
        restarted_list.status, 200,
        "restarted list response: {}",
        restarted_list.body
    );
    let restarted_page: serde_json::Value = serde_json::from_str(&restarted_list.body)?;
    assert!(restarted_page["items"].as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item["id"].as_str() == Some(record_id.as_str())
                && item["name"].as_str() == Some(record_name)
        })
    }));
    let migration_after = compose_migration_status(&compose)?;
    assert_eq!(migration_after, migration_before);

    compose.remove()?;
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
#[allow(clippy::too_many_lines)] // Compile and metadata checks share one generated-root lifecycle.
async fn generated_reference_roots_compile_and_report_selected_profiles() -> TestResult {
    for (profile, service_name) in [
        ("minimal", "compile-minimal"),
        ("api", "compile-api"),
        ("authenticated-api", "compile-authenticated"),
        ("oauth-provider", "compile-oauth-provider"),
    ] {
        let harness = ProfileGenerationHarness::new(profile)?;
        render_project(RenderRequest {
            service_name,
            profile,
            destination: harness.root(),
        })?;

        let output = cargo_command(&harness)
            .arg("check")
            .arg("--workspace")
            .arg("--all-targets")
            .arg("--exclude")
            .arg("omnius-generator")
            .timeout(Duration::from_secs(600))
            .output()
            .await?;
        require_success("cargo check --workspace --all-targets", &output)?;

        if matches!(profile, "minimal" | "api") {
            let output = cargo_command(&harness)
                .arg("nextest")
                .arg("run")
                .arg("--package")
                .arg(service_name)
                .arg("--package")
                .arg(format!("{service_name}-kit"))
                .timeout(Duration::from_secs(600))
                .output()
                .await?;
            require_success("cargo nextest run", &output)?;
        }

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
    assert_eq!(state.kit_version, KIT_VERSION);
    assert!(
        state
            .modules
            .iter()
            .all(|module| !module.version.is_empty())
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

    assert!(tree.contains("path = \".omnius/service.toml\""));
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
