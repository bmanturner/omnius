use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use csv::Reader;
use omnius_generator::{
    ApplicationRequirement, ModuleCatalog as GeneratorModuleCatalog, ModuleDefinition,
};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::{
    extensions::{self, Overlay},
    model::{
        AcceptanceCatalog, Frontmatter, ModuleCatalog, Patterns, Task, TaskCatalog, ensure_unique,
    },
    profiles,
};

const PROHIBITED_MARKERS: &[&str] = &["TODO", "TBD", "FIXME", "???", "unimplemented!()", "todo!()"];

pub(crate) struct SpecSummary {
    pub(crate) modules: usize,
    pub(crate) profiles: usize,
    pub(crate) criteria: usize,
    pub(crate) tasks: usize,
    pub(crate) recommendations: usize,
}
struct BundleCounts {
    modules: usize,
    profiles: usize,
    criteria: usize,
    tasks: usize,
    recommendations: usize,
    sources: usize,
}
const SERVICE_KIT_MANIFEST: &str = "crates/service-kit/Cargo.toml";
const SERVICE_KIT_CATALOG: &str = "crates/service-kit/src/catalog.rs";
const STATIC_SERVICE_KIT_DEPENDENCIES: &[&str] = &[
    "axum",
    "humantime-serde",
    "omnius-core",
    "omnius-config",
    "omnius-health",
    "omnius-runtime",
    "serde",
    "serde_json",
    "tokio",
];
const SERVICE_KIT_FEATURE_SUPPORT_DEPENDENCIES: &[(&str, &str)] = &[
    ("migrations", "omnius-migrations-macros"),
    ("migrations", "sqlx"),
];

#[derive(Debug, Eq, PartialEq)]
struct GeneratedServiceKit {
    manifest: String,
    catalog: String,
}

pub(crate) fn generate_service_kit(workspace: &Path) -> Result<()> {
    let generated = generated_service_kit(workspace)?;
    write_if_changed(&workspace.join(SERVICE_KIT_MANIFEST), &generated.manifest)?;
    write_if_changed(&workspace.join(SERVICE_KIT_CATALOG), &generated.catalog)
}

fn verify_service_kit(workspace: &Path) -> Result<()> {
    let generated = generated_service_kit(workspace)?;
    for (relative, expected) in [
        (SERVICE_KIT_MANIFEST, generated.manifest.as_str()),
        (SERVICE_KIT_CATALOG, generated.catalog.as_str()),
    ] {
        let actual = fs::read_to_string(workspace.join(relative))
            .with_context(|| format!("read generated service-kit artifact {relative}"))?;
        ensure!(
            actual == expected,
            "{relative} is stale; run `cargo xtask specs generate`"
        );
    }
    Ok(())
}

fn generated_service_kit(workspace: &Path) -> Result<GeneratedServiceKit> {
    let catalog = GeneratorModuleCatalog::bundled()
        .context("load authoritative module catalogs for service-kit generation")?;
    ensure!(
        catalog.module("generator").is_none(),
        "the generator tooling module must not appear in the runtime catalog"
    );
    let test_support = catalog
        .module("test-support")
        .context("module catalog is missing tooling capability `test-support`")?;
    ensure!(
        test_support.kind == "tooling",
        "module `test-support` must remain tooling-only"
    );
    let runtime_modules = runtime_modules(&catalog)?;

    let manifest_path = workspace.join(SERVICE_KIT_MANIFEST);
    let manifest_source = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let features = render_service_kit_features(&runtime_modules, test_support);
    let dependencies = render_service_kit_dependencies(&runtime_modules, test_support);
    let manifest = replace_managed_region(&manifest_source, "composition-features", &features)
        .and_then(|source| {
            replace_managed_region(&source, "composition-dependencies", &dependencies)
        })?;

    Ok(GeneratedServiceKit {
        manifest,
        catalog: render_service_kit_catalog(&runtime_modules),
    })
}

fn runtime_modules(catalog: &GeneratorModuleCatalog) -> Result<Vec<&ModuleDefinition>> {
    let runtime = catalog
        .modules
        .iter()
        .filter(|module| module.kind != "tooling")
        .collect::<Vec<_>>();
    let selected = runtime
        .iter()
        .map(|module| module.id.as_str())
        .collect::<BTreeSet<_>>();
    for module in &runtime {
        for required in &module.requires {
            ensure!(
                selected.contains(required.as_str()),
                "runtime module `{}` requires non-runtime module `{required}`",
                module.id
            );
        }
    }

    let mut ordered = Vec::with_capacity(runtime.len());
    let mut emitted = BTreeSet::new();
    while ordered.len() < runtime.len() {
        let module = runtime
            .iter()
            .copied()
            .find(|module| {
                !emitted.contains(module.id.as_str())
                    && module
                        .requires
                        .iter()
                        .all(|required| emitted.contains(required.as_str()))
            })
            .context("runtime modules cannot be ordered by prerequisites")?;
        emitted.insert(module.id.as_str());
        ordered.push(module);
    }
    Ok(ordered)
}

fn render_service_kit_features(
    runtime_modules: &[&ModuleDefinition],
    test_support: &ModuleDefinition,
) -> String {
    let mut output = String::from("default = []\n");
    for module in runtime_modules
        .iter()
        .copied()
        .chain(std::iter::once(test_support))
    {
        let mut features = Vec::<String>::new();
        for required in &module.requires {
            push_unique(&mut features, required.clone());
        }
        for dependency in &module.composition.crates {
            if !STATIC_SERVICE_KIT_DEPENDENCIES.contains(&dependency.dependency.as_str()) {
                push_unique(&mut features, format!("dep:{}", dependency.dependency));
            }
            for feature in &dependency.features {
                push_unique(
                    &mut features,
                    format!("{}/{}", dependency.dependency, feature),
                );
            }
        }
        for (_, dependency) in SERVICE_KIT_FEATURE_SUPPORT_DEPENDENCIES
            .iter()
            .filter(|(feature_module, _)| *feature_module == module.id)
        {
            push_unique(&mut features, format!("dep:{dependency}"));
        }
        let _ = write!(output, "{} = [", module.id);
        for (index, feature) in features.iter().enumerate() {
            if index > 0 {
                output.push_str(", ");
            }
            push_rust_string(&mut output, feature);
        }
        output.push_str("]\n");
    }
    output
}

fn render_service_kit_dependencies(
    runtime_modules: &[&ModuleDefinition],
    test_support: &ModuleDefinition,
) -> String {
    let mut dependencies = runtime_modules
        .iter()
        .copied()
        .chain(std::iter::once(test_support))
        .flat_map(|module| &module.composition.crates)
        .map(|dependency| dependency.dependency.as_str())
        .filter(|dependency| !STATIC_SERVICE_KIT_DEPENDENCIES.contains(dependency))
        .collect::<BTreeSet<_>>();
    dependencies.extend(
        SERVICE_KIT_FEATURE_SUPPORT_DEPENDENCIES
            .iter()
            .map(|(_, dependency)| *dependency),
    );
    let mut output = String::new();
    for dependency in dependencies {
        let _ = writeln!(
            output,
            "{dependency} = {{ workspace = true, optional = true }}"
        );
    }
    output
}

fn render_service_kit_catalog(runtime_modules: &[&ModuleDefinition]) -> String {
    let mut output = String::from(
        "//! Generated canonical module contracts and feature-gated dispatch.\n\
         //!\n\
         //! Regenerate with `cargo xtask specs generate`; do not edit by hand.\n\n",
    );
    render_application_requirement_enum(&mut output);
    output.push_str(
        "/// Canonical runtime contract for one catalog module.\n\
         #[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
         pub struct SelectedModuleContract {\n\
         \x20   /// Stable module ID.\n\
         \x20   pub module: &'static str,\n\
         \x20   /// Whether configuration may disable this compiled module.\n\
         \x20   pub runtime_toggle: bool,\n\
         \x20   /// Declared route IDs.\n\
         \x20   pub routes: &'static [&'static str],\n\
         \x20   /// Declared background-task IDs.\n\
         \x20   pub tasks: &'static [&'static str],\n\
         \x20   /// Declared health-check IDs.\n\
         \x20   pub health_checks: &'static [&'static str],\n\
         \x20   /// Application-owned contributions required by this module.\n\
         \x20   pub application_requirements: &'static [ApplicationRequirement],\n\
         }\n\n",
    );

    output.push_str(
        "#[cfg(any(feature = \"core\", test))]\n\
         #[rustfmt::skip]\n\
         pub(crate) const COMPILED_MODULES: &[&str] = &[\n",
    );
    for module in runtime_modules {
        let _ = writeln!(
            output,
            "    #[cfg(feature = {:?})]\n    {:?},",
            module.id, module.id
        );
    }
    output.push_str("];\n\n");

    output.push_str(
        "#[rustfmt::skip]\n\
         pub(crate) const COMPILED_CONTRACTS: &[SelectedModuleContract] = &[\n",
    );
    for module in runtime_modules {
        let _ = writeln!(output, "    #[cfg(feature = {:?})]", module.id);
        output.push_str("    SelectedModuleContract {\n        module: ");
        push_rust_string(&mut output, &module.id);
        output.push_str(",\n        runtime_toggle: ");
        output.push_str(if module.runtime_toggle {
            "true"
        } else {
            "false"
        });
        output.push_str(",\n        routes: &");
        push_rust_string_array(&mut output, &module.routes);
        output.push_str(",\n        tasks: &");
        push_rust_string_array(&mut output, &module.background_tasks);
        output.push_str(",\n        health_checks: &");
        push_rust_string_array(&mut output, &module.health_checks);
        output.push_str(",\n        application_requirements: &");
        push_application_requirement_array(
            &mut output,
            &module.composition.application_requirements,
        );
        output.push_str(",\n    },\n");
    }
    output.push_str("];\n\n");

    render_service_kit_contract_resolution(&mut output, runtime_modules);
    render_service_kit_registration(&mut output, runtime_modules);
    output
}

fn render_service_kit_contract_resolution(
    output: &mut String,
    runtime_modules: &[&ModuleDefinition],
) {
    output.push_str(
        "#[cfg(any(feature = \"core\", test))]\n\
         #[rustfmt::skip]\n\
         fn is_known_module(module: &str) -> bool {\n\
         \x20   matches!(\n\
         \x20       module,\n",
    );
    push_module_match_patterns(output, runtime_modules, None);
    output.push_str(
        "    )\n\
         }\n\n\
         #[cfg(any(feature = \"core\", test))]\n\
         pub(crate) fn canonical_contract(\n\
         \x20   module: &'static str,\n\
         ) -> Result<&'static SelectedModuleContract, crate::CompositionError> {\n\
         \x20   if let Some(contract) = COMPILED_CONTRACTS\n\
         \x20       .iter()\n\
         \x20       .find(|contract| contract.module == module)\n\
         \x20   {\n\
         \x20       return Ok(contract);\n\
         \x20   }\n\
         \x20   if is_known_module(module) {\n\
         \x20       Err(crate::CompositionError::FeatureNotEnabled { module })\n\
         \x20   } else {\n\
         \x20       Err(crate::CompositionError::UnknownModule { module })\n\
         \x20   }\n\
         }\n\n\
         #[cfg(any(feature = \"core\", test))]\n\
         pub(crate) fn validate_selection(\n\
         \x20   modules: &'static [&'static str],\n\
         ) -> Result<(), crate::CompositionError> {\n\
         \x20   for &module in modules {\n\
         \x20       canonical_contract(module)?;\n\
         \x20   }\n\
         \x20   if modules != COMPILED_MODULES {\n\
         \x20       return Err(crate::CompositionError::SelectionMismatch);\n\
         \x20   }\n\
         \x20   Ok(())\n\
         }\n\n",
    );
}

fn render_service_kit_registration(output: &mut String, runtime_modules: &[&ModuleDefinition]) {
    output.push_str(
        "#[cfg(any(feature = \"core\", test))]\n\
         #[rustfmt::skip]\n\
         fn is_registrarless_module(module: &str) -> bool {\n\
         \x20   matches!(\n\
         \x20       module,\n",
    );
    push_module_match_patterns(output, runtime_modules, Some(false));
    output.push_str(
        "    )\n\
         }\n\n\
         #[cfg(any(feature = \"core\", test))]\n\
         #[rustfmt::skip]\n\
         fn register_selected_module(\n\
         \x20   #[cfg(feature = \"core\")]\n\
         \x20   builder: &mut crate::AppCompositionBuilder<'_>,\n\
         \x20   #[cfg(not(feature = \"core\"))]\n\
         \x20   _: &mut crate::AppCompositionBuilder<'_>,\n\
         \x20   module: &'static str,\n\
         ) -> Result<(), crate::CompositionError> {\n\
         \x20   match module {\n",
    );
    for module in runtime_modules
        .iter()
        .filter(|module| module.composition.registrar)
    {
        let _ = writeln!(
            output,
            "        #[cfg(feature = {:?})] {:?} => crate::modules::{}::register(builder),",
            module.id,
            module.id,
            module.id.replace('-', "_")
        );
    }
    output.push_str(
        "        _ if is_registrarless_module(module) => Ok(()),\n\
         \x20       _ => Err(crate::CompositionError::SelectionMismatch),\n\
         \x20   }\n\
         }\n\n\
         #[cfg(any(feature = \"core\", test))]\n\
         pub(crate) fn register_selected(\n\
         \x20   builder: &mut crate::AppCompositionBuilder<'_>,\n\
         ) -> Result<(), crate::CompositionError> {\n\
         \x20   let selected = builder.input.modules;\n\
         \x20   validate_selection(selected)?;\n\
         \x20   for &module in selected {\n\
         \x20       register_selected_module(builder, module)?;\n\
         \x20   }\n\
         \x20   #[cfg(feature = \"http\")]\n\
         \x20   crate::modules::http::finalize(builder)?;\n\
         \x20   Ok(())\n\
         }\n",
    );
}

fn push_module_match_patterns(
    output: &mut String,
    runtime_modules: &[&ModuleDefinition],
    registrar: Option<bool>,
) {
    let mut emitted = 0_usize;
    for module in runtime_modules.iter().filter(|module| {
        registrar.is_none_or(|registrar| module.composition.registrar == registrar)
    }) {
        if emitted == 0 {
            output.push_str("        ");
        } else if emitted.is_multiple_of(3) {
            output.push_str("\n        | ");
        } else {
            output.push_str(" | ");
        }
        push_rust_string(output, &module.id);
        emitted += 1;
    }
    assert!(emitted > 0, "service-kit match pattern must not be empty");
    output.push('\n');
}

fn render_application_requirement_enum(output: &mut String) {
    output.push_str(
        "/// Closed application-owned requirements accepted by the module graph.\n\
         #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]\n\
         pub enum ApplicationRequirement {\n",
    );
    for requirement in ApplicationRequirement::ALL {
        let _ = writeln!(
            output,
            "    /// `{}`.\n    {requirement:?},",
            requirement.as_str()
        );
    }
    output.push_str(
        "}\n\n\
         impl ApplicationRequirement {\n\
         \x20   /// Every application requirement accepted by the module graph.\n\
         \x20   pub const ALL: &[Self] = &[\n",
    );
    for requirement in ApplicationRequirement::ALL {
        let _ = writeln!(output, "        Self::{requirement:?},");
    }
    output.push_str(
        "    ];\n\n\
         \x20   /// Returns the canonical diagnostic identifier.\n\
         \x20   #[must_use = \"use the canonical identifier when reporting this requirement\"]\n\
         \x20   pub const fn as_str(&self) -> &'static str {\n\
         \x20       match self {\n",
    );
    for requirement in ApplicationRequirement::ALL {
        let _ = writeln!(
            output,
            "            Self::{requirement:?} => {:?},",
            requirement.as_str()
        );
    }
    output.push_str("        }\n    }\n}\n\n");
}

fn push_application_requirement_array(
    output: &mut String,
    requirements: &[ApplicationRequirement],
) {
    output.push('[');
    for (index, requirement) in requirements.iter().enumerate() {
        if index > 0 {
            output.push_str(", ");
        }
        let _ = write!(output, "ApplicationRequirement::{requirement:?}");
    }
    output.push(']');
}

fn push_rust_string(output: &mut String, value: &str) {
    let _ = write!(output, "{value:?}");
}

fn push_rust_string_array(output: &mut String, values: &[String]) {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push_str(", ");
        }
        push_rust_string(output, value);
    }
    output.push(']');
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn replace_managed_region(source: &str, id: &str, content: &str) -> Result<String> {
    ensure!(
        content.ends_with('\n'),
        "generated managed region `{id}` must end with a newline"
    );
    let begin = marker_line(source, &format!("omnius:managed-begin id={id}"))?;
    let end = marker_line(source, &format!("omnius:managed-end id={id}"))?;
    ensure!(
        begin.1 <= end.0,
        "managed region `{id}` has an invalid marker order"
    );
    let begin_line = &source[begin.0..begin.1];
    let hash_offset = begin_line
        .find(" hash=")
        .map(|offset| offset + " hash=".len())
        .with_context(|| format!("managed region `{id}` opening marker has no hash"))?;
    let hash_end = hash_offset + 64;
    let recorded = begin_line
        .get(hash_offset..hash_end)
        .with_context(|| format!("managed region `{id}` opening marker has a short hash"))?;
    ensure!(
        recorded.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "managed region `{id}` opening marker has an invalid hash"
    );
    let digest = sha256(content.as_bytes());
    let mut rendered =
        String::with_capacity(source.len() + content.len().saturating_sub(end.0 - begin.1));
    rendered.push_str(&source[..begin.0]);
    rendered.push_str(&begin_line[..hash_offset]);
    rendered.push_str(&digest);
    rendered.push_str(&begin_line[hash_end..]);
    rendered.push_str(content);
    rendered.push_str(&source[end.0..]);
    Ok(rendered)
}

fn marker_line(source: &str, needle: &str) -> Result<(usize, usize)> {
    let mut found = None;
    let mut offset = 0;
    for line in source.split_inclusive('\n') {
        if line.contains(needle) {
            ensure!(found.is_none(), "duplicate managed marker `{needle}`");
            found = Some((offset, offset + line.len()));
        }
        offset += line.len();
    }
    found.with_context(|| format!("missing managed marker `{needle}`"))
}

fn write_if_changed(path: &Path, content: &str) -> Result<()> {
    if fs::read_to_string(path).ok().as_deref() == Some(content) {
        return Ok(());
    }
    fs::write(path, content).with_context(|| format!("write {}", path.display()))
}

#[derive(Debug, Deserialize)]
struct TraceRow {
    #[serde(rename = "recommendation_id")]
    id: String,
    #[serde(rename = "recommendation")]
    text: String,
    specification: String,
    acceptance_id: String,
}

pub(crate) fn verify(root: &Path) -> Result<SpecSummary> {
    let patterns = Patterns::new()?;
    let workspace = root
        .parent()
        .context("specification root has no workspace parent")?;
    verify_service_kit(workspace)?;
    validate_structured_files(root)?;
    let frontmatter = validate_frontmatter(root, &patterns)?;
    let overlay = Overlay::verify(root)?;

    let base_modules: ModuleCatalog =
        profiles::load_yaml(&root.join("machine/module-catalog.yaml"))?;
    let base_acceptance: AcceptanceCatalog =
        profiles::load_yaml(&root.join("machine/acceptance-criteria.yaml"))?;
    let base_tasks: TaskCatalog = profiles::load_yaml(&root.join("machine/tasks.yaml"))?;
    let modules: ModuleCatalog = overlay.yaml(root, "machine/module-catalog.yaml")?;
    let acceptance: AcceptanceCatalog = overlay.yaml(root, "machine/acceptance-criteria.yaml")?;
    let tasks: TaskCatalog = overlay.yaml(root, "machine/tasks.yaml")?;
    modules.validate(&patterns)?;
    acceptance.validate(&patterns)?;
    tasks.validate(&patterns)?;

    let profile_summary = profiles::verify(root)?;
    validate_catalog_schemas(root, &overlay)?;
    validate_frontend_exposure(root, &modules, &overlay)?;
    validate_references(&frontmatter, &modules, &acceptance, &tasks)?;
    let recommendation_count = validate_recommendations(root, &frontmatter, &acceptance, &overlay)?;
    let source_count = validate_source_references(root)?;
    validate_contract_examples(root)?;
    validate_integrity(
        root,
        &frontmatter,
        &BundleCounts {
            modules: base_modules.modules.len(),
            profiles: base_profile_count(root)?,
            criteria: base_acceptance.criteria.len(),
            tasks: base_tasks.tasks.len(),
            recommendations: csv_record_count(
                root.join("machine/recommendation-traceability.csv"),
            )?,
            sources: source_count,
        },
    )?;
    validate_markers(root)?;

    Ok(SpecSummary {
        modules: profile_summary.modules,
        profiles: profile_summary.profiles,
        criteria: acceptance.criteria.len(),
        tasks: tasks.tasks.len(),
        recommendations: recommendation_count,
    })
}

fn validate_structured_files(root: &Path) -> Result<()> {
    for path in files(root)? {
        let extension = path.extension().and_then(|extension| extension.to_str());
        if !matches!(extension, Some("yaml" | "yml" | "json" | "toml")) {
            continue;
        }
        let contents =
            fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        match extension {
            Some("yaml" | "yml") => {
                serde_yaml::from_str::<serde_yaml::Value>(&contents)
                    .with_context(|| format!("parse {}", path.display()))?;
            }
            Some("json") => {
                serde_json::from_str::<Value>(&contents)
                    .with_context(|| format!("parse {}", path.display()))?;
            }
            Some("toml") => {
                toml::from_str::<toml::Value>(&contents)
                    .with_context(|| format!("parse {}", path.display()))?;
            }
            _ => unreachable!("structured extensions were filtered above"),
        }
    }
    Ok(())
}

fn validate_frontmatter(root: &Path, patterns: &Patterns) -> Result<HashMap<String, Document>> {
    let mut by_id = HashMap::new();
    for path in files(root)?
        .into_iter()
        .filter(|path| path.extension().is_some_and(|extension| extension == "md"))
    {
        let contents =
            fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let relative_path = relative(root, &path)?;
        let yaml = contents
            .strip_prefix("---\n")
            .and_then(|rest| rest.split_once("\n---\n").map(|(header, _)| header))
            .with_context(|| format!("{relative_path} has invalid YAML frontmatter"))?;
        let metadata: Frontmatter = serde_yaml::from_str(yaml)
            .with_context(|| format!("parse frontmatter for {relative_path}"))?;
        metadata.validate(patterns)?;
        let id = metadata.spec_id.clone();
        let document = Document {
            path: relative_path,
            metadata,
        };
        ensure!(
            by_id.insert(id.clone(), document).is_none(),
            "duplicate spec_id {id}"
        );
    }
    Ok(by_id)
}

struct Document {
    path: String,
    metadata: Frontmatter,
}

fn validate_catalog_schemas(root: &Path, overlay: &Overlay) -> Result<()> {
    for (catalog_name, key, schema_name) in [
        (
            "module-catalog.yaml",
            "modules",
            "module-manifest.schema.json",
        ),
        ("profiles.yaml", "profiles", "profile.schema.json"),
    ] {
        let target = format!("machine/{catalog_name}");
        let catalog = extensions::json_value(overlay.yaml_value(root, &target)?)?;
        let schema: Value =
            serde_json::from_str(&fs::read_to_string(root.join("machine").join(schema_name))?)?;
        let validator = jsonschema::validator_for(&schema)
            .with_context(|| format!("compile machine/{schema_name}"))?;
        let entries = catalog
            .get(key)
            .and_then(Value::as_array)
            .with_context(|| format!("{target} missing {key}"))?;
        for entry in entries {
            let errors: Vec<String> = validator
                .iter_errors(entry)
                .map(|error| error.to_string())
                .collect();
            ensure!(
                errors.is_empty(),
                "{target} schema failure: {}",
                errors.join("; ")
            );
        }
    }
    Ok(())
}

fn validate_frontend_exposure(
    root: &Path,
    modules: &ModuleCatalog,
    overlay: &Overlay,
) -> Result<()> {
    let module_ids = modules
        .modules
        .iter()
        .map(|module| module.id.as_str())
        .collect::<HashSet<_>>();
    let mut exposed = HashSet::<String>::new();
    let sources = overlay.independent_sources("frontend-capabilities.yaml");
    ensure!(
        !sources.is_empty(),
        "no extension declares frontend-capabilities.yaml"
    );

    for source in sources {
        let capability_path = root.join(source);
        let extension = capability_path
            .parent()
            .context("frontend capability catalog has no parent")?;
        let capability_document: Value = extensions::json_value(serde_yaml::from_str(
            &fs::read_to_string(&capability_path)?,
        )?)?;
        let records = capability_document
            .get("capabilities")
            .and_then(Value::as_array)
            .with_context(|| format!("{source} is missing capabilities"))?;
        let schema: Value = serde_json::from_str(&fs::read_to_string(
            extension.join("schemas/frontend-capability.schema.json"),
        )?)?;
        let validator = jsonschema::validator_for(&schema)
            .with_context(|| format!("compile frontend capability schema for {source}"))?;

        for record in records {
            let id = record
                .get("module_id")
                .and_then(Value::as_str)
                .context("frontend capability has no module_id")?;
            ensure!(
                exposed.insert(id.to_owned()),
                "duplicate frontend capability declaration for module {id}"
            );
            ensure!(
                module_ids.contains(id),
                "frontend capability references unknown module {id}"
            );
            let errors = validator
                .iter_errors(record)
                .map(|error| error.to_string())
                .collect::<Vec<_>>();
            ensure!(
                errors.is_empty(),
                "frontend capability {id} schema failure: {}",
                errors.join("; ")
            );
            if record.get("exposure").and_then(Value::as_str) == Some("none") {
                for (section, fields) in [
                    (
                        "contracts",
                        &["openapi_tags", "asyncapi_events", "runtime_capabilities"][..],
                    ),
                    (
                        "provides",
                        &[
                            "core_exports",
                            "react_exports",
                            "route_requirements",
                            "query_effects",
                            "testing",
                        ][..],
                    ),
                ] {
                    let values = record
                        .get(section)
                        .and_then(Value::as_object)
                        .context("frontend capability section is not an object")?;
                    ensure!(
                        fields.iter().all(|field| {
                            values
                                .get(*field)
                                .and_then(Value::as_array)
                                .is_none_or(Vec::is_empty)
                        }),
                        "headless module {id} declares frontend contracts or exports"
                    );
                }
            }
        }
    }

    let mut missing = module_ids
        .iter()
        .copied()
        .filter(|id| !exposed.contains(*id))
        .collect::<Vec<_>>();
    missing.sort_unstable();
    ensure!(
        missing.is_empty(),
        "modules missing frontend exposure declarations: {}",
        missing.join(", ")
    );
    Ok(())
}

fn validate_references(
    documents: &HashMap<String, Document>,
    modules: &ModuleCatalog,
    acceptance: &AcceptanceCatalog,
    tasks: &TaskCatalog,
) -> Result<()> {
    let spec_ids: HashSet<&str> = documents.keys().map(String::as_str).collect();
    let acceptance_by_id: HashMap<&str, _> = acceptance
        .criteria
        .iter()
        .map(|criterion| (criterion.id.as_str(), criterion))
        .collect();
    let task_by_id: HashMap<&str, &Task> = tasks
        .tasks
        .iter()
        .map(|task| (task.id.as_str(), task))
        .collect();

    for criterion in &acceptance.criteria {
        ensure!(
            spec_ids.contains(criterion.spec.as_str()),
            "acceptance {} references unknown spec {}",
            criterion.id,
            criterion.spec
        );
    }
    for module in &modules.modules {
        ensure!(
            spec_ids.contains(module.spec.as_str()),
            "module {} references unknown spec {}",
            module.id,
            module.spec
        );
        for criterion in &module.acceptance {
            ensure!(
                acceptance_by_id.contains_key(criterion.as_str()),
                "module {} references unknown acceptance {criterion}",
                module.id
            );
        }
    }
    for task in &tasks.tasks {
        let phase = phase_rank(&task.phase)?;
        for dependency in &task.depends_on {
            let dependency_task = task_by_id.get(dependency.as_str()).with_context(|| {
                format!(
                    "task {} references unknown dependency {dependency}",
                    task.id
                )
            })?;
            ensure!(
                phase_rank(&dependency_task.phase)? <= phase,
                "task {} depends on later-phase task {dependency}",
                task.id
            );
        }
        for criterion_id in &task.acceptance {
            let criterion = acceptance_by_id
                .get(criterion_id.as_str())
                .with_context(|| {
                    format!(
                        "task {} references unknown acceptance {criterion_id}",
                        task.id
                    )
                })?;
            if task.phase == "0" {
                ensure!(
                    ["build", "compile", "dependency"].contains(&criterion.verification.as_str()),
                    "phase 0 task {} maps behavioral acceptance {criterion_id}",
                    task.id
                );
            }
        }
    }
    validate_task_dag(&task_by_id)
}

fn validate_task_dag(tasks: &HashMap<&str, &Task>) -> Result<()> {
    fn visit<'a>(
        id: &'a str,
        tasks: &HashMap<&'a str, &'a Task>,
        visiting: &mut HashSet<&'a str>,
        complete: &mut HashSet<&'a str>,
    ) -> Result<()> {
        if complete.contains(id) {
            return Ok(());
        }
        ensure!(visiting.insert(id), "task dependency cycle at {id}");
        let task = tasks
            .get(id)
            .with_context(|| format!("unknown task {id}"))?;
        for dependency in &task.depends_on {
            visit(dependency, tasks, visiting, complete)?;
        }
        visiting.remove(id);
        complete.insert(id);
        Ok(())
    }

    let mut visiting = HashSet::new();
    let mut complete = HashSet::new();
    for id in tasks.keys() {
        visit(id, tasks, &mut visiting, &mut complete)?;
    }
    Ok(())
}

fn validate_recommendations(
    root: &Path,
    documents: &HashMap<String, Document>,
    acceptance: &AcceptanceCatalog,
    overlay: &Overlay,
) -> Result<usize> {
    let mut recommendations = Vec::new();
    for source in overlay.csv_sources("machine/recommendation-traceability.csv")? {
        let mut reader = Reader::from_path(root.join(source))?;
        recommendations.extend(reader.deserialize().collect::<Result<Vec<TraceRow>, _>>()?);
    }
    ensure_unique(
        recommendations.iter().map(|item| item.id.as_str()),
        "recommendation IDs",
    )?;
    let acceptance_ids: HashSet<&str> = acceptance
        .criteria
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    for item in &recommendations {
        ensure!(
            !item.text.trim().is_empty(),
            "recommendation {} is empty",
            item.id
        );
        for spec in split_references(&item.specification) {
            ensure!(
                documents.contains_key(spec),
                "recommendation {} references unknown spec {spec}",
                item.id
            );
        }
        for criterion in split_references(&item.acceptance_id) {
            ensure!(
                acceptance_ids.contains(criterion),
                "recommendation {} references unknown acceptance {criterion}",
                item.id
            );
        }
    }
    Ok(recommendations.len())
}

fn phase_rank(phase: &str) -> Result<u16> {
    if let Some(web_phase) = phase.strip_prefix('W') {
        return Ok(100 + web_phase.parse::<u16>()?);
    }
    if let Some(ai_phase) = phase.strip_prefix('A') {
        return Ok(200 + ai_phase.parse::<u16>()?);
    }
    Ok(phase.parse::<u16>()?)
}

fn base_profile_count(root: &Path) -> Result<usize> {
    let document: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(root.join("machine/profiles.yaml"))?)?;
    document
        .get("profiles")
        .and_then(serde_yaml::Value::as_sequence)
        .map(Vec::len)
        .context("machine/profiles.yaml is missing profiles")
}

fn csv_record_count(path: PathBuf) -> Result<usize> {
    let mut reader = Reader::from_path(path)?;
    Ok(reader.records().collect::<Result<Vec<_>, _>>()?.len())
}

fn split_references(value: &str) -> impl Iterator<Item = &str> {
    value
        .split([';', ','])
        .map(str::trim)
        .filter(|part| !part.is_empty())
}

fn validate_source_references(root: &Path) -> Result<usize> {
    let pattern = Regex::new(r"SRC-[A-Z0-9-]+")?;
    let source_text = fs::read_to_string(root.join("research/sources.md"))?;
    let sources: HashSet<&str> = pattern
        .find_iter(&source_text)
        .map(|item| item.as_str())
        .collect();
    for relative_path in [
        "21-crate-selection-matrix.md",
        "research/compatibility-findings.md",
    ] {
        let contents = fs::read_to_string(root.join(relative_path))?;
        for source in pattern.find_iter(&contents).map(|item| item.as_str()) {
            ensure!(
                sources.contains(source),
                "{relative_path} references unknown source {source}"
            );
        }
    }
    Ok(sources.len())
}

fn validate_contract_examples(root: &Path) -> Result<()> {
    for (schema_name, example_name) in [
        ("problem-details.schema.json", "problem-details.json"),
        ("event-envelope.schema.json", "event-envelope.json"),
        ("job-envelope.schema.json", "job-envelope.json"),
    ] {
        let schema: Value =
            serde_json::from_str(&fs::read_to_string(root.join("machine").join(schema_name))?)?;
        let example: Value = serde_json::from_str(&fs::read_to_string(
            root.join("examples").join(example_name),
        )?)?;
        let validator = jsonschema::validator_for(&schema)
            .with_context(|| format!("compile machine/{schema_name}"))?;
        let errors: Vec<String> = validator
            .iter_errors(&example)
            .map(|error| error.to_string())
            .collect();
        ensure!(
            errors.is_empty(),
            "examples/{example_name} schema failure: {}",
            errors.join("; ")
        );
    }
    Ok(())
}

fn validate_integrity(
    root: &Path,
    documents: &HashMap<String, Document>,
    bundle_counts: &BundleCounts,
) -> Result<()> {
    let manifest: Value = serde_json::from_str(&fs::read_to_string(root.join("MANIFEST.json"))?)?;
    let manifest_files = manifest
        .get("files")
        .and_then(Value::as_array)
        .context("MANIFEST.json missing files")?;
    let mut declared = HashSet::new();
    for entry in manifest_files {
        let path = json_string(entry, "path")?;
        ensure!(
            declared.insert(path),
            "MANIFEST.json contains duplicate path {path}"
        );
        validate_digest_entry(root, path, entry)?;
    }
    let extension_files = validate_extension_integrity(root, &declared)?;
    let actual: HashSet<String> = files(root)?
        .into_iter()
        .map(|path| relative(root, &path))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|path| {
            path != "MANIFEST.json" && path != "SHA256SUMS" && !extension_files.contains(path)
        })
        .collect();
    ensure!(
        declared == actual.iter().map(String::as_str).collect(),
        "MANIFEST.json file inventory differs from the bundle"
    );

    let counts = manifest
        .get("counts")
        .and_then(Value::as_object)
        .context("MANIFEST.json missing counts")?;
    let markdown_count = actual
        .iter()
        .filter(|path| has_extension(path, "md"))
        .count();
    let numbered_count = actual
        .iter()
        .filter(|path| {
            path.len() >= 6
                && path.as_bytes()[0].is_ascii_digit()
                && path.as_bytes()[1].is_ascii_digit()
                && path.as_bytes()[2] == b'-'
                && has_extension(path, "md")
        })
        .count();
    let adr_count = actual
        .iter()
        .filter(|path| path.starts_with("adr/") && has_extension(path, "md"))
        .count();
    for (key, expected) in [
        ("files_excluding_manifest_and_checksums", actual.len()),
        ("markdown_documents", markdown_count),
        ("numbered_specs", numbered_count),
        ("adrs", adr_count),
        ("modules", bundle_counts.modules),
        ("profiles", bundle_counts.profiles),
        ("acceptance_criteria", bundle_counts.criteria),
        ("tasks", bundle_counts.tasks),
        ("recommendations", bundle_counts.recommendations),
        ("research_sources", bundle_counts.sources),
    ] {
        ensure!(
            counts.get(key).and_then(Value::as_u64) == Some(expected as u64),
            "MANIFEST.json count {key} is stale"
        );
    }

    validate_spec_manifest(root, documents)?;
    validate_checksum_file(root, &actual)?;
    Ok(())
}

fn extension_bundle_paths(root: &Path) -> Result<HashSet<String>> {
    let mut paths = HashSet::new();
    for manifest_path in files(root)? {
        if manifest_path.parent() != Some(root) {
            continue;
        }
        let manifest_name = relative(root, &manifest_path)?;
        if !manifest_name.ends_with("_FEATURE_SUITE_MANIFEST.json") {
            continue;
        }
        let manifest: Value = serde_json::from_str(&fs::read_to_string(&manifest_path)?)?;
        let entries = manifest
            .get("files")
            .and_then(Value::as_array)
            .with_context(|| format!("{manifest_name} missing files"))?;
        paths.insert(manifest_name.clone());
        for entry in entries {
            paths.insert(json_string(entry, "path")?.to_owned());
        }
        let checksum_name = manifest_name.replace("MANIFEST.json", "SHA256SUMS");
        if root.join(&checksum_name).is_file() {
            paths.insert(checksum_name);
        }
    }
    Ok(paths)
}

fn validate_spec_manifest(root: &Path, documents: &HashMap<String, Document>) -> Result<()> {
    let manifest: Value = serde_json::from_str(&fs::read_to_string(
        root.join("machine/spec-manifest.json"),
    )?)?;
    ensure!(
        manifest.get("schema_version").and_then(Value::as_u64) == Some(1),
        "spec manifest schema_version must be 1"
    );
    let entries = manifest
        .get("documents")
        .and_then(Value::as_array)
        .context("spec manifest missing documents")?;
    let extension_paths = extension_bundle_paths(root)?;
    let base_document_count = documents
        .values()
        .filter(|document| !extension_paths.contains(&document.path))
        .count();
    ensure!(
        entries.len() == base_document_count,
        "spec manifest document count is stale"
    );
    let mut seen = HashSet::new();
    for entry in entries {
        let id = json_string(entry, "spec_id")?;
        ensure!(
            seen.insert(id),
            "spec manifest contains duplicate spec_id {id}"
        );
        let document = documents
            .get(id)
            .with_context(|| format!("spec manifest references unknown spec_id {id}"))?;
        ensure!(
            json_string(entry, "path")? == document.path,
            "spec manifest path mismatch for {id}"
        );
        ensure!(
            json_string(entry, "title")? == document.metadata.title,
            "spec manifest title mismatch for {id}"
        );
        ensure!(
            json_string(entry, "version")? == document.metadata.version,
            "spec manifest version mismatch for {id}"
        );
        ensure!(
            json_string(entry, "status")? == document.metadata.status,
            "spec manifest status mismatch for {id}"
        );
        ensure!(
            json_string(entry, "last_verified")? == document.metadata.last_verified,
            "spec manifest last_verified mismatch for {id}"
        );
        validate_digest_entry(root, &document.path, entry)?;
    }
    Ok(())
}

fn validate_extension_integrity(
    root: &Path,
    base_paths: &HashSet<&str>,
) -> Result<HashSet<String>> {
    let mut extension_files = HashSet::new();
    for (manifest_name, checksums_name) in [
        (
            "WEB_FEATURE_SUITE_MANIFEST.json",
            "WEB_FEATURE_SUITE_SHA256SUMS",
        ),
        (
            "LLM_MCP_FEATURE_SUITE_MANIFEST.json",
            "LLM_MCP_FEATURE_SUITE_SHA256SUMS",
        ),
    ] {
        let extension_manifest: Value =
            serde_json::from_str(&fs::read_to_string(root.join(manifest_name))?)?;
        let files = extension_manifest
            .get("files")
            .and_then(Value::as_array)
            .with_context(|| format!("{manifest_name} missing files"))?;
        for own_path in [manifest_name, checksums_name] {
            ensure!(
                !base_paths.contains(own_path),
                "extension control path {own_path} collides with the base manifest"
            );
            ensure!(
                extension_files.insert(own_path.to_owned()),
                "extension control path collision at {own_path}"
            );
        }
        let mut extension_declared = HashSet::new();
        for entry in files {
            let path = json_string(entry, "path")?;
            ensure!(
                !base_paths.contains(path),
                "extension path {path} collides with the base manifest"
            );
            ensure!(
                extension_declared.insert(path),
                "{manifest_name} contains duplicate path {path}"
            );
            ensure!(
                extension_files.insert(path.to_owned()),
                "extension path collision at {path}"
            );
            validate_digest_entry(root, path, entry)?;
        }
        validate_extension_checksum_file(root, checksums_name, manifest_name, &extension_declared)?;
    }
    Ok(extension_files)
}

fn validate_extension_checksum_file(
    root: &Path,
    checksum_name: &str,
    manifest_name: &str,
    declared: &HashSet<&str>,
) -> Result<()> {
    let contents = fs::read_to_string(root.join(checksum_name))?;
    let mut checksums = HashMap::new();
    for line in contents.lines() {
        let (digest, path) = line
            .split_once("  ")
            .with_context(|| format!("invalid {checksum_name} line"))?;
        ensure!(
            checksums.insert(path, digest).is_none(),
            "duplicate {checksum_name} path {path}"
        );
    }
    let mut expected = declared.clone();
    expected.insert(manifest_name);
    ensure!(
        checksums.keys().copied().collect::<HashSet<_>>() == expected,
        "{checksum_name} inventory differs from {manifest_name}"
    );
    for (path, expected_digest) in checksums {
        let bytes = fs::read(root.join(path))?;
        ensure!(
            sha256(&bytes) == expected_digest,
            "{checksum_name} digest mismatch for {path}"
        );
    }
    Ok(())
}

fn validate_checksum_file(root: &Path, actual: &HashSet<String>) -> Result<()> {
    let contents = fs::read_to_string(root.join("SHA256SUMS"))?;
    let mut checksums = HashMap::new();
    for line in contents.lines() {
        let (digest, path) = line.split_once("  ").context("invalid SHA256SUMS line")?;
        ensure!(
            checksums.insert(path, digest).is_none(),
            "duplicate SHA256SUMS path {path}"
        );
    }
    let mut expected = actual.clone();
    expected.insert("MANIFEST.json".into());
    ensure!(
        checksums.keys().copied().collect::<HashSet<_>>()
            == expected.iter().map(String::as_str).collect(),
        "SHA256SUMS inventory differs from MANIFEST.json"
    );
    for (path, expected_digest) in checksums {
        let bytes = fs::read(root.join(path))?;
        ensure!(
            sha256(&bytes) == expected_digest,
            "SHA256SUMS digest mismatch for {path}"
        );
    }
    Ok(())
}

fn validate_digest_entry(root: &Path, path: &str, entry: &Value) -> Result<()> {
    let bytes = fs::read(root.join(path)).with_context(|| format!("read manifest path {path}"))?;
    ensure!(
        entry.get("bytes").and_then(Value::as_u64) == Some(bytes.len() as u64),
        "manifest byte count mismatch for {path}"
    );
    ensure!(
        json_string(entry, "sha256")? == sha256(&bytes),
        "manifest digest mismatch for {path}"
    );
    Ok(())
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

fn json_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string field {key}"))
}

fn validate_markers(root: &Path) -> Result<()> {
    for path in files(root)? {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if !["md", "yaml", "yml", "toml", "json", "csv"].contains(&extension) {
            continue;
        }
        let contents = fs::read_to_string(&path)?;
        for marker in PROHIBITED_MARKERS {
            ensure!(
                !contents.contains(marker),
                "{} contains prohibited marker {marker}",
                relative(root, &path)?
            );
        }
    }
    Ok(())
}

fn files(root: &Path) -> Result<Vec<PathBuf>> {
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .map(|entry| entry.context("walk specification bundle"))
        .filter_map(|entry| match entry {
            Ok(entry) if entry.file_type().is_file() => {
                let hidden = entry.path().strip_prefix(root).is_ok_and(|relative| {
                    relative
                        .components()
                        .any(|component| component.as_os_str().to_string_lossy().starts_with('.'))
                });
                (!hidden).then(|| Ok(entry.into_path()))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}
fn has_extension(path: &str, extension: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case(extension))
}

fn relative(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)
        .with_context(|| format!("{} is outside {}", path.display(), root.display()))?
        .to_string_lossy()
        .replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> Result<PathBuf> {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("xtask must be a workspace member")
            .map(Path::to_path_buf)
    }

    #[test]
    fn service_kit_generation_is_deterministic() -> Result<()> {
        let first = generated_service_kit(&workspace()?)?;
        let second = generated_service_kit(&workspace()?)?;

        assert_eq!(first, second);
        Ok(())
    }

    #[test]
    fn service_kit_features_exclude_runtime_tooling() -> Result<()> {
        let generated = generated_service_kit(&workspace()?)?;
        let features = generated
            .manifest
            .split_once("omnius:managed-begin id=composition-features")
            .and_then(|(_, source)| {
                source.split_once("# omnius:managed-end id=composition-features")
            })
            .map(|(features, _)| features)
            .context("generated manifest is missing its feature region")?;

        assert!(features.contains("default = []\n"));
        assert!(features.contains("test-support = ["));
        assert!(!features.contains("\ngenerator = ["));
        assert!(!features.contains("\nconsumer-contracts = ["));
        Ok(())
    }

    #[test]
    fn service_kit_catalog_validates_before_dispatch() -> Result<()> {
        let generated = generated_service_kit(&workspace()?)?;
        let validation = generated
            .catalog
            .find("validate_selection(selected)?;")
            .context("generated catalog has no pre-dispatch validation")?;
        let dispatch = generated
            .catalog
            .find("for &module in selected")
            .context("generated catalog has no registrar dispatch")?;

        assert!(validation < dispatch);
        Ok(())
    }
}
