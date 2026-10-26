use std::collections::HashSet;

use anyhow::{Result, ensure};
use omnius_generator::{ApplicationRequirement, hierarchical_environment_key};
use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModuleCatalog {
    pub(crate) schema_version: u64,
    pub(crate) bundle_version: String,
    pub(crate) modules: Vec<Module>,
    #[serde(rename = "runtime_dependencies")]
    pub(crate) _runtime_dependencies: Vec<serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Module {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) version: String,
    pub(crate) owner: String,
    pub(crate) spec: String,
    pub(crate) kind: String,
    pub(crate) requires: Vec<String>,
    pub(crate) conflicts_with: Vec<String>,
    pub(crate) provider_slot: Option<String>,
    pub(crate) criticality: String,
    #[serde(rename = "runtime_toggle")]
    pub(crate) _runtime_toggle: bool,
    pub(crate) runtime_dependencies: Vec<String>,
    pub(crate) primary_crates: Vec<String>,
    pub(crate) composition: ModuleComposition,
    pub(crate) acceptance: Vec<String>,
    pub(crate) persistence: Vec<String>,
    pub(crate) configuration: ModuleConfiguration,
    pub(crate) routes: Vec<String>,
    pub(crate) background_tasks: Vec<String>,
    pub(crate) health_checks: Vec<String>,
    pub(crate) metrics_prefix: String,
    pub(crate) test_fixtures: Vec<String>,
    #[serde(default)]
    pub(crate) application_templates: Vec<String>,
    pub(crate) generator_ownership: GeneratorOwnership,
    pub(crate) removal_behavior: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModuleComposition {
    pub(crate) crates: Vec<CompositionCrate>,
    pub(crate) registrar: bool,
    pub(crate) application_requirements: Vec<ApplicationRequirement>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompositionCrate {
    pub(crate) dependency: String,
    pub(crate) features: Vec<String>,
    #[serde(default)]
    pub(crate) weak_features: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModuleConfiguration {
    pub(crate) prefix: String,
    pub(crate) schema: Option<String>,
    pub(crate) secret_fields: Vec<String>,
    #[serde(default)]
    pub(crate) fields: Vec<ConfigurationField>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfigurationField {
    pub(crate) path: String,
    #[serde(rename = "type")]
    pub(crate) value_type: ConfigurationValueType,
    pub(crate) required: bool,
    #[serde(default)]
    pub(crate) reference_default: Option<ConfigurationValue>,
    #[serde(default)]
    pub(crate) environment: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ConfigurationValueType {
    String,
    Integer,
    Boolean,
    StringArray,
    IntegerArray,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum ConfigurationValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    StringArray(Vec<String>),
    IntegerArray(Vec<i64>),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GeneratorOwnership {
    pub(crate) managed_regions: Vec<String>,
    pub(crate) derived: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcceptanceCatalog {
    pub(crate) schema_version: u64,
    pub(crate) bundle_version: String,
    pub(crate) last_verified: String,
    pub(crate) criteria: Vec<AcceptanceCriterion>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcceptanceCriterion {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) verification: String,
    pub(crate) spec: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskCatalog {
    pub(crate) schema_version: u64,
    pub(crate) bundle_version: String,
    pub(crate) tasks: Vec<Task>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Task {
    pub(crate) id: String,
    pub(crate) phase: String,
    pub(crate) title: String,
    pub(crate) depends_on: Vec<String>,
    pub(crate) outputs: String,
    pub(crate) acceptance: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Frontmatter {
    pub(crate) spec_id: String,
    pub(crate) title: String,
    pub(crate) version: String,
    pub(crate) status: String,
    pub(crate) last_verified: String,
}

pub(crate) struct Patterns {
    module_id: Regex,
    version: Regex,
    spec_id: Regex,
    numbered_spec_id: Regex,
    acceptance_id: Regex,
    config_prefix: Regex,
    task_id: Regex,
    date: Regex,
}

impl Patterns {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            module_id: Regex::new(r"^[a-z][a-z0-9-]*$")?,
            version: Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+].*)?$")?,
            spec_id: Regex::new(r"^(?:OMNIUS-[A-Z0-9]+(?:-[A-Z0-9]+)*|ADR-[0-9]{4})$")?,
            numbered_spec_id: Regex::new(r"^OMNIUS-[0-9]{3}$")?,
            acceptance_id: Regex::new(r"^AC-[A-Z]+-[0-9]{3}$")?,
            config_prefix: Regex::new(r"^[a-z][a-z0-9_]*$")?,
            task_id: Regex::new(r"^T[0-9]{3}$")?,
            date: Regex::new(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")?,
        })
    }
}

impl ModuleCatalog {
    pub(crate) fn validate(&self, patterns: &Patterns) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "module catalog schema_version must be 1"
        );
        ensure!(
            patterns.version.is_match(&self.bundle_version),
            "invalid module catalog bundle_version"
        );
        ensure_unique(
            self.modules.iter().map(|module| module.id.as_str()),
            "module IDs",
        )?;
        for module in &self.modules {
            module.validate(patterns)?;
        }
        Ok(())
    }
}

impl Module {
    #[allow(clippy::too_many_lines)] // Keeping catalog invariants together makes validation auditable.
    fn validate(&self, patterns: &Patterns) -> Result<()> {
        let label = format!("module {}", self.id);
        ensure!(patterns.module_id.is_match(&self.id), "{label}: invalid ID");
        ensure!(!self.title.trim().is_empty(), "{label}: title is empty");
        ensure!(
            patterns.version.is_match(&self.version),
            "{label}: invalid version"
        );
        ensure!(!self.owner.trim().is_empty(), "{label}: owner is empty");
        ensure!(
            patterns.numbered_spec_id.is_match(&self.spec),
            "{label}: invalid spec ID"
        );
        ensure!(
            [
                "kernel",
                "capability",
                "infrastructure",
                "transport",
                "product",
                "tooling"
            ]
            .contains(&self.kind.as_str()),
            "{label}: invalid kind {}",
            self.kind
        );
        ensure!(
            ["required", "degraded", "best-effort"].contains(&self.criticality.as_str()),
            "{label}: invalid criticality {}",
            self.criticality
        );
        validate_string_list(&self.requires, "requires", &label)?;
        validate_string_list(&self.conflicts_with, "conflicts_with", &label)?;
        validate_string_list(&self.runtime_dependencies, "runtime_dependencies", &label)?;
        validate_string_list(&self.primary_crates, "primary_crates", &label)?;
        ensure_unique(
            self.composition
                .crates
                .iter()
                .map(|dependency| dependency.dependency.as_str()),
            &format!("{label}.composition.crates"),
        )?;
        for dependency in &self.composition.crates {
            ensure!(
                !dependency.dependency.trim().is_empty(),
                "{label}: composition crate dependency is empty"
            );
            validate_string_list(&dependency.features, "composition.crates.features", &label)?;
            validate_string_list(
                &dependency.weak_features,
                "composition.crates.weak_features",
                &label,
            )?;
            ensure!(
                dependency.features.is_empty() || dependency.weak_features.is_empty(),
                "{label}: composition crate dependency cannot declare both strong and weak features"
            );
        }
        ensure_unique(
            self.composition
                .application_requirements
                .iter()
                .map(ApplicationRequirement::as_str),
            &format!("{label}.composition.application_requirements"),
        )?;
        validate_string_list(&self.persistence, "persistence", &label)?;
        validate_string_list(&self.routes, "routes", &label)?;
        validate_string_list(&self.background_tasks, "background_tasks", &label)?;
        validate_string_list(&self.health_checks, "health_checks", &label)?;
        ensure!(
            self.composition.registrar
                || !self.composition.application_requirements.is_empty()
                || (self.routes.is_empty()
                    && self.background_tasks.is_empty()
                    && self.health_checks.is_empty()),
            "{label}: declares a route, task, or health contract without a registrar or application requirement"
        );
        validate_string_list(&self.test_fixtures, "test_fixtures", &label)?;
        validate_string_list(
            &self.configuration.secret_fields,
            "configuration.secret_fields",
            &label,
        )?;
        validate_string_list(&self.application_templates, "application_templates", &label)?;
        validate_string_list(
            &self.generator_ownership.managed_regions,
            "generator_ownership.managed_regions",
            &label,
        )?;
        validate_string_list(
            &self.generator_ownership.derived,
            "generator_ownership.derived",
            &label,
        )?;
        ensure!(!self.acceptance.is_empty(), "{label}: acceptance is empty");
        validate_string_list(&self.acceptance, "acceptance", &label)?;
        ensure!(
            self.acceptance
                .iter()
                .all(|id| patterns.acceptance_id.is_match(id)),
            "{label}: invalid acceptance ID"
        );
        ensure!(
            patterns.config_prefix.is_match(&self.configuration.prefix),
            "{label}: invalid configuration prefix"
        );
        if let Some(schema) = &self.configuration.schema {
            ensure!(
                !schema.trim().is_empty(),
                "{label}: configuration schema is empty"
            );
        }
        if let Some(slot) = &self.provider_slot {
            ensure!(!slot.trim().is_empty(), "{label}: provider slot is empty");
        }
        validate_configuration(&self.configuration, &label)?;
        ensure!(
            patterns.config_prefix.is_match(&self.metrics_prefix),
            "{label}: invalid metrics prefix"
        );
        ensure!(
            !self.removal_behavior.trim().is_empty(),
            "{label}: removal behavior is empty"
        );
        Ok(())
    }
}

fn validate_configuration(configuration: &ModuleConfiguration, label: &str) -> Result<()> {
    ensure_unique(
        configuration.fields.iter().map(|field| field.path.as_str()),
        &format!("{label}.configuration.fields"),
    )?;
    for secret in &configuration.secret_fields {
        ensure!(
            valid_configuration_path(secret, true),
            "{label}: invalid secret configuration path {secret}"
        );
    }
    for field in &configuration.fields {
        ensure!(
            valid_configuration_path(&field.path, false),
            "{label}: invalid configuration field path {}",
            field.path
        );
        if let Some(value) = &field.reference_default {
            ensure!(
                value.matches(field.value_type),
                "{label}: configuration default for {} does not match declared type",
                field.path
            );
            ensure!(
                !configuration_path_is_secret(&field.path, &configuration.secret_fields),
                "{label}: secret configuration field {} cannot have a reference default",
                field.path
            );
            if let ConfigurationValue::String(value) = value {
                ensure!(
                    !has_unsupported_placeholder(value),
                    "{label}: configuration default for {} contains an unsupported placeholder",
                    field.path
                );
            }
        }
        ensure!(
            field.reference_default.is_none() || field.environment.is_none(),
            "{label}: configuration field {} cannot have both a reference default and required environment binding",
            field.path
        );
        ensure!(
            !field.required || field.reference_default.is_some() || field.environment.is_some(),
            "{label}: required configuration field {} needs a reference default or environment binding",
            field.path
        );
        ensure!(
            field.required || field.environment.is_none(),
            "{label}: optional configuration field {} cannot declare a required environment binding",
            field.path
        );
        if let Some(environment) = &field.environment {
            let expected = hierarchical_environment_key(&field.path);
            ensure!(
                environment == &expected,
                "{label}: configuration field {} must bind exact environment key {expected}",
                field.path
            );
        }
    }
    Ok(())
}

fn valid_configuration_path(path: &str, allow_array: bool) -> bool {
    path.len() <= 256
        && path.split('.').count() >= 2
        && path
            .split('.')
            .all(|component| valid_configuration_component(component, allow_array))
}

fn valid_configuration_component(component: &str, allow_array: bool) -> bool {
    let canonical = if allow_array {
        component.strip_suffix("[]").unwrap_or(component)
    } else {
        component
    };
    (allow_array && canonical == "*")
        || (!canonical.is_empty()
            && canonical
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'))
}

fn configuration_path_is_secret(path: &str, secret_fields: &[String]) -> bool {
    secret_fields.iter().any(|secret| {
        path.split('.')
            .zip(secret.split('.'))
            .all(|(actual, expected)| {
                let actual = actual.strip_suffix("[]").unwrap_or(actual);
                let expected = expected.strip_suffix("[]").unwrap_or(expected);
                expected == "*" || actual == expected
            })
            && path.split('.').count() == secret.split('.').count()
    })
}

fn has_unsupported_placeholder(value: &str) -> bool {
    if value.contains("${") {
        return true;
    }
    let without_service_name = value.replace("{{service-name}}", "");
    without_service_name.contains("{{") || without_service_name.contains("}}")
}

impl ConfigurationValue {
    fn matches(&self, expected: ConfigurationValueType) -> bool {
        match (self, expected) {
            (Self::String(value), ConfigurationValueType::String) => {
                let _ = value;
                true
            }
            (Self::Integer(value), ConfigurationValueType::Integer) => {
                let _ = value;
                true
            }
            (Self::Boolean(value), ConfigurationValueType::Boolean) => {
                let _ = value;
                true
            }
            (Self::StringArray(values), ConfigurationValueType::StringArray) => {
                let _ = values;
                true
            }
            (Self::IntegerArray(values), ConfigurationValueType::IntegerArray) => {
                let _ = values;
                true
            }
            _ => false,
        }
    }
}

impl AcceptanceCatalog {
    pub(crate) fn validate(&self, patterns: &Patterns) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "acceptance catalog schema_version must be 1"
        );
        ensure!(
            patterns.version.is_match(&self.bundle_version),
            "invalid acceptance bundle_version"
        );
        ensure!(
            patterns.date.is_match(&self.last_verified),
            "invalid acceptance last_verified"
        );
        ensure_unique(
            self.criteria.iter().map(|criterion| criterion.id.as_str()),
            "acceptance IDs",
        )?;
        for criterion in &self.criteria {
            ensure!(
                patterns.numbered_spec_id.is_match(&criterion.spec),
                "acceptance {} has invalid spec",
                criterion.id
            );
            ensure!(
                !criterion.title.trim().is_empty(),
                "acceptance {} has empty title",
                criterion.id
            );
            ensure!(
                !criterion.verification.trim().is_empty(),
                "acceptance {} has empty verification",
                criterion.id
            );
        }
        Ok(())
    }
}

impl TaskCatalog {
    pub(crate) fn validate(&self, patterns: &Patterns) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "task catalog schema_version must be 1"
        );
        ensure!(
            patterns.version.is_match(&self.bundle_version),
            "invalid task bundle_version"
        );
        ensure_unique(self.tasks.iter().map(|task| task.id.as_str()), "task IDs")?;
        for task in &self.tasks {
            ensure!(
                patterns.task_id.is_match(&task.id),
                "invalid task ID {}",
                task.id
            );
            ensure!(
                task.phase.parse::<u8>().is_ok()
                    || ['W', 'A'].iter().any(|prefix| {
                        task.phase
                            .strip_prefix(*prefix)
                            .is_some_and(|phase| phase.parse::<u8>().is_ok())
                    }),
                "task {} has invalid phase",
                task.id
            );
            ensure!(
                !task.title.trim().is_empty(),
                "task {} has empty title",
                task.id
            );
            ensure!(
                !task.outputs.trim().is_empty(),
                "task {} has empty outputs",
                task.id
            );
            validate_string_list(&task.depends_on, "depends_on", &format!("task {}", task.id))?;
            ensure!(
                !task.acceptance.is_empty(),
                "task {} has no acceptance criteria",
                task.id
            );
            validate_string_list(&task.acceptance, "acceptance", &format!("task {}", task.id))?;
            ensure!(
                task.acceptance
                    .iter()
                    .all(|id| patterns.acceptance_id.is_match(id)),
                "task {} has invalid acceptance ID",
                task.id
            );
        }
        Ok(())
    }
}

impl Frontmatter {
    pub(crate) fn validate(&self, patterns: &Patterns) -> Result<()> {
        ensure!(
            patterns.spec_id.is_match(&self.spec_id),
            "invalid spec_id {}",
            self.spec_id
        );
        ensure!(
            !self.title.trim().is_empty(),
            "{} has empty title",
            self.spec_id
        );
        ensure!(
            patterns.version.is_match(&self.version),
            "{} has invalid version",
            self.spec_id
        );
        ensure!(
            !self.status.trim().is_empty(),
            "{} has empty status",
            self.spec_id
        );
        ensure!(
            patterns.date.is_match(&self.last_verified),
            "{} has invalid last_verified",
            self.spec_id
        );
        Ok(())
    }
}

fn validate_string_list(values: &[String], field: &str, label: &str) -> Result<()> {
    ensure!(
        values.iter().all(|value| !value.trim().is_empty()),
        "{label}: {field} contains an empty value"
    );
    ensure_unique(
        values.iter().map(String::as_str),
        &format!("{label}.{field}"),
    )
}

pub(crate) fn ensure_unique<'a>(values: impl Iterator<Item = &'a str>, label: &str) -> Result<()> {
    let mut seen = HashSet::new();
    for value in values {
        ensure!(seen.insert(value), "duplicate {label}: {value}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configuration(fields: &str, secrets: &str) -> Result<ModuleConfiguration> {
        Ok(serde_yaml::from_str(&format!(
            "prefix: app\nsecret_fields: {secrets}\nfields: {fields}\n"
        ))?)
    }

    fn rejection(configuration: &ModuleConfiguration) -> String {
        validate_configuration(configuration, "module m")
            .err()
            .map_or_else(String::new, |error| error.to_string())
    }

    #[test]
    fn configuration_paths_require_two_lowercase_components() {
        assert!(valid_configuration_path("http.port", false));
        assert!(valid_configuration_path("a_1.b_2.c", false));
        assert!(!valid_configuration_path("port", false));
        assert!(!valid_configuration_path("http.Port", false));
        assert!(!valid_configuration_path("http..port", false));
        assert!(!valid_configuration_path("http.ports[]", false));
        assert!(valid_configuration_path("http.ports[]", true));
        assert!(valid_configuration_path("providers.*.key", true));
        assert!(!valid_configuration_path("providers.*.key", false));
        assert!(!valid_configuration_path(
            &format!("a.{}", "b".repeat(256)),
            false
        ));
    }

    #[test]
    fn secret_matching_requires_equal_depth_and_honours_wildcards() {
        let secrets = vec!["providers.*.key".to_owned(), "db.urls[]".to_owned()];
        assert!(configuration_path_is_secret(
            "providers.openai.key",
            &secrets
        ));
        assert!(configuration_path_is_secret("db.urls", &secrets));
        assert!(!configuration_path_is_secret("providers.openai", &secrets));
        assert!(!configuration_path_is_secret(
            "providers.openai.key.extra",
            &secrets
        ));
        assert!(!configuration_path_is_secret(
            "providers.openai.token",
            &secrets
        ));
    }

    #[test]
    fn placeholders_allow_only_the_service_name_token() {
        assert!(!has_unsupported_placeholder("{{service-name}}-db"));
        assert!(has_unsupported_placeholder("${HOME}"));
        assert!(has_unsupported_placeholder("{{other}}"));
        assert!(has_unsupported_placeholder("dangling }}"));
    }

    #[test]
    fn configuration_values_match_only_their_declared_type() {
        assert!(ConfigurationValue::Integer(1).matches(ConfigurationValueType::Integer));
        assert!(!ConfigurationValue::Integer(1).matches(ConfigurationValueType::Boolean));
        assert!(
            !ConfigurationValue::StringArray(vec![]).matches(ConfigurationValueType::IntegerArray)
        );
    }

    #[test]
    fn configuration_field_rules_are_enforced() -> Result<()> {
        let valid = configuration(
            "[{path: http.port, type: integer, required: true, reference_default: 8080}, \
              {path: db.url, type: string, required: true, environment: OMNIUS__DB__URL}, \
              {path: db.pool, type: integer, required: false}]",
            "[db.url]",
        )?;
        validate_configuration(&valid, "module m")?;

        let cases = [
            (
                "[{path: a.b, type: string, required: false, reference_default: 1}]",
                "[]",
                "does not match declared type",
            ),
            (
                "[{path: a.b, type: string, required: false, reference_default: x}]",
                "[a.b]",
                "cannot have a reference default",
            ),
            (
                "[{path: a.b, type: string, required: false, reference_default: '${X}'}]",
                "[]",
                "unsupported placeholder",
            ),
            (
                "[{path: a.b, type: string, required: true, reference_default: x, environment: OMNIUS__A__B}]",
                "[]",
                "both a reference default",
            ),
            (
                "[{path: a.b, type: string, required: true}]",
                "[]",
                "needs a reference default or environment",
            ),
            (
                "[{path: a.b, type: string, required: false, environment: OMNIUS__A__B}]",
                "[]",
                "cannot declare a required environment",
            ),
            (
                "[{path: a.b, type: string, required: true, environment: OMNIUS__A__C}]",
                "[]",
                "must bind exact environment key OMNIUS__A__B",
            ),
            (
                "[{path: a.b, type: string, required: false}, {path: a.b, type: string, required: false}]",
                "[]",
                "duplicate",
            ),
            (
                "[{path: Bad, type: string, required: false}]",
                "[]",
                "invalid configuration field path",
            ),
        ];
        for (fields, secrets, expected) in cases {
            let message = rejection(&configuration(fields, secrets)?);
            assert!(message.contains(expected), "{fields}: {message}");
        }
        Ok(())
    }

    type Mutation = fn(&mut Task);

    fn patterns() -> Result<Patterns> {
        Patterns::new()
    }

    fn task(overrides: &str) -> Result<TaskCatalog> {
        Ok(serde_yaml::from_str(&format!(
            "schema_version: 1\nbundle_version: 1.0.0\ntasks:\n  - id: T001\n    phase: W2\n    \
             title: t\n    depends_on: []\n    outputs: o\n    acceptance: [AC-AB-001]\n{overrides}"
        ))?)
    }

    #[test]
    fn task_catalog_accepts_numeric_and_prefixed_phases_only() -> Result<()> {
        let patterns = patterns()?;
        task("")?.validate(&patterns)?;
        for (phase, valid) in [
            ("3", true),
            ("A4", true),
            ("W2", true),
            ("X1", false),
            ("W", false),
            ("1.5", false),
        ] {
            let mut catalog = task("")?;
            catalog.tasks[0].phase = phase.to_owned();
            assert_eq!(catalog.validate(&patterns).is_ok(), valid, "phase {phase}");
        }
        Ok(())
    }

    #[test]
    fn task_catalog_rejects_bad_ids_dependencies_and_acceptance() -> Result<()> {
        let patterns = patterns()?;
        let mutations: [(&str, Mutation); 5] = [
            ("invalid task ID", |task| task.id = "T1".into()),
            ("has no acceptance criteria", |task| task.acceptance.clear()),
            ("invalid acceptance ID", |task| {
                task.acceptance = vec!["AC-ab-1".into()];
            }),
            ("contains an empty value", |task| {
                task.depends_on = vec![" ".into()];
            }),
            ("duplicate", |task| {
                task.acceptance = vec!["AC-AB-001".into(), "AC-AB-001".into()];
            }),
        ];
        for (expected, mutate) in mutations {
            let mut catalog = task("")?;
            mutate(&mut catalog.tasks[0]);
            let message = catalog
                .validate(&patterns)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            assert!(message.contains(expected), "{expected}: {message}");
        }
        let mut wrong_schema = task("")?;
        wrong_schema.schema_version = 2;
        assert!(wrong_schema.validate(&patterns).is_err());
        Ok(())
    }

    #[test]
    fn frontmatter_validates_ids_versions_and_dates() -> Result<()> {
        let patterns = patterns()?;
        let valid = |spec_id: &str, version: &str, date: &str| Frontmatter {
            spec_id: spec_id.into(),
            title: "t".into(),
            version: version.into(),
            status: "draft".into(),
            last_verified: date.into(),
        };
        valid("OMNIUS-001", "1.2.3", "2026-01-31").validate(&patterns)?;
        valid("ADR-0007", "1.0.0-rc.1", "2026-01-31").validate(&patterns)?;
        for (spec_id, version, date) in [
            ("ADR-7", "1.0.0", "2026-01-31"),
            ("omnius-001", "1.0.0", "2026-01-31"),
            ("OMNIUS-001", "1.0", "2026-01-31"),
            ("OMNIUS-001", "1.0.0", "2026-1-31"),
        ] {
            assert!(
                valid(spec_id, version, date).validate(&patterns).is_err(),
                "{spec_id} {version} {date}"
            );
        }
        Ok(())
    }

    #[test]
    fn acceptance_catalog_requires_numbered_specs_and_nonblank_text() -> Result<()> {
        let patterns = patterns()?;
        let catalog = |spec: &str, title: &str| -> Result<AcceptanceCatalog> {
            Ok(serde_yaml::from_str(&format!(
                "schema_version: 1\nbundle_version: 1.0.0\nlast_verified: 2026-01-01\ncriteria:\n  \
                 - {{id: AC-A-001, title: '{title}', verification: v, spec: {spec}}}\n"
            ))?)
        };
        catalog("OMNIUS-012", "t")?.validate(&patterns)?;
        assert!(catalog("ADR-0001", "t")?.validate(&patterns).is_err());
        assert!(catalog("OMNIUS-012", "  ")?.validate(&patterns).is_err());
        Ok(())
    }

    #[test]
    fn ensure_unique_names_the_duplicate() {
        let error = ensure_unique(["a", "b", "a"].into_iter(), "ids")
            .err()
            .map(|e| e.to_string());
        assert_eq!(error.as_deref(), Some("duplicate ids: a"));
    }
}
