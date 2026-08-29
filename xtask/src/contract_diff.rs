use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_CONTRACT_BYTES: u64 = 8 * 1024 * 1024;
const OPENAPI_FILE: &str = "openapi.json";
const ASYNCAPI_FILE: &str = "asyncapi.json";
const PERMISSIONS_FILE: &str = "permissions.json";
const CAPABILITIES_FILE: &str = "capabilities.json";
const MANIFEST_FILE: &str = "contract-manifest.json";
const HTTP_METHODS: &[&str] = &[
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Severity {
    Info,
    Warning,
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) enum ChangeClass {
    #[serde(rename = "additive")]
    Additive,
    #[serde(rename = "behavioral-schema-compatible")]
    BehavioralCompatible,
    #[serde(rename = "deprecated")]
    Deprecated,
    #[serde(rename = "breaking")]
    Breaking,
}

impl ChangeClass {
    const fn severity(self) -> Severity {
        match self {
            Self::Additive => Severity::Info,
            Self::BehavioralCompatible | Self::Deprecated => Severity::Warning,
            Self::Breaking => Severity::Error,
        }
    }
}

impl fmt::Display for ChangeClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Additive => "additive",
            Self::BehavioralCompatible => "behavioral/schema-compatible",
            Self::Deprecated => "deprecated",
            Self::Breaking => "breaking",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Finding {
    pub(crate) severity: Severity,
    pub(crate) class: ChangeClass,
    pub(crate) code: String,
    pub(crate) path: String,
    pub(crate) message: String,
}

impl Finding {
    fn new(
        class: ChangeClass,
        code: impl Into<String>,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity: class.severity(),
            class,
            code: code.into(),
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} [{}] {} {}: {}",
            self.severity, self.class, self.code, self.path, self.message
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub(crate) struct Report {
    pub(crate) findings: Vec<Finding>,
}

impl Report {
    #[must_use]
    pub(crate) fn is_compatible(&self) -> bool {
        !self
            .findings
            .iter()
            .any(|finding| finding.class == ChangeClass::Breaking)
    }

    #[must_use]
    pub(crate) fn breaking_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.class == ChangeClass::Breaking)
            .count()
    }

    fn normalize(&mut self) {
        self.findings.sort_by(|left, right| {
            (&left.path, &left.code, left.class, &left.message).cmp(&(
                &right.path,
                &right.code,
                right.class,
                &right.message,
            ))
        });
        self.findings.dedup();
    }
}

/// Compares the committed candidate against an in-repository artifact or Git revision.
///
/// # Errors
///
/// Returns an error when the baseline is untrusted, a revision cannot be resolved,
/// or either contract set is malformed.
pub(crate) fn compare_against(
    workspace: &Path,
    baseline: &str,
    candidate_input: &Path,
) -> Result<Report> {
    let artifact = workspace.join(baseline);
    if artifact.exists() {
        return compare(workspace, &artifact, candidate_input);
    }
    let absolute_artifact = Path::new(baseline);
    if absolute_artifact.is_absolute() && absolute_artifact.exists() {
        return compare(workspace, absolute_artifact, candidate_input);
    }
    ensure!(
        !baseline.is_empty()
            && baseline.len() <= 128
            && baseline.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b'/' | b'@' | b'~' | b'^' | b'+' | b'-')
            }),
        "baseline is neither a trusted artifact nor a valid Git revision"
    );

    let snapshot = workspace
        .join("target/contract-diff")
        .join(format!("revision-{}", std::process::id()));
    if snapshot.exists() {
        fs::remove_dir_all(&snapshot).context("reset contract revision snapshot")?;
    }
    fs::create_dir_all(&snapshot).context("create contract revision snapshot")?;
    let result = (|| {
        for file in [
            OPENAPI_FILE,
            ASYNCAPI_FILE,
            PERMISSIONS_FILE,
            CAPABILITIES_FILE,
            MANIFEST_FILE,
        ] {
            let object = format!("{baseline}:contracts/{file}");
            let output = Command::new("git")
                .args(["show", object.as_str()])
                .current_dir(workspace)
                .output()
                .context("read contract artifact from Git revision")?;
            ensure!(
                output.status.success(),
                "Git revision does not contain a complete contract set"
            );
            ensure!(
                u64::try_from(output.stdout.len()).is_ok_and(|length| length <= MAX_CONTRACT_BYTES),
                "Git revision contract artifact exceeds its byte limit"
            );
            fs::write(snapshot.join(file), output.stdout)
                .context("write contract revision snapshot")?;
        }
        compare(workspace, &snapshot, candidate_input)
    })();
    let cleanup = fs::remove_dir_all(&snapshot).context("remove contract revision snapshot");
    match (result, cleanup) {
        (Ok(report), Ok(())) => Ok(report),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

/// Compares two complete contract sets located below `workspace`.
///
/// Each input may name a contract directory, a repository/artifact directory
/// containing `contracts/`, or its `contract-manifest.json` file.
///
/// # Errors
///
/// Returns an error when an input escapes the trusted workspace, an artifact is
/// missing or malformed, or a contract set is internally incoherent. Errors do
/// not include caller-supplied filesystem paths.
pub(crate) fn compare(
    workspace: &Path,
    baseline_input: &Path,
    candidate_input: &Path,
) -> Result<Report> {
    let trusted_root = fs::canonicalize(workspace).context("resolve trusted repository root")?;
    ensure!(
        trusted_root.is_dir(),
        "trusted repository root is not a directory"
    );

    let baseline_dir = resolve_contract_dir(&trusted_root, baseline_input, Side::Baseline)?;
    let candidate_dir = resolve_contract_dir(&trusted_root, candidate_input, Side::Candidate)?;
    let baseline = ContractSet::load(&baseline_dir, Side::Baseline)?;
    let candidate = ContractSet::load(&candidate_dir, Side::Candidate)?;

    let mut report = Report::default();
    compare_openapi(&baseline, &candidate, &mut report)?;
    compare_asyncapi(
        baseline.asyncapi.as_ref(),
        candidate.asyncapi.as_ref(),
        &mut report,
    );
    compare_permissions(&baseline.permissions, &candidate.permissions, &mut report);
    compare_capabilities(&baseline.capabilities, &candidate.capabilities, &mut report);
    compare_manifest(&baseline.manifest, &candidate.manifest, &mut report);
    report.normalize();
    Ok(report)
}

/// Prints stable diagnostics and returns an error only for a breaking report.
///
/// Parsing and trust-boundary failures occur in [`compare`], before a report is
/// available. Additive, behavioral, and deprecation findings never fail here.
pub(crate) fn emit_and_enforce(report: &Report) -> Result<()> {
    for finding in &report.findings {
        eprintln!("{finding}");
    }
    let breaking_count = report.breaking_count();
    if !report.is_compatible() {
        bail!("contract compatibility check found {breaking_count} breaking change(s)");
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Side {
    Baseline,
    Candidate,
}

impl Side {
    const fn label(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Candidate => "candidate",
        }
    }
}

fn resolve_contract_dir(trusted_root: &Path, input: &Path, side: Side) -> Result<PathBuf> {
    let canonical = fs::canonicalize(input)
        .with_context(|| format!("resolve {} contract input", side.label()))?;
    ensure!(
        canonical.starts_with(trusted_root),
        "{} contract input is outside trusted repository root",
        side.label()
    );

    let input_dir = if canonical.is_file() {
        ensure!(
            canonical.file_name().and_then(|name| name.to_str()) == Some(MANIFEST_FILE),
            "{} contract input is not a contract directory or manifest",
            side.label()
        );
        canonical
            .parent()
            .context("contract manifest has no parent directory")?
            .to_path_buf()
    } else {
        ensure!(
            canonical.is_dir(),
            "{} contract input is not a directory",
            side.label()
        );
        canonical
    };

    let direct = input_dir.join(OPENAPI_FILE);
    let nested_dir = input_dir.join("contracts");
    let selected = if direct.is_file() {
        input_dir
    } else if nested_dir.join(OPENAPI_FILE).is_file() {
        fs::canonicalize(nested_dir)
            .with_context(|| format!("resolve {} contracts directory", side.label()))?
    } else {
        bail!(
            "{} contract input does not contain a complete contract set",
            side.label()
        );
    };
    ensure!(
        selected.starts_with(trusted_root),
        "{} contracts directory is outside trusted repository root",
        side.label()
    );
    Ok(selected)
}

struct ContractSet {
    openapi_bytes: Vec<u8>,
    openapi: Value,
    asyncapi: Option<AsyncApiDocument>,
    permissions: PermissionCatalog,
    capabilities: CapabilityCatalog,
    manifest: ContractManifest,
}

impl ContractSet {
    fn load(directory: &Path, side: Side) -> Result<Self> {
        let manifest_bytes = read_artifact(directory, MANIFEST_FILE, side)?;
        let manifest: ContractManifest = serde_json::from_slice(&manifest_bytes)
            .with_context(|| format!("parse {} contract manifest", side.label()))?;
        manifest.validate(side)?;

        let openapi_bytes = read_artifact(directory, OPENAPI_FILE, side)?;
        let openapi: Value = serde_json::from_slice(&openapi_bytes)
            .with_context(|| format!("parse {} OpenAPI document", side.label()))?;

        let permissions_bytes = read_artifact(directory, PERMISSIONS_FILE, side)?;
        let permissions: PermissionCatalog = serde_json::from_slice(&permissions_bytes)
            .with_context(|| format!("parse {} permission catalog", side.label()))?;
        permissions.validate(side)?;

        let capabilities_bytes = read_artifact(directory, CAPABILITIES_FILE, side)?;
        let capabilities: CapabilityCatalog = serde_json::from_slice(&capabilities_bytes)
            .with_context(|| format!("parse {} capability catalog", side.label()))?;
        capabilities.validate(side)?;

        let asyncapi_declared = manifest.declares_contract("contracts/asyncapi.json");
        let asyncapi_exists = directory
            .join(ASYNCAPI_FILE)
            .try_exists()
            .with_context(|| format!("inspect {} AsyncAPI artifact", side.label()))?;
        ensure!(
            asyncapi_declared == asyncapi_exists,
            "{} AsyncAPI artifact presence differs from its manifest inventory",
            side.label()
        );
        let asyncapi = if asyncapi_declared {
            let bytes = read_artifact(directory, ASYNCAPI_FILE, side)?;
            Some(AsyncApiDocument::parse(&bytes, side)?)
        } else {
            None
        };

        Ok(Self {
            openapi_bytes,
            openapi,
            asyncapi,
            permissions,
            capabilities,
            manifest,
        })
    }
}

fn read_artifact(directory: &Path, file_name: &str, side: Side) -> Result<Vec<u8>> {
    let path = fs::canonicalize(directory.join(file_name))
        .with_context(|| format!("resolve {} contract artifact", side.label()))?;
    ensure!(
        path.starts_with(directory),
        "{} contract artifact escapes its contract directory",
        side.label()
    );
    let metadata = fs::metadata(&path)
        .with_context(|| format!("inspect {} contract artifact", side.label()))?;
    ensure!(
        metadata.is_file(),
        "{} contract artifact is not a file",
        side.label()
    );
    ensure!(
        metadata.len() <= MAX_CONTRACT_BYTES,
        "{} contract artifact exceeds the size limit",
        side.label()
    );
    fs::read(path).with_context(|| format!("read {} contract artifact", side.label()))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PermissionCatalog {
    schema_version: String,
    permissions: Vec<Permission>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Permission {
    id: String,
    description: String,
    resource: String,
    action: String,
    group: Option<String>,
    deprecated: bool,
    replacement: Option<String>,
}

impl PermissionCatalog {
    fn validate(&self, side: Side) -> Result<()> {
        ensure_nonempty(&self.schema_version, side, "permission schema version")?;
        let mut previous = None;
        let ids: BTreeSet<_> = self
            .permissions
            .iter()
            .map(|permission| permission.id.as_str())
            .collect();
        ensure!(
            ids.len() == self.permissions.len(),
            "{} permission catalog contains duplicate identifiers",
            side.label()
        );
        for permission in &self.permissions {
            ensure!(
                is_permission_id(&permission.id),
                "{} permission catalog contains an invalid identifier",
                side.label()
            );
            ensure_nonempty(&permission.description, side, "permission description")?;
            ensure_nonempty(&permission.resource, side, "permission resource")?;
            ensure_nonempty(&permission.action, side, "permission action")?;
            if let Some(group) = &permission.group {
                ensure_nonempty(group, side, "permission group")?;
            }
            if let Some(replacement) = &permission.replacement {
                ensure!(
                    permission.deprecated
                        && replacement != &permission.id
                        && ids.contains(replacement.as_str()),
                    "{} permission catalog contains an invalid replacement",
                    side.label()
                );
            }
            ensure_sorted(previous, &permission.id, side, "permission catalog")?;
            previous = Some(permission.id.as_str());
        }
        Ok(())
    }

    fn by_id(&self) -> BTreeMap<&str, &Permission> {
        self.permissions
            .iter()
            .map(|permission| (permission.id.as_str(), permission))
            .collect()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityCatalog {
    schema_version: String,
    service_version: String,
    profile: String,
    contract_hash: String,
    capabilities: Vec<Capability>,
    transports: Transports,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capability {
    id: String,
    compiled: bool,
    runtime_available: bool,
    minimum_sdk_version: String,
    #[serde(default)]
    auth_modes: Vec<String>,
    #[serde(default)]
    auth_roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transports {
    api: String,
    websocket: Option<String>,
    sse: Option<String>,
}

impl CapabilityCatalog {
    fn validate(&self, side: Side) -> Result<()> {
        ensure_nonempty(&self.schema_version, side, "capability schema version")?;
        ensure_nonempty(&self.service_version, side, "capability service version")?;
        ensure_nonempty(&self.profile, side, "capability profile")?;
        ensure!(
            self.contract_hash
                .strip_prefix("sha256:")
                .is_some_and(is_sha256),
            "{} capability catalog contains an invalid contract hash",
            side.label()
        );
        ensure_nonempty(&self.transports.api, side, "API transport")?;
        for transport in [&self.transports.websocket, &self.transports.sse]
            .into_iter()
            .flatten()
        {
            ensure_nonempty(transport, side, "realtime transport")?;
        }

        let mut previous = None;
        let mut ids = BTreeSet::new();
        for capability in &self.capabilities {
            ensure!(
                ids.insert(capability.id.as_str()),
                "{} capability catalog contains duplicate identifiers",
                side.label()
            );
            ensure!(
                is_capability_id(&capability.id),
                "{} capability catalog contains an invalid identifier",
                side.label()
            );
            ensure_nonempty(&capability.minimum_sdk_version, side, "minimum SDK version")?;
            let auth_modes: BTreeSet<_> =
                capability.auth_modes.iter().map(String::as_str).collect();
            ensure!(
                auth_modes.len() == capability.auth_modes.len()
                    && capability
                        .auth_modes
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
                    && auth_modes.iter().all(|mode| matches!(
                        *mode,
                        "none" | "session" | "bearer" | "oidc-redirect"
                    )),
                "{} capability contains invalid authentication modes",
                side.label()
            );
            let auth_roles: BTreeSet<_> =
                capability.auth_roles.iter().map(String::as_str).collect();
            ensure!(
                auth_roles.len() == capability.auth_roles.len()
                    && capability
                        .auth_roles
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
                    && auth_roles.iter().all(|role| matches!(
                        *role,
                        "oauth-resource-server" | "oauth-authorization-server" | "openid-provider"
                    )),
                "{} capability contains invalid authentication roles",
                side.label()
            );
            ensure_sorted(previous, &capability.id, side, "capability catalog")?;
            previous = Some(capability.id.as_str());
        }
        Ok(())
    }

    fn by_id(&self) -> BTreeMap<&str, &Capability> {
        self.capabilities
            .iter()
            .map(|capability| (capability.id.as_str(), capability))
            .collect()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractManifest {
    schema_version: String,
    service_kit_version: String,
    application_version: String,
    build_revision: String,
    #[serde(default)]
    generated_at: Option<String>,
    profile: String,
    modules: Vec<String>,
    contracts: Vec<ManifestContract>,
    aggregate_sha256: String,
    minimum_sdk_version: Option<String>,
    maximum_sdk_version: Option<String>,
    generators: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestContract {
    path: String,
    sha256: String,
    required: bool,
}

impl ContractManifest {
    fn validate(&self, side: Side) -> Result<()> {
        const REQUIRED: &[&str] = &[
            "contracts/capabilities.json",
            "contracts/openapi.json",
            "contracts/permissions.json",
        ];
        for (value, label) in [
            (&self.schema_version, "manifest schema version"),
            (&self.service_kit_version, "service-kit version"),
            (&self.application_version, "application version"),
            (&self.build_revision, "build revision"),
            (&self.profile, "manifest profile"),
        ] {
            ensure_nonempty(value, side, label)?;
        }
        ensure!(
            is_sha256(&self.aggregate_sha256),
            "{} manifest contains an invalid aggregate digest",
            side.label()
        );
        if let Some(generated_at) = &self.generated_at {
            ensure_nonempty(generated_at, side, "manifest generation sentinel")?;
        }
        for version in [&self.minimum_sdk_version, &self.maximum_sdk_version]
            .into_iter()
            .flatten()
        {
            ensure_nonempty(version, side, "manifest SDK version")?;
        }
        ensure!(
            self.modules.windows(2).all(|pair| pair[0] < pair[1])
                && self.modules.iter().all(|module| !module.trim().is_empty()),
            "{} manifest modules are invalid or unsorted",
            side.label()
        );
        ensure!(
            !self.generators.is_empty()
                && self
                    .generators
                    .iter()
                    .all(|(name, version)| !name.trim().is_empty() && !version.trim().is_empty()),
            "{} manifest generator metadata is invalid",
            side.label()
        );

        let has_asyncapi = self.declares_contract("contracts/asyncapi.json");
        let mut expected = Vec::with_capacity(REQUIRED.len() + usize::from(has_asyncapi));
        if has_asyncapi {
            expected.push("contracts/asyncapi.json");
        }
        expected.extend(REQUIRED);
        ensure!(
            self.contracts.len() == expected.len(),
            "{} manifest contract inventory is incomplete",
            side.label()
        );
        for (entry, expected) in self.contracts.iter().zip(expected) {
            ensure!(
                entry.path == expected && entry.required && is_sha256(&entry.sha256),
                "{} manifest contract inventory is invalid, unsorted, or optional",
                side.label()
            );
        }
        ensure!(
            has_asyncapi || !self.generators.contains_key("asyncapi"),
            "{} manifest claims AsyncAPI generator ownership without an AsyncAPI contract",
            side.label()
        );
        Ok(())
    }

    fn declares_contract(&self, path: &str) -> bool {
        self.contracts.iter().any(|entry| entry.path == path)
    }
}

fn ensure_nonempty(value: &str, side: Side, label: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty(),
        "{} {label} is empty",
        side.label()
    );
    Ok(())
}

fn ensure_sorted(previous: Option<&str>, current: &str, side: Side, label: &str) -> Result<()> {
    ensure!(
        previous.is_none_or(|previous| previous < current),
        "{} {label} is not deterministically sorted",
        side.label()
    );
    Ok(())
}

fn is_permission_id(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '_' | '.' | ':' | '-')
        })
}

fn is_capability_id(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn compare_openapi(
    baseline: &ContractSet,
    candidate: &ContractSet,
    report: &mut Report,
) -> Result<()> {
    let breaking =
        omnius_openapi::breaking_changes(&baseline.openapi_bytes, &candidate.openapi_bytes)
            .context("validate and compare OpenAPI documents")?;
    for change in breaking {
        report.findings.push(Finding::new(
            ChangeClass::Breaking,
            openapi_breaking_code(change.kind()),
            artifact_pointer(OPENAPI_FILE, change.location()),
            change.kind().to_string(),
        ));
    }

    let baseline_operations = openapi_operations(&baseline.openapi);
    let candidate_operations = openapi_operations(&candidate.openapi);
    for (operation_id, baseline_operation) in &baseline_operations {
        let path = format!(
            "{OPENAPI_FILE}#/operations/{}",
            escape_pointer(operation_id)
        );
        let Some(candidate_operation) = candidate_operations.get(operation_id) else {
            report.findings.push(Finding::new(
                ChangeClass::Breaking,
                "openapi.operation.removed",
                path,
                "public OpenAPI operation identifier was removed or renamed",
            ));
            continue;
        };
        if baseline_operation.location != candidate_operation.location {
            report.findings.push(Finding::new(
                ChangeClass::Breaking,
                "openapi.operation.location-changed",
                path.clone(),
                "public OpenAPI operation moved to a different method or path",
            ));
        }
        compare_deprecation(
            baseline_operation.value,
            candidate_operation.value,
            "openapi.operation.deprecated",
            &path,
            "OpenAPI operation",
            report,
        );
        if baseline_operation.value.get("security") != candidate_operation.value.get("security") {
            report.findings.push(Finding::new(
                ChangeClass::BehavioralCompatible,
                "openapi.operation.security-changed",
                format!("{path}/security"),
                "OpenAPI operation security metadata changed",
            ));
        }
        compare_success_response_additions(
            baseline_operation.value,
            candidate_operation.value,
            &path,
            report,
        );
    }
    for operation_id in candidate_operations.keys() {
        if !baseline_operations.contains_key(operation_id) {
            report.findings.push(Finding::new(
                ChangeClass::Additive,
                "openapi.operation.added",
                format!(
                    "{OPENAPI_FILE}#/operations/{}",
                    escape_pointer(operation_id)
                ),
                "public OpenAPI operation identifier was added",
            ));
        }
    }

    let baseline_schemas = openapi_schemas(&baseline.openapi);
    let candidate_schemas = openapi_schemas(&candidate.openapi);
    compare_named_openapi_schemas(&baseline_schemas, &candidate_schemas, report);
    Ok(())
}

fn openapi_breaking_code(kind: omnius_openapi::BreakingChangeKind) -> &'static str {
    use omnius_openapi::BreakingChangeKind;

    match kind {
        BreakingChangeKind::PathRemoved => "openapi.path-removed",
        BreakingChangeKind::MethodRemoved => "openapi.method-removed",
        BreakingChangeKind::RequestMediaTypeRemoved => "openapi.request-media-type-removed",
        BreakingChangeKind::ResponseStatusRemoved => "openapi.response-status-removed",
        BreakingChangeKind::ResponseMediaTypeRemoved => "openapi.response-media-type-removed",
        BreakingChangeKind::ParameterRemoved => "openapi.parameter-removed",
        BreakingChangeKind::ParameterNowRequired => "openapi.parameter-now-required",
        BreakingChangeKind::RequestBodyNowRequired => "openapi.request-body-now-required",
        BreakingChangeKind::SchemaPropertyRemoved => "openapi.schema-property-removed",
        BreakingChangeKind::SchemaPropertyNowRequired => "openapi.schema-property-now-required",
        BreakingChangeKind::SchemaTypeChanged => "openapi.schema-type-changed",
        BreakingChangeKind::SchemaFormatChanged => "openapi.schema-format-changed",
        BreakingChangeKind::EnumNarrowed => "openapi.enum-narrowed",
        BreakingChangeKind::SchemaConstraintNarrowed => "openapi.schema-constraint-narrowed",
        BreakingChangeKind::SecurityRequirementsStrengthened => {
            "openapi.security-requirements-strengthened"
        }
        _ => "openapi.breaking-change",
    }
}

struct OpenApiOperation<'a> {
    location: String,
    value: &'a Value,
}

fn openapi_operations(root: &Value) -> BTreeMap<String, OpenApiOperation<'_>> {
    let mut operations = BTreeMap::new();
    let Some(paths) = root.get("paths").and_then(Value::as_object) else {
        return operations;
    };
    for (path, path_item) in paths {
        let Some(path_item) = path_item.as_object() else {
            continue;
        };
        for method in HTTP_METHODS {
            let Some(operation) = path_item.get(*method) else {
                continue;
            };
            let Some(operation_id) = operation.get("operationId").and_then(Value::as_str) else {
                continue;
            };
            operations.insert(
                operation_id.to_owned(),
                OpenApiOperation {
                    location: format!("/paths/{}/{method}", escape_pointer(path)),
                    value: operation,
                },
            );
        }
    }
    operations
}

fn openapi_schemas(root: &Value) -> BTreeMap<&str, &Value> {
    root.pointer("/components/schemas")
        .and_then(Value::as_object)
        .map_or_else(BTreeMap::new, |schemas| {
            schemas
                .iter()
                .map(|(name, schema)| (name.as_str(), schema))
                .collect()
        })
}

fn compare_named_openapi_schemas(
    baseline: &BTreeMap<&str, &Value>,
    candidate: &BTreeMap<&str, &Value>,
    report: &mut Report,
) {
    for (name, baseline_schema) in baseline {
        let path = format!(
            "{OPENAPI_FILE}#/components/schemas/{}",
            escape_pointer(name)
        );
        let Some(candidate_schema) = candidate.get(name) else {
            report.findings.push(Finding::new(
                ChangeClass::Breaking,
                "openapi.schema.component-removed",
                path,
                "public OpenAPI schema name was removed or renamed",
            ));
            continue;
        };
        compare_deprecation(
            baseline_schema,
            candidate_schema,
            "openapi.schema.deprecated",
            &path,
            "OpenAPI schema",
            report,
        );
    }
    for name in candidate.keys() {
        if !baseline.contains_key(name) {
            report.findings.push(Finding::new(
                ChangeClass::Additive,
                "openapi.schema.component-added",
                format!(
                    "{OPENAPI_FILE}#/components/schemas/{}",
                    escape_pointer(name)
                ),
                "public OpenAPI schema name was added",
            ));
        }
    }
}

fn compare_success_response_additions(
    baseline: &Value,
    candidate: &Value,
    operation_path: &str,
    report: &mut Report,
) {
    let baseline_statuses = response_statuses(baseline);
    let candidate_statuses = response_statuses(candidate);
    for status in candidate_statuses.difference(&baseline_statuses) {
        if status.starts_with('2') {
            report.findings.push(Finding::new(
                ChangeClass::Additive,
                "openapi.success-response-added",
                format!("{operation_path}/responses/{}", escape_pointer(status)),
                "OpenAPI success response was added",
            ));
        }
    }
}

fn response_statuses(operation: &Value) -> BTreeSet<&str> {
    operation
        .get("responses")
        .and_then(Value::as_object)
        .map_or_else(BTreeSet::new, |responses| {
            responses.keys().map(String::as_str).collect()
        })
}

fn compare_deprecation(
    baseline: &Value,
    candidate: &Value,
    code: &str,
    path: &str,
    subject: &str,
    report: &mut Report,
) {
    let baseline_deprecated = baseline
        .get("deprecated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let candidate_deprecated = candidate
        .get("deprecated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !baseline_deprecated && candidate_deprecated {
        report.findings.push(Finding::new(
            ChangeClass::Deprecated,
            code,
            format!("{path}/deprecated"),
            format!("{subject} was deprecated"),
        ));
    } else if baseline_deprecated && !candidate_deprecated {
        report.findings.push(Finding::new(
            ChangeClass::BehavioralCompatible,
            format!("{code}-removed"),
            format!("{path}/deprecated"),
            format!("{subject} deprecation was removed"),
        ));
    }
}

#[derive(Debug)]
struct AsyncApiDocument {
    root: Value,
    messages: BTreeMap<String, AsyncMessage>,
    channels: BTreeMap<String, AsyncChannel>,
    directions: BTreeMap<String, BTreeSet<MessageRoute>>,
    schema_names: BTreeSet<String>,
}

#[derive(Debug)]
struct AsyncMessage {
    name: String,
    wire_name: String,
    wire_field: &'static str,
    version: String,
    direction: String,
    deprecated: bool,
}

#[derive(Debug)]
struct AsyncChannel {
    address: String,
    messages: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MessageRoute {
    channel: String,
    action: String,
}

impl AsyncApiDocument {
    #[allow(clippy::too_many_lines)] // One pass keeps cross-reference validation coherent.
    fn parse(bytes: &[u8], side: Side) -> Result<Self> {
        let root: Value = serde_json::from_slice(bytes)
            .with_context(|| format!("parse {} AsyncAPI document", side.label()))?;
        ensure!(
            root.get("asyncapi").and_then(Value::as_str) == Some("3.1.0"),
            "{} AsyncAPI document does not use version 3.1.0",
            side.label()
        );
        for pointer in ["/info/title", "/info/version"] {
            ensure!(
                root.pointer(pointer)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty()),
                "{} AsyncAPI document contains invalid info metadata",
                side.label()
            );
        }
        validate_local_references(&root, side)?;

        let component_messages = root
            .pointer("/components/messages")
            .and_then(Value::as_object)
            .context("AsyncAPI components.messages is missing")?;
        ensure!(
            !component_messages.is_empty(),
            "{} AsyncAPI message catalog is empty",
            side.label()
        );
        let mut messages = BTreeMap::new();
        let mut identities = BTreeSet::new();
        let mut message_names = BTreeSet::new();
        for (component, value) in component_messages {
            ensure!(
                !component.trim().is_empty(),
                "{} AsyncAPI contains an empty message component name",
                side.label()
            );
            let message = parse_async_message(value, side)?;
            ensure!(
                message_names.insert(message.name.clone()),
                "{} AsyncAPI contains duplicate public message names",
                side.label()
            );
            ensure!(
                identities.insert((message.wire_name.clone(), message.version.clone())),
                "{} AsyncAPI contains duplicate event name/version identifiers",
                side.label()
            );
            let payload = value
                .get("payload")
                .context("AsyncAPI message payload is missing")?;
            validate_schema_node(payload, side)?;
            messages.insert(component.clone(), message);
        }

        let component_schemas = root
            .pointer("/components/schemas")
            .and_then(Value::as_object)
            .context("AsyncAPI components.schemas is missing")?;
        let mut schema_names = BTreeSet::new();
        for (name, schema) in component_schemas {
            ensure!(
                !name.trim().is_empty() && schema_names.insert(name.clone()),
                "{} AsyncAPI contains an invalid schema component name",
                side.label()
            );
            validate_schema_node(schema, side)?;
        }

        let channel_values = root
            .get("channels")
            .and_then(Value::as_object)
            .context("AsyncAPI channels are missing")?;
        ensure!(
            !channel_values.is_empty(),
            "{} AsyncAPI channel catalog is empty",
            side.label()
        );
        let mut channels = BTreeMap::new();
        let mut channel_coverage = BTreeSet::new();
        for (name, value) in channel_values {
            ensure!(
                !name.trim().is_empty(),
                "{} AsyncAPI contains an empty channel identifier",
                side.label()
            );
            let address = value
                .get("address")
                .and_then(Value::as_str)
                .filter(|address| !address.trim().is_empty())
                .context("AsyncAPI channel address is missing")?;
            let channel_messages = value
                .get("messages")
                .and_then(Value::as_object)
                .context("AsyncAPI channel messages are missing")?;
            ensure!(
                !channel_messages.is_empty(),
                "{} AsyncAPI channel contains no messages",
                side.label()
            );
            let mut names = BTreeSet::new();
            for (component, reference) in channel_messages {
                ensure!(
                    messages.contains_key(component)
                        && referenced_message_component(reference).as_deref() == Some(component),
                    "{} AsyncAPI channel contains an invalid message reference",
                    side.label()
                );
                names.insert(component.clone());
                channel_coverage.insert(component.clone());
            }
            channels.insert(
                name.clone(),
                AsyncChannel {
                    address: address.to_owned(),
                    messages: names,
                },
            );
        }
        ensure!(
            messages.keys().all(|name| channel_coverage.contains(name)),
            "{} AsyncAPI message is not assigned to a channel",
            side.label()
        );

        let operations = root
            .get("operations")
            .and_then(Value::as_object)
            .context("AsyncAPI operations are missing")?;
        ensure!(
            !operations.is_empty(),
            "{} AsyncAPI operation catalog is empty",
            side.label()
        );
        let mut directions: BTreeMap<String, BTreeSet<MessageRoute>> = BTreeMap::new();
        for (operation_name, operation) in operations {
            ensure!(
                !operation_name.trim().is_empty(),
                "{} AsyncAPI contains an empty operation identifier",
                side.label()
            );
            let action = operation
                .get("action")
                .and_then(Value::as_str)
                .filter(|action| matches!(*action, "send" | "receive"))
                .context("AsyncAPI operation action is invalid")?;
            let channel = operation
                .get("channel")
                .and_then(Value::as_object)
                .and_then(|value| value.get("$ref"))
                .and_then(Value::as_str)
                .and_then(referenced_channel)
                .context("AsyncAPI operation channel reference is invalid")?;
            ensure!(
                channels.contains_key(&channel),
                "{} AsyncAPI operation references an unknown channel",
                side.label()
            );
            let operation_messages = operation
                .get("messages")
                .and_then(Value::as_array)
                .context("AsyncAPI operation messages are missing")?;
            ensure!(
                !operation_messages.is_empty(),
                "{} AsyncAPI operation contains no messages",
                side.label()
            );
            for reference in operation_messages {
                let (reference_channel, component) = referenced_channel_message(reference)
                    .context("AsyncAPI operation message reference is invalid")?;
                ensure!(
                    reference_channel == channel
                        && channels
                            .get(&channel)
                            .is_some_and(|entry| entry.messages.contains(&component)),
                    "{} AsyncAPI operation references a message outside its channel",
                    side.label()
                );
                directions
                    .entry(component)
                    .or_default()
                    .insert(MessageRoute {
                        channel: channel.clone(),
                        action: action.to_owned(),
                    });
            }
        }
        for (component, message) in &messages {
            let expected_action = match message.direction.as_str() {
                "client-to-server" => "receive",
                "server-to-client" => "send",
                _ => {
                    bail!("{} AsyncAPI message direction is invalid", side.label())
                }
            };
            ensure!(
                directions.get(component).is_some_and(|routes| {
                    !routes.is_empty() && routes.iter().all(|route| route.action == expected_action)
                }),
                "{} AsyncAPI message direction conflicts with its operations",
                side.label()
            );
        }

        Ok(Self {
            root,
            messages,
            channels,
            directions,
            schema_names,
        })
    }

    fn message_payload(&self, component: &str) -> Option<&Value> {
        self.root.pointer(&format!(
            "/components/messages/{}/payload",
            escape_pointer(component)
        ))
    }

    fn component_schema(&self, name: &str) -> Option<&Value> {
        self.root
            .pointer(&format!("/components/schemas/{}", escape_pointer(name)))
    }
}

fn parse_async_message(value: &Value, side: Side) -> Result<AsyncMessage> {
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .context("AsyncAPI message name is missing")?;
    let (wire_field, wire_value) = ["x-wire-name", "x-event-name", "x-sse-event"]
        .into_iter()
        .find_map(|field| value.get(field).map(|value| (field, value)))
        .context("AsyncAPI event wire identity is missing")?;
    let wire_name =
        public_wire_identity(wire_value).context("AsyncAPI event wire identity is invalid")?;
    let version = value
        .get("x-message-version")
        .or_else(|| value.get("x-event-version"))
        .or_else(|| value.get("x-version"))
        .and_then(public_scalar)
        .context("AsyncAPI message version is missing")?;
    let direction = value
        .get("x-direction")
        .and_then(Value::as_str)
        .filter(|direction| matches!(*direction, "client-to-server" | "server-to-client"))
        .with_context(|| format!("{} AsyncAPI message direction is missing", side.label()))?;
    Ok(AsyncMessage {
        name: name.to_owned(),
        wire_name,
        wire_field,
        version,
        direction: direction.to_owned(),
        deprecated: value
            .get("deprecated")
            .or_else(|| value.get("x-deprecated"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn public_scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn public_wire_identity(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.clone()),
        Value::Object(value) if !value.is_empty() => serde_json::to_string(value).ok(),
        _ => None,
    }
}

fn validate_local_references(root: &Value, side: Side) -> Result<()> {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(object) => {
                if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                    let pointer = reference.strip_prefix('#').with_context(|| {
                        format!("{} AsyncAPI contains a non-local reference", side.label())
                    })?;
                    ensure!(
                        root.pointer(pointer).is_some(),
                        "{} AsyncAPI contains an unresolved local reference",
                        side.label()
                    );
                }
                stack.extend(object.values());
            }
            Value::Array(values) => stack.extend(values),
            _ => {}
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // JSON Schema keyword validation is intentionally centralized.
fn validate_schema_node(schema: &Value, side: Side) -> Result<()> {
    let object = schema
        .as_object()
        .with_context(|| format!("{} AsyncAPI contains a non-object schema", side.label()))?;
    if object.contains_key("$ref") {
        return Ok(());
    }
    if let Some(types) = object.get("type") {
        let valid = match types {
            Value::String(value) => is_json_type(value),
            Value::Array(values) => {
                !values.is_empty()
                    && values
                        .iter()
                        .all(|value| value.as_str().is_some_and(is_json_type))
            }
            _ => false,
        };
        ensure!(valid, "{} AsyncAPI schema type is invalid", side.label());
    }
    if let Some(required) = object.get("required") {
        let required = required
            .as_array()
            .with_context(|| format!("{} AsyncAPI schema required is invalid", side.label()))?;
        let values: BTreeSet<_> = required.iter().filter_map(Value::as_str).collect();
        ensure!(
            values.len() == required.len(),
            "{} AsyncAPI schema required is invalid or duplicated",
            side.label()
        );
    }
    if let Some(properties) = object.get("properties") {
        let properties = properties
            .as_object()
            .with_context(|| format!("{} AsyncAPI schema properties are invalid", side.label()))?;
        for property in properties.values() {
            validate_schema_node(property, side)?;
        }
    }
    if let Some(items) = object.get("items") {
        validate_schema_node(items, side)?;
    }
    if let Some(Value::Object(_)) = object.get("additionalProperties") {
        validate_schema_node(&object["additionalProperties"], side)?;
    } else if object
        .get("additionalProperties")
        .is_some_and(|value| !value.is_boolean())
    {
        bail!(
            "{} AsyncAPI schema additionalProperties is invalid",
            side.label()
        );
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = object.get(keyword) {
            let branches = branches.as_array().with_context(|| {
                format!("{} AsyncAPI schema composition is invalid", side.label())
            })?;
            ensure!(
                !branches.is_empty(),
                "{} AsyncAPI schema composition is empty",
                side.label()
            );
            for branch in branches {
                validate_schema_node(branch, side)?;
            }
        }
    }
    if let Some(negated) = object.get("not") {
        validate_schema_node(negated, side)?;
    }
    if let Some(values) = object.get("enum") {
        let values = values
            .as_array()
            .with_context(|| format!("{} AsyncAPI schema enum is invalid", side.label()))?;
        let canonical: BTreeSet<_> = values.iter().map(canonical_value).collect();
        ensure!(
            !values.is_empty() && canonical.len() == values.len(),
            "{} AsyncAPI schema enum is empty or duplicated",
            side.label()
        );
    }
    for keyword in [
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "minProperties",
        "maxProperties",
    ] {
        ensure!(
            object.get(keyword).is_none_or(Value::is_number),
            "{} AsyncAPI schema constraint is invalid",
            side.label()
        );
    }
    for keyword in ["pattern", "format"] {
        ensure!(
            object.get(keyword).is_none_or(Value::is_string),
            "{} AsyncAPI schema string constraint is invalid",
            side.label()
        );
    }
    Ok(())
}

fn is_json_type(value: &str) -> bool {
    matches!(
        value,
        "null" | "boolean" | "object" | "array" | "number" | "string" | "integer"
    )
}

fn referenced_message_component(value: &Value) -> Option<String> {
    value
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|reference| reference.strip_prefix("#/components/messages/"))
        .and_then(unescape_pointer)
}

fn referenced_channel(value: &str) -> Option<String> {
    value.strip_prefix("#/channels/").and_then(unescape_pointer)
}

fn referenced_channel_message(value: &Value) -> Option<(String, String)> {
    let reference = value.get("$ref")?.as_str()?;
    let remainder = reference.strip_prefix("#/channels/")?;
    let (channel, component) = remainder.split_once("/messages/")?;
    Some((unescape_pointer(channel)?, unescape_pointer(component)?))
}

fn unescape_pointer(value: &str) -> Option<String> {
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character == '~' {
            match characters.next()? {
                '0' => output.push('~'),
                '1' => output.push('/'),
                _ => return None,
            }
        } else {
            output.push(character);
        }
    }
    Some(output)
}

fn compare_asyncapi(
    baseline: Option<&AsyncApiDocument>,
    candidate: Option<&AsyncApiDocument>,
    report: &mut Report,
) {
    let (Some(baseline), Some(candidate)) = (baseline, candidate) else {
        match (baseline, candidate) {
            (Some(_), None) => report.findings.push(Finding::new(
                ChangeClass::Breaking,
                "asyncapi.document.removed",
                ASYNCAPI_FILE,
                "public AsyncAPI document was removed",
            )),
            (None, Some(_)) => report.findings.push(Finding::new(
                ChangeClass::Additive,
                "asyncapi.document.added",
                ASYNCAPI_FILE,
                "public AsyncAPI document was added",
            )),
            (None, None) => {}
            (Some(_), Some(_)) => unreachable!(),
        }
        return;
    };

    for (component, baseline_message) in &baseline.messages {
        let path = format!(
            "{ASYNCAPI_FILE}#/components/messages/{}",
            escape_pointer(component)
        );
        let Some(candidate_message) = candidate.messages.get(component) else {
            report.findings.push(Finding::new(
                ChangeClass::Breaking,
                "asyncapi.message.component-removed",
                path,
                "public AsyncAPI message component was removed or renamed",
            ));
            continue;
        };
        compare_async_message(
            baseline_message,
            candidate_message,
            baseline.message_payload(component),
            candidate.message_payload(component),
            &path,
            report,
        );
    }
    for component in candidate.messages.keys() {
        if !baseline.messages.contains_key(component) {
            report.findings.push(Finding::new(
                ChangeClass::Additive,
                "asyncapi.message.component-added",
                format!(
                    "{ASYNCAPI_FILE}#/components/messages/{}",
                    escape_pointer(component)
                ),
                "public AsyncAPI message component was added",
            ));
        }
    }

    compare_async_schemas(baseline, candidate, report);
    compare_async_channels(baseline, candidate, report);
    compare_async_directions(baseline, candidate, report);
}

fn compare_async_message(
    baseline: &AsyncMessage,
    candidate: &AsyncMessage,
    baseline_payload: Option<&Value>,
    candidate_payload: Option<&Value>,
    path: &str,
    report: &mut Report,
) {
    for (baseline_value, candidate_value, code, field, message) in [
        (
            &baseline.name,
            &candidate.name,
            "asyncapi.message.name-changed",
            "name",
            "public AsyncAPI message name changed",
        ),
        (
            &baseline.wire_name,
            &candidate.wire_name,
            "asyncapi.message.event-name-changed",
            baseline.wire_field,
            "public event wire name changed",
        ),
        (
            &baseline.version,
            &candidate.version,
            "asyncapi.message.version-changed",
            "x-message-version",
            "public event version changed",
        ),
        (
            &baseline.direction,
            &candidate.direction,
            "asyncapi.message.direction-changed",
            "x-direction",
            "public message direction changed",
        ),
    ] {
        if baseline_value != candidate_value {
            report.findings.push(Finding::new(
                ChangeClass::Breaking,
                code,
                format!("{path}/{field}"),
                message,
            ));
        }
    }
    if baseline.wire_field != candidate.wire_field {
        report.findings.push(Finding::new(
            ChangeClass::Breaking,
            "asyncapi.message.event-identity-field-changed",
            format!("{path}/{}", baseline.wire_field),
            "public event wire identity field changed",
        ));
    }
    if !baseline.deprecated && candidate.deprecated {
        report.findings.push(Finding::new(
            ChangeClass::Deprecated,
            "asyncapi.message.deprecated",
            format!("{path}/deprecated"),
            "AsyncAPI message was deprecated",
        ));
    } else if baseline.deprecated && !candidate.deprecated {
        report.findings.push(Finding::new(
            ChangeClass::BehavioralCompatible,
            "asyncapi.message.deprecation-removed",
            format!("{path}/deprecated"),
            "AsyncAPI message deprecation was removed",
        ));
    }
    if let (Some(baseline_payload), Some(candidate_payload)) = (baseline_payload, candidate_payload)
    {
        compare_schema(
            baseline_payload,
            candidate_payload,
            &format!("{path}/payload"),
            report,
        );
    }
}

fn compare_async_schemas(
    baseline: &AsyncApiDocument,
    candidate: &AsyncApiDocument,
    report: &mut Report,
) {
    for name in &baseline.schema_names {
        let path = format!(
            "{ASYNCAPI_FILE}#/components/schemas/{}",
            escape_pointer(name)
        );
        let Some(candidate_schema) = candidate.component_schema(name) else {
            report.findings.push(Finding::new(
                ChangeClass::Breaking,
                "asyncapi.schema.component-removed",
                path,
                "public AsyncAPI schema name was removed or renamed",
            ));
            continue;
        };
        if let Some(baseline_schema) = baseline.component_schema(name) {
            compare_schema(baseline_schema, candidate_schema, &path, report);
        }
    }
    for name in candidate.schema_names.difference(&baseline.schema_names) {
        report.findings.push(Finding::new(
            ChangeClass::Additive,
            "asyncapi.schema.component-added",
            format!(
                "{ASYNCAPI_FILE}#/components/schemas/{}",
                escape_pointer(name)
            ),
            "public AsyncAPI schema name was added",
        ));
    }
}

fn compare_async_channels(
    baseline: &AsyncApiDocument,
    candidate: &AsyncApiDocument,
    report: &mut Report,
) {
    for (name, baseline_channel) in &baseline.channels {
        let path = format!("{ASYNCAPI_FILE}#/channels/{}", escape_pointer(name));
        let Some(candidate_channel) = candidate.channels.get(name) else {
            report.findings.push(Finding::new(
                ChangeClass::Breaking,
                "asyncapi.channel.removed",
                path,
                "public AsyncAPI channel was removed or renamed",
            ));
            continue;
        };
        if baseline_channel.address != candidate_channel.address {
            report.findings.push(Finding::new(
                ChangeClass::Breaking,
                "asyncapi.channel.address-changed",
                format!("{path}/address"),
                "public AsyncAPI channel address changed",
            ));
        }
        for component in baseline_channel
            .messages
            .difference(&candidate_channel.messages)
        {
            report.findings.push(Finding::new(
                ChangeClass::Breaking,
                "asyncapi.channel.message-removed",
                format!("{path}/messages/{}", escape_pointer(component)),
                "message was removed from a public AsyncAPI channel",
            ));
        }
        for component in candidate_channel
            .messages
            .difference(&baseline_channel.messages)
        {
            report.findings.push(Finding::new(
                ChangeClass::Additive,
                "asyncapi.channel.message-added",
                format!("{path}/messages/{}", escape_pointer(component)),
                "message was added to a public AsyncAPI channel",
            ));
        }
    }
    for name in candidate.channels.keys() {
        if !baseline.channels.contains_key(name) {
            report.findings.push(Finding::new(
                ChangeClass::Additive,
                "asyncapi.channel.added",
                format!("{ASYNCAPI_FILE}#/channels/{}", escape_pointer(name)),
                "public AsyncAPI channel was added",
            ));
        }
    }
}

fn compare_async_directions(
    baseline: &AsyncApiDocument,
    candidate: &AsyncApiDocument,
    report: &mut Report,
) {
    for (component, baseline_routes) in &baseline.directions {
        let candidate_routes = candidate.directions.get(component);
        for route in baseline_routes {
            if !candidate_routes.is_some_and(|routes| routes.contains(route)) {
                report.findings.push(Finding::new(
                    ChangeClass::Breaking,
                    "asyncapi.message.route-removed",
                    format!(
                        "{ASYNCAPI_FILE}#/message-routes/{}/{}/{}",
                        escape_pointer(component),
                        escape_pointer(&route.channel),
                        route.action
                    ),
                    "public message channel or direction was removed",
                ));
            }
        }
    }
    for (component, candidate_routes) in &candidate.directions {
        let baseline_routes = baseline.directions.get(component);
        for route in candidate_routes {
            if !baseline_routes.is_some_and(|routes| routes.contains(route)) {
                report.findings.push(Finding::new(
                    ChangeClass::Additive,
                    "asyncapi.message.route-added",
                    format!(
                        "{ASYNCAPI_FILE}#/message-routes/{}/{}/{}",
                        escape_pointer(component),
                        escape_pointer(&route.channel),
                        route.action
                    ),
                    "public message channel and direction was added",
                ));
            }
        }
    }
}

fn compare_schema(baseline: &Value, candidate: &Value, path: &str, report: &mut Report) {
    let (Some(baseline), Some(candidate)) = (baseline.as_object(), candidate.as_object()) else {
        if baseline != candidate {
            schema_change(
                ChangeClass::Breaking,
                "shape-changed",
                path,
                "schema shape changed incompatibly",
                report,
            );
        }
        return;
    };

    compare_schema_types(baseline.get("type"), candidate.get("type"), path, report);
    compare_schema_required(baseline, candidate, path, report);
    compare_schema_properties(baseline, candidate, path, report);
    compare_schema_enum(baseline.get("enum"), candidate.get("enum"), path, report);
    compare_schema_const(baseline.get("const"), candidate.get("const"), path, report);
    compare_schema_reference(baseline.get("$ref"), candidate.get("$ref"), path, report);
    compare_schema_constraints(baseline, candidate, path, report);
    compare_schema_composition(baseline, candidate, path, report);

    if let (Some(baseline_items), Some(candidate_items)) =
        (baseline.get("items"), candidate.get("items"))
    {
        compare_schema(
            baseline_items,
            candidate_items,
            &format!("{path}/items"),
            report,
        );
    } else if baseline.contains_key("items") && !candidate.contains_key("items") {
        schema_change(
            ChangeClass::Additive,
            "items-relaxed",
            &format!("{path}/items"),
            "array item schema constraint was removed",
            report,
        );
    } else if !baseline.contains_key("items") && candidate.contains_key("items") {
        schema_change(
            ChangeClass::Breaking,
            "items-narrowed",
            &format!("{path}/items"),
            "array item schema constraint was added",
            report,
        );
    }

    compare_additional_properties(
        baseline.get("additionalProperties"),
        candidate.get("additionalProperties"),
        path,
        report,
    );
}

fn compare_schema_types(
    baseline: Option<&Value>,
    candidate: Option<&Value>,
    path: &str,
    report: &mut Report,
) {
    let baseline_types = schema_types(baseline);
    let candidate_types = schema_types(candidate);
    match (baseline_types, candidate_types) {
        (Some(baseline), Some(candidate)) if !candidate.is_superset(&baseline) => schema_change(
            ChangeClass::Breaking,
            "type-narrowed",
            &format!("{path}/type"),
            "schema accepts fewer JSON types",
            report,
        ),
        (Some(baseline), Some(candidate)) if candidate != baseline => schema_change(
            ChangeClass::Additive,
            "type-widened",
            &format!("{path}/type"),
            "schema accepts additional JSON types",
            report,
        ),
        (None, Some(_)) => schema_change(
            ChangeClass::Breaking,
            "type-narrowed",
            &format!("{path}/type"),
            "schema added a JSON type constraint",
            report,
        ),
        (Some(_), None) => schema_change(
            ChangeClass::Additive,
            "type-widened",
            &format!("{path}/type"),
            "schema removed a JSON type constraint",
            report,
        ),
        _ => {}
    }
}

fn schema_types(value: Option<&Value>) -> Option<BTreeSet<&str>> {
    match value? {
        Value::String(value) => Some(BTreeSet::from([value.as_str()])),
        Value::Array(values) => Some(values.iter().filter_map(Value::as_str).collect()),
        _ => None,
    }
}

fn compare_schema_required(
    baseline: &serde_json::Map<String, Value>,
    candidate: &serde_json::Map<String, Value>,
    path: &str,
    report: &mut Report,
) {
    let baseline_required = string_array_set(baseline.get("required"));
    let candidate_required = string_array_set(candidate.get("required"));
    for property in candidate_required.difference(&baseline_required) {
        schema_change(
            ChangeClass::Breaking,
            "property-now-required",
            &format!("{path}/required/{}", escape_pointer(property)),
            "schema property changed from optional to required",
            report,
        );
    }
    for property in baseline_required.difference(&candidate_required) {
        schema_change(
            ChangeClass::Additive,
            "property-now-optional",
            &format!("{path}/required/{}", escape_pointer(property)),
            "schema property changed from required to optional",
            report,
        );
    }
}

fn compare_schema_properties(
    baseline: &serde_json::Map<String, Value>,
    candidate: &serde_json::Map<String, Value>,
    path: &str,
    report: &mut Report,
) {
    let baseline_properties = baseline.get("properties").and_then(Value::as_object);
    let candidate_properties = candidate.get("properties").and_then(Value::as_object);
    if let Some(baseline_properties) = baseline_properties {
        for (property, baseline_schema) in baseline_properties {
            let property_path = format!("{path}/properties/{}", escape_pointer(property));
            let Some(candidate_schema) =
                candidate_properties.and_then(|properties| properties.get(property))
            else {
                schema_change(
                    ChangeClass::Breaking,
                    "property-removed",
                    &property_path,
                    "schema property was removed",
                    report,
                );
                continue;
            };
            compare_schema(baseline_schema, candidate_schema, &property_path, report);
        }
    }
    if let Some(candidate_properties) = candidate_properties {
        for property in candidate_properties.keys() {
            if !baseline_properties.is_some_and(|properties| properties.contains_key(property)) {
                schema_change(
                    ChangeClass::Additive,
                    "property-added",
                    &format!("{path}/properties/{}", escape_pointer(property)),
                    "optional schema property was added",
                    report,
                );
            }
        }
    }
}

fn compare_schema_enum(
    baseline: Option<&Value>,
    candidate: Option<&Value>,
    path: &str,
    report: &mut Report,
) {
    let baseline = canonical_array_set(baseline);
    let candidate = canonical_array_set(candidate);
    match (baseline, candidate) {
        (Some(baseline), Some(candidate)) if !candidate.is_superset(&baseline) => schema_change(
            ChangeClass::Breaking,
            "enum-narrowed",
            &format!("{path}/enum"),
            "schema enum accepts fewer values",
            report,
        ),
        (Some(baseline), Some(candidate)) if candidate != baseline => schema_change(
            ChangeClass::Additive,
            "enum-widened",
            &format!("{path}/enum"),
            "schema enum accepts additional values",
            report,
        ),
        (None, Some(_)) => schema_change(
            ChangeClass::Breaking,
            "enum-narrowed",
            &format!("{path}/enum"),
            "schema added an enum constraint",
            report,
        ),
        (Some(_), None) => schema_change(
            ChangeClass::Additive,
            "enum-widened",
            &format!("{path}/enum"),
            "schema removed an enum constraint",
            report,
        ),
        _ => {}
    }
}

fn compare_schema_const(
    baseline: Option<&Value>,
    candidate: Option<&Value>,
    path: &str,
    report: &mut Report,
) {
    match (baseline, candidate) {
        (Some(baseline), Some(candidate)) if baseline != candidate => schema_change(
            ChangeClass::Breaking,
            "const-changed",
            &format!("{path}/const"),
            "schema constant changed",
            report,
        ),
        (None, Some(_)) => schema_change(
            ChangeClass::Breaking,
            "const-added",
            &format!("{path}/const"),
            "schema added a constant constraint",
            report,
        ),
        (Some(_), None) => schema_change(
            ChangeClass::Additive,
            "const-removed",
            &format!("{path}/const"),
            "schema removed a constant constraint",
            report,
        ),
        _ => {}
    }
}

fn compare_schema_reference(
    baseline: Option<&Value>,
    candidate: Option<&Value>,
    path: &str,
    report: &mut Report,
) {
    if baseline != candidate && (baseline.is_some() || candidate.is_some()) {
        schema_change(
            ChangeClass::Breaking,
            "reference-changed",
            &format!("{path}/$ref"),
            "schema reference changed",
            report,
        );
    }
}

fn compare_schema_constraints(
    baseline: &serde_json::Map<String, Value>,
    candidate: &serde_json::Map<String, Value>,
    path: &str,
    report: &mut Report,
) {
    for keyword in [
        "minimum",
        "exclusiveMinimum",
        "minLength",
        "minItems",
        "minProperties",
    ] {
        compare_lower_bound(
            baseline.get(keyword),
            candidate.get(keyword),
            path,
            keyword,
            report,
        );
    }
    for keyword in [
        "maximum",
        "exclusiveMaximum",
        "maxLength",
        "maxItems",
        "maxProperties",
    ] {
        compare_upper_bound(
            baseline.get(keyword),
            candidate.get(keyword),
            path,
            keyword,
            report,
        );
    }
    for keyword in ["pattern", "format", "multipleOf"] {
        let baseline_value = baseline.get(keyword);
        let candidate_value = candidate.get(keyword);
        match (baseline_value, candidate_value) {
            (Some(baseline), Some(candidate)) if baseline != candidate => schema_change(
                ChangeClass::Breaking,
                "constraint-changed",
                &format!("{path}/{keyword}"),
                "schema constraint changed incompatibly",
                report,
            ),
            (None, Some(_)) => schema_change(
                ChangeClass::Breaking,
                "constraint-added",
                &format!("{path}/{keyword}"),
                "schema constraint was added",
                report,
            ),
            (Some(_), None) => schema_change(
                ChangeClass::Additive,
                "constraint-relaxed",
                &format!("{path}/{keyword}"),
                "schema constraint was removed",
                report,
            ),
            _ => {}
        }
    }
}

fn compare_lower_bound(
    baseline: Option<&Value>,
    candidate: Option<&Value>,
    path: &str,
    keyword: &str,
    report: &mut Report,
) {
    match (number(baseline), number(candidate)) {
        (Some(baseline), Some(candidate)) if candidate > baseline => schema_change(
            ChangeClass::Breaking,
            "constraint-narrowed",
            &format!("{path}/{keyword}"),
            "schema lower bound became stricter",
            report,
        ),
        (Some(baseline), Some(candidate)) if candidate < baseline => schema_change(
            ChangeClass::Additive,
            "constraint-relaxed",
            &format!("{path}/{keyword}"),
            "schema lower bound was relaxed",
            report,
        ),
        (None, Some(_)) => schema_change(
            ChangeClass::Breaking,
            "constraint-narrowed",
            &format!("{path}/{keyword}"),
            "schema lower bound was added",
            report,
        ),
        (Some(_), None) => schema_change(
            ChangeClass::Additive,
            "constraint-relaxed",
            &format!("{path}/{keyword}"),
            "schema lower bound was removed",
            report,
        ),
        _ => {}
    }
}

fn compare_upper_bound(
    baseline: Option<&Value>,
    candidate: Option<&Value>,
    path: &str,
    keyword: &str,
    report: &mut Report,
) {
    match (number(baseline), number(candidate)) {
        (Some(baseline), Some(candidate)) if candidate < baseline => schema_change(
            ChangeClass::Breaking,
            "constraint-narrowed",
            &format!("{path}/{keyword}"),
            "schema upper bound became stricter",
            report,
        ),
        (Some(baseline), Some(candidate)) if candidate > baseline => schema_change(
            ChangeClass::Additive,
            "constraint-relaxed",
            &format!("{path}/{keyword}"),
            "schema upper bound was relaxed",
            report,
        ),
        (None, Some(_)) => schema_change(
            ChangeClass::Breaking,
            "constraint-narrowed",
            &format!("{path}/{keyword}"),
            "schema upper bound was added",
            report,
        ),
        (Some(_), None) => schema_change(
            ChangeClass::Additive,
            "constraint-relaxed",
            &format!("{path}/{keyword}"),
            "schema upper bound was removed",
            report,
        ),
        _ => {}
    }
}

fn number(value: Option<&Value>) -> Option<f64> {
    value?.as_f64()
}

fn compare_schema_composition(
    baseline: &serde_json::Map<String, Value>,
    candidate: &serde_json::Map<String, Value>,
    path: &str,
    report: &mut Report,
) {
    for keyword in ["anyOf", "oneOf"] {
        let baseline = canonical_array_set(baseline.get(keyword));
        let candidate = canonical_array_set(candidate.get(keyword));
        match (baseline, candidate) {
            (Some(baseline), Some(candidate)) if !candidate.is_superset(&baseline) => {
                schema_change(
                    ChangeClass::Breaking,
                    "composition-narrowed",
                    &format!("{path}/{keyword}"),
                    "schema union accepts fewer alternatives",
                    report,
                );
            }
            (Some(baseline), Some(candidate)) if candidate != baseline => schema_change(
                ChangeClass::Additive,
                "composition-widened",
                &format!("{path}/{keyword}"),
                "schema union accepts additional alternatives",
                report,
            ),
            (None, Some(_)) => schema_change(
                ChangeClass::Breaking,
                "composition-narrowed",
                &format!("{path}/{keyword}"),
                "schema union constraint was added",
                report,
            ),
            (Some(_), None) => schema_change(
                ChangeClass::Additive,
                "composition-widened",
                &format!("{path}/{keyword}"),
                "schema union constraint was removed",
                report,
            ),
            _ => {}
        }
    }

    let baseline_all = canonical_array_set(baseline.get("allOf"));
    let candidate_all = canonical_array_set(candidate.get("allOf"));
    match (baseline_all, candidate_all) {
        (Some(baseline), Some(candidate)) if !baseline.is_superset(&candidate) => schema_change(
            ChangeClass::Breaking,
            "composition-narrowed",
            &format!("{path}/allOf"),
            "schema intersection added or changed constraints",
            report,
        ),
        (Some(baseline), Some(candidate)) if candidate != baseline => schema_change(
            ChangeClass::Additive,
            "composition-relaxed",
            &format!("{path}/allOf"),
            "schema intersection removed constraints",
            report,
        ),
        (None, Some(_)) => schema_change(
            ChangeClass::Breaking,
            "composition-narrowed",
            &format!("{path}/allOf"),
            "schema intersection constraint was added",
            report,
        ),
        (Some(_), None) => schema_change(
            ChangeClass::Additive,
            "composition-relaxed",
            &format!("{path}/allOf"),
            "schema intersection constraint was removed",
            report,
        ),
        _ => {}
    }

    match (baseline.get("not"), candidate.get("not")) {
        (Some(baseline), Some(candidate)) if baseline != candidate => schema_change(
            ChangeClass::Breaking,
            "negation-changed",
            &format!("{path}/not"),
            "schema negation constraint changed",
            report,
        ),
        (None, Some(_)) => schema_change(
            ChangeClass::Breaking,
            "negation-added",
            &format!("{path}/not"),
            "schema negation constraint was added",
            report,
        ),
        (Some(_), None) => schema_change(
            ChangeClass::Additive,
            "negation-removed",
            &format!("{path}/not"),
            "schema negation constraint was removed",
            report,
        ),
        _ => {}
    }
}

fn compare_additional_properties(
    baseline: Option<&Value>,
    candidate: Option<&Value>,
    path: &str,
    report: &mut Report,
) {
    match (baseline, candidate) {
        (Some(Value::Bool(false)), Some(Value::Bool(true)) | None) => schema_change(
            ChangeClass::Additive,
            "additional-properties-relaxed",
            &format!("{path}/additionalProperties"),
            "schema now permits additional properties",
            report,
        ),
        (Some(Value::Bool(true)) | None, Some(Value::Bool(false))) => schema_change(
            ChangeClass::Breaking,
            "additional-properties-narrowed",
            &format!("{path}/additionalProperties"),
            "schema no longer permits additional properties",
            report,
        ),
        (Some(baseline), Some(Value::Bool(true)) | None) if baseline.is_object() => schema_change(
            ChangeClass::Additive,
            "additional-properties-relaxed",
            &format!("{path}/additionalProperties"),
            "additional-property schema constraint was removed",
            report,
        ),
        (Some(Value::Bool(true)) | None, Some(candidate)) if candidate.is_object() => {
            schema_change(
                ChangeClass::Breaking,
                "additional-properties-narrowed",
                &format!("{path}/additionalProperties"),
                "additional-property schema constraint was added",
                report,
            );
        }
        (Some(Value::Bool(false)), Some(candidate)) if candidate.is_object() => schema_change(
            ChangeClass::Additive,
            "additional-properties-relaxed",
            &format!("{path}/additionalProperties"),
            "schema now permits constrained additional properties",
            report,
        ),
        (Some(baseline), Some(Value::Bool(false))) if baseline.is_object() => schema_change(
            ChangeClass::Breaking,
            "additional-properties-narrowed",
            &format!("{path}/additionalProperties"),
            "schema no longer permits additional properties",
            report,
        ),
        (Some(baseline), Some(candidate)) if baseline.is_object() && candidate.is_object() => {
            compare_schema(
                baseline,
                candidate,
                &format!("{path}/additionalProperties"),
                report,
            );
        }
        (Some(baseline), Some(candidate)) if baseline != candidate => schema_change(
            ChangeClass::Breaking,
            "additional-properties-changed",
            &format!("{path}/additionalProperties"),
            "additional-property schema changed incompatibly",
            report,
        ),
        _ => {}
    }
}

fn schema_change(class: ChangeClass, suffix: &str, path: &str, message: &str, report: &mut Report) {
    report.findings.push(Finding::new(
        class,
        format!("asyncapi.schema.{suffix}"),
        path,
        message,
    ));
}

fn string_array_set(value: Option<&Value>) -> BTreeSet<&str> {
    value
        .and_then(Value::as_array)
        .map_or_else(BTreeSet::new, |values| {
            values.iter().filter_map(Value::as_str).collect()
        })
}

fn canonical_array_set(value: Option<&Value>) -> Option<BTreeSet<String>> {
    value?
        .as_array()
        .map(|values| values.iter().map(canonical_value).collect::<BTreeSet<_>>())
}

fn canonical_value(value: &Value) -> String {
    value.to_string()
}

fn compare_permissions(
    baseline: &PermissionCatalog,
    candidate: &PermissionCatalog,
    report: &mut Report,
) {
    if baseline.schema_version != candidate.schema_version {
        report.findings.push(Finding::new(
            ChangeClass::Breaking,
            "permissions.schema-version-changed",
            format!("{PERMISSIONS_FILE}#/schema_version"),
            "permission catalog schema version changed",
        ));
    }
    let baseline_permissions = baseline.by_id();
    let candidate_permissions = candidate.by_id();
    for (id, baseline_permission) in &baseline_permissions {
        let path = format!("{PERMISSIONS_FILE}#/permissions/{}", escape_pointer(id));
        let Some(candidate_permission) = candidate_permissions.get(id) else {
            report.findings.push(Finding::new(
                ChangeClass::Breaking,
                "permission.removed",
                path,
                "public permission identifier was removed or renamed",
            ));
            continue;
        };
        if baseline_permission.resource != candidate_permission.resource
            || baseline_permission.action != candidate_permission.action
        {
            report.findings.push(Finding::new(
                ChangeClass::Breaking,
                "permission.definition-changed",
                path.clone(),
                "permission resource or action changed",
            ));
        }
        if !baseline_permission.deprecated && candidate_permission.deprecated {
            report.findings.push(Finding::new(
                ChangeClass::Deprecated,
                "permission.deprecated",
                format!("{path}/deprecated"),
                "public permission was deprecated",
            ));
        } else if baseline_permission.deprecated && !candidate_permission.deprecated {
            report.findings.push(Finding::new(
                ChangeClass::BehavioralCompatible,
                "permission.deprecation-removed",
                format!("{path}/deprecated"),
                "permission deprecation was removed",
            ));
        }
        if baseline_permission.description != candidate_permission.description
            || baseline_permission.group != candidate_permission.group
            || baseline_permission.replacement != candidate_permission.replacement
        {
            report.findings.push(Finding::new(
                ChangeClass::BehavioralCompatible,
                "permission.metadata-changed",
                path,
                "permission presentation or replacement metadata changed",
            ));
        }
    }
    for id in candidate_permissions.keys() {
        if !baseline_permissions.contains_key(id) {
            report.findings.push(Finding::new(
                ChangeClass::Additive,
                "permission.added",
                format!("{PERMISSIONS_FILE}#/permissions/{}", escape_pointer(id)),
                "public permission identifier was added",
            ));
        }
    }
}

fn compare_capabilities(
    baseline: &CapabilityCatalog,
    candidate: &CapabilityCatalog,
    report: &mut Report,
) {
    compare_root_identity(
        &baseline.schema_version,
        &candidate.schema_version,
        "capabilities.schema-version-changed",
        &format!("{CAPABILITIES_FILE}#/schema_version"),
        "capability catalog schema version changed",
        report,
    );
    compare_root_identity(
        &baseline.profile,
        &candidate.profile,
        "capabilities.profile-changed",
        &format!("{CAPABILITIES_FILE}#/profile"),
        "capability profile changed",
        report,
    );
    if baseline.service_version != candidate.service_version {
        report.findings.push(Finding::new(
            ChangeClass::BehavioralCompatible,
            "capabilities.service-version-changed",
            format!("{CAPABILITIES_FILE}#/service_version"),
            "capability service version changed",
        ));
    }

    let baseline_capabilities = baseline.by_id();
    let candidate_capabilities = candidate.by_id();
    for (id, baseline_capability) in &baseline_capabilities {
        let path = format!("{CAPABILITIES_FILE}#/capabilities/{}", escape_pointer(id));
        let Some(candidate_capability) = candidate_capabilities.get(id) else {
            report.findings.push(Finding::new(
                ChangeClass::Breaking,
                "capability.removed",
                path,
                "public capability identifier was removed",
            ));
            continue;
        };
        if baseline_capability.compiled && !candidate_capability.compiled {
            report.findings.push(Finding::new(
                ChangeClass::Breaking,
                "capability.no-longer-compiled",
                format!("{path}/compiled"),
                "compiled public capability was removed",
            ));
        } else if !baseline_capability.compiled && candidate_capability.compiled {
            report.findings.push(Finding::new(
                ChangeClass::Additive,
                "capability.compiled",
                format!("{path}/compiled"),
                "public capability became compiled",
            ));
        }
        if baseline_capability.runtime_available != candidate_capability.runtime_available {
            report.findings.push(Finding::new(
                ChangeClass::BehavioralCompatible,
                "capability.runtime-availability-changed",
                format!("{path}/runtime_available"),
                "public capability runtime availability changed",
            ));
        }
        if baseline_capability.minimum_sdk_version != candidate_capability.minimum_sdk_version {
            report.findings.push(Finding::new(
                ChangeClass::BehavioralCompatible,
                "capability.minimum-sdk-version-changed",
                format!("{path}/minimum_sdk_version"),
                "capability minimum SDK version changed",
            ));
        }
        compare_auth_modes(baseline_capability, candidate_capability, &path, report);
        compare_auth_roles(baseline_capability, candidate_capability, &path, report);
    }
    for id in candidate_capabilities.keys() {
        if !baseline_capabilities.contains_key(id) {
            report.findings.push(Finding::new(
                ChangeClass::Additive,
                "capability.added",
                format!("{CAPABILITIES_FILE}#/capabilities/{}", escape_pointer(id)),
                "public capability identifier was added",
            ));
        }
    }

    compare_transport(
        Some(baseline.transports.api.as_str()),
        Some(candidate.transports.api.as_str()),
        "api",
        report,
    );
    compare_transport(
        baseline.transports.websocket.as_deref(),
        candidate.transports.websocket.as_deref(),
        "websocket",
        report,
    );
    compare_transport(
        baseline.transports.sse.as_deref(),
        candidate.transports.sse.as_deref(),
        "sse",
        report,
    );
}

fn compare_root_identity(
    baseline: &str,
    candidate: &str,
    code: &str,
    path: &str,
    message: &str,
    report: &mut Report,
) {
    if baseline != candidate {
        report
            .findings
            .push(Finding::new(ChangeClass::Breaking, code, path, message));
    }
}

fn compare_auth_modes(
    baseline: &Capability,
    candidate: &Capability,
    path: &str,
    report: &mut Report,
) {
    let baseline_modes: BTreeSet<_> = baseline.auth_modes.iter().map(String::as_str).collect();
    let candidate_modes: BTreeSet<_> = candidate.auth_modes.iter().map(String::as_str).collect();
    for mode in baseline_modes.difference(&candidate_modes) {
        report.findings.push(Finding::new(
            ChangeClass::Breaking,
            "capability.auth-mode-removed",
            format!("{path}/auth_modes/{}", escape_pointer(mode)),
            "supported capability authentication mode was removed",
        ));
    }
    for mode in candidate_modes.difference(&baseline_modes) {
        report.findings.push(Finding::new(
            ChangeClass::Additive,
            "capability.auth-mode-added",
            format!("{path}/auth_modes/{}", escape_pointer(mode)),
            "supported capability authentication mode was added",
        ));
    }
}

fn compare_auth_roles(
    baseline: &Capability,
    candidate: &Capability,
    path: &str,
    report: &mut Report,
) {
    let baseline_roles: BTreeSet<_> = baseline.auth_roles.iter().map(String::as_str).collect();
    let candidate_roles: BTreeSet<_> = candidate.auth_roles.iter().map(String::as_str).collect();
    for role in baseline_roles.difference(&candidate_roles) {
        report.findings.push(Finding::new(
            ChangeClass::Breaking,
            "capability.auth-role-removed",
            format!("{path}/auth_roles/{}", escape_pointer(role)),
            "supported capability authentication role was removed",
        ));
    }
    for role in candidate_roles.difference(&baseline_roles) {
        report.findings.push(Finding::new(
            ChangeClass::Additive,
            "capability.auth-role-added",
            format!("{path}/auth_roles/{}", escape_pointer(role)),
            "supported capability authentication role was added",
        ));
    }
}

fn compare_transport(
    baseline: Option<&str>,
    candidate: Option<&str>,
    name: &str,
    report: &mut Report,
) {
    let path = format!("{CAPABILITIES_FILE}#/transports/{name}");
    match (baseline, candidate) {
        (Some(baseline), Some(candidate)) if baseline != candidate => {
            report.findings.push(Finding::new(
                ChangeClass::Breaking,
                "capability.transport-location-changed",
                path,
                "public transport location changed",
            ));
        }
        (Some(_), None) => report.findings.push(Finding::new(
            ChangeClass::Breaking,
            "capability.transport-removed",
            path,
            "public transport location was removed",
        )),
        (None, Some(_)) => report.findings.push(Finding::new(
            ChangeClass::Additive,
            "capability.transport-added",
            path,
            "public transport location was added",
        )),
        _ => {}
    }
}

fn compare_manifest(
    baseline: &ContractManifest,
    candidate: &ContractManifest,
    report: &mut Report,
) {
    compare_root_identity(
        &baseline.schema_version,
        &candidate.schema_version,
        "manifest.schema-version-changed",
        &format!("{MANIFEST_FILE}#/schema_version"),
        "contract manifest schema version changed",
        report,
    );
    compare_root_identity(
        &baseline.profile,
        &candidate.profile,
        "manifest.profile-changed",
        &format!("{MANIFEST_FILE}#/profile"),
        "contract manifest profile changed",
        report,
    );

    let baseline_modules: BTreeSet<_> = baseline.modules.iter().map(String::as_str).collect();
    let candidate_modules: BTreeSet<_> = candidate.modules.iter().map(String::as_str).collect();
    for module in baseline_modules.difference(&candidate_modules) {
        report.findings.push(Finding::new(
            ChangeClass::Breaking,
            "manifest.module-removed",
            format!("{MANIFEST_FILE}#/modules/{}", escape_pointer(module)),
            "public contract module was removed",
        ));
    }
    for module in candidate_modules.difference(&baseline_modules) {
        report.findings.push(Finding::new(
            ChangeClass::Additive,
            "manifest.module-added",
            format!("{MANIFEST_FILE}#/modules/{}", escape_pointer(module)),
            "public contract module was added",
        ));
    }

    for (field, baseline_version, candidate_version) in [
        (
            "service_kit_version",
            Some(&baseline.service_kit_version),
            Some(&candidate.service_kit_version),
        ),
        (
            "application_version",
            Some(&baseline.application_version),
            Some(&candidate.application_version),
        ),
        (
            "minimum_sdk_version",
            baseline.minimum_sdk_version.as_ref(),
            candidate.minimum_sdk_version.as_ref(),
        ),
        (
            "maximum_sdk_version",
            baseline.maximum_sdk_version.as_ref(),
            candidate.maximum_sdk_version.as_ref(),
        ),
    ] {
        if baseline_version != candidate_version {
            report.findings.push(Finding::new(
                ChangeClass::BehavioralCompatible,
                "manifest.compatibility-metadata-changed",
                format!("{MANIFEST_FILE}#/{field}"),
                "contract compatibility version metadata changed",
            ));
        }
    }

    for baseline_contract in &baseline.contracts {
        if let Some(candidate_contract) = candidate
            .contracts
            .iter()
            .find(|entry| entry.path == baseline_contract.path)
            && baseline_contract.required != candidate_contract.required
        {
            report.findings.push(Finding::new(
                ChangeClass::BehavioralCompatible,
                "manifest.artifact-requirement-changed",
                format!(
                    "{MANIFEST_FILE}#/contracts/{}/required",
                    escape_pointer(&baseline_contract.path)
                ),
                "contract artifact requirement changed",
            ));
        }
    }
}

fn artifact_pointer(artifact: &str, pointer: &str) -> String {
    format!("{artifact}#{pointer}")
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "fixture setup and comparison failures must stop focused compatibility tests"
)]
mod tests {
    use super::*;

    fn workspace() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is inside the workspace")
            .to_path_buf()
    }

    fn fixture(name: &str) -> PathBuf {
        workspace()
            .join("fixtures")
            .join("contract-compatibility")
            .join(name)
    }

    fn capability_catalog(auth_roles: &[&str]) -> CapabilityCatalog {
        CapabilityCatalog {
            schema_version: "1.0.0".to_owned(),
            service_version: "0.1.0".to_owned(),
            profile: "test".to_owned(),
            contract_hash: format!("sha256:{}", "a".repeat(64)),
            capabilities: vec![Capability {
                id: "authentication".to_owned(),
                compiled: true,
                runtime_available: true,
                minimum_sdk_version: "0.1.0".to_owned(),
                auth_modes: vec!["bearer".to_owned()],
                auth_roles: auth_roles.iter().map(|role| (*role).to_owned()).collect(),
            }],
            transports: Transports {
                api: "/api".to_owned(),
                websocket: None,
                sse: None,
            },
        }
    }

    fn contract_manifest(include_asyncapi: bool) -> ContractManifest {
        let mut contracts = Vec::with_capacity(3 + usize::from(include_asyncapi));
        if include_asyncapi {
            contracts.push(ManifestContract {
                path: "contracts/asyncapi.json".to_owned(),
                sha256: "a".repeat(64),
                required: true,
            });
        }
        contracts.extend(
            [
                "contracts/capabilities.json",
                "contracts/openapi.json",
                "contracts/permissions.json",
            ]
            .map(|path| ManifestContract {
                path: path.to_owned(),
                sha256: "a".repeat(64),
                required: true,
            }),
        );
        let mut generators = BTreeMap::from([("contracts".to_owned(), "test/1.0.0".to_owned())]);
        if include_asyncapi {
            generators.insert("asyncapi".to_owned(), "test/1.0.0".to_owned());
        }

        ContractManifest {
            schema_version: "1.0.0".to_owned(),
            service_kit_version: "1.0.0".to_owned(),
            application_version: "1.0.0".to_owned(),
            build_revision: "test".to_owned(),
            generated_at: Some("reproducible".to_owned()),
            profile: "test".to_owned(),
            modules: vec!["core".to_owned()],
            contracts,
            aggregate_sha256: "a".repeat(64),
            minimum_sdk_version: Some("1.0.0".to_owned()),
            maximum_sdk_version: None,
            generators,
        }
    }

    #[test]
    fn manifest_validation_accepts_profile_aware_leaf_inventories() {
        let without_realtime = contract_manifest(false);
        let with_realtime = contract_manifest(true);

        assert!(
            without_realtime.validate(Side::Candidate).is_ok()
                && with_realtime.validate(Side::Candidate).is_ok()
        );
    }

    #[test]
    fn capability_validation_accepts_exact_authentication_roles() {
        let catalog = capability_catalog(&[
            "oauth-authorization-server",
            "oauth-resource-server",
            "openid-provider",
        ]);

        assert!(catalog.validate(Side::Candidate).is_ok());
    }

    #[test]
    fn capability_validation_rejects_unknown_and_duplicate_authentication_roles() {
        let unknown = capability_catalog(&["oauth-client"]);
        let duplicate = capability_catalog(&["oauth-resource-server", "oauth-resource-server"]);

        assert!(
            unknown.validate(Side::Candidate).is_err()
                && duplicate.validate(Side::Candidate).is_err()
        );
    }

    #[test]
    fn capability_deserialization_defaults_authentication_roles_for_older_contracts() {
        let capability: Capability = serde_json::from_value(serde_json::json!({
            "id": "authentication",
            "compiled": true,
            "runtime_available": true,
            "minimum_sdk_version": "0.1.0",
            "auth_modes": ["bearer"]
        }))
        .expect("capability without auth_roles should remain compatible");

        assert!(capability.auth_roles.is_empty());
    }

    #[test]
    fn capability_comparison_reports_authentication_role_drift() {
        let baseline = capability_catalog(&["oauth-resource-server"])
            .capabilities
            .pop()
            .expect("fixture contains one capability");
        let candidate = capability_catalog(&["oauth-authorization-server"])
            .capabilities
            .pop()
            .expect("fixture contains one capability");
        let mut report = Report::default();

        compare_auth_roles(
            &baseline,
            &candidate,
            "capabilities.json#/capabilities/authentication",
            &mut report,
        );

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.class))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                ("capability.auth-role-added", ChangeClass::Additive),
                ("capability.auth-role-removed", ChangeClass::Breaking),
            ])
        );
    }

    #[test]
    fn compare_accepts_complete_additive_contract_set() {
        let report = compare(&workspace(), &fixture("baseline"), &fixture("additive"))
            .expect("complete additive fixtures should compare");

        assert!(
            report.is_compatible()
                && report
                    .findings
                    .iter()
                    .any(|finding| finding.class == ChangeClass::Additive),
            "additive report should be compatible and contain additions: {report:?}"
        );
    }

    #[test]
    fn compare_classifies_all_nonbreaking_fixture_changes() {
        let report = compare(&workspace(), &fixture("baseline"), &fixture("additive"))
            .expect("complete additive fixtures should compare");
        let classes: BTreeSet<_> = report
            .findings
            .iter()
            .map(|finding| finding.class)
            .collect();

        assert_eq!(
            classes,
            BTreeSet::from([
                ChangeClass::Additive,
                ChangeClass::BehavioralCompatible,
                ChangeClass::Deprecated,
            ])
        );
    }

    #[test]
    fn compare_reports_all_required_breaking_contract_categories() {
        let report = compare(&workspace(), &fixture("baseline"), &fixture("breaking"))
            .expect("complete breaking fixtures should compare");
        let codes: BTreeSet<_> = report
            .findings
            .iter()
            .filter(|finding| finding.class == ChangeClass::Breaking)
            .map(|finding| finding.code.as_str())
            .collect();
        let expected = BTreeSet::from([
            "asyncapi.message.component-removed",
            "asyncapi.message.direction-changed",
            "asyncapi.message.event-name-changed",
            "asyncapi.message.version-changed",
            "asyncapi.schema.component-removed",
            "asyncapi.schema.type-narrowed",
            "openapi.operation.removed",
            "openapi.response-status-removed",
            "openapi.schema-type-changed",
            "permission.definition-changed",
            "permission.removed",
        ]);

        assert!(
            expected.is_subset(&codes),
            "missing required breaking diagnostics: expected {expected:?}, got {codes:?}"
        );
    }

    #[test]
    fn compare_returns_deterministically_sorted_diagnostics() {
        let report = compare(&workspace(), &fixture("baseline"), &fixture("breaking"))
            .expect("complete breaking fixtures should compare");

        assert!(
            report.findings.windows(2).all(|pair| {
                (
                    &pair[0].path,
                    &pair[0].code,
                    pair[0].class,
                    &pair[0].message,
                ) <= (
                    &pair[1].path,
                    &pair[1].code,
                    pair[1].class,
                    &pair[1].message,
                )
            }),
            "diagnostics are not sorted: {report:?}"
        );
    }

    #[test]
    fn compare_accepts_manifest_as_baseline_input() {
        let report = compare(
            &workspace(),
            &fixture("baseline").join(MANIFEST_FILE),
            &fixture("additive"),
        )
        .expect("manifest input should resolve its contract directory");

        assert!(report.is_compatible(), "manifest input report: {report:?}");
    }

    #[test]
    fn compare_rejects_and_redacts_input_outside_workspace() {
        let root = workspace();
        let outside = root.parent().expect("workspace has a parent");
        let error = compare(&root, outside, &fixture("additive"))
            .expect_err("outside baseline must be rejected");

        assert_eq!(
            error.to_string(),
            "baseline contract input is outside trusted repository root"
        );
    }

    #[test]
    fn emit_and_enforce_fails_only_for_breaking_reports() {
        let compatible = Report {
            findings: vec![Finding::new(
                ChangeClass::BehavioralCompatible,
                "fixture.behavioral",
                "fixture.json#/value",
                "fixture behavior changed",
            )],
        };
        let breaking = Report {
            findings: vec![Finding::new(
                ChangeClass::Breaking,
                "fixture.breaking",
                "fixture.json#/value",
                "fixture broke",
            )],
        };

        assert!(
            emit_and_enforce(&compatible).is_ok() && emit_and_enforce(&breaking).is_err(),
            "enforcement must fail only for breaking findings"
        );
    }
}
