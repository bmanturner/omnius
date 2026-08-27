use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const OPENAPI_PATH: &str = "contracts/openapi.json";
const ASYNCAPI_PATH: &str = "contracts/asyncapi.json";
const PERMISSIONS_PATH: &str = "contracts/permissions.json";
const CAPABILITIES_PATH: &str = "contracts/capabilities.json";
const MANIFEST_PATH: &str = "contracts/contract-manifest.json";
const PERMISSIONS_SCHEMA: &str =
    "specs/machine/extensions/web-application-suite/schemas/permissions.schema.json";
const CAPABILITIES_SCHEMA: &str =
    "specs/machine/extensions/web-application-suite/schemas/capabilities.schema.json";
const MANIFEST_SCHEMA: &str =
    "specs/machine/extensions/web-application-suite/schemas/contract-manifest.schema.json";
const LEAF_PATHS: [&str; 4] = [
    ASYNCAPI_PATH,
    CAPABILITIES_PATH,
    OPENAPI_PATH,
    PERMISSIONS_PATH,
];

pub(crate) fn generate(workspace: &Path) -> Result<()> {
    let generated = generate_contracts(workspace)?;
    validate_generated(workspace, &generated)?;

    fs::create_dir_all(workspace.join("contracts")).context("create public contract directory")?;
    write_contract(workspace, OPENAPI_PATH, &generated.openapi)?;
    write_contract(workspace, PERMISSIONS_PATH, &generated.permissions)?;
    write_contract(workspace, CAPABILITIES_PATH, &generated.capabilities)?;
    write_contract(workspace, MANIFEST_PATH, &generated.manifest)?;
    Ok(())
}

pub(crate) fn check(workspace: &Path) -> Result<()> {
    let committed = read_committed(workspace)?;
    validate_generated(workspace, &committed)
        .context("committed public contracts are malformed or hash-inconsistent")?;

    let generated = generate_contracts(workspace)?;
    validate_generated(workspace, &generated)?;
    ensure_current(OPENAPI_PATH, &committed.openapi, &generated.openapi)?;
    ensure_current(
        PERMISSIONS_PATH,
        &committed.permissions,
        &generated.permissions,
    )?;
    ensure_current(
        CAPABILITIES_PATH,
        &committed.capabilities,
        &generated.capabilities,
    )?;
    ensure_current(MANIFEST_PATH, &committed.manifest, &generated.manifest)
}

struct ContractSet {
    openapi: Vec<u8>,
    asyncapi: Vec<u8>,
    permissions: Vec<u8>,
    capabilities: Vec<u8>,
    manifest: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ContractManifest {
    schema_version: String,
    service_kit_version: String,
    application_version: String,
    build_revision: String,
    generated_at: String,
    profile: String,
    modules: Vec<String>,
    contracts: Vec<ContractDigest>,
    aggregate_sha256: String,
    minimum_sdk_version: String,
    maximum_sdk_version: Option<String>,
    generators: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ContractDigest {
    path: String,
    sha256: String,
    required: bool,
}

fn generate_contracts(workspace: &Path) -> Result<ContractSet> {
    let openapi =
        omnius_api_server::openapi_json().context("generate canonical public OpenAPI document")?;
    let asyncapi = read_contract(workspace, ASYNCAPI_PATH)?;
    ensure_json_document(ASYNCAPI_PATH, &asyncapi)?;
    let permissions = omnius_api_server::permissions_contract_json()
        .context("generate canonical public permission vocabulary")?;
    let aggregate_sha256 =
        omnius_api_server::aggregate_contract_sha256(&openapi, &asyncapi, &permissions);
    let capabilities = omnius_api_server::capabilities_contract_json(&aggregate_sha256)
        .context("generate canonical public capability descriptor")?;
    let manifest = canonical_json(&build_manifest(
        &openapi,
        &asyncapi,
        &permissions,
        &capabilities,
        aggregate_sha256,
    ))?;

    Ok(ContractSet {
        openapi,
        asyncapi,
        permissions,
        capabilities,
        manifest,
    })
}

fn build_manifest(
    openapi: &[u8],
    asyncapi: &[u8],
    permissions: &[u8],
    capabilities: &[u8],
    aggregate_sha256: String,
) -> ContractManifest {
    let leaf_bytes = [
        (ASYNCAPI_PATH, asyncapi),
        (CAPABILITIES_PATH, capabilities),
        (OPENAPI_PATH, openapi),
        (PERMISSIONS_PATH, permissions),
    ];
    let contracts = leaf_bytes
        .into_iter()
        .map(|(path, bytes)| ContractDigest {
            path: path.to_owned(),
            sha256: sha256(bytes),
            required: true,
        })
        .collect();
    let generators = BTreeMap::from([
        (
            "asyncapi".to_owned(),
            format!("omnius-realtime-core/{}", env!("CARGO_PKG_VERSION")),
        ),
        (
            "contracts".to_owned(),
            format!("omnius-xtask/{}", env!("CARGO_PKG_VERSION")),
        ),
        (
            "openapi".to_owned(),
            format!("omnius-api-server/{}", env!("CARGO_PKG_VERSION")),
        ),
    ]);

    ContractManifest {
        schema_version: omnius_api_server::CONTRACT_SCHEMA_VERSION.to_owned(),
        service_kit_version: env!("CARGO_PKG_VERSION").to_owned(),
        application_version: env!("CARGO_PKG_VERSION").to_owned(),
        build_revision: omnius_api_server::BUILD_REVISION.to_owned(),
        generated_at: "reproducible".to_owned(),
        profile: omnius_api_server::PUBLIC_PROFILE.to_owned(),
        modules: omnius_api_server::PUBLIC_PROFILE_MODULES
            .iter()
            .map(ToString::to_string)
            .collect(),
        contracts,
        aggregate_sha256,
        minimum_sdk_version: omnius_api_server::MINIMUM_SDK_VERSION.to_owned(),
        maximum_sdk_version: None,
        generators,
    }
}

fn validate_generated(workspace: &Path, contracts: &ContractSet) -> Result<()> {
    ensure_json_document(OPENAPI_PATH, &contracts.openapi)?;
    ensure_json_document(ASYNCAPI_PATH, &contracts.asyncapi)?;
    ensure_canonical_json(PERMISSIONS_PATH, &contracts.permissions)?;
    ensure_canonical_json(CAPABILITIES_PATH, &contracts.capabilities)?;
    ensure_canonical_json(MANIFEST_PATH, &contracts.manifest)?;
    validate_schema(
        workspace,
        PERMISSIONS_SCHEMA,
        PERMISSIONS_PATH,
        &contracts.permissions,
    )?;
    validate_schema(
        workspace,
        CAPABILITIES_SCHEMA,
        CAPABILITIES_PATH,
        &contracts.capabilities,
    )?;
    validate_schema(
        workspace,
        MANIFEST_SCHEMA,
        MANIFEST_PATH,
        &contracts.manifest,
    )?;
    validate_permission_coverage(&contracts.permissions)?;
    validate_hashes(contracts)
}

fn validate_hashes(contracts: &ContractSet) -> Result<()> {
    let manifest: ContractManifest =
        serde_json::from_slice(&contracts.manifest).context("parse public contract manifest")?;
    ensure!(
        manifest.contracts.len() == LEAF_PATHS.len(),
        "public contract manifest leaf inventory is invalid"
    );
    let mut entries = manifest.contracts.iter().collect::<Vec<_>>();
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    ensure!(
        entries
            .iter()
            .map(|entry| entry.path.as_str())
            .eq(LEAF_PATHS),
        "public contract manifest leaf inventory is invalid"
    );
    for entry in entries {
        let bytes = match entry.path.as_str() {
            OPENAPI_PATH => &contracts.openapi,
            ASYNCAPI_PATH => &contracts.asyncapi,
            PERMISSIONS_PATH => &contracts.permissions,
            CAPABILITIES_PATH => &contracts.capabilities,
            _ => {
                return Err(anyhow::anyhow!(
                    "public contract manifest leaf inventory is invalid"
                ));
            }
        };
        ensure!(
            entry.required && entry.sha256 == sha256(bytes),
            "public contract manifest leaf hash is inconsistent"
        );
    }

    let aggregate = omnius_api_server::aggregate_contract_sha256(
        &contracts.openapi,
        &contracts.asyncapi,
        &contracts.permissions,
    );
    ensure!(
        manifest.aggregate_sha256 == aggregate,
        "public contract aggregate hash is inconsistent"
    );
    let capabilities: Value = serde_json::from_slice(&contracts.capabilities)
        .context("parse public capability descriptor")?;
    let capability_hash = capabilities
        .get("contract_hash")
        .and_then(Value::as_str)
        .context("public capability descriptor has no contract hash")?;
    ensure!(
        capability_hash == format!("sha256:{aggregate}"),
        "public capability contract hash is inconsistent"
    );
    Ok(())
}

fn validate_permission_coverage(bytes: &[u8]) -> Result<()> {
    let document: Value =
        serde_json::from_slice(bytes).context("parse public permission vocabulary")?;
    let permissions = document
        .get("permissions")
        .and_then(Value::as_array)
        .context("public permission vocabulary has no permission array")?;
    let mut actual = permissions
        .iter()
        .map(|permission| {
            let id = permission
                .get("id")
                .and_then(Value::as_str)
                .context("public permission entry has no identifier")?;
            let action = permission
                .get("action")
                .and_then(Value::as_str)
                .context("public permission entry has no action")?;
            Ok((id.to_owned(), action.to_owned()))
        })
        .collect::<Result<Vec<_>>>()?;
    actual.sort_unstable();
    ensure!(
        !actual
            .windows(2)
            .any(|entries| entries[0].0 == entries[1].0),
        "public permission vocabulary contains a duplicate identifier"
    );

    let mut registry = omnius_api_server::public_permissions()
        .iter()
        .map(|permission| (permission.id().to_owned(), permission.action().to_owned()))
        .collect::<Vec<_>>();
    registry.sort_unstable();
    ensure!(
        actual == registry,
        "public permission vocabulary does not exactly match its typed registry"
    );
    let mut selected_actions = omnius_api_server::selected_browser_command_actions().to_vec();
    selected_actions.sort_unstable();
    let registry_actions = registry
        .iter()
        .map(|(_, action)| action.as_str())
        .collect::<Vec<_>>();
    ensure!(
        registry_actions == selected_actions,
        "public permission registry does not exactly cover selected browser commands"
    );
    Ok(())
}

fn validate_schema(
    workspace: &Path,
    schema_path: &str,
    contract_path: &str,
    bytes: &[u8],
) -> Result<()> {
    let schema: Value = serde_json::from_slice(&read_contract(workspace, schema_path)?)
        .with_context(|| format!("parse schema for {contract_path}"))?;
    let document: Value = serde_json::from_slice(bytes)
        .with_context(|| format!("parse {contract_path} for schema validation"))?;
    let validator = jsonschema::validator_for(&schema)
        .with_context(|| format!("compile schema for {contract_path}"))?;
    let error_count = validator.iter_errors(&document).count();
    ensure!(
        error_count == 0,
        "{contract_path} does not satisfy its normative schema ({error_count} errors)"
    );
    Ok(())
}

fn read_committed(workspace: &Path) -> Result<ContractSet> {
    Ok(ContractSet {
        openapi: read_contract(workspace, OPENAPI_PATH)?,
        asyncapi: read_contract(workspace, ASYNCAPI_PATH)?,
        permissions: read_contract(workspace, PERMISSIONS_PATH)?,
        capabilities: read_contract(workspace, CAPABILITIES_PATH)?,
        manifest: read_contract(workspace, MANIFEST_PATH)?,
    })
}

fn read_contract(workspace: &Path, path: &str) -> Result<Vec<u8>> {
    fs::read(workspace.join(path)).with_context(|| format!("read {path}"))
}

fn write_contract(workspace: &Path, path: &str, bytes: &[u8]) -> Result<()> {
    fs::write(workspace.join(path), bytes).with_context(|| format!("write {path}"))
}

fn ensure_current(path: &str, committed: &[u8], generated: &[u8]) -> Result<()> {
    ensure!(
        committed == generated,
        "{path} is stale; run `cargo xtask contracts generate`"
    );
    Ok(())
}

fn ensure_json_document(path: &str, bytes: &[u8]) -> Result<()> {
    let _: Value =
        serde_json::from_slice(bytes).with_context(|| format!("parse canonical {path}"))?;
    Ok(())
}

fn ensure_canonical_json(path: &str, bytes: &[u8]) -> Result<()> {
    let value: Value =
        serde_json::from_slice(bytes).with_context(|| format!("parse canonical {path}"))?;
    ensure!(
        canonical_json(&value)? == bytes,
        "{path} is not canonical sorted JSON with one trailing newline"
    );
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).context("construct canonical public contract JSON")?;
    let mut bytes =
        serde_json::to_vec_pretty(&value).context("serialize canonical public contract JSON")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
