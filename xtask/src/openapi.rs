use std::{fs, path::Path};

use anyhow::{Context, Result, bail, ensure};

const DOCUMENT_PATH: &str = "contracts/openapi.json";

pub(crate) fn generate(workspace: &Path) -> Result<()> {
    let path = workspace.join(DOCUMENT_PATH);
    let parent = path
        .parent()
        .context("public OpenAPI document path has no parent")?;
    fs::create_dir_all(parent).context("create public OpenAPI document directory")?;
    fs::write(path, generated_document()?).context("write public OpenAPI document")
}

pub(crate) fn verify(workspace: &Path) -> Result<()> {
    let committed = fs::read(workspace.join(DOCUMENT_PATH))
        .context("read committed public OpenAPI document; run `cargo xtask openapi generate`")?;
    let generated = generated_document()?;
    ensure!(
        committed == generated,
        "public OpenAPI document is stale; run `cargo xtask openapi generate`"
    );
    Ok(())
}

pub(crate) fn verify_breaking(workspace: &Path, baseline: &str) -> Result<()> {
    verify(workspace)?;
    let baseline = fs::read(baseline).context("read baseline public OpenAPI document")?;
    let candidate = generated_document()?;
    let changes = omnius_openapi::breaking_changes(&baseline, &candidate)
        .context("validate and compare public OpenAPI documents")?;
    if changes.is_empty() {
        return Ok(());
    }
    for change in &changes {
        eprintln!("breaking OpenAPI change: {change}");
    }
    bail!(
        "public OpenAPI document contains {} breaking change(s)",
        changes.len()
    )
}

fn generated_document() -> Result<Vec<u8>> {
    omnius_api_server::openapi_json().context("generate validated public OpenAPI document")
}
