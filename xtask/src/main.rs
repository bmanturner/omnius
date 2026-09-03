//! Repository automation entry point.

mod ai;
mod asyncapi;
mod contract_diff;
mod contracts;
mod docs;
mod email;
mod extensions;
mod model;
mod openapi;
mod profiles;
mod spec_archive;
mod specs;
mod web_release;

use std::{
    env,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Result, bail};

fn main() -> ExitCode {
    match run() {
        Ok(exit) => exit,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let workspace = workspace_root()?;
    let root = workspace.join("specs");
    dispatch_command(&arguments, &workspace, &root)?;
    Ok(ExitCode::SUCCESS)
}

fn dispatch_command(arguments: &[String], workspace: &Path, root: &Path) -> Result<()> {
    match arguments {
        [scope, command] if scope == "specs" && command == "generate" => {
            spec_generate(workspace, root)?;
        }
        [scope, command] if scope == "specs" && command == "verify" => spec_verify(root)?,
        [scope, area, command]
            if scope == "specs" && area == "extensions" && command == "record" =>
        {
            let markers = extensions::Overlay::record(root)?;
            for marker in markers {
                println!(
                    "recorded deterministic specification extension overlay at {}",
                    marker.display()
                );
            }
        }
        [scope, command, rest @ ..] if scope == "profiles" && command == "generate-verify" => {
            let report = profiles::generate_verify(workspace, rest)?;
            println!(
                "all {} generated profiles passed the deterministic matrix",
                report.expected_profiles()
            );
        }
        [scope, command] if scope == "profiles" && command == "verify" => {
            let summary = profiles::verify(root)?;
            println!(
                "profiles valid: {} profiles compose {} catalog modules",
                summary.profiles, summary.modules
            );
        }
        [scope, command] if scope == "openapi" && command == "generate" => {
            openapi::generate(workspace)?;
            println!("generated deterministic public OpenAPI document");
        }
        [scope, command] if scope == "openapi" && command == "verify" => {
            openapi::verify(workspace)?;
            println!("public OpenAPI document is valid and current");
        }
        [scope, command, baseline] if scope == "openapi" && command == "breaking" => {
            openapi::verify_breaking(workspace, baseline)?;
            println!("public OpenAPI document has no breaking changes");
        }
        [scope, command] if scope == "docs" && command == "verify" => {
            let summary = docs::verify(workspace)?;
            println!(
                "documentation valid: {} pages, {} capabilities, {} navigation entries",
                summary.pages, summary.capabilities, summary.navigation_entries
            );
        }
        [scope, command] if scope == "ai" && command == "verify" => {
            let summary = ai::verify(workspace)?;
            println!(
                "AI architecture valid: {} modules, {} Rust sources checked",
                summary.modules, summary.rust_files
            );
        }
        [scope, command] if scope == "asyncapi" && command == "generate" => {
            asyncapi::generate(workspace)?;
            println!("generated deterministic public AsyncAPI document");
        }
        [scope, command] if scope == "asyncapi" && command == "verify" => {
            asyncapi::verify(workspace)?;
            println!("public AsyncAPI document is valid and current");
        }
        [scope, command] if scope == "contracts" && command == "generate" => {
            generate_contracts(workspace)?;
        }
        [scope, command] if scope == "contracts" && command == "check" => {
            check_contracts(workspace)?;
        }
        [scope, command, flag, baseline]
            if scope == "contracts" && command == "diff" && flag == "--against" =>
        {
            let report =
                contract_diff::compare_against(workspace, baseline, &workspace.join("contracts"))?;
            contract_diff::emit_and_enforce(&report)?;
            println!("public contract set has no breaking changes");
        }
        [scope, command, template_root, template_name] if scope == "email" && command == "lint" => {
            email::lint(Path::new(template_root), template_name)?;
        }
        [scope, command, template_root, template_name, context]
            if scope == "email" && command == "preview" =>
        {
            email::preview(Path::new(template_root), template_name, Path::new(context))?;
        }
        _ => bail!(
            "usage: cargo xtask specs <generate|verify|extensions record> | profiles <verify|generate-verify [--jobs 1] [--report PATH] [--automated-evidence-only] [--matrix-only (local diagnostics only)]> | ai verify | docs verify | contracts <generate|check|diff --against PATH> | openapi <generate|verify|breaking BASELINE> | asyncapi <generate|verify> | email lint TEMPLATE_ROOT TEMPLATE | email preview TEMPLATE_ROOT TEMPLATE CONTEXT_JSON"
        ),
    }
    Ok(())
}

fn generate_contracts(workspace: &Path) -> Result<()> {
    openapi::generate(workspace)?;
    if omnius_reference_api::PUBLIC_PROFILE_MODULES.contains(&"realtime-core") {
        asyncapi::generate(workspace)?;
    }
    contracts::generate(workspace)?;
    println!("generated deterministic public contract set");
    Ok(())
}

fn check_contracts(workspace: &Path) -> Result<()> {
    openapi::verify(workspace)?;
    if omnius_reference_api::PUBLIC_PROFILE_MODULES.contains(&"realtime-core") {
        asyncapi::verify(workspace)?;
    }
    contracts::check(workspace)?;
    println!("public contract set is valid and current");
    Ok(())
}

fn spec_generate(workspace: &Path, root: &Path) -> Result<()> {
    specs::generate_service_kit(workspace)?;
    spec_archive::generate(root)?;
    println!("generated deterministic specifications and root service-kit catalog");
    Ok(())
}

fn spec_verify(root: &Path) -> Result<()> {
    let summary = specs::verify(root)?;
    println!(
        "specifications valid: {} modules, {} profiles, {} acceptance criteria, {} tasks, {} recommendations",
        summary.modules, summary.profiles, summary.criteria, summary.tasks, summary.recommendations
    );
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("xtask manifest has no workspace parent"))
}
