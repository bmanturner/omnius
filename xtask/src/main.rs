//! Repository automation entry point.

mod asyncapi;
mod contract_diff;
mod contracts;
mod email;
mod extensions;
mod model;
mod openapi;
mod profiles;
mod service;
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
    if let Some((scope, service_arguments)) = arguments.split_first()
        && scope == "service"
    {
        return service::execute(service_arguments, &workspace);
    }
    let root = workspace.join("specs");
    match arguments.as_slice() {
        [scope, command] if scope == "specs" && command == "generate" => spec_generate(&root)?,
        [scope, command] if scope == "specs" && command == "verify" => spec_verify(&root)?,
        [scope, area, command]
            if scope == "specs" && area == "extensions" && command == "record" =>
        {
            let marker = extensions::Overlay::record(&root)?;
            println!(
                "recorded deterministic web extension overlay at {}",
                marker.display()
            );
        }
        [scope, command, rest @ ..] if scope == "profiles" && command == "generate-verify" => {
            let report = profiles::generate_verify(&workspace, rest)?;
            println!(
                "all {} generated profiles passed the deterministic matrix",
                report.expected_profiles()
            );
        }
        [scope, command] if scope == "profiles" && command == "verify" => {
            let summary = profiles::verify(&root)?;
            println!(
                "profiles valid: {} profiles compose {} catalog modules",
                summary.profiles, summary.modules
            );
        }
        [scope, command] if scope == "openapi" && command == "generate" => {
            openapi::generate(&workspace)?;
            println!("generated deterministic public OpenAPI document");
        }
        [scope, command] if scope == "openapi" && command == "verify" => {
            openapi::verify(&workspace)?;
            println!("public OpenAPI document is valid and current");
        }
        [scope, command, baseline] if scope == "openapi" && command == "breaking" => {
            openapi::verify_breaking(&workspace, baseline)?;
            println!("public OpenAPI document has no breaking changes");
        }
        [scope, command] if scope == "asyncapi" && command == "generate" => {
            asyncapi::generate(&workspace)?;
            println!("generated deterministic public AsyncAPI document");
        }
        [scope, command] if scope == "asyncapi" && command == "verify" => {
            asyncapi::verify(&workspace)?;
            println!("public AsyncAPI document is valid and current");
        }
        [scope, command] if scope == "contracts" && command == "generate" => {
            openapi::generate(&workspace)?;
            if omnius_api_server::PUBLIC_PROFILE_MODULES.contains(&"realtime-core") {
                asyncapi::generate(&workspace)?;
            }
            contracts::generate(&workspace)?;
            println!("generated deterministic public contract set");
        }
        [scope, command] if scope == "contracts" && command == "check" => {
            openapi::verify(&workspace)?;
            if omnius_api_server::PUBLIC_PROFILE_MODULES.contains(&"realtime-core") {
                asyncapi::verify(&workspace)?;
            }
            contracts::check(&workspace)?;
            println!("public contract set is valid and current");
        }
        [scope, command, flag, baseline]
            if scope == "contracts" && command == "diff" && flag == "--against" =>
        {
            let report =
                contract_diff::compare_against(&workspace, baseline, &workspace.join("contracts"))?;
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
            "usage: cargo xtask specs <generate|verify|extensions record> | profiles <verify|generate-verify [--jobs N] [--report PATH] [--automated-evidence-only] [--matrix-only (local diagnostics only)]> | contracts <generate|check|diff --against PATH> | openapi <generate|verify|breaking BASELINE> | asyncapi <generate|verify> | email lint TEMPLATE_ROOT TEMPLATE | email preview TEMPLATE_ROOT TEMPLATE CONTEXT_JSON | service <add|remove|upgrade|doctor|diff> ..."
        ),
    }
    Ok(ExitCode::SUCCESS)
}

fn spec_generate(root: &Path) -> Result<()> {
    spec_archive::generate(root)?;
    println!("generated deterministic complete specifications and archive metadata");
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
