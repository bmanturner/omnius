//! Repository automation entry point.

mod email;
mod model;
mod openapi;
mod profiles;
mod specs;

use std::{
    env,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Result, bail};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let workspace = workspace_root()?;
    let root = workspace.join("specs");
    match arguments.as_slice() {
        [scope, command] if scope == "specs" && command == "verify" => {
            let summary = specs::verify(&root)?;
            println!(
                "specifications valid: {} modules, {} profiles, {} acceptance criteria, {} tasks, {} recommendations",
                summary.modules,
                summary.profiles,
                summary.criteria,
                summary.tasks,
                summary.recommendations
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
        [scope, command, template_root, template_name] if scope == "email" && command == "lint" => {
            email::lint(Path::new(template_root), template_name)?;
        }
        [scope, command, template_root, template_name, context]
            if scope == "email" && command == "preview" =>
        {
            email::preview(Path::new(template_root), template_name, Path::new(context))?;
        }
        _ => bail!(
            "usage: cargo xtask <specs|profiles> verify | openapi <generate|verify|breaking BASELINE> | email lint TEMPLATE_ROOT TEMPLATE | email preview TEMPLATE_ROOT TEMPLATE CONTEXT_JSON"
        ),
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("xtask manifest has no workspace parent"))
}
