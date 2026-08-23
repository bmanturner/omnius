//! Repository automation entry point.

mod model;
mod profiles;
mod specs;

use std::{env, path::PathBuf, process::ExitCode};

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
    let root = specification_root()?;
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
        _ => bail!("usage: cargo xtask <specs|profiles> verify"),
    }
    Ok(())
}

fn specification_root() -> Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("xtask manifest has no workspace parent"))?;
    Ok(workspace.join("specs"))
}
