use std::{env, path::PathBuf, process::ExitCode};

use anyhow::{Context as _, Result, bail};
use omnius_generator::{ManagementPlan, ModuleCatalog, PlanOperation, ProjectManager};
use serde::Serialize;

const MACHINE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    Add,
    Remove,
    Upgrade,
    Doctor,
    Diff,
}

impl Command {
    fn name(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Upgrade => "upgrade",
            Self::Doctor => "doctor",
            Self::Diff => "diff",
        }
    }
}

struct Options {
    command: Command,
    module: Option<String>,
    target_version: Option<String>,
    project: PathBuf,
    dry_run: bool,
    json: bool,
}

#[derive(Serialize)]
struct MachineSuccess<T> {
    schema_version: u32,
    command: &'static str,
    status: &'static str,
    result: T,
}

#[derive(Serialize)]
struct MachineError<'a> {
    schema_version: u32,
    command: &'a str,
    status: &'static str,
    error: MachineErrorBody,
}

#[derive(Serialize)]
struct MachineErrorBody {
    code: &'static str,
    message: String,
}

/// Parses and executes `cargo xtask service ...`, including deterministic JSON
/// error envelopes when machine output was requested.
pub(crate) fn execute(arguments: &[String], kit_root: &std::path::Path) -> Result<ExitCode> {
    let wants_json = arguments
        .iter()
        .any(|argument| matches!(argument.as_str(), "--json" | "--machine"));
    match execute_inner(arguments, kit_root) {
        Ok(exit) => Ok(exit),
        Err(error) if wants_json => {
            let command = arguments.first().map_or("unknown", String::as_str);
            print_json(&MachineError {
                schema_version: MACHINE_SCHEMA_VERSION,
                command,
                status: "error",
                error: MachineErrorBody {
                    code: "service-command-failed",
                    message: format!("{error:#}"),
                },
            })?;
            Ok(ExitCode::FAILURE)
        }
        Err(error) => Err(error),
    }
}

fn execute_inner(arguments: &[String], kit_root: &std::path::Path) -> Result<ExitCode> {
    let options = parse_options(arguments)?;
    let catalog = ModuleCatalog::bundled().context("cannot load bundled module catalog")?;
    let manager = ProjectManager::new(&options.project, kit_root, &catalog);
    match options.command {
        Command::Add | Command::Remove | Command::Upgrade => execute_mutation(&manager, &options),
        Command::Doctor => {
            let report = manager.doctor().context("service doctor failed")?;
            if options.json {
                print_json(&MachineSuccess {
                    schema_version: MACHINE_SCHEMA_VERSION,
                    command: options.command.name(),
                    status: if report.healthy { "clean" } else { "unhealthy" },
                    result: &report,
                })?;
            } else if report.healthy {
                println!("service doctor: clean");
            } else {
                println!("service doctor: {} finding(s)", report.diagnostics.len());
                for diagnostic in &report.diagnostics {
                    match &diagnostic.path {
                        Some(path) => {
                            println!("- {} [{}]: {}", diagnostic.code, path, diagnostic.message);
                        }
                        None => println!("- {}: {}", diagnostic.code, diagnostic.message),
                    }
                }
            }
            Ok(if report.healthy {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Command::Diff => {
            let plan = manager.diff().context("service diff failed")?;
            if options.json {
                print_json(&MachineSuccess {
                    schema_version: MACHINE_SCHEMA_VERSION,
                    command: options.command.name(),
                    status: if plan.is_empty() { "clean" } else { "changes" },
                    result: &plan,
                })?;
            } else {
                print_human_plan(&plan, true);
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn execute_mutation(manager: &ProjectManager<'_>, options: &Options) -> Result<ExitCode> {
    let (subject, planned) = match options.command {
        Command::Add => {
            let module = options.module.as_deref().ok_or_else(|| {
                anyhow::anyhow!("{} requires one module id", options.command.name())
            })?;
            (module, manager.plan_add(module))
        }
        Command::Remove => {
            let module = options.module.as_deref().ok_or_else(|| {
                anyhow::anyhow!("{} requires one module id", options.command.name())
            })?;
            (module, manager.plan_remove(module))
        }
        Command::Upgrade => {
            let target = options
                .target_version
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("upgrade requires --to VERSION"))?;
            (target, manager.plan_upgrade(target))
        }
        Command::Doctor | Command::Diff => {
            unreachable!("mutation dispatcher validated command")
        }
    };
    let plan = planned
        .with_context(|| format!("service {} `{subject}` failed", options.command.name()))?;

    if options.dry_run {
        if options.json {
            print_json(&MachineSuccess {
                schema_version: MACHINE_SCHEMA_VERSION,
                command: options.command.name(),
                status: if plan.is_empty() {
                    "unchanged"
                } else {
                    "planned"
                },
                result: &plan,
            })?;
        } else {
            print_human_plan(&plan, true);
        }
        return Ok(ExitCode::SUCCESS);
    }

    let outcome = manager
        .apply(&plan)
        .context("safe plan application failed")?;
    if options.json {
        print_json(&MachineSuccess {
            schema_version: MACHINE_SCHEMA_VERSION,
            command: options.command.name(),
            status: if outcome.changed_files == 0 {
                "unchanged"
            } else {
                "applied"
            },
            result: &outcome,
        })?;
    } else if outcome.changed_files == 0 {
        println!(
            "service {} `{subject}`: already in requested state",
            options.command.name()
        );
    } else {
        println!(
            "service {} `{subject}`: applied {} file change(s); backup {}",
            options.command.name(),
            outcome.changed_files,
            outcome.backup_artifact
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn parse_options(arguments: &[String]) -> Result<Options> {
    let (command_name, rest) = arguments
        .split_first()
        .ok_or_else(|| anyhow::anyhow!(usage()))?;
    let command = match command_name.as_str() {
        "add" => Command::Add,
        "remove" => Command::Remove,
        "upgrade" => Command::Upgrade,
        "doctor" => Command::Doctor,
        "diff" => Command::Diff,
        _ => bail!(usage()),
    };
    let mut module = None;
    let mut target_version = None;
    let mut project = None;
    let mut dry_run = false;
    let mut json = false;
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--project" => {
                index += 1;
                let value = rest
                    .get(index)
                    .ok_or_else(|| anyhow::anyhow!("--project requires a path"))?;
                if project.replace(PathBuf::from(value)).is_some() {
                    bail!("--project may be specified only once");
                }
            }
            "--to" => {
                index += 1;
                let value = rest
                    .get(index)
                    .ok_or_else(|| anyhow::anyhow!("--to requires a version"))?;
                if target_version.replace(value.clone()).is_some() {
                    bail!("--to may be specified only once");
                }
            }
            "--dry-run" => {
                if dry_run {
                    bail!("--dry-run may be specified only once");
                }
                dry_run = true;
            }
            "--json" | "--machine" => {
                json = true;
            }
            value if value.starts_with('-') => bail!("unknown service option `{value}`"),
            value => {
                if module.replace(value.to_owned()).is_some() {
                    bail!("service command accepts only one module id");
                }
            }
        }
        index += 1;
    }
    if matches!(command, Command::Add | Command::Remove) && module.is_none() {
        bail!("{} requires one module id", command.name());
    }
    if command == Command::Upgrade && target_version.is_none() {
        bail!("upgrade requires --to VERSION");
    }
    if matches!(command, Command::Doctor | Command::Diff | Command::Upgrade) && module.is_some() {
        bail!("{} does not accept a module id", command.name());
    }
    if command != Command::Upgrade && target_version.is_some() {
        bail!("--to is valid only for service upgrade");
    }
    if dry_run && matches!(command, Command::Doctor | Command::Diff) {
        bail!("--dry-run is valid only for service add/remove/upgrade");
    }
    let project = match project {
        Some(project) => project,
        None => env::current_dir().context("cannot read current directory")?,
    };
    Ok(Options {
        command,
        module,
        target_version,
        project,
        dry_run,
        json,
    })
}

fn print_human_plan(plan: &ManagementPlan, dry_run: bool) {
    let disposition = if plan.is_empty() {
        "no changes"
    } else if dry_run {
        "planned"
    } else {
        "changes"
    };
    println!(
        "service {}: {disposition} (plan {})",
        match plan.action {
            omnius_generator::PlanAction::Add => "add",
            omnius_generator::PlanAction::Remove => "remove",
            omnius_generator::PlanAction::Diff => "diff",
            omnius_generator::PlanAction::Upgrade => "upgrade",
        },
        plan.plan_id
    );
    for operation in &plan.operations {
        let (kind, path) = match operation {
            PlanOperation::CreateFile { path, .. } => ("create", path),
            PlanOperation::ReplaceKitFile { path, .. } => ("replace", path),
            PlanOperation::ReconcileRegions { path, .. } => ("reconcile", path),
            PlanOperation::RegenerateDerived { path, .. } => ("regenerate", path),
            PlanOperation::RemoveFile { path, .. } => ("remove", path),
            PlanOperation::WriteLock { path, .. } => ("lock", path),
            PlanOperation::WriteState { path, .. } => ("state", path),
        };
        println!("- {kind}: {path}");
    }
    for path in &plan.preserved_paths {
        println!("- preserve: {path}");
    }
}

fn print_json(value: &impl Serialize) -> Result<()> {
    let encoded = serde_json::to_string(value).context("cannot encode machine output")?;
    println!("{encoded}");
    Ok(())
}

fn usage() -> &'static str {
    "usage: cargo xtask service add MODULE [--project PATH] [--dry-run] [--json|--machine] | service remove MODULE [--project PATH] [--dry-run] [--json|--machine] | service upgrade --to VERSION [--project PATH] [--dry-run] [--json|--machine] | service doctor [--project PATH] [--json|--machine] | service diff [--project PATH] [--json|--machine]"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_options_accept_project_dry_run_and_machine_output_in_any_order() -> Result<()> {
        let arguments = vec![
            "add".to_owned(),
            "--machine".to_owned(),
            "feature-flags".to_owned(),
            "--dry-run".to_owned(),
            "--project".to_owned(),
            "fixture".to_owned(),
        ];
        let options = parse_options(&arguments)?;

        assert_eq!(
            (
                options.command,
                options.module.as_deref(),
                options.project.as_path(),
                options.dry_run,
                options.json,
            ),
            (
                Command::Add,
                Some("feature-flags"),
                std::path::Path::new("fixture"),
                true,
                true,
            )
        );
        Ok(())
    }

    #[test]
    fn upgrade_options_require_explicit_target() -> Result<()> {
        let arguments = vec![
            "upgrade".to_owned(),
            "--project".to_owned(),
            "fixture".to_owned(),
            "--to".to_owned(),
            "0.1.0".to_owned(),
            "--json".to_owned(),
        ];
        let options = parse_options(&arguments)?;

        assert_eq!(
            (
                options.command,
                options.target_version.as_deref(),
                options.project.as_path(),
                options.json,
            ),
            (
                Command::Upgrade,
                Some("0.1.0"),
                std::path::Path::new("fixture"),
                true,
            )
        );
        Ok(())
    }

    #[test]
    fn machine_error_schema_is_byte_deterministic() -> Result<()> {
        let error = MachineError {
            schema_version: MACHINE_SCHEMA_VERSION,
            command: "add",
            status: "error",
            error: MachineErrorBody {
                code: "service-command-failed",
                message: "conflict".to_owned(),
            },
        };

        assert_eq!(
            serde_json::to_string(&error)?,
            r#"{"schema_version":1,"command":"add","status":"error","error":{"code":"service-command-failed","message":"conflict"}}"#
        );
        Ok(())
    }

    #[test]
    fn doctor_rejects_mutation_only_flags() {
        let arguments = vec!["doctor".to_owned(), "--dry-run".to_owned()];
        let error = parse_options(&arguments)
            .err()
            .map(|error| error.to_string());

        assert_eq!(
            error.as_deref(),
            Some("--dry-run is valid only for service add/remove/upgrade")
        );
    }
}
