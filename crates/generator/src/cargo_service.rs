//! Installable `cargo service` command-line boundary.

use std::{
    ffi::OsString,
    fmt, fs,
    io::Write,
    path::{Path, PathBuf},
};

use clap::{Args, Parser, Subcommand, error::ErrorKind};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    CANONICAL_REPOSITORY, CargoGraphError, CargoResolverError, Diagnostic, GENERATOR_VERSION,
    KIT_VERSION, ManagementPlan, ManagerError, ModuleCatalog, PROJECT_STATE_PATH, ProjectManager,
    ProjectState, ReleaseBuildStatus, ReleaseIdentity, ReleaseIdentityError, RenderError,
    RenderRequest, render_project_with_options,
};

const JSON_SCHEMA_VERSION: u32 = 1;
const EXIT_SUCCESS: u8 = 0;
const EXIT_OPERATIONAL: u8 = 1;
const EXIT_SYNTAX: u8 = 2;

#[derive(Debug, Parser)]
#[command(
    name = "cargo-service",
    bin_name = "cargo service",
    about = "Manage an Omnius service project",
    disable_version_flag = true,
    arg_required_else_help = true
)]
struct Cli {
    /// Print the release identity of this cargo-service build.
    #[arg(long, exclusive = true)]
    version: bool,

    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Create a service from a bundled profile.
    New(NewArgs),
    /// Add a runtime module.
    Add(ModuleArgs),
    /// Remove a runtime module.
    Remove(ModuleArgs),
    /// Replace the runtime selection with a bundled profile.
    Profile(ProfileArgs),
    /// Update the project to this CLI's immutable release.
    Update(ProjectMutationArgs),
    /// Diagnose project integrity and provenance.
    Doctor(ProjectArgs),
    /// Show deterministic generated-file drift.
    Diff(ProjectArgs),
}

#[derive(Debug, Args)]
struct NewArgs {
    /// Canonical lowercase kebab-case service name.
    name: String,
    /// Bundled runtime profile.
    #[arg(long)]
    profile: String,
    /// Destination path; defaults to ./NAME.
    #[arg(long)]
    path: Option<PathBuf>,
    /// Resolve only from Cargo's local cache.
    #[arg(long)]
    offline: bool,
    /// Emit one stable JSON document.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ModuleArgs {
    /// Runtime module identifier.
    module: String,
    /// Managed project root.
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Resolve and seal the exact plan without applying it.
    #[arg(long)]
    dry_run: bool,
    /// Resolve only from Cargo's local cache.
    #[arg(long)]
    offline: bool,
    /// Emit one stable JSON document.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ProfileArgs {
    #[command(subcommand)]
    command: ProfileCommand,
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// Replace the runtime selection with the exact profile closure.
    Set(ProfileSetArgs),
}

#[derive(Debug, Args)]
struct ProfileSetArgs {
    /// Bundled runtime profile.
    profile: String,
    /// Managed project root.
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Resolve and seal the exact plan without applying it.
    #[arg(long)]
    dry_run: bool,
    /// Resolve only from Cargo's local cache.
    #[arg(long)]
    offline: bool,
    /// Emit one stable JSON document.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ProjectMutationArgs {
    /// Managed project root.
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Resolve and seal the exact plan without applying it.
    #[arg(long)]
    dry_run: bool,
    /// Resolve only from Cargo's local cache.
    #[arg(long)]
    offline: bool,
    /// Emit one stable JSON document.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ProjectArgs {
    /// Managed project root.
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Emit one stable JSON document.
    #[arg(long)]
    json: bool,
}

/// Canonical command request after direct and Cargo-prefixed argv normalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceInvocation {
    /// Create a new service.
    New {
        /// Service name.
        name: String,
        /// Profile identifier.
        profile: String,
        /// Destination path.
        project: PathBuf,
        /// Cargo cache-only resolution.
        offline: bool,
        /// Machine-readable output.
        json: bool,
    },
    /// Add one module.
    Add(ModuleInvocation),
    /// Remove one module.
    Remove(ModuleInvocation),
    /// Set one exact profile.
    ProfileSet(ProfileSetInvocation),
    /// Update to this CLI release.
    Update(ProjectMutationInvocation),
    /// Diagnose one project.
    Doctor(ProjectInvocation),
    /// Diff one project.
    Diff(ProjectInvocation),
}

/// Shared arguments for add and remove.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleInvocation {
    /// Module identifier.
    pub module: String,
    /// Project root.
    pub project: PathBuf,
    /// Seal without applying.
    pub dry_run: bool,
    /// Cargo cache-only resolution.
    pub offline: bool,
    /// Machine-readable output.
    pub json: bool,
}

/// Parsed exact-profile transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileSetInvocation {
    /// Profile identifier.
    pub profile: String,
    /// Project root.
    pub project: PathBuf,
    /// Seal without applying.
    pub dry_run: bool,
    /// Cargo cache-only resolution.
    pub offline: bool,
    /// Machine-readable output.
    pub json: bool,
}

/// Parsed project mutation without a separate operand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectMutationInvocation {
    /// Project root.
    pub project: PathBuf,
    /// Seal without applying.
    pub dry_run: bool,
    /// Cargo cache-only resolution.
    pub offline: bool,
    /// Machine-readable output.
    pub json: bool,
}

/// Parsed read-only project command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectInvocation {
    /// Project root.
    pub project: PathBuf,
    /// Machine-readable output.
    pub json: bool,
}

impl ServiceInvocation {
    fn command_name(&self) -> &'static str {
        match self {
            Self::New { .. } => "new",
            Self::Add(_) => "add",
            Self::Remove(_) => "remove",
            Self::ProfileSet(_) => "profile-set",
            Self::Update(_) => "update",
            Self::Doctor(_) => "doctor",
            Self::Diff(_) => "diff",
        }
    }

    fn project(&self) -> &Path {
        match self {
            Self::New { project, .. } => project,
            Self::Add(arguments) | Self::Remove(arguments) => &arguments.project,
            Self::ProfileSet(arguments) => &arguments.project,
            Self::Update(arguments) => &arguments.project,
            Self::Doctor(arguments) | Self::Diff(arguments) => &arguments.project,
        }
    }

    const fn wants_json(&self) -> bool {
        match self {
            Self::New { json, .. } => *json,
            Self::Add(arguments) | Self::Remove(arguments) => arguments.json,
            Self::ProfileSet(arguments) => arguments.json,
            Self::Update(arguments) => arguments.json,
            Self::Doctor(arguments) | Self::Diff(arguments) => arguments.json,
        }
    }
}

/// Stable operational failure returned by a service command runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceError {
    /// Stable machine-readable classification.
    pub code: &'static str,
    /// Actionable diagnostic text.
    pub message: String,
}

impl ServiceError {
    /// Constructs an explicitly classified runner failure.
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ServiceError {}

/// Successful runner result before human or JSON presentation.
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceExecution {
    /// Stable status string.
    pub status: &'static str,
    /// Reviewable plan or result details.
    pub plan: Option<Value>,
    /// Structured diagnostics.
    pub diagnostics: Vec<Diagnostic>,
    /// Human result lines written to stdout.
    pub human_output: Vec<String>,
    /// Process exit classification.
    pub exit_code: u8,
}

/// Injectable orchestration boundary used by the binary and CLI-local tests.
pub trait ServiceRunner {
    /// Reports the executing build's release binding.
    ///
    /// # Errors
    ///
    /// Returns an error when the compiled release binding is invalid.
    fn release_status(&self) -> Result<ReleaseBuildStatus, ServiceError>;

    /// Executes one fully parsed command.
    ///
    /// # Errors
    ///
    /// Returns an error when the command cannot be completed or its result cannot be encoded.
    fn execute(
        &self,
        invocation: &ServiceInvocation,
        release: &ReleaseBuildStatus,
    ) -> Result<ServiceExecution, ServiceError>;
}

/// Filesystem and Cargo-backed production runner.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionServiceRunner;

impl ServiceRunner for ProductionServiceRunner {
    fn release_status(&self) -> Result<ReleaseBuildStatus, ServiceError> {
        ReleaseBuildStatus::current().map_err(|error| classify_release_error(&error))
    }

    fn execute(
        &self,
        invocation: &ServiceInvocation,
        release: &ReleaseBuildStatus,
    ) -> Result<ServiceExecution, ServiceError> {
        execute_production(invocation, release)
    }
}

#[derive(Debug, Serialize)]
struct JsonEnvelope {
    schema_version: u32,
    command: String,
    status: &'static str,
    project: Option<String>,
    release: Value,
    plan: Option<Value>,
    diagnostics: Vec<Diagnostic>,
    error: Option<JsonError>,
}

#[derive(Debug, Serialize)]
struct JsonError {
    code: &'static str,
    message: String,
}

/// Runs the CLI from a complete process argv sequence through an injected runner.
///
/// The first element is the executable name. Exactly one following `service` token is removed so
/// direct `cargo-service ...` and Cargo's `cargo-service service ...` invocation are identical.
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "the presentation boundary keeps every exit and stream policy in one auditable function"
)]
pub fn run_with<R, I, T, O, E>(runner: &R, arguments: I, stdout: &mut O, stderr: &mut E) -> u8
where
    R: ServiceRunner,
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
    O: Write,
    E: Write,
{
    let normalized = normalize_argv(arguments);
    let wants_json = normalized.iter().any(|argument| argument == "--json");
    let command_hint = command_hint(&normalized);
    let parsed = Cli::try_parse_from(
        std::iter::once(OsString::from("cargo-service")).chain(normalized.iter().cloned()),
    );
    let cli = match parsed {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            let _ = write!(stdout, "{error}");
            return EXIT_SUCCESS;
        }
        Err(error) if wants_json => {
            let envelope = error_envelope(
                command_hint,
                None,
                release_json(None),
                "invalid-arguments",
                error.to_string(),
            );
            write_json(stdout, &envelope);
            return EXIT_SYNTAX;
        }
        Err(error) => {
            let _ = write!(stderr, "{error}");
            return EXIT_SYNTAX;
        }
    };

    let release = match runner.release_status() {
        Ok(release) => release,
        Err(error) => {
            let envelope = error_envelope(
                cli.command
                    .as_ref()
                    .map_or_else(|| "version".to_owned(), cli_command_name),
                None,
                release_json(None),
                error.code,
                error.message,
            );
            if wants_json {
                write_json(stdout, &envelope);
            } else {
                let _ = writeln!(
                    stderr,
                    "error: {}",
                    envelope.error.as_ref().map_or("", |e| &e.message)
                );
            }
            return EXIT_OPERATIONAL;
        }
    };

    if cli.version {
        let _ = writeln!(stdout, "{}", format_version(&release));
        return EXIT_SUCCESS;
    }

    let Some(command) = cli.command else {
        let _ = writeln!(stderr, "error: a command is required");
        return EXIT_SYNTAX;
    };
    let invocation = ServiceInvocation::from(command);
    match runner.execute(&invocation, &release) {
        Ok(execution) if invocation.wants_json() => {
            let envelope = JsonEnvelope {
                schema_version: JSON_SCHEMA_VERSION,
                command: invocation.command_name().to_owned(),
                status: execution.status,
                project: Some(invocation.project().display().to_string()),
                release: release_json(Some(&release)),
                plan: execution.plan,
                diagnostics: execution.diagnostics,
                error: None,
            };
            write_json(stdout, &envelope);
            execution.exit_code
        }
        Ok(execution) => {
            for line in execution.human_output {
                let _ = writeln!(stdout, "{line}");
            }
            for diagnostic in execution.diagnostics {
                if let Some(path) = diagnostic.path {
                    let _ = writeln!(
                        stderr,
                        "{} [{}]: {}",
                        diagnostic.code, path, diagnostic.message
                    );
                } else {
                    let _ = writeln!(stderr, "{}: {}", diagnostic.code, diagnostic.message);
                }
            }
            execution.exit_code
        }
        Err(error) if invocation.wants_json() => {
            let envelope = error_envelope(
                invocation.command_name().to_owned(),
                Some(invocation.project()),
                release_json(Some(&release)),
                error.code,
                error.message,
            );
            write_json(stdout, &envelope);
            EXIT_OPERATIONAL
        }
        Err(error) => {
            let _ = writeln!(stderr, "error: {}", error.message);
            EXIT_OPERATIONAL
        }
    }
}

/// Runs the production CLI using the current process arguments and standard streams.
#[must_use]
pub fn main_entry() -> u8 {
    run_with(
        &ProductionServiceRunner,
        std::env::args_os(),
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )
}

fn normalize_argv<I, T>(arguments: I) -> Vec<OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let _executable = arguments.next();
    let mut normalized: Vec<_> = arguments.collect();
    if normalized
        .first()
        .is_some_and(|argument| argument == "service")
    {
        normalized.remove(0);
    }
    normalized
}

fn command_hint(arguments: &[OsString]) -> String {
    match (
        arguments.first().and_then(|value| value.to_str()),
        arguments.get(1).and_then(|value| value.to_str()),
    ) {
        (Some("profile"), Some("set")) => "profile-set".to_owned(),
        (Some(command), _) if !command.starts_with('-') => command.to_owned(),
        _ => "unknown".to_owned(),
    }
}

fn cli_command_name(command: &CliCommand) -> String {
    match command {
        CliCommand::New(_) => "new",
        CliCommand::Add(_) => "add",
        CliCommand::Remove(_) => "remove",
        CliCommand::Profile(_) => "profile-set",
        CliCommand::Update(_) => "update",
        CliCommand::Doctor(_) => "doctor",
        CliCommand::Diff(_) => "diff",
    }
    .to_owned()
}

impl From<CliCommand> for ServiceInvocation {
    fn from(command: CliCommand) -> Self {
        match command {
            CliCommand::New(arguments) => {
                let project = arguments
                    .path
                    .unwrap_or_else(|| PathBuf::from(format!("./{}", arguments.name)));
                Self::New {
                    name: arguments.name,
                    profile: arguments.profile,
                    project,
                    offline: arguments.offline,
                    json: arguments.json,
                }
            }
            CliCommand::Add(arguments) => Self::Add(arguments.into()),
            CliCommand::Remove(arguments) => Self::Remove(arguments.into()),
            CliCommand::Profile(ProfileArgs {
                command: ProfileCommand::Set(arguments),
            }) => Self::ProfileSet(ProfileSetInvocation {
                profile: arguments.profile,
                project: arguments.project,
                dry_run: arguments.dry_run,
                offline: arguments.offline,
                json: arguments.json,
            }),
            CliCommand::Update(arguments) => Self::Update(arguments.into()),
            CliCommand::Doctor(arguments) => Self::Doctor(arguments.into()),
            CliCommand::Diff(arguments) => Self::Diff(arguments.into()),
        }
    }
}

impl From<ModuleArgs> for ModuleInvocation {
    fn from(arguments: ModuleArgs) -> Self {
        Self {
            module: arguments.module,
            project: arguments.project,
            dry_run: arguments.dry_run,
            offline: arguments.offline,
            json: arguments.json,
        }
    }
}

impl From<ProjectMutationArgs> for ProjectMutationInvocation {
    fn from(arguments: ProjectMutationArgs) -> Self {
        Self {
            project: arguments.project,
            dry_run: arguments.dry_run,
            offline: arguments.offline,
            json: arguments.json,
        }
    }
}

impl From<ProjectArgs> for ProjectInvocation {
    fn from(arguments: ProjectArgs) -> Self {
        Self {
            project: arguments.project,
            json: arguments.json,
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the production boundary keeps lifecycle dispatch centralized and explicit"
)]
fn execute_production(
    invocation: &ServiceInvocation,
    release: &ReleaseBuildStatus,
) -> Result<ServiceExecution, ServiceError> {
    match invocation {
        ServiceInvocation::New {
            name,
            profile,
            project,
            offline,
            ..
        } => {
            let identity = mutation_identity()?;
            let outcome = render_project_with_options(
                RenderRequest {
                    service_name: name,
                    profile,
                    destination: project,
                    release_identity: &identity,
                },
                *offline,
            )
            .map_err(|error| classify_render_error(&error, *offline))?;
            Ok(ServiceExecution {
                status: "created",
                plan: Some(json!({ "rendered_files": outcome.files })),
                diagnostics: Vec::new(),
                human_output: vec![format!(
                    "created service `{name}` with profile `{profile}` at {}",
                    project.display()
                )],
                exit_code: EXIT_SUCCESS,
            })
        }
        ServiceInvocation::Add(arguments) => {
            let identity = mutation_identity()?;
            let catalog = load_catalog()?;
            let manager = ProjectManager::new(&arguments.project, &identity, &catalog);
            let sealed = manager
                .seal_add(&arguments.module, arguments.offline)
                .map_err(|error| classify_manager_error(&error, arguments.offline))?;
            finish_mutation(
                &manager,
                &sealed,
                arguments.dry_run,
                "add",
                &arguments.module,
            )
        }
        ServiceInvocation::Remove(arguments) => {
            let identity = mutation_identity()?;
            let catalog = load_catalog()?;
            let manager = ProjectManager::new(&arguments.project, &identity, &catalog);
            let sealed = manager
                .seal_remove(&arguments.module, arguments.offline)
                .map_err(|error| classify_manager_error(&error, arguments.offline))?;
            finish_mutation(
                &manager,
                &sealed,
                arguments.dry_run,
                "remove",
                &arguments.module,
            )
        }
        ServiceInvocation::ProfileSet(arguments) => {
            let identity = mutation_identity()?;
            let catalog = load_catalog()?;
            let manager = ProjectManager::new(&arguments.project, &identity, &catalog);
            let sealed = manager
                .seal_profile_set(&arguments.profile, arguments.offline)
                .map_err(|error| classify_manager_error(&error, arguments.offline))?;
            finish_mutation(
                &manager,
                &sealed,
                arguments.dry_run,
                "profile set",
                &arguments.profile,
            )
        }
        ServiceInvocation::Update(arguments) => {
            let identity = mutation_identity()?;
            let catalog = load_catalog()?;
            let manager = ProjectManager::new(&arguments.project, &identity, &catalog);
            let sealed = manager
                .seal_update(arguments.offline)
                .map_err(|error| classify_manager_error(&error, arguments.offline))?;
            finish_mutation(
                &manager,
                &sealed,
                arguments.dry_run,
                "update",
                identity.version(),
            )
        }
        ServiceInvocation::Doctor(arguments) => {
            let Some(identity) = inspection_identity(&arguments.project, release) else {
                return Ok(unbound_inspection("doctor"));
            };
            let catalog = load_catalog()?;
            let manager = ProjectManager::new(&arguments.project, &identity, &catalog);
            let report = manager
                .doctor()
                .map_err(|error| classify_manager_error(&error, false))?;
            let mut diagnostics = report.diagnostics;
            diagnostics.extend(build_diagnostic(release));
            let healthy = report.healthy && diagnostics.is_empty();
            Ok(ServiceExecution {
                status: if healthy { "clean" } else { "unhealthy" },
                plan: None,
                diagnostics,
                human_output: vec![if healthy {
                    "service doctor: clean".to_owned()
                } else {
                    "service doctor: findings reported on stderr".to_owned()
                }],
                exit_code: if healthy {
                    EXIT_SUCCESS
                } else {
                    EXIT_OPERATIONAL
                },
            })
        }
        ServiceInvocation::Diff(arguments) => {
            let Some(identity) = inspection_identity(&arguments.project, release) else {
                return Ok(unbound_inspection("diff"));
            };
            let catalog = load_catalog()?;
            let manager = ProjectManager::new(&arguments.project, &identity, &catalog);
            let plan = manager
                .diff()
                .map_err(|error| classify_manager_error(&error, false))?;
            let status = if plan.is_empty() { "clean" } else { "changes" };
            let human_output = vec![plan_summary("diff", &plan, false)];
            Ok(ServiceExecution {
                status,
                plan: Some(plan_value(&plan)?),
                diagnostics: build_diagnostic(release).into_iter().collect(),
                human_output,
                exit_code: EXIT_SUCCESS,
            })
        }
    }
}

fn mutation_identity() -> Result<ReleaseIdentity, ServiceError> {
    ReleaseIdentity::current().map_err(|error| classify_release_error(&error))
}

fn inspection_identity(project: &Path, release: &ReleaseBuildStatus) -> Option<ReleaseIdentity> {
    match release {
        ReleaseBuildStatus::Clean(identity) => Some(identity.clone()),
        ReleaseBuildStatus::Dirty { revision } => {
            ReleaseIdentity::new(GENERATOR_VERSION, CANONICAL_REPOSITORY, revision).ok()
        }
        ReleaseBuildStatus::Unbound => fs::read_to_string(project.join(PROJECT_STATE_PATH))
            .ok()
            .and_then(|source| ProjectState::parse(&source).ok())
            .map(|state| state.framework),
    }
}

fn build_diagnostic(release: &ReleaseBuildStatus) -> Option<Diagnostic> {
    match release {
        ReleaseBuildStatus::Clean(_) => None,
        ReleaseBuildStatus::Dirty { revision } => Some(Diagnostic {
            code: "release-dirty".to_owned(),
            path: None,
            message: format!(
                "cargo-service was built from dirty source at revision {revision}; inspection is read-only"
            ),
        }),
        ReleaseBuildStatus::Unbound => Some(Diagnostic {
            code: "release-unbound".to_owned(),
            path: None,
            message: "cargo-service is not bound to an immutable revision; inspection uses the project's recorded release".to_owned(),
        }),
    }
}

fn unbound_inspection(command: &str) -> ServiceExecution {
    ServiceExecution {
        status: "unavailable",
        plan: None,
        diagnostics: vec![Diagnostic {
            code: "release-unbound".to_owned(),
            path: Some(PROJECT_STATE_PATH.to_owned()),
            message: format!(
                "cargo service {command} could not derive a release identity from this unbound build and project state"
            ),
        }],
        human_output: vec![format!("service {command}: inspection unavailable")],
        exit_code: EXIT_OPERATIONAL,
    }
}

fn load_catalog() -> Result<ModuleCatalog, ServiceError> {
    ModuleCatalog::bundled()
        .map_err(|error| ServiceError::new("invalid-project", error.to_string()))
}

fn finish_mutation(
    manager: &ProjectManager<'_>,
    sealed: &crate::SealedManagementPlan,
    dry_run: bool,
    command: &str,
    subject: &str,
) -> Result<ServiceExecution, ServiceError> {
    let plan = sealed.plan();
    let unchanged = plan.is_empty();
    let plan_json = plan_value(plan)?;
    let summary = plan_summary(command, plan, dry_run);
    if !dry_run {
        manager
            .apply(sealed)
            .map_err(|error| classify_manager_error(&error, false))?;
    }
    Ok(ServiceExecution {
        status: if unchanged {
            "noop"
        } else if dry_run {
            "planned"
        } else {
            "applied"
        },
        plan: Some(plan_json),
        diagnostics: Vec::new(),
        human_output: vec![format!("{summary}; target `{subject}`")],
        exit_code: EXIT_SUCCESS,
    })
}

fn plan_summary(command: &str, plan: &ManagementPlan, dry_run: bool) -> String {
    let disposition = if plan.is_empty() {
        "no changes"
    } else if dry_run {
        "planned"
    } else {
        "applied"
    };
    format!(
        "service {command}: {disposition} (plan {}, {} file operation(s))",
        plan.plan_id,
        plan.operations.len()
    )
}

fn plan_value(plan: &ManagementPlan) -> Result<Value, ServiceError> {
    serde_json::to_value(plan).map_err(|error| {
        ServiceError::new("internal-error", format!("cannot encode plan: {error}"))
    })
}

fn classify_release_error(error: &ReleaseIdentityError) -> ServiceError {
    let code = match error {
        ReleaseIdentityError::DirtyBuild { .. } => "release-dirty",
        _ => "release-unbound",
    };
    ServiceError::new(code, error.to_string())
}

fn classify_render_error(error: &RenderError, offline: bool) -> ServiceError {
    let code = match error {
        RenderError::DestinationExists(_) => "destination-exists",
        RenderError::Provenance(_) => "source-override",
        RenderError::Resolver(error) => classify_resolver_error(error, offline),
        _ => "invalid-project",
    };
    ServiceError::new(code, error.to_string())
}

fn classify_manager_error(error: &ManagerError, offline: bool) -> ServiceError {
    let code = match error {
        ManagerError::StalePlan(_) => "stale-plan",
        ManagerError::Resolver(error) => classify_resolver_error(error, offline),
        ManagerError::Preflight(diagnostics) if has_diagnostic(diagnostics, "source-override") => {
            "source-override"
        }
        ManagerError::Preflight(diagnostics) if has_diagnostic(diagnostics, "release-mismatch") => {
            "release-mismatch"
        }
        ManagerError::InvalidProject(message) if message.contains("baseline") => {
            "legacy-baseline-mismatch"
        }
        _ => "invalid-project",
    };
    ServiceError::new(code, error.to_string())
}

fn has_diagnostic(diagnostics: &[Diagnostic], code: &str) -> bool {
    diagnostics.iter().any(|diagnostic| diagnostic.code == code)
}

fn classify_resolver_error(error: &CargoResolverError, offline: bool) -> &'static str {
    match error {
        CargoResolverError::Graph(CargoGraphError::OmniusSourceMismatch { .. }) => {
            "lock-source-mismatch"
        }
        CargoResolverError::Graph(
            CargoGraphError::OutOfScopeWorkspaceChange { .. }
            | CargoGraphError::OutOfScopePackageChange { .. }
            | CargoGraphError::OutOfScopeNodeChange { .. },
        ) => "lock-diff-out-of-scope",
        CargoResolverError::CommandFailed { .. } | CargoResolverError::Spawn { .. } if offline => {
            "offline-resolution-failed"
        }
        _ => "cargo-resolution-failed",
    }
}

fn release_json(release: Option<&ReleaseBuildStatus>) -> Value {
    match release {
        Some(ReleaseBuildStatus::Clean(identity)) => json!({
            "status": "clean",
            "version": identity.version(),
            "repository": identity.repository(),
            "revision": identity.revision(),
        }),
        Some(ReleaseBuildStatus::Dirty { revision }) => json!({
            "status": "dirty",
            "version": GENERATOR_VERSION,
            "repository": CANONICAL_REPOSITORY,
            "revision": revision,
        }),
        Some(ReleaseBuildStatus::Unbound) | None => json!({
            "status": "unbound",
            "version": GENERATOR_VERSION,
            "repository": CANONICAL_REPOSITORY,
            "revision": null,
        }),
    }
}

/// Formats the exact release-aware `--version` line.
#[must_use]
pub fn format_version(release: &ReleaseBuildStatus) -> String {
    match release {
        ReleaseBuildStatus::Clean(identity) => format!(
            "cargo-service {GENERATOR_VERSION} (kit {KIT_VERSION}, {})",
            identity.revision()
        ),
        ReleaseBuildStatus::Dirty { revision } => {
            format!("cargo-service {GENERATOR_VERSION} (kit {KIT_VERSION}, {revision}, dirty)")
        }
        ReleaseBuildStatus::Unbound => {
            format!("cargo-service {GENERATOR_VERSION} (kit {KIT_VERSION}, unbound)")
        }
    }
}

fn error_envelope(
    command: String,
    project: Option<&Path>,
    release: Value,
    code: &'static str,
    message: String,
) -> JsonEnvelope {
    JsonEnvelope {
        schema_version: JSON_SCHEMA_VERSION,
        command,
        status: "error",
        project: project.map(|path| path.display().to_string()),
        release,
        plan: None,
        diagnostics: Vec::new(),
        error: Some(JsonError { code, message }),
    }
}

fn write_json(output: &mut impl Write, envelope: &JsonEnvelope) {
    if serde_json::to_writer(&mut *output, envelope).is_ok() {
        let _ = writeln!(output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

    fn test_value<T, E>(result: Result<T, E>, context: &str) -> T {
        let Ok(value) = result else {
            panic!("{context}");
        };
        value
    }

    fn test_some<T>(value: Option<T>, context: &str) -> T {
        let Some(value) = value else {
            panic!("{context}");
        };
        value
    }

    struct RecordingRunner {
        release: ReleaseBuildStatus,
        invocations: RefCell<Vec<ServiceInvocation>>,
        result: Result<ServiceExecution, ServiceError>,
    }

    impl RecordingRunner {
        fn succeeding() -> Self {
            Self {
                release: ReleaseBuildStatus::Clean(test_value(
                    ReleaseIdentity::new(GENERATOR_VERSION, CANONICAL_REPOSITORY, REVISION),
                    "test identity is valid",
                )),
                invocations: RefCell::new(Vec::new()),
                result: Ok(ServiceExecution {
                    status: "planned",
                    plan: Some(json!({"plan_id": "test-plan"})),
                    diagnostics: Vec::new(),
                    human_output: vec!["planned test change".to_owned()],
                    exit_code: EXIT_SUCCESS,
                }),
            }
        }
    }

    impl ServiceRunner for RecordingRunner {
        fn release_status(&self) -> Result<ReleaseBuildStatus, ServiceError> {
            Ok(self.release.clone())
        }

        fn execute(
            &self,
            invocation: &ServiceInvocation,
            _release: &ReleaseBuildStatus,
        ) -> Result<ServiceExecution, ServiceError> {
            self.invocations.borrow_mut().push(invocation.clone());
            self.result.clone()
        }
    }

    fn run(arguments: &[&str], runner: &RecordingRunner) -> (u8, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run_with(runner, arguments.iter().copied(), &mut stdout, &mut stderr);
        (
            exit,
            test_value(String::from_utf8(stdout), "stdout is UTF-8"),
            test_value(String::from_utf8(stderr), "stderr is UTF-8"),
        )
    }

    #[test]
    fn direct_and_cargo_prefixed_argv_normalize_identically() {
        let direct_runner = RecordingRunner::succeeding();
        let cargo_runner = RecordingRunner::succeeding();

        let direct = run(
            &["cargo-service", "add", "postgres", "--dry-run"],
            &direct_runner,
        );
        let cargo = run(
            &["cargo-service", "service", "add", "postgres", "--dry-run"],
            &cargo_runner,
        );

        assert_eq!(direct, cargo);
        assert_eq!(direct_runner.invocations, cargo_runner.invocations);
    }

    #[test]
    fn strips_exactly_one_cargo_service_token() {
        let runner = RecordingRunner::succeeding();

        let (exit, _, _) = run(&["cargo-service", "service", "service", "doctor"], &runner);

        assert_eq!(exit, EXIT_SYNTAX);
        assert!(runner.invocations.borrow().is_empty());
    }

    #[test]
    fn canonical_defaults_are_applied_without_touching_production() {
        let new_runner = RecordingRunner::succeeding();
        let add_runner = RecordingRunner::succeeding();

        assert_eq!(
            run(
                &[
                    "cargo-service",
                    "new",
                    "short-link-service",
                    "--profile",
                    "api",
                ],
                &new_runner,
            )
            .0,
            EXIT_SUCCESS
        );
        assert_eq!(
            run(&["cargo-service", "add", "postgres"], &add_runner).0,
            EXIT_SUCCESS
        );

        assert!(matches!(
            &new_runner.invocations.borrow()[0],
            ServiceInvocation::New { project, .. }
                if project == Path::new("./short-link-service")
        ));
        assert!(matches!(
            &add_runner.invocations.borrow()[0],
            ServiceInvocation::Add(arguments) if arguments.project == Path::new(".")
        ));

        let remaining_runner = RecordingRunner::succeeding();
        for arguments in [
            &["cargo-service", "remove", "postgres"][..],
            &["cargo-service", "profile", "set", "minimal"][..],
            &["cargo-service", "update"][..],
            &["cargo-service", "doctor"][..],
            &["cargo-service", "diff"][..],
        ] {
            assert_eq!(run(arguments, &remaining_runner).0, EXIT_SUCCESS);
        }
        assert!(
            remaining_runner
                .invocations
                .borrow()
                .iter()
                .all(|invocation| invocation.project() == Path::new("."))
        );
    }

    #[test]
    fn removed_upgrade_and_flags_are_syntax_errors_before_runner_execution() {
        for arguments in [
            vec!["cargo-service", "upgrade", "--to", "0.3.0"],
            vec!["cargo-service", "doctor", "--machine"],
            vec!["cargo-service", "doctor", "--kit-root", "../omnius"],
        ] {
            let runner = RecordingRunner::succeeding();
            let (exit, _, _) = run(&arguments, &runner);
            assert_eq!(exit, EXIT_SYNTAX);
            assert!(runner.invocations.borrow().is_empty());
        }
    }

    #[test]
    fn json_success_has_exact_top_level_shape_and_no_stderr_prose() {
        let runner = RecordingRunner::succeeding();

        let (exit, stdout, stderr) = run(
            &[
                "cargo-service",
                "profile",
                "set",
                "minimal",
                "--dry-run",
                "--json",
            ],
            &runner,
        );
        let document: Value = test_value(serde_json::from_str(&stdout), "JSON output is valid");
        let mut keys = test_some(document.as_object(), "JSON envelope is an object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort_unstable();

        assert_eq!(exit, EXIT_SUCCESS);
        assert_eq!(stderr, "");
        assert_eq!(
            keys,
            [
                "command",
                "diagnostics",
                "error",
                "plan",
                "project",
                "release",
                "schema_version",
                "status",
            ]
        );
        assert_eq!(document["command"], "profile-set");
        assert!(document["error"].is_null());
    }

    #[test]
    fn json_syntax_error_is_one_document_and_exit_two() {
        let runner = RecordingRunner::succeeding();

        let (exit, stdout, stderr) = run(&["cargo-service", "upgrade", "--json"], &runner);
        let document: Value = test_value(serde_json::from_str(&stdout), "JSON output is valid");

        assert_eq!(exit, EXIT_SYNTAX);
        assert_eq!(stderr, "");
        assert_eq!(document["error"]["code"], "invalid-arguments");
        assert_eq!(stdout.lines().count(), 1);
        assert!(runner.invocations.borrow().is_empty());
    }

    #[test]
    fn operational_failure_is_exit_one_with_stable_json_code() {
        let mut runner = RecordingRunner::succeeding();
        runner.result = Err(ServiceError::new("stale-plan", "project changed"));

        let (exit, stdout, stderr) =
            run(&["cargo-service", "update", "--dry-run", "--json"], &runner);
        let document: Value = test_value(serde_json::from_str(&stdout), "JSON output is valid");

        assert_eq!(exit, EXIT_OPERATIONAL);
        assert_eq!(stderr, "");
        assert_eq!(document["error"]["code"], "stale-plan");
    }

    #[test]
    fn version_format_reports_clean_dirty_and_unbound_builds() {
        let clean = ReleaseBuildStatus::Clean(test_value(
            ReleaseIdentity::new(GENERATOR_VERSION, CANONICAL_REPOSITORY, REVISION),
            "test identity is valid",
        ));

        assert_eq!(
            format_version(&clean),
            format!("cargo-service {GENERATOR_VERSION} (kit {KIT_VERSION}, {REVISION})")
        );
        assert_eq!(
            format_version(&ReleaseBuildStatus::Dirty {
                revision: REVISION.to_owned(),
            }),
            format!("cargo-service {GENERATOR_VERSION} (kit {KIT_VERSION}, {REVISION}, dirty)")
        );
        assert_eq!(
            format_version(&ReleaseBuildStatus::Unbound),
            format!("cargo-service {GENERATOR_VERSION} (kit {KIT_VERSION}, unbound)")
        );
    }

    #[test]
    fn version_and_help_do_not_execute_a_command() {
        let runner = RecordingRunner::succeeding();

        let (version_exit, version_stdout, _) = run(&["cargo-service", "--version"], &runner);
        let (help_exit, help_stdout, _) = run(&["cargo-service", "--help"], &runner);
        let (cargo_help_exit, cargo_help_stdout, _) =
            run(&["cargo-service", "service", "--help"], &runner);

        assert_eq!(version_exit, EXIT_SUCCESS);
        assert!(version_stdout.starts_with("cargo-service "));
        assert_eq!(help_exit, EXIT_SUCCESS);
        assert!(help_stdout.contains("Usage: cargo service"));
        assert!(help_stdout.contains("new"));
        assert_eq!(cargo_help_exit, EXIT_SUCCESS);
        assert_eq!(cargo_help_stdout, help_stdout);
        assert!(runner.invocations.borrow().is_empty());
    }
}
