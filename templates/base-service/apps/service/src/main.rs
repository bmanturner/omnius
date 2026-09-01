//! Generated service process lifecycle and command surface.

use std::{io, net::SocketAddr, path::PathBuf, process::ExitCode, time::Duration};

use clap::{Args, Parser, Subcommand, ValueEnum};
use garde::Validate;
use omnius_config::{ConfigLoadError, ConfigLoader, DeploymentEnvironment};
use omnius_health::HealthConfig;
use omnius_http::{
    HttpShellConfig,
    server::{ConnectionMode, HttpServer, HttpServerConfig, PeerAddressMode},
};
use omnius_runtime::{RegisterError, StartError, Supervisor, TerminationSignals};
use omnius_telemetry::{TelemetryConfig, TelemetryError, TelemetryGuard};
use serde::Deserialize;
use service_kit::{
    CompositionError, ExampleRateLimitConfig, SelectedRuntime, SelectedRuntimeConfig,
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    time,
};
use tracing::Instrument as _;

#[derive(Debug, Parser)]
#[command(name = "{{project-name}}", version, about = "Generated Omnius service")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the public HTTP server.
    Server(ServerArgs),
    /// Print safe compiled profile and build information.
    ProfileInfo,
    /// Probe a running service readiness endpoint.
    Healthcheck(HealthcheckArgs),
    /// Apply selected database migrations.
    Migrate(ConfigArgs),
    /// Report selected database migration status.
    MigrationStatus(ConfigArgs),
    /// Provision resources for selected external providers.
    Provision,
    /// Run the selected MCP stdio transport.
    McpStdio,
    /// Run selected AI evaluation cases.
    Evaluate,
    /// Export the selected API or consumer contract.
    Contracts(ContractsArgs),
}

#[derive(Debug, Args)]
struct ServerArgs {
    #[command(flatten)]
    config: ConfigArgs,
    /// Highest-precedence listener override, including port.
    #[arg(long)]
    listen_address: Option<SocketAddr>,
}

#[derive(Debug, Args)]
struct ConfigArgs {
    /// Required base configuration file.
    #[arg(long, default_value = "config/base.toml")]
    config: PathBuf,
    /// Deployment class controlling local-file policy.
    #[arg(long, value_enum, default_value_t = EnvironmentArg::Development)]
    environment: EnvironmentArg,
    /// Optional environment-specific configuration layer.
    #[arg(long)]
    environment_config: Option<PathBuf>,
    /// Optional development-only local configuration layer.
    #[arg(long)]
    local_config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct HealthcheckArgs {
    /// Address of the running service.
    #[arg(long, default_value = "127.0.0.1:3000")]
    address: SocketAddr,
}

#[derive(Debug, Args)]
struct ContractsArgs {
    /// Destination for the selected contract document.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum EnvironmentArg {
    Development,
    Test,
    Production,
}

impl EnvironmentArg {
    const fn deployment(self) -> DeploymentEnvironment {
        match self {
            Self::Development => DeploymentEnvironment::Development,
            Self::Test => DeploymentEnvironment::Test,
            Self::Production => DeploymentEnvironment::Production,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Test => "test",
            Self::Production => "production",
        }
    }
}

#[derive(Deserialize, Validate)]
#[serde(deny_unknown_fields)]
struct AppConfig {
    #[garde(dive)]
    telemetry: TelemetryConfig,
    #[garde(skip)]
    server: ServerConfig,
    #[garde(skip)]
    http: HttpShellConfig,
    #[garde(skip)]
    health: HealthConfig,
    #[garde(skip)]
    rate_limit_local: ExampleRateLimitConfig,
    #[garde(skip)]
    #[serde(flatten)]
    selected: SelectedRuntimeConfig,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerConfig {
    listen_address: SocketAddr,
    #[serde(with = "humantime_serde")]
    listener_shutdown_timeout: Duration,
    #[serde(with = "humantime_serde")]
    telemetry_flush_timeout: Duration,
}

impl AppConfig {
    fn validate_composition(&self, environment: EnvironmentArg) -> Result<(), StartupError> {
        if self.telemetry.service != "{{project-name}}"
            || self.telemetry.version != env!("CARGO_PKG_VERSION")
            || self.telemetry.environment != environment.name()
        {
            return Err(StartupError::IdentityMismatch);
        }
        if self.server.listener_shutdown_timeout.is_zero()
            || self.server.telemetry_flush_timeout.is_zero()
        {
            return Err(StartupError::ZeroShutdownTimeout);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunOutcome {
    Graceful,
    Forced,
}

enum Trigger {
    Server(Result<(), io::Error>),
    Termination,
    Supervisor,
}

#[derive(Debug, Error)]
enum StartupError {
    #[error("configuration load or validation failed: {0}")]
    Config(#[from] ConfigLoadError),
    #[error("configured telemetry identity does not match the compiled service")]
    IdentityMismatch,
    #[error("shutdown timeouts must be greater than zero")]
    ZeroShutdownTimeout,
    #[error("build metadata validation failed: {0}")]
    Metadata(#[from] service_kit::InvalidBuildMetadata),
    #[error("telemetry initialization or shutdown failed: {0}")]
    Telemetry(#[from] TelemetryError),
    #[error("application composition failed: {0}")]
    Application(Box<dyn std::error::Error>),
    #[error("supervisor task registration failed: {0}")]
    Register(#[from] RegisterError),
    #[error("supervisor start failed: {0}")]
    Supervisor(#[from] StartError),
    #[error("termination signal setup failed: {0}")]
    Signal(io::Error),
    #[error("listener bind failed: {0}")]
    Bind(io::Error),
    #[error("HTTP server failed: {0}")]
    Serve(io::Error),
    #[error("HTTP server stopped without a drain request")]
    UnexpectedServerExit,
    #[error("HTTP listener did not drain before its deadline")]
    ListenerShutdownDeadline,
    #[error("a required supervised task exited")]
    RequiredTaskExit,
    #[error("profile information encoding failed: {0}")]
    ProfileEncoding(serde_json::Error),
    #[error("healthcheck transport failed: {0}")]
    Healthcheck(io::Error),
    #[error("healthcheck returned a non-ready response")]
    HealthcheckUnready,
    #[error(transparent)]
    Composition(#[from] CompositionError),
}

impl StartupError {
    const fn code(&self) -> &'static str {
        match self {
            Self::Config(_) => "STARTUP_CONFIG",
            Self::IdentityMismatch => "STARTUP_IDENTITY",
            Self::ZeroShutdownTimeout => "STARTUP_TIMEOUT",
            Self::Metadata(_) => "STARTUP_METADATA",
            Self::Telemetry(_) => "STARTUP_TELEMETRY",
            Self::Application(_) => "STARTUP_APPLICATION",
            Self::Register(_) => "STARTUP_TASK_REGISTER",
            Self::Supervisor(_) => "STARTUP_SUPERVISOR",
            Self::Signal(_) => "STARTUP_SIGNAL",
            Self::Bind(_) => "STARTUP_BIND",
            Self::Serve(_) => "RUNTIME_HTTP",
            Self::UnexpectedServerExit => "RUNTIME_HTTP_EXIT",
            Self::ListenerShutdownDeadline => "SHUTDOWN_LISTENER_DEADLINE",
            Self::RequiredTaskExit => "RUNTIME_REQUIRED_TASK",
            Self::ProfileEncoding(_) => "PROFILE_ENCODING",
            Self::Healthcheck(_) => "HEALTHCHECK_TRANSPORT",
            Self::HealthcheckUnready => "HEALTHCHECK_UNREADY",
            Self::Composition(_) => "COMMAND_UNAVAILABLE",
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    install_panic_hook();
    match execute(Cli::parse()).await {
        Ok(RunOutcome::Graceful) => ExitCode::SUCCESS,
        Ok(RunOutcome::Forced) => ExitCode::from(130),
        Err(error) => {
            eprintln!("service failed code={} detail={error}", error.code());
            ExitCode::FAILURE
        }
    }
}

async fn execute(cli: Cli) -> Result<RunOutcome, StartupError> {
    match cli.command {
        Command::Server(args) => run_server(args).await,
        Command::ProfileInfo => {
            println!(
                "{}",
                serde_json::to_string(&service::build_metadata()?)
                    .map_err(StartupError::ProfileEncoding)?
            );
            Ok(RunOutcome::Graceful)
        }
        Command::Healthcheck(args) => run_healthcheck(args.address).await,
        Command::Migrate(args) => {
            run_migration(args, service_kit::SelectedMigrationCommand::Migrate).await
        }
        Command::MigrationStatus(args) => {
            run_migration(args, service_kit::SelectedMigrationCommand::Status).await
        }
        Command::Provision => unavailable("provision"),
        Command::McpStdio => unavailable("mcp-stdio"),
        Command::Evaluate => unavailable("evaluate"),
        Command::Contracts(args) => {
            let _ = args.output;
            unavailable("contracts")
        }
    }
}

fn unavailable(command: &'static str) -> Result<RunOutcome, StartupError> {
    Err(CompositionError::command_unavailable(service::selected_profile(), command).into())
}

async fn run_healthcheck(address: SocketAddr) -> Result<RunOutcome, StartupError> {
    let mut stream = TcpStream::connect(address)
        .await
        .map_err(StartupError::Healthcheck)?;
    stream
        .write_all(b"GET /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .map_err(StartupError::Healthcheck)?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(StartupError::Healthcheck)?;
    if response.starts_with(b"HTTP/1.1 200") {
        Ok(RunOutcome::Graceful)
    } else {
        Err(StartupError::HealthcheckUnready)
    }
}

async fn run_migration(
    args: ConfigArgs,
    command: service_kit::SelectedMigrationCommand,
) -> Result<RunOutcome, StartupError> {
    let environment = args.environment;
    let config = load_config(args, None)?;
    config.validate_composition(environment)?;
    let status = service_kit::execute_selected_migration(
        &config.selected,
        environment.deployment(),
        service::selected_profile(),
        command,
    )
    .await?;
    println!(
        "{}",
        serde_json::to_string(&status).map_err(StartupError::ProfileEncoding)?
    );
    Ok(RunOutcome::Graceful)
}

async fn run_server(args: ServerArgs) -> Result<RunOutcome, StartupError> {
    eprintln!("bootstrap phase=config");
    let environment = args.config.environment;
    let config = load_config(args.config, args.listen_address)?;
    config.validate_composition(environment)?;

    eprintln!("bootstrap phase=telemetry");
    let telemetry = omnius_telemetry::bootstrap(&config.telemetry)?;
    let result = run_application(&config, environment.deployment())
        .instrument(telemetry.service_span())
        .await;

    let forced = matches!(result, Ok(RunOutcome::Forced));
    let shutdown = shutdown_telemetry(telemetry, config.server.telemetry_flush_timeout);
    if forced {
        return Ok(RunOutcome::Forced);
    }
    match (result, shutdown) {
        (Err(primary), _) => Err(primary),
        (Ok(_), Err(error)) => Err(error),
        (Ok(outcome), Ok(())) => Ok(outcome),
    }
}

fn load_config(
    args: ConfigArgs,
    listen_address: Option<SocketAddr>,
) -> Result<AppConfig, StartupError> {
    let mut loader =
        ConfigLoader::new("OMNIUS", args.environment.deployment())?.with_base_file(args.config);
    if let Some(path) = args.environment_config {
        loader = loader.with_environment_file(path);
    }
    if let Some(path) = args.local_config {
        loader = loader.with_local_file(path)?;
    }
    if let Some(address) = listen_address {
        loader = loader.with_override("server.listen_address", address.to_string());
    }
    Ok(loader.load::<AppConfig>()?.into_value())
}

async fn run_application(
    config: &AppConfig,
    deployment: DeploymentEnvironment,
) -> Result<RunOutcome, StartupError> {
    eprintln!("bootstrap phase=application");
    let selected_runtime = SelectedRuntime::connect(&config.selected, deployment, true).await?;
    let composition = service::compose(
        config.health,
        config.http.clone(),
        config.rate_limit_local,
        selected_runtime,
    )
    .await
    .map_err(StartupError::Application)?;
    let health = composition.health;
    let app = composition.router;
    let server = HttpServer::bind(
        config.server.listen_address,
        app,
        HttpServerConfig {
            header_read_timeout: config.http.header_read_timeout,
            connection_mode: ConnectionMode::AutoWithUpgrades,
            peer_address_mode: PeerAddressMode::ConnectInfo,
        },
    )
    .await
    .map_err(StartupError::Bind)?;
    let bound_address = server.local_addr().map_err(StartupError::Bind)?;
    let http_drain = server.drain_handle();
    let mut signals = TerminationSignals::new().map_err(StartupError::Signal)?;

    let mut supervisor = Supervisor::new();
    for task in composition.task_specs {
        supervisor.register(task)?;
    }
    let supervisor = supervisor.start()?;
    let control = supervisor.control();
    let mut server = Box::pin(server.serve());

    health.mark_started();
    eprintln!("startup complete listen_address={bound_address}");

    let trigger = tokio::select! {
        result = &mut server => Trigger::Server(result),
        () = signals.recv() => Trigger::Termination,
        () = control.shutdown_requested() => Trigger::Supervisor,
    };
    let unexpected_server_exit = matches!(trigger, Trigger::Server(_));
    let mut serve_error = match trigger {
        Trigger::Server(result) => result.err(),
        Trigger::Termination | Trigger::Supervisor => None,
    };

    health.begin_drain_with(&control, || http_drain.begin_drain());
    let mut forced = false;
    let mut listener_timed_out = false;
    if !unexpected_server_exit {
        tokio::select! {
            result = &mut server => serve_error = result.err(),
            () = signals.recv() => {
                control.force_cancel();
                forced = true;
            }
            () = time::sleep(config.server.listener_shutdown_timeout) => {
                control.force_cancel();
                listener_timed_out = true;
            }
        }
    }
    drop(server);

    let report = supervisor.shutdown().await;
    if forced {
        return Ok(RunOutcome::Forced);
    }
    if listener_timed_out {
        return Err(StartupError::ListenerShutdownDeadline);
    }
    if report.fatal {
        return Err(StartupError::RequiredTaskExit);
    }
    if let Some(error) = serve_error {
        return Err(StartupError::Serve(error));
    }
    if unexpected_server_exit {
        return Err(StartupError::UnexpectedServerExit);
    }
    Ok(RunOutcome::Graceful)
}

fn shutdown_telemetry(telemetry: TelemetryGuard, timeout: Duration) -> Result<(), StartupError> {
    telemetry.shutdown(timeout).map_err(StartupError::Telemetry)
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("process panic captured");
    }));
}
