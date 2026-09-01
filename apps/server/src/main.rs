//! Minimal no-external-service reference composition.

use std::{io, net::SocketAddr, path::PathBuf, process::ExitCode, time::Duration};

use axum::{Json, routing::get};
use clap::{Args, Parser, Subcommand, ValueEnum};
use garde::Validate;
use omnius_config::{ConfigLoadError, ConfigLoader, DeploymentEnvironment};
use omnius_core::{BuildMetadata, BuildMetadataInput, ProviderMetadata, SchemaCompatibility};
use omnius_health::{HealthBuildError, HealthBuilder, HealthConfig};
use omnius_http::{
    HttpShell, HttpShellConfig, HttpShellError,
    server::{ConnectionMode, HttpServer, HttpServerConfig, PeerAddressMode},
};
use omnius_runtime::{RegisterError, StartError, Supervisor, TerminationSignals};
use omnius_telemetry::{TelemetryConfig, TelemetryError, TelemetryGuard};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time;
use tracing::Instrument as _;

const SERVICE_NAME: &str = "minimal-reference";
const PROFILE: &str = "minimal-reference";
const MODULES: &[&str] = &[
    "core",
    "config",
    "telemetry",
    "runtime",
    "http",
    "health",
    "test-support",
];
const PROVIDERS: &[ProviderMetadata] = &[];
const SCHEMA: SchemaCompatibility = SchemaCompatibility {
    minimum: "none",
    maximum: "none",
};

#[derive(Debug, Parser)]
#[command(name = "omnius-server", version, about = "Omnius reference process")]
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
}

#[derive(Debug, Args)]
struct ServerArgs {
    /// Required base configuration file.
    #[arg(long, default_value = "config/minimal.toml")]
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
    /// Highest-precedence listener override, including port.
    #[arg(long)]
    listen_address: Option<SocketAddr>,
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
        if self.telemetry.service != SERVICE_NAME
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

#[derive(Clone, Copy, Debug, Serialize)]
struct ExampleResponse {
    message: &'static str,
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
    Metadata(#[from] omnius_core::InvalidBuildMetadata),
    #[error("telemetry initialization or shutdown failed: {0}")]
    Telemetry(#[from] TelemetryError),
    #[error("health composition failed: {0}")]
    Health(#[from] HealthBuildError),
    #[error("HTTP composition failed: {0}")]
    Http(#[from] HttpShellError),
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
}

impl StartupError {
    const fn code(&self) -> &'static str {
        match self {
            Self::Config(_) => "STARTUP_CONFIG",
            Self::IdentityMismatch => "STARTUP_IDENTITY",
            Self::ZeroShutdownTimeout => "STARTUP_TIMEOUT",
            Self::Metadata(_) => "STARTUP_METADATA",
            Self::Telemetry(_) => "STARTUP_TELEMETRY",
            Self::Health(_) => "STARTUP_HEALTH",
            Self::Http(_) => "STARTUP_HTTP",
            Self::Register(_) => "STARTUP_TASK_REGISTER",
            Self::Supervisor(_) => "STARTUP_SUPERVISOR",
            Self::Signal(_) => "STARTUP_SIGNAL",
            Self::Bind(_) => "STARTUP_BIND",
            Self::Serve(_) => "RUNTIME_HTTP",
            Self::UnexpectedServerExit => "RUNTIME_HTTP_EXIT",
            Self::ListenerShutdownDeadline => "SHUTDOWN_LISTENER_DEADLINE",
            Self::RequiredTaskExit => "RUNTIME_REQUIRED_TASK",
            Self::ProfileEncoding(_) => "PROFILE_ENCODING",
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    install_panic_hook();
    let cli = Cli::parse();

    match execute(cli).await {
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
        Command::ProfileInfo => {
            eprintln!("bootstrap phase=profile-info");
            let metadata = build_metadata()?;
            println!(
                "{}",
                serde_json::to_string(&metadata).map_err(StartupError::ProfileEncoding)?
            );
            Ok(RunOutcome::Graceful)
        }
        Command::Server(args) => run_server(args).await,
    }
}

async fn run_server(args: ServerArgs) -> Result<RunOutcome, StartupError> {
    eprintln!("bootstrap phase=config");
    let environment = args.environment;
    let config = load_config(args)?;
    config.validate_composition(environment)?;

    eprintln!("bootstrap phase=telemetry");
    let telemetry = omnius_telemetry::bootstrap(&config.telemetry)?;
    let span = telemetry.service_span();
    let result = run_application(&config).instrument(span).await;

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

fn load_config(args: ServerArgs) -> Result<AppConfig, StartupError> {
    let mut loader =
        ConfigLoader::new("OMNIUS", args.environment.deployment())?.with_base_file(args.config);
    if let Some(path) = args.environment_config {
        loader = loader.with_environment_file(path);
    }
    if let Some(path) = args.local_config {
        loader = loader.with_local_file(path)?;
    }
    if let Some(address) = args.listen_address {
        loader = loader.with_override("server.listen_address", address.to_string());
    }
    Ok(loader.load::<AppConfig>()?.into_value())
}

fn build_metadata() -> Result<BuildMetadata, StartupError> {
    Ok(BuildMetadata::current(BuildMetadataInput {
        service: SERVICE_NAME,
        profile: PROFILE,
        modules: MODULES,
        providers: PROVIDERS,
        schema: SCHEMA,
    })?)
}

async fn run_application(config: &AppConfig) -> Result<RunOutcome, StartupError> {
    eprintln!("bootstrap phase=application");
    let metadata = build_metadata()?;
    let health = HealthBuilder::new(metadata, config.health)?.build();
    let shell = HttpShell::new(config.http.clone())?;
    let routes = health.public_router().route("/example", get(example));
    let app = shell.apply(routes)?;
    let header_read_timeout = shell.header_read_timeout();
    let server = HttpServer::bind(
        config.server.listen_address,
        app,
        HttpServerConfig {
            header_read_timeout,
            connection_mode: ConnectionMode::Http1,
            peer_address_mode: PeerAddressMode::None,
        },
    )
    .await
    .map_err(StartupError::Bind)?;
    let bound_address = server.local_addr().map_err(StartupError::Bind)?;
    let http_drain = server.drain_handle();
    let mut signals = TerminationSignals::new().map_err(StartupError::Signal)?;

    let mut supervisor = Supervisor::new();
    supervisor.register(health.supervised_refresh_task())?;
    let supervisor = supervisor.start()?;
    let control = supervisor.control();
    let mut server = Box::pin(server.serve());

    health.mark_started();
    tracing::info!(listen_address = %bound_address, profile = PROFILE, "startup complete");
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

async fn example() -> Json<ExampleResponse> {
    Json(ExampleResponse {
        message: "hello from minimal-reference",
    })
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("process panic captured");
    }));
}
