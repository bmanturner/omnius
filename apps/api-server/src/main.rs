//! PostgreSQL-backed reference API composition.

use std::{io, net::SocketAddr, path::PathBuf, process::ExitCode, sync::Arc, time::Duration};

use axum::Router;
use clap::{Args, Parser, Subcommand, ValueEnum};
use garde::Validate;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as AutoBuilder,
    service::TowerToHyperService,
};
use rsk_api_server::{ReferenceApiState, openapi_catalog, reference_router};
use rsk_config::{
    ConfigLoadError, ConfigLoader, DeploymentEnvironment, ExposeSecret as _, SecretString,
};
use rsk_core::{BuildMetadata, BuildMetadataInput, Clock, SchemaCompatibility, SystemClock};
use rsk_health::{HealthBuildError, HealthBuilder, HealthConfig};
use rsk_http::{HttpShell, HttpShellConfig, HttpShellError};
use rsk_idempotency::{IdempotencyConfig, IdempotencyConfigError, PostgresIdempotencyStore};
use rsk_migrations::{
    MIGRATOR, MigrationCommand, MigrationCommandOutput, MigrationConfig, MigrationConfigError,
    MigrationError, MigrationRunner, MigrationStatus, SchemaVersionRange,
};
use rsk_openapi::{OpenApiConfig, OpenApiError};
use rsk_outbound_http::{
    BuildError as OutboundBuildError, ConfigError as OutboundConfigError, OutboundHttpClients,
    OutboundHttpConfig,
};
use rsk_pagination::{CursorCodec, CursorSigningKey, CursorSigningKeyError};
use rsk_postgres::{PostgresConfig, PostgresConfigError, PostgresError, PostgresPool};
use rsk_runtime::{RegisterError, StartError, Supervisor};
use rsk_telemetry::{TelemetryConfig, TelemetryError, TelemetryGuard};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    task::{JoinError, JoinSet},
    time,
};
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

type ConnectionError = Box<dyn std::error::Error + Send + Sync>;

const SERVICE_NAME: &str = "api-reference";
const PROFILE: &str = "api";
const MODULES: &[&str] = &[
    "core",
    "config",
    "telemetry",
    "runtime",
    "http",
    "health",
    "test-support",
    "postgres",
    "migrations",
    "validation",
    "openapi",
    "idempotency",
    "outbound-http",
];
const SCHEMA: SchemaCompatibility = SchemaCompatibility {
    minimum: "2026082301",
    maximum: "2026082303",
};

#[derive(Debug, Parser)]
#[command(
    name = "rsk-api-server",
    version,
    about = "Rust service kit PostgreSQL reference API"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the public HTTP API server.
    Server(ServerArgs),
    /// Apply all pending forward database migrations.
    Migrate(ConfigArgs),
    /// Print safe read-only database migration status.
    MigrationStatus(ConfigArgs),
    /// Print safe compiled profile and build information.
    ProfileInfo,
}

#[derive(Debug, Args)]
struct ConfigArgs {
    /// Required base configuration file.
    #[arg(long, default_value = "config/reference.toml")]
    config: PathBuf,
    /// Deployment class controlling local-file and migration policy.
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
struct ServerArgs {
    #[command(flatten)]
    config: ConfigArgs,
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
    #[garde(skip)]
    postgres: PostgresConfig,
    #[garde(skip)]
    migrations: MigrationConfig,
    #[garde(skip)]
    idempotency: IdempotencyConfig,
    #[garde(skip)]
    pagination: PaginationConfig,
    #[garde(skip)]
    openapi: OpenApiConfig,
    #[garde(skip)]
    outbound_http: OutboundHttpConfig,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PaginationConfig {
    cursor_signing_key: SecretString,
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

        self.postgres.validate_for(environment.deployment())?;
        self.migrations.validate_for(environment.deployment())?;
        let _shell = HttpShell::new(self.http.clone())?;
        let _health = HealthBuilder::new(build_metadata()?, self.health)?;
        let _idempotency_store = PostgresIdempotencyStore::new(self.idempotency)?;
        let _cursor_key = cursor_signing_key(&self.pagination)?;
        let _openapi = self.openapi.validate()?;
        self.outbound_http.validate()?;
        schema_range()?;
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

#[derive(Serialize)]
struct MigrationStatusOutput<'status> {
    current_version: Option<i64>,
    target_version: i64,
    applied_count: usize,
    pending_versions: &'status [i64],
    unknown_versions: &'status [i64],
    checksum_mismatches: &'status [i64],
    history_gaps: &'status [i64],
    dirty_version: Option<i64>,
}

impl<'status> From<&'status MigrationStatus> for MigrationStatusOutput<'status> {
    fn from(status: &'status MigrationStatus) -> Self {
        Self {
            current_version: status.current_version,
            target_version: status.target_version,
            applied_count: status.applied_count,
            pending_versions: &status.pending_versions,
            unknown_versions: &status.unknown_versions,
            checksum_mismatches: &status.checksum_mismatches,
            history_gaps: &status.history_gaps,
            dirty_version: status.dirty_version,
        }
    }
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
    Metadata(#[from] rsk_core::InvalidBuildMetadata),
    #[error("PostgreSQL configuration failed: {0}")]
    PostgresConfig(#[from] PostgresConfigError),
    #[error("migration configuration failed: {0}")]
    MigrationConfig(#[from] MigrationConfigError),
    #[error("idempotency configuration failed: {0}")]
    Idempotency(#[from] IdempotencyConfigError),
    #[error("pagination configuration failed: {0}")]
    Pagination(#[from] CursorSigningKeyError),
    #[error("OpenAPI composition failed: {0}")]
    OpenApi(#[from] OpenApiError),
    #[error("outbound HTTP configuration failed: {0}")]
    OutboundConfig(#[from] OutboundConfigError),
    #[error("outbound HTTP client construction failed: {0}")]
    OutboundBuild(#[from] OutboundBuildError),
    #[error("telemetry initialization or shutdown failed: {0}")]
    Telemetry(#[from] TelemetryError),
    #[error("health composition failed: {0}")]
    Health(#[from] HealthBuildError),
    #[error("HTTP composition failed: {0}")]
    Http(#[from] HttpShellError),
    #[error("PostgreSQL operation failed: {0}")]
    Postgres(#[from] PostgresError),
    #[error("database migration operation failed: {0}")]
    Migration(#[from] MigrationError),
    #[error("supervisor task registration failed: {0}")]
    Register(#[from] RegisterError),
    #[error("supervisor start failed: {0}")]
    Supervisor(#[from] StartError),
    #[error("termination signal setup failed")]
    Signal,
    #[error("listener bind failed")]
    Bind,
    #[error("HTTP server failed")]
    Serve,
    #[error("HTTP server stopped without a drain request")]
    UnexpectedServerExit,
    #[error("HTTP listener did not drain before its deadline")]
    ListenerShutdownDeadline,
    #[error("a required supervised task exited")]
    RequiredTaskExit,
    #[error("PostgreSQL pool did not close cleanly")]
    PoolShutdown(#[source] PostgresError),
    #[error("safe command output encoding failed")]
    OutputEncoding(#[source] serde_json::Error),
}

impl StartupError {
    const fn code(&self) -> &'static str {
        match self {
            Self::Config(_) => "STARTUP_CONFIG",
            Self::IdentityMismatch => "STARTUP_IDENTITY",
            Self::ZeroShutdownTimeout => "STARTUP_TIMEOUT",
            Self::Metadata(_) => "STARTUP_METADATA",
            Self::PostgresConfig(_) => "STARTUP_POSTGRES_CONFIG",
            Self::MigrationConfig(_) => "STARTUP_MIGRATION_CONFIG",
            Self::Idempotency(_) => "STARTUP_IDEMPOTENCY",
            Self::Pagination(_) => "STARTUP_PAGINATION",
            Self::OpenApi(_) => "STARTUP_OPENAPI",
            Self::OutboundConfig(_) | Self::OutboundBuild(_) => "STARTUP_OUTBOUND_HTTP",
            Self::Telemetry(_) => "STARTUP_TELEMETRY",
            Self::Health(_) => "STARTUP_HEALTH",
            Self::Http(_) => "STARTUP_HTTP",
            Self::Postgres(_) => "POSTGRES_OPERATION",
            Self::Migration(_) => "MIGRATION_OPERATION",
            Self::Register(_) => "STARTUP_TASK_REGISTER",
            Self::Supervisor(_) => "STARTUP_SUPERVISOR",
            Self::Signal => "STARTUP_SIGNAL",
            Self::Bind => "STARTUP_BIND",
            Self::Serve => "RUNTIME_HTTP",
            Self::UnexpectedServerExit => "RUNTIME_HTTP_EXIT",
            Self::ListenerShutdownDeadline => "SHUTDOWN_LISTENER_DEADLINE",
            Self::RequiredTaskExit => "RUNTIME_REQUIRED_TASK",
            Self::PoolShutdown(_) => "SHUTDOWN_POSTGRES",
            Self::OutputEncoding(_) => "OUTPUT_ENCODING",
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
        Command::ProfileInfo => run_profile_info(),
        Command::Server(args) => run_server(args).await,
        Command::Migrate(args) => run_database_command(args, MigrationCommand::Migrate).await,
        Command::MigrationStatus(args) => {
            run_database_command(args, MigrationCommand::Status).await
        }
    }
}

fn run_profile_info() -> Result<RunOutcome, StartupError> {
    eprintln!("bootstrap phase=profile-info");
    let metadata = build_metadata()?;
    println!(
        "{}",
        serde_json::to_string(&metadata).map_err(StartupError::OutputEncoding)?
    );
    Ok(RunOutcome::Graceful)
}

async fn run_server(args: ServerArgs) -> Result<RunOutcome, StartupError> {
    eprintln!("bootstrap phase=config");
    let environment = args.config.environment;
    let config = load_config(args.config, args.listen_address)?;
    config.validate_composition(environment)?;

    eprintln!("bootstrap phase=telemetry");
    let telemetry = rsk_telemetry::bootstrap(&config.telemetry)?;
    let span = telemetry.service_span();
    let result = run_application(&config, environment).instrument(span).await;

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

async fn run_database_command(
    args: ConfigArgs,
    command: MigrationCommand,
) -> Result<RunOutcome, StartupError> {
    eprintln!("bootstrap phase=config");
    let environment = args.environment;
    let config = load_config(args, None)?;
    config.validate_composition(environment)?;

    eprintln!("bootstrap phase=telemetry");
    let telemetry = rsk_telemetry::bootstrap(&config.telemetry)?;
    let span = telemetry.service_span();
    let result = execute_database_command(&config, environment, command)
        .instrument(span)
        .await
        .and_then(|status| {
            serde_json::to_string(&MigrationStatusOutput::from(&status))
                .map_err(StartupError::OutputEncoding)
        });
    let shutdown = shutdown_telemetry(telemetry, config.server.telemetry_flush_timeout);

    let output = match (result, shutdown) {
        (Err(primary), _) => return Err(primary),
        (Ok(_), Err(error)) => return Err(error),
        (Ok(output), Ok(())) => output,
    };
    println!("{output}");
    Ok(RunOutcome::Graceful)
}

fn load_config(
    args: ConfigArgs,
    listen_address: Option<SocketAddr>,
) -> Result<AppConfig, StartupError> {
    let mut loader =
        ConfigLoader::new("RSK", args.environment.deployment())?.with_base_file(args.config);
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

fn build_metadata() -> Result<BuildMetadata, StartupError> {
    Ok(BuildMetadata::current(BuildMetadataInput {
        service: SERVICE_NAME,
        profile: PROFILE,
        modules: MODULES,
        schema: SCHEMA,
    })?)
}

fn schema_range() -> Result<SchemaVersionRange, StartupError> {
    SchemaVersionRange::try_from(SCHEMA).map_err(StartupError::Migration)
}

fn cursor_signing_key(config: &PaginationConfig) -> Result<CursorSigningKey, StartupError> {
    CursorSigningKey::from_slice(config.cursor_signing_key.expose_secret().as_bytes())
        .map_err(StartupError::Pagination)
}

async fn execute_database_command(
    config: &AppConfig,
    environment: EnvironmentArg,
    command: MigrationCommand,
) -> Result<MigrationStatus, StartupError> {
    let pool = PostgresPool::connect(&config.postgres, environment.deployment()).await?;
    let result: Result<MigrationStatus, StartupError> = async {
        let runner = MigrationRunner::new(
            pool.clone(),
            &MIGRATOR,
            schema_range()?,
            config.migrations,
            environment.deployment(),
        )?;
        let output = runner.execute(command).await?;
        Ok(match output {
            MigrationCommandOutput::Migrated(status) | MigrationCommandOutput::Status(status) => {
                status
            }
        })
    }
    .await;
    let close = pool.close().await.map_err(StartupError::PoolShutdown);

    match (result, close) {
        (Err(primary), _) => Err(primary),
        (Ok(_), Err(error)) => Err(error),
        (Ok(status), Ok(())) => Ok(status),
    }
}

async fn run_application(
    config: &AppConfig,
    environment: EnvironmentArg,
) -> Result<RunOutcome, StartupError> {
    eprintln!("bootstrap phase=application");
    let outbound_clients = OutboundHttpClients::new(&config.outbound_http)?;
    let pool = PostgresPool::connect(&config.postgres, environment.deployment()).await?;
    let result = run_application_with_pool(config, environment, pool.clone()).await;
    let close = pool.close().await.map_err(StartupError::PoolShutdown);
    drop(outbound_clients);

    let forced = matches!(result, Ok(RunOutcome::Forced));
    if forced {
        return Ok(RunOutcome::Forced);
    }
    match (result, close) {
        (Err(primary), _) => Err(primary),
        (Ok(_), Err(error)) => Err(error),
        (Ok(outcome), Ok(())) => Ok(outcome),
    }
}

async fn run_application_with_pool(
    config: &AppConfig,
    environment: EnvironmentArg,
    pool: PostgresPool,
) -> Result<RunOutcome, StartupError> {
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        schema_range()?,
        config.migrations,
        environment.deployment(),
    )?;
    runner.apply_startup_policy().await?;

    let metadata = build_metadata()?;
    let mut health_builder = HealthBuilder::new(metadata, config.health)?;
    health_builder.register(pool.health_check())?;
    let health = health_builder.build();

    let shell = HttpShell::new(config.http.clone())?;
    let idempotency_store = PostgresIdempotencyStore::new(config.idempotency)?;
    let cursor_codec = CursorCodec::new(cursor_signing_key(&config.pagination)?);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let state = ReferenceApiState::new(pool, cursor_codec, idempotency_store, clock);
    let catalog = openapi_catalog(config.openapi)?;
    let routes = health
        .public_router()
        .merge(reference_router(state))
        .merge(catalog.router());
    let app = shell.apply(routes)?;
    let header_read_timeout = shell.header_read_timeout();
    let listener = TcpListener::bind(config.server.listen_address)
        .await
        .map_err(|_| StartupError::Bind)?;
    let bound_address = listener.local_addr().map_err(|_| StartupError::Bind)?;
    let mut signals = TerminationSignals::new().map_err(|_| StartupError::Signal)?;

    let mut supervisor = Supervisor::new();
    supervisor.register(health.supervised_refresh_task())?;
    let supervisor = supervisor.start()?;
    let control = supervisor.control();
    let listener_drain = CancellationToken::new();
    let graceful_drain = listener_drain.clone();
    let mut server = Box::pin(serve_http(
        listener,
        app,
        header_read_timeout,
        graceful_drain,
    ));

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

    health.begin_drain(&control);
    listener_drain.cancel();

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
    if serve_error.is_some() {
        return Err(StartupError::Serve);
    }
    if unexpected_server_exit {
        return Err(StartupError::UnexpectedServerExit);
    }
    Ok(RunOutcome::Graceful)
}

async fn serve_http(
    listener: TcpListener,
    app: Router,
    header_read_timeout: Duration,
    draining: CancellationToken,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = draining.cancelled() => break,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                observe_connection(result);
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                connections.spawn(serve_connection(
                    stream,
                    app.clone(),
                    header_read_timeout,
                    draining.clone(),
                ));
            }
        }
    }
    while let Some(result) = connections.join_next().await {
        observe_connection(result);
    }
    Ok(())
}

async fn serve_connection(
    stream: TcpStream,
    app: Router,
    header_read_timeout: Duration,
    draining: CancellationToken,
) -> Result<(), ConnectionError> {
    let mut builder = AutoBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout);
    let connection = builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(app));
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => result,
        () = draining.cancelled() => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    }
}

fn observe_connection(result: Result<Result<(), ConnectionError>, JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(_)) => tracing::debug!("HTTP connection ended with a protocol error"),
        Err(error) => tracing::error!(
            cancelled = error.is_cancelled(),
            panicked = error.is_panic(),
            "HTTP connection task failed"
        ),
    }
}

fn shutdown_telemetry(telemetry: TelemetryGuard, timeout: Duration) -> Result<(), StartupError> {
    telemetry.shutdown(timeout).map_err(StartupError::Telemetry)
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("process panic captured");
    }));
}

#[cfg(unix)]
struct TerminationSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl TerminationSignals {
    fn new() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    async fn recv(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
    }
}

#[cfg(not(unix))]
struct TerminationSignals;

#[cfg(not(unix))]
impl TerminationSignals {
    fn new() -> io::Result<Self> {
        Ok(Self)
    }

    async fn recv(&mut self) {
        let _ = tokio::signal::ctrl_c().await;
    }
}
