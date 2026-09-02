//! Dedicated OAuth-authenticated reference MCP process.

use std::{io, net::SocketAddr, path::PathBuf, process::ExitCode, sync::Arc, time::Duration};

use axum::Router;
use clap::{Args, Parser, Subcommand, ValueEnum};
use garde::Validate;
use omnius_config::{ConfigLoadError, ConfigLoader, DeploymentEnvironment};
use omnius_core::{BuildMetadata, BuildMetadataInput, ProviderMetadata, SchemaCompatibility};
use omnius_health::{HealthBuildError, HealthBuilder, HealthConfig, HealthService};
use omnius_http::{
    HttpShell, HttpShellConfig, HttpShellError,
    server::{ConnectionMode, HttpServer, HttpServerConfig, PeerAddressMode},
};
use omnius_idempotency::IdempotencyConfig;
use omnius_mcp_server::{
    ReferenceMcpApplicationInput, ReferenceMcpBuildError, build_reference_mcp_application,
};
use omnius_mcp_transport_http::{McpDrainOutcome, McpHttpConfig};
use omnius_migrations::{
    MIGRATOR, MigrationCommand, MigrationCommandOutput, MigrationConfig, MigrationConfigError,
    MigrationError, MigrationRunner, MigrationStatus, SchemaVersionRange,
};
use omnius_openapi::OpenApiConfig;
use omnius_outbound_http::{
    BuildError as OutboundBuildError, ConfigError as OutboundConfigError, OutboundHttpClients,
    OutboundHttpConfig,
};
use omnius_postgres::{PostgresConfig, PostgresConfigError, PostgresError, PostgresPool};
use omnius_reference_api::{
    AccountEmailConfig, AuthConfig, PaginationConfig, ReferenceRuntimeConfigError,
    oauth_provider::{OAuthResourceVerifierBuildError, mcp_resource_uri},
};
use omnius_runtime::{RegisterError, StartError, Supervisor, TerminationSignals};
use omnius_telemetry::{TelemetryConfig, TelemetryError, TelemetryGuard};
use omnius_tenancy::TenancyConfig;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time;
use tracing::Instrument as _;

const SERVICE_NAME: &str = "mcp-reference";
const PROFILE: &str = "mcp-http";
const MODULES: &[&str] = &[
    "agent-capability-registry",
    "auth-core",
    "auth-oauth-server",
    "authz-basic",
    "config",
    "core",
    "health",
    "http",
    "mcp-auth-oauth",
    "mcp-server-core",
    "mcp-tools",
    "mcp-transport-http",
    "migrations",
    "outbound-http",
    "pagination",
    "postgres",
    "reference-api",
    "runtime",
    "telemetry",
];
const PROVIDERS: &[ProviderMetadata] = &[
    ProviderMetadata {
        slot: "oauth-access-token",
        module: "auth-oauth-server",
    },
    ProviderMetadata {
        slot: "primary-database",
        module: "postgres",
    },
];
const SCHEMA: SchemaCompatibility = SchemaCompatibility {
    minimum: "2026082301",
    maximum: "2026082809",
};

#[derive(Debug, Parser)]
#[command(
    name = "omnius-mcp-server",
    version,
    about = "Omnius OAuth-authenticated reference MCP server"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run authenticated Streamable HTTP at `POST /mcp`.
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
    /// Required shared reference configuration file.
    #[arg(long, default_value = "config/reference.toml")]
    config: PathBuf,
    /// Deployment class controlling local-file and migration policy.
    #[arg(long, value_enum, default_value_t = EnvironmentArg::Development)]
    environment: EnvironmentArg,
    /// Required MCP process configuration layer.
    #[arg(long, default_value = "config/mcp.toml")]
    environment_config: PathBuf,
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
    #[serde(default, rename = "static_delivery")]
    _static_delivery: omnius_http::StaticDeliveryConfig,
    #[garde(skip)]
    health: HealthConfig,
    #[garde(skip)]
    postgres: PostgresConfig,
    #[garde(skip)]
    migrations: MigrationConfig,
    #[garde(skip)]
    #[serde(rename = "idempotency")]
    _idempotency: IdempotencyConfig,
    #[garde(skip)]
    pagination: PaginationConfig,
    #[garde(skip)]
    #[serde(rename = "openapi")]
    _openapi: OpenApiConfig,
    #[garde(skip)]
    outbound_http: OutboundHttpConfig,
    #[garde(skip)]
    auth: AuthConfig,
    #[garde(skip)]
    #[serde(rename = "email")]
    _email: AccountEmailConfig,
    #[garde(skip)]
    #[serde(rename = "tenancy")]
    _tenancy: TenancyConfig,
    #[garde(skip)]
    mcp_http: McpHttpTransportConfig,
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

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct McpHttpTransportConfig {
    allowed_hosts: Vec<String>,
    max_json_response_bytes: usize,
    max_response_frame_bytes: usize,
    #[serde(with = "humantime_serde")]
    drain_timeout: Duration,
}

impl McpHttpTransportConfig {
    fn build(&self, http: HttpShellConfig) -> McpHttpConfig {
        McpHttpConfig {
            http,
            allowed_hosts: self.allowed_hosts.clone(),
            max_json_response_bytes: self.max_json_response_bytes,
            max_response_frame_bytes: self.max_response_frame_bytes,
            drain_timeout: self.drain_timeout,
        }
    }

    fn validate(&self, listener_shutdown_timeout: Duration) -> Result<(), StartupError> {
        if self.allowed_hosts.is_empty()
            || self.max_json_response_bytes == 0
            || self.max_response_frame_bytes == 0
            || self.drain_timeout.is_zero()
            || self.drain_timeout > listener_shutdown_timeout
        {
            return Err(StartupError::McpHttpPolicy);
        }
        Ok(())
    }
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
        self.outbound_http.validate()?;
        self.mcp_http
            .validate(self.server.listener_shutdown_timeout)?;
        let authorization_server = self.auth.validated_authorization_server(
            environment.deployment(),
            ::time::OffsetDateTime::now_utc(),
        )?;
        let _resource = mcp_resource_uri(&authorization_server)?;
        let _cursor_codec = self.pagination.cursor_codec()?;
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
    #[error("configured telemetry identity does not match the compiled MCP service")]
    IdentityMismatch,
    #[error("shutdown timeouts must be greater than zero")]
    ZeroShutdownTimeout,
    #[error("MCP transport bounds are invalid or exceed the listener shutdown deadline")]
    McpHttpPolicy,
    #[error("build metadata validation failed: {0}")]
    Metadata(#[from] omnius_core::InvalidBuildMetadata),
    #[error("PostgreSQL configuration failed: {0}")]
    PostgresConfig(#[from] PostgresConfigError),
    #[error("migration configuration failed: {0}")]
    MigrationConfig(#[from] MigrationConfigError),
    #[error("reference runtime configuration failed: {0}")]
    ReferenceRuntimeConfig(#[from] ReferenceRuntimeConfigError),
    #[error("MCP OAuth resource configuration failed: {0}")]
    OAuthResource(#[from] OAuthResourceVerifierBuildError),
    #[error("outbound HTTP configuration failed: {0}")]
    OutboundConfig(#[from] OutboundConfigError),
    #[error("outbound HTTP client construction failed: {0}")]
    OutboundBuild(#[from] OutboundBuildError),
    #[error("reference MCP application composition failed: {0}")]
    Mcp(#[from] ReferenceMcpBuildError),
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
    #[error("HTTP listener bind failed")]
    Bind,
    #[error("HTTP server failed")]
    Serve,
    #[error("HTTP server stopped without a drain request")]
    UnexpectedServerExit,
    #[error("HTTP listener or MCP work did not drain before its deadline")]
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
            Self::ZeroShutdownTimeout | Self::McpHttpPolicy => "STARTUP_TIMEOUT",
            Self::Metadata(_) => "STARTUP_METADATA",
            Self::PostgresConfig(_) => "STARTUP_POSTGRES_CONFIG",
            Self::MigrationConfig(_) => "STARTUP_MIGRATION_CONFIG",
            Self::ReferenceRuntimeConfig(_) | Self::OAuthResource(_) => "STARTUP_AUTH_CONFIG",
            Self::OutboundConfig(_) | Self::OutboundBuild(_) => "STARTUP_OUTBOUND_HTTP",
            Self::Mcp(_) => "STARTUP_MCP",
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
    match Box::pin(execute(Cli::parse())).await {
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
        Command::Server(args) => Box::pin(run_server(args)).await,
        Command::Migrate(args) => run_database_command(args, MigrationCommand::Migrate).await,
        Command::MigrationStatus(args) => {
            run_database_command(args, MigrationCommand::Status).await
        }
    }
}

fn run_profile_info() -> Result<RunOutcome, StartupError> {
    eprintln!("bootstrap phase=profile-info");
    println!(
        "{}",
        serde_json::to_string(&build_metadata()?).map_err(StartupError::OutputEncoding)?
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
    let span = telemetry.service_span();
    let telemetry_flush_timeout = config.server.telemetry_flush_timeout;
    let result = Box::pin(run_application(config, environment).instrument(span)).await;
    let shutdown = shutdown_telemetry(telemetry, telemetry_flush_timeout);
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
    eprintln!("bootstrap phase=telemetry");
    let telemetry = omnius_telemetry::bootstrap(&config.telemetry)?;
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
    let mut loader = ConfigLoader::new("OMNIUS", args.environment.deployment())?
        .with_base_file(args.config)
        .with_environment_file(args.environment_config);
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
        providers: PROVIDERS,
        schema: SCHEMA,
    })?)
}

fn schema_range() -> Result<SchemaVersionRange, StartupError> {
    SchemaVersionRange::try_from(SCHEMA).map_err(StartupError::Migration)
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
    config: AppConfig,
    environment: EnvironmentArg,
) -> Result<RunOutcome, StartupError> {
    eprintln!("bootstrap phase=application");
    let outbound_clients = Arc::new(OutboundHttpClients::new(&config.outbound_http)?);
    let pool = PostgresPool::connect(&config.postgres, environment.deployment()).await?;
    let result =
        run_application_with_pool(config, environment, pool.clone(), outbound_clients).await;
    let close = pool.close().await.map_err(StartupError::PoolShutdown);
    match (result, close) {
        (Err(primary), _) => Err(primary),
        (Ok(_), Err(error)) => Err(error),
        (Ok(outcome), Ok(())) => Ok(outcome),
    }
}

async fn run_application_with_pool(
    config: AppConfig,
    environment: EnvironmentArg,
    pool: PostgresPool,
    _outbound_clients: Arc<OutboundHttpClients>,
) -> Result<RunOutcome, StartupError> {
    let deployment = environment.deployment();
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        schema_range()?,
        config.migrations,
        deployment,
    )?;
    runner.apply_startup_policy().await?;

    let health = build_health_service(&config, &pool)?;
    let authorization_server = Arc::new(
        config
            .auth
            .validated_authorization_server(deployment, ::time::OffsetDateTime::now_utc())?,
    );
    let cursor_codec = config.pagination.cursor_codec()?;
    let mcp = build_reference_mcp_application(ReferenceMcpApplicationInput {
        authorization_server,
        pool,
        local_identity_provider: config.auth.registration.local_identity_provider,
        cursor_codec,
        http: config.mcp_http.build(config.http.clone()),
    })?;
    let health_routes = HttpShell::new(config.http.clone())?.apply(health.public_router())?;
    let (mcp_routes, mcp_drain) = mcp.into_parts();
    let router = health_routes.merge(mcp_routes);

    run_application_runtime(ApplicationRuntime {
        router,
        header_read_timeout: config.http.header_read_timeout,
        listen_address: config.server.listen_address,
        listener_shutdown_timeout: config.server.listener_shutdown_timeout,
        health: &health,
        mcp_drain,
    })
    .await
}

fn build_health_service(
    config: &AppConfig,
    pool: &PostgresPool,
) -> Result<HealthService, StartupError> {
    let mut builder = HealthBuilder::new(build_metadata()?, config.health)?;
    builder.register(pool.health_check())?;
    Ok(builder.build())
}

struct ApplicationRuntime<'runtime> {
    router: Router,
    header_read_timeout: Duration,
    listen_address: SocketAddr,
    listener_shutdown_timeout: Duration,
    health: &'runtime HealthService,
    mcp_drain: omnius_mcp_transport_http::McpHttpDrainHandle,
}

async fn run_application_runtime(
    runtime: ApplicationRuntime<'_>,
) -> Result<RunOutcome, StartupError> {
    let ApplicationRuntime {
        router,
        header_read_timeout,
        listen_address,
        listener_shutdown_timeout,
        health,
        mcp_drain,
    } = runtime;
    let server = HttpServer::bind(
        listen_address,
        router,
        HttpServerConfig {
            header_read_timeout,
            connection_mode: ConnectionMode::AutoWithUpgrades,
            peer_address_mode: PeerAddressMode::ConnectInfo,
        },
    )
    .await
    .map_err(|_| StartupError::Bind)?;
    let bound_address = server.local_addr().map_err(|_| StartupError::Bind)?;
    let http_drain = server.drain_handle();
    let mut signals = TerminationSignals::new().map_err(|_| StartupError::Signal)?;

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
    health.begin_drain_with(&control, || {
        http_drain.begin_drain();
        mcp_drain.begin_drain();
    });

    let mut forced = false;
    let mut listener_timed_out = false;
    let mut mcp_outcome = McpDrainOutcome::Complete;
    if unexpected_server_exit {
        mcp_outcome = mcp_drain.drain().await;
    } else {
        let drain = async {
            let (server_result, mcp_result) = tokio::join!(&mut server, mcp_drain.drain());
            (server_result, mcp_result)
        };
        tokio::pin!(drain);
        tokio::select! {
            (result, result_mcp) = &mut drain => {
                serve_error = result.err();
                mcp_outcome = result_mcp;
            }
            () = signals.recv() => {
                control.force_cancel();
                forced = true;
            }
            () = time::sleep(listener_shutdown_timeout) => {
                control.force_cancel();
                listener_timed_out = true;
            }
        }
    }
    drop(server);

    let report = supervisor.shutdown().await;
    if forced || mcp_outcome == McpDrainOutcome::Forced {
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

fn shutdown_telemetry(telemetry: TelemetryGuard, timeout: Duration) -> Result<(), StartupError> {
    telemetry.shutdown(timeout).map_err(StartupError::Telemetry)
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|information| {
        if let Some(location) = information.location() {
            eprintln!(
                "process panic captured at {}:{}:{}",
                location.file(),
                location.line(),
                location.column()
            );
        } else {
            eprintln!("process panic captured at unknown location");
        }
    }));
}

#[cfg(test)]
mod composition_tests {
    use super::*;

    #[test]
    fn schema_range_tracks_embedded_migration_head() -> Result<(), StartupError> {
        let range = schema_range()?;
        assert_eq!(range.maximum(), omnius_migrations::CURRENT_SCHEMA_VERSION);
        Ok(())
    }

    #[test]
    fn mcp_drain_must_fit_inside_listener_deadline() {
        let config = McpHttpTransportConfig {
            allowed_hosts: vec!["127.0.0.1".to_owned()],
            max_json_response_bytes: 1024,
            max_response_frame_bytes: 1024,
            drain_timeout: Duration::from_secs(11),
        };
        assert!(matches!(
            config.validate(Duration::from_secs(10)),
            Err(StartupError::McpHttpPolicy)
        ));
    }
}
