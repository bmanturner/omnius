//! PostgreSQL-backed reference API composition.

use std::{
    io::{self, IsTerminal as _, Read as _},
    net::SocketAddr,
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use axum::Router;
use clap::{Args, Parser, Subcommand, ValueEnum};
use garde::Validate;
use omnius_auth_oauth_server::{
    ClientId, OsEntropy, SystemClock, TokenEndpointAuthMethod, ValidatedAuthorizationServerConfig,
};
use omnius_auth_password::{
    InvitationIssueRequest, OsInvitationTokenGenerator, PasswordStoreError, PostgresPasswordStore,
    RegistrationMode,
};
use omnius_auth_session_postgres::session_store_health_check;
use omnius_config::{ConfigLoadError, ConfigLoader, DeploymentEnvironment};
use omnius_core::{
    BuildMetadata, BuildMetadataInput, ErrorCode, ProviderMetadata, SchemaCompatibility,
};
use omnius_health::{
    CheckFailure, HealthBuildError, HealthBuilder, HealthCheckSpec, HealthConfig, HealthService,
};
use omnius_http::{
    HttpShell, HttpShellConfig, HttpShellError, StaticDelivery, StaticDeliveryConfig,
    StaticDeliveryError,
    server::{ConnectionMode, HttpServer, HttpServerConfig, PeerAddressMode},
};
use omnius_idempotency::IdempotencyConfig;
use omnius_migrations::{
    MIGRATOR, MigrationCommand, MigrationCommandOutput, MigrationConfig, MigrationConfigError,
    MigrationError, MigrationRunner, MigrationStatus, SchemaVersionRange,
};
use omnius_openapi::{OpenApiConfig, OpenApiError};
use omnius_outbound_http::{
    BuildError as OutboundBuildError, ConfigError as OutboundConfigError, OutboundHttpClients,
    OutboundHttpConfig,
};
use omnius_postgres::{PostgresConfig, PostgresConfigError, PostgresError, PostgresPool};
use omnius_reference_api::{
    AccountEmailConfig, AuthConfig, AuthenticatedRuntimeBuildError, AuthenticatedRuntimeInput,
    OAuthRuntimeBuildError, OAuthRuntimeInput, PaginationConfig, ReferenceRuntimeConfigError,
    account_auth::{
        AccountAuthBuildError, AccountAuthState, AccountAuthStateInput, canonical_email,
    },
    build_authenticated_runtime, extend_oauth_runtime, metadata_router,
    oauth_provider::{OAuthAdapterBuildInput, OAuthProviderBuildError, build_oauth_adapter},
    openapi_catalog,
};
use omnius_runtime::{
    Criticality, RegisterError, StartError, Supervisor, TaskSpec, TerminationSignals,
};
use omnius_telemetry::{TelemetryConfig, TelemetryError, TelemetryGuard};
use omnius_tenancy::TenancyConfig;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time;
use tracing::Instrument as _;
use uuid::Uuid;

const SERVICE_NAME: &str = "api-reference";
const PROFILE: &str = "oauth-provider";
const MODULES: &[&str] = &[
    "audit",
    "auth-api-key",
    "auth-core",
    "auth-jwt",
    "auth-oauth-server",
    "auth-password",
    "auth-session-postgres",
    "authz-basic",
    "config",
    "core",
    "email",
    "generator",
    "health",
    "http",
    "idempotency",
    "jobs-core",
    "migrations",
    "openapi",
    "outbound-http",
    "postgres",
    "rate-limit-local",
    "runtime",
    "telemetry",
    "tenancy",
    "test-support",
    "validation",
];
const PROVIDERS: &[ProviderMetadata] = &[
    ProviderMetadata {
        slot: "primary-database",
        module: "postgres",
    },
    ProviderMetadata {
        slot: "rate-limit-provider",
        module: "rate-limit-local",
    },
];
const SCHEMA: SchemaCompatibility = SchemaCompatibility {
    minimum: "2026082301",
    maximum: "2026082809",
};

#[derive(Debug, Parser)]
#[command(
    name = "omnius-api-server",
    version,
    about = "Omnius PostgreSQL reference API"
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
    /// Bootstrap registration invitation management.
    RegistrationInvite(RegistrationInviteArgs),
    /// Administrator-managed OAuth client registration and disable operations.
    OAuthClient(OAuthClientArgs),
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

#[derive(Debug, Args)]
struct RegistrationInviteArgs {
    #[command(subcommand)]
    command: RegistrationInviteCommand,
}

#[derive(Debug, Subcommand)]
enum RegistrationInviteCommand {
    /// Issue and deliver one invite without accepting an address on the command line.
    Issue(RegistrationInviteIssueArgs),
}

#[derive(Debug, Args)]
struct RegistrationInviteIssueArgs {
    #[command(flatten)]
    config: ConfigArgs,
    /// Read the invitee address from redirected standard input.
    #[arg(long, required = true)]
    email_stdin: bool,
}

#[derive(Debug, Args)]
struct OAuthClientArgs {
    #[command(subcommand)]
    command: OAuthClientCommand,
}

#[derive(Debug, Subcommand)]
enum OAuthClientCommand {
    /// Register strict client metadata read from redirected standard input.
    Register(OAuthClientRegisterArgs),
    /// Disable one exact client and atomically revoke all derived authority.
    Disable(OAuthClientDisableArgs),
}

#[derive(Debug, Args)]
struct OAuthClientRegisterArgs {
    #[command(flatten)]
    config: ConfigArgs,
    /// Read the complete bounded metadata document from redirected standard input.
    #[arg(long, required = true)]
    metadata_stdin: bool,
}

#[derive(Debug, Args)]
struct OAuthClientDisableArgs {
    #[command(flatten)]
    config: ConfigArgs,
    /// Exact registered OAuth client identifier.
    client_id: String,
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
    #[serde(default)]
    static_delivery: StaticDeliveryConfig,
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
    #[garde(skip)]
    auth: AuthConfig,
    #[garde(skip)]
    email: AccountEmailConfig,
    #[garde(skip)]
    tenancy: TenancyConfig,
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

        self.postgres.validate_for(environment.deployment())?;
        self.migrations.validate_for(environment.deployment())?;
        let _shell = HttpShell::new(self.http.clone())?;
        let _static_delivery = self.static_delivery.clone().validate()?;
        let _health = HealthBuilder::new(build_metadata()?, self.health)?;
        let _openapi = self.openapi.validate()?;
        self.outbound_http.validate()?;
        self.auth.validate_authenticated_for(
            &self.email,
            &self.pagination,
            environment.deployment(),
        )?;
        let _authorization_server = self.auth.validate_oauth_for(
            &self.tenancy,
            environment.deployment(),
            ::time::OffsetDateTime::now_utc(),
        )?;
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

#[derive(Serialize)]
struct RegistrationInviteOutput {
    invitation_id: Uuid,
    created_at: String,
    expires_at: String,
}
#[derive(Serialize)]
struct OAuthClientRegisterOutput {
    client_id: String,
    token_endpoint_auth_method: &'static str,
    client_secret: Option<String>,
}

#[derive(Serialize)]
struct OAuthClientDisableOutput {
    newly_disabled: bool,
    grants_revoked: u64,
    refresh_families_revoked: u64,
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
    #[error("PostgreSQL configuration failed: {0}")]
    PostgresConfig(#[from] PostgresConfigError),
    #[error("migration configuration failed: {0}")]
    MigrationConfig(#[from] MigrationConfigError),
    #[error("reference runtime configuration failed: {0}")]
    ReferenceRuntimeConfig(#[from] ReferenceRuntimeConfigError),
    #[error("OpenAPI composition failed: {0}")]
    OpenApi(#[from] OpenApiError),
    #[error("outbound HTTP configuration failed: {0}")]
    OutboundConfig(#[from] OutboundConfigError),
    #[error("outbound HTTP client construction failed: {0}")]
    OutboundBuild(#[from] OutboundBuildError),
    #[error("authenticated runtime composition failed: {0}")]
    AuthenticatedRuntime(#[from] AuthenticatedRuntimeBuildError),
    #[error("OAuth runtime composition failed: {0}")]
    OAuthRuntime(#[from] OAuthRuntimeBuildError),
    #[error("account lifecycle composition failed: {0}")]
    AccountAuth(#[from] AccountAuthBuildError),
    #[error("account email delivery failed")]
    AccountMailDelivery,
    #[error("registration invitation issuance requires invite-only registration mode")]
    RegistrationInviteMode,
    #[error("registration invitation input must be redirected through standard input")]
    RegistrationInviteInput,
    #[error("registration invitation persistence failed")]
    RegistrationInviteDatabase,
    #[error("registration invitation store operation failed: {0}")]
    RegistrationInviteStore(#[from] PasswordStoreError),
    #[error("registration invitation timestamp encoding failed")]
    RegistrationInviteTimestamp,
    #[error("authorization-server composition failed: {0}")]
    OAuthProvider(#[from] OAuthProviderBuildError),
    #[error("OAuth client metadata input must be bounded redirected standard input")]
    OAuthClientInput,
    #[error("OAuth client administrator operation failed")]
    OAuthClientOperation,
    #[error("telemetry initialization or shutdown failed: {0}")]
    Telemetry(#[from] TelemetryError),
    #[error("health composition failed: {0}")]
    Health(#[from] HealthBuildError),
    #[error("HTTP composition failed: {0}")]
    Http(#[from] HttpShellError),
    #[error("static production delivery failed: {0}")]
    StaticDelivery(#[from] StaticDeliveryError),
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
            Self::ReferenceRuntimeConfig(_) => "STARTUP_AUTH_CONFIG",
            Self::OpenApi(_) => "STARTUP_OPENAPI",
            Self::OutboundConfig(_) | Self::OutboundBuild(_) => "STARTUP_OUTBOUND_HTTP",
            Self::AuthenticatedRuntime(_) => "STARTUP_BROWSER_AUTH",
            Self::OAuthRuntime(_) | Self::OAuthProvider(_) => "STARTUP_OAUTH_PROVIDER",
            Self::AccountAuth(_) | Self::AccountMailDelivery => "STARTUP_ACCOUNT_AUTH",
            Self::RegistrationInviteMode
            | Self::RegistrationInviteInput
            | Self::RegistrationInviteDatabase
            | Self::RegistrationInviteStore(_)
            | Self::RegistrationInviteTimestamp => "REGISTRATION_INVITATION",
            Self::OAuthClientInput | Self::OAuthClientOperation => "OAUTH_CLIENT_ADMIN",
            Self::Telemetry(_) => "STARTUP_TELEMETRY",
            Self::Health(_) => "STARTUP_HEALTH",
            Self::Http(_) | Self::StaticDelivery(_) => "STARTUP_HTTP",
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

    match Box::pin(execute(cli)).await {
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
        Command::RegistrationInvite(args) => match args.command {
            RegistrationInviteCommand::Issue(args) => run_registration_invite(args).await,
        },
        Command::OAuthClient(args) => match args.command {
            OAuthClientCommand::Register(args) => run_oauth_client_register(args).await,
            OAuthClientCommand::Disable(args) => run_oauth_client_disable(args).await,
        },
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
    let telemetry = omnius_telemetry::bootstrap(&config.telemetry)?;
    let span = telemetry.service_span();
    let telemetry_flush_timeout = config.server.telemetry_flush_timeout;
    let result = Box::pin(run_application(config, environment).instrument(span)).await;

    let forced = matches!(result, Ok(RunOutcome::Forced));
    let shutdown = shutdown_telemetry(telemetry, telemetry_flush_timeout);
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

async fn run_registration_invite(
    args: RegistrationInviteIssueArgs,
) -> Result<RunOutcome, StartupError> {
    if !args.email_stdin {
        return Err(StartupError::RegistrationInviteInput);
    }
    let canonical_email = read_registration_invite_email()?;
    eprintln!("bootstrap phase=config");
    let environment = args.config.environment;
    let config = load_config(args.config, None)?;
    config.validate_composition(environment)?;

    eprintln!("bootstrap phase=telemetry");
    let telemetry = omnius_telemetry::bootstrap(&config.telemetry)?;
    let span = telemetry.service_span();
    let telemetry_flush_timeout = config.server.telemetry_flush_timeout;
    let result = execute_registration_invite(config, environment, &canonical_email)
        .instrument(span)
        .await;
    let shutdown = shutdown_telemetry(telemetry, telemetry_flush_timeout);
    let output = match (result, shutdown) {
        (Err(primary), _) => return Err(primary),
        (Ok(_), Err(error)) => return Err(error),
        (Ok(output), Ok(())) => output,
    };
    println!(
        "{}",
        serde_json::to_string(&output).map_err(StartupError::OutputEncoding)?
    );
    Ok(RunOutcome::Graceful)
}

fn read_registration_invite_email() -> Result<String, StartupError> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Err(StartupError::RegistrationInviteInput);
    }
    let mut input = String::new();
    stdin
        .take(323)
        .read_to_string(&mut input)
        .map_err(|_| StartupError::RegistrationInviteInput)?;
    if input.len() > 322 {
        return Err(StartupError::RegistrationInviteInput);
    }
    let candidate = input
        .strip_suffix("\r\n")
        .or_else(|| input.strip_suffix('\n'))
        .unwrap_or(&input);
    if candidate.contains(['\r', '\n']) {
        return Err(StartupError::RegistrationInviteInput);
    }
    canonical_email(candidate).map_err(|_| StartupError::RegistrationInviteInput)
}

async fn execute_registration_invite(
    config: AppConfig,
    environment: EnvironmentArg,
    canonical_email: &str,
) -> Result<RegistrationInviteOutput, StartupError> {
    let deployment = environment.deployment();
    let (password_worker, _login_provider, password_policy) = config.auth.password.build()?;
    let (registration, invitation_pepper, response_floor) = config
        .auth
        .registration
        .build(deployment, &password_policy)?;
    if registration.mode() != RegistrationMode::InviteOnly {
        return Err(StartupError::RegistrationInviteMode);
    }
    let (email, mail) = config.email.build(deployment)?;
    let pool = PostgresPool::connect(&config.postgres, deployment).await?;
    let state = AccountAuthState::new(AccountAuthStateInput {
        pool: pool.clone(),
        session_config: config.auth.session,
        password_worker,
        registration,
        invitation_pepper,
        response_floor,
        email: email.clone(),
        mail,
    })?;
    let result = async {
        let mut transaction = pool
            .sqlx_pool()
            .begin()
            .await
            .map_err(|_| StartupError::RegistrationInviteDatabase)?;
        let issued = PostgresPasswordStore
            .issue_invitation_with(
                &mut transaction,
                InvitationIssueRequest {
                    identity_provider: state.registration().local_identity_provider(),
                    canonical_email,
                    issuer: omnius_auth_password::InvitationIssuer::System,
                    now: ::time::OffsetDateTime::now_utc(),
                    ttl: state.registration().invitation_ttl(),
                },
                state.invitation_pepper(),
                &OsInvitationTokenGenerator,
            )
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| StartupError::RegistrationInviteDatabase)?;
        state
            .deliver_invitation(canonical_email, &issued.token)
            .await
            .map_err(|_| StartupError::AccountMailDelivery)?;
        Ok(RegistrationInviteOutput {
            invitation_id: issued.metadata.id,
            created_at: issued
                .metadata
                .created_at
                .format(&::time::format_description::well_known::Rfc3339)
                .map_err(|_| StartupError::RegistrationInviteTimestamp)?,
            expires_at: issued
                .metadata
                .expires_at
                .format(&::time::format_description::well_known::Rfc3339)
                .map_err(|_| StartupError::RegistrationInviteTimestamp)?,
        })
    }
    .await;
    email.shutdown().await;
    let close = pool.close().await.map_err(StartupError::PoolShutdown);
    match (result, close) {
        (Err(primary), _) => Err(primary),
        (Ok(_), Err(error)) => Err(error),
        (Ok(output), Ok(())) => Ok(output),
    }
}

async fn run_oauth_client_register(
    args: OAuthClientRegisterArgs,
) -> Result<RunOutcome, StartupError> {
    if !args.metadata_stdin {
        return Err(StartupError::OAuthClientInput);
    }
    let metadata = read_oauth_client_metadata()?;
    let environment = args.config.environment;
    let config = load_config(args.config, None)?;
    config.validate_composition(environment)?;
    let deployment = environment.deployment();
    let validated = validated_authorization_server(&config, deployment)?;
    if metadata.len() > validated.max_client_metadata_bytes() {
        return Err(StartupError::OAuthClientInput);
    }
    let pool = PostgresPool::connect(&config.postgres, deployment).await?;
    let result = async {
        let adapter = build_oauth_adapter(OAuthAdapterBuildInput {
            config: Arc::new(validated),
            pool: pool.clone(),
            outbound_http: Arc::new(OutboundHttpClients::new(&config.outbound_http)?),
            session_config: config.auth.session,
            local_identity_provider: config.auth.registration.local_identity_provider,
            clock: Arc::new(SystemClock),
            entropy: Arc::new(OsEntropy),
        })?;
        let mut onboarded = adapter
            .register_pre_registered_json(
                &metadata,
                config.auth.authorization_server.max_client_metadata_bytes,
            )
            .await
            .map_err(|_| StartupError::OAuthClientOperation)?;
        let token_endpoint_auth_method = match onboarded.client.token_endpoint_auth_method {
            TokenEndpointAuthMethod::None => "none",
            TokenEndpointAuthMethod::ClientSecretBasic => "client_secret_basic",
            TokenEndpointAuthMethod::PrivateKeyJwt => "private_key_jwt",
        };
        Ok(OAuthClientRegisterOutput {
            client_id: onboarded.client.client_id.as_str().to_owned(),
            token_endpoint_auth_method,
            client_secret: onboarded
                .client_secret
                .take()
                .map(omnius_auth_oauth_server::OpaqueBearer::expose_once),
        })
    }
    .await;
    let close = pool.close().await.map_err(StartupError::PoolShutdown);
    let output = match (result, close) {
        (Err(primary), _) => return Err(primary),
        (Ok(_), Err(error)) => return Err(error),
        (Ok(output), Ok(())) => output,
    };
    println!(
        "{}",
        serde_json::to_string(&output).map_err(StartupError::OutputEncoding)?
    );
    Ok(RunOutcome::Graceful)
}

async fn run_oauth_client_disable(
    args: OAuthClientDisableArgs,
) -> Result<RunOutcome, StartupError> {
    let client_id = ClientId::parse(args.client_id).map_err(|_| StartupError::OAuthClientInput)?;
    let environment = args.config.environment;
    let config = load_config(args.config, None)?;
    config.validate_composition(environment)?;
    let deployment = environment.deployment();
    let validated = validated_authorization_server(&config, deployment)?;
    let pool = PostgresPool::connect(&config.postgres, deployment).await?;
    let result = async {
        let adapter = build_oauth_adapter(OAuthAdapterBuildInput {
            config: Arc::new(validated),
            pool: pool.clone(),
            outbound_http: Arc::new(OutboundHttpClients::new(&config.outbound_http)?),
            session_config: config.auth.session,
            local_identity_provider: config.auth.registration.local_identity_provider,
            clock: Arc::new(SystemClock),
            entropy: Arc::new(OsEntropy),
        })?;
        let outcome = adapter
            .disable_client(&client_id)
            .await
            .map_err(|_| StartupError::OAuthClientOperation)?
            .ok_or(StartupError::OAuthClientOperation)?;
        Ok(OAuthClientDisableOutput {
            newly_disabled: outcome.newly_disabled,
            grants_revoked: outcome.grants_revoked,
            refresh_families_revoked: outcome.refresh_families_revoked,
        })
    }
    .await;
    let close = pool.close().await.map_err(StartupError::PoolShutdown);
    let output = match (result, close) {
        (Err(primary), _) => return Err(primary),
        (Ok(_), Err(error)) => return Err(error),
        (Ok(output), Ok(())) => output,
    };
    println!(
        "{}",
        serde_json::to_string(&output).map_err(StartupError::OutputEncoding)?
    );
    Ok(RunOutcome::Graceful)
}

fn read_oauth_client_metadata() -> Result<Vec<u8>, StartupError> {
    const MAX_ADMIN_METADATA_BYTES: u64 = 256 * 1024;
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Err(StartupError::OAuthClientInput);
    }
    let mut input = Vec::new();
    stdin
        .take(MAX_ADMIN_METADATA_BYTES + 1)
        .read_to_end(&mut input)
        .map_err(|_| StartupError::OAuthClientInput)?;
    if input.is_empty()
        || u64::try_from(input.len()).map_err(|_| StartupError::OAuthClientInput)?
            > MAX_ADMIN_METADATA_BYTES
    {
        return Err(StartupError::OAuthClientInput);
    }
    Ok(input)
}

fn validated_authorization_server(
    config: &AppConfig,
    deployment: DeploymentEnvironment,
) -> Result<ValidatedAuthorizationServerConfig, StartupError> {
    Ok(config
        .auth
        .validated_authorization_server(deployment, ::time::OffsetDateTime::now_utc())?)
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
    let static_delivery = build_static_delivery(&config, environment)?;
    let outbound_clients = OutboundHttpClients::new(&config.outbound_http)?;
    let pool = PostgresPool::connect(&config.postgres, environment.deployment()).await?;
    let result = run_application_with_pool(
        config,
        environment,
        pool.clone(),
        outbound_clients,
        static_delivery,
    )
    .await;
    let close = pool.close().await.map_err(StartupError::PoolShutdown);

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

fn build_static_delivery(
    config: &AppConfig,
    environment: EnvironmentArg,
) -> Result<Option<StaticDelivery>, StartupError> {
    if (matches!(environment, EnvironmentArg::Production)
        && config.static_delivery.production_required)
        || config.static_delivery.serve_in_nonproduction
    {
        return Ok(Some(StaticDelivery::new(config.static_delivery.clone())?));
    }
    Ok(None)
}

fn static_asset_health_check(delivery: StaticDelivery) -> HealthCheckSpec {
    HealthCheckSpec::new(
        "static-assets",
        "http",
        Criticality::Required,
        Duration::from_secs(1),
        move || {
            let delivery = delivery.clone();
            async move {
                delivery
                    .check_readiness()
                    .map_err(|_| CheckFailure::new(static_assets_unavailable_code()))
            }
        },
    )
}

fn static_assets_unavailable_code() -> ErrorCode {
    let Ok(code) = ErrorCode::try_new("STATIC_ASSETS_UNAVAILABLE") else {
        unreachable!("static asset health code is valid");
    };
    code
}

fn build_health_service(
    config: &AppConfig,
    pool: &PostgresPool,
    static_delivery: Option<&StaticDelivery>,
) -> Result<HealthService, StartupError> {
    let mut builder = HealthBuilder::new(build_metadata()?, config.health)?;
    builder.register(pool.health_check())?;
    builder.register(session_store_health_check(
        pool.clone(),
        config.postgres.health_timeout,
    ))?;
    if let Some(delivery) = static_delivery {
        builder.register(static_asset_health_check(delivery.clone()))?;
    }
    Ok(builder.build())
}

struct HttpComposition {
    shell: HttpShell,
    application_routes: Router,
    static_delivery: Option<StaticDelivery>,
}

struct HttpApplication {
    router: Router,
    header_read_timeout: Duration,
}

struct ApplicationRuntime<'runtime> {
    http: HttpApplication,
    listen_address: SocketAddr,
    listener_shutdown_timeout: Duration,
    health: &'runtime HealthService,
    oauth_cleanup_task: TaskSpec,
}

impl HttpComposition {
    fn finish(self, browser_routes: Router) -> Result<HttpApplication, StartupError> {
        let Self {
            shell,
            application_routes,
            static_delivery,
        } = self;
        let header_read_timeout = shell.header_read_timeout();
        let mut router = shell.apply(application_routes.merge(browser_routes))?;
        if let Some(delivery) = static_delivery {
            router = router.merge(delivery.router());
        }
        Ok(HttpApplication {
            router,
            header_read_timeout,
        })
    }
}

fn build_http_composition(
    config: &AppConfig,
    health: &HealthService,
    static_delivery: Option<StaticDelivery>,
) -> Result<HttpComposition, StartupError> {
    let shell = HttpShell::new(config.http.clone())?;
    let catalog = openapi_catalog(config.openapi)?;
    let application_routes = health
        .public_router()
        .merge(metadata_router(
            include_bytes!("../../../contracts/openapi.json"),
            include_bytes!("../../../contracts/permissions.json"),
        ))
        .merge(catalog.router());
    Ok(HttpComposition {
        shell,
        application_routes,
        static_delivery,
    })
}

async fn run_application_with_pool(
    config: AppConfig,
    environment: EnvironmentArg,
    pool: PostgresPool,
    outbound_clients: OutboundHttpClients,
    static_delivery: Option<StaticDelivery>,
) -> Result<RunOutcome, StartupError> {
    let deployment = environment.deployment();
    let listen_address = config.server.listen_address;
    let listener_shutdown_timeout = config.server.listener_shutdown_timeout;
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        schema_range()?,
        config.migrations,
        deployment,
    )?;
    runner.apply_startup_policy().await?;
    let outbound_clients = Arc::new(outbound_clients);

    let health = build_health_service(&config, &pool, static_delivery.as_ref())?;
    let http_composition = build_http_composition(&config, &health, static_delivery)?;
    let trusted_origins = config.http.trusted_origins.clone();
    let authenticated = build_authenticated_runtime(AuthenticatedRuntimeInput {
        pool: pool.clone(),
        auth: config.auth,
        account_email: config.email,
        trusted_origins,
        idempotency: config.idempotency,
        pagination: config.pagination,
        outbound_http: Arc::clone(&outbound_clients),
        deployment,
    })
    .await?;
    let parts = extend_oauth_runtime(
        authenticated,
        OAuthRuntimeInput {
            tenancy: config.tenancy,
        },
    )?
    .into_parts();
    let routes = parts.routes;
    let email = parts.email;
    let oauth_cleanup_task = parts.cleanup_task;
    let http = http_composition.finish(routes)?;

    let outcome = run_application_runtime(ApplicationRuntime {
        http,
        listen_address,
        listener_shutdown_timeout,
        health: &health,
        oauth_cleanup_task,
    })
    .await;
    email.shutdown().await;
    outcome
}

async fn run_application_runtime(
    runtime: ApplicationRuntime<'_>,
) -> Result<RunOutcome, StartupError> {
    let ApplicationRuntime {
        http: HttpApplication {
            router,
            header_read_timeout,
        },
        listen_address,
        listener_shutdown_timeout,
        health,
        oauth_cleanup_task,
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
    supervisor.register(oauth_cleanup_task)?;
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
            () = time::sleep(listener_shutdown_timeout) => {
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
}
