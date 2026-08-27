//! PostgreSQL-backed reference API composition.

use std::{
    io, net::SocketAddr, num::NonZeroUsize, path::PathBuf, process::ExitCode, sync::Arc,
    time::Duration,
};

use axum::{Extension, Router, extract::ConnectInfo};
use clap::{Args, Parser, Subcommand, ValueEnum};
use garde::Validate;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as AutoBuilder,
    service::TowerToHyperService,
};
use omnius_api_server::{
    AuthenticatedIdentityBuildError, AuthenticatedIdentityState, ReferenceApiState,
    authenticated_identity_router,
    browser_auth::{
        BrowserAuthBuildError, BrowserAuthState, BrowserAuthorization, PasswordLoginProvider,
        PasswordLoginProviderError, browser_auth_router, protected_browser_router,
    },
    browser_realtime::{
        BrowserRealtime, BrowserRealtimeBuildError, BrowserRealtimeConfig,
        BrowserSessionRealtimeIdentity,
    },
    browser_uploads::{
        BrowserUploadBuildError, BrowserUploadPolicy, ClamdScanner, ClamdScannerConfig,
        assemble_browser_uploads, browser_upload_router,
    },
    metadata_router, openapi_catalog, reference_router,
};
use omnius_auth_core::{SessionConfig, SessionConfigError};
use omnius_auth_jwt::{JwtBuildError, JwtConfig, JwtConfigError, JwtVerifier};
use omnius_auth_password::{
    PasswordEngine, PasswordError, PasswordPepper, PasswordPolicy, PasswordPolicyConfig,
    PasswordPolicyError, PasswordWorker,
};
use omnius_auth_session_postgres::session_store_health_check;
use omnius_authz_basic::{
    Action, AuthorizationService, BasicPolicy, IdentifierError, PolicyError, PolicyMatrix,
    ResourceKind,
};
use omnius_config::{
    ConfigLoadError, ConfigLoader, DeploymentEnvironment, ExposeSecret as _, SecretString,
};
use omnius_core::{
    BuildMetadata, BuildMetadataInput, Clock, ErrorCode, InvalidErrorCode, SchemaCompatibility,
    SystemClock,
};
use omnius_health::{
    CheckFailure, HealthBuildError, HealthBuilder, HealthCheckSpec, HealthConfig, HealthService,
};
use omnius_http::{
    HttpShell, HttpShellConfig, HttpShellError, StaticDelivery, StaticDeliveryConfig,
    StaticDeliveryError,
};
use omnius_idempotency::{IdempotencyConfig, IdempotencyConfigError, PostgresIdempotencyStore};
use omnius_migrations::{
    MIGRATOR, MigrationCommand, MigrationCommandOutput, MigrationConfig, MigrationConfigError,
    MigrationError, MigrationRunner, MigrationStatus, SchemaVersionRange,
};
use omnius_object_storage::{
    BlobStoreError, ObjectStorageConfig, ObjectStorageLimits, ProviderConfig,
};
use omnius_openapi::{OpenApiConfig, OpenApiError};
use omnius_outbound_http::{
    BuildError as OutboundBuildError, ConfigError as OutboundConfigError, OutboundHttpClients,
    OutboundHttpConfig, OutboundUrlPolicy,
};
use omnius_pagination::{CursorCodec, CursorSigningKey, CursorSigningKeyError};
use omnius_postgres::{PostgresConfig, PostgresConfigError, PostgresError, PostgresPool};
use omnius_realtime_core::{DeliveryQueueConfig, FanoutRouterConfig, RegistryConfig};
use omnius_realtime_sse::SseConfig;
use omnius_realtime_websocket::{WebSocketConfig, WebSocketConfigError};
use omnius_runtime::{Criticality, RegisterError, StartError, Supervisor};
use omnius_telemetry::{TelemetryConfig, TelemetryError, TelemetryGuard};
use omnius_tenancy::{TenancyConfig, TenancyConfigError, TenancyStoreError};
use omnius_upload_workflow::{ReconcilerConfig, UploadError, UploadReconciler};
use omnius_webhooks_inbound::{
    HandlerRegistry, InboundWebhookService, PostgresReceiptStore, ReceiptRepository,
    ReceiveBuildError, ReceiveLimits, WebhookConfig, WebhookConfigError, WebhookHandler,
    WebhookProcessor, processor_task, webhook_router,
};
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
const PROFILE: &str = "authenticated-api";
const MAX_PASSWORD_WORKER_CONCURRENCY: usize = 16;
const MAX_PASSWORD_WORKER_MEMORY_KIB: u64 = 1024 * 1024;
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
    "auth-core",
    "auth-password",
    "auth-session-postgres",
    "auth-jwt",
    "auth-api-key",
    "authz-basic",
    "tenancy",
    "audit",
    "webhooks-inbound",
    "realtime-core",
    "sse",
    "websockets",
    "object-storage",
    "upload-workflow",
];
const SCHEMA: SchemaCompatibility = SchemaCompatibility {
    minimum: "2026082301",
    maximum: "2026082701",
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
    webhooks_inbound: WebhookConfig,
    #[garde(skip)]
    auth: AuthConfig,
    #[garde(skip)]
    realtime: RealtimeConfig,
    #[garde(skip)]
    tenancy: TenancyConfig,
    #[garde(skip)]
    object_storage: RuntimeObjectStorageConfig,
    #[garde(skip)]
    uploads: UploadConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthConfig {
    session: SessionConfig,
    jwt: JwtConfig,
    password: PasswordConfig,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordConfig {
    login_provider: String,
    max_concurrency: NonZeroUsize,
    policy: PasswordPolicyConfig,
    pepper: PasswordPepperConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordPepperConfig {
    version: u32,
    secret: SecretString,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RealtimeConfig {
    trusted_origins: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeObjectStorageConfig {
    provider: ProviderConfig,
    #[serde(default)]
    limits: ObjectStorageLimits,
}

impl RuntimeObjectStorageConfig {
    fn as_config(&self) -> ObjectStorageConfig {
        ObjectStorageConfig {
            provider: match &self.provider {
                ProviderConfig::Memory => ProviderConfig::Memory,
                ProviderConfig::Local { root } => ProviderConfig::Local { root: root.clone() },
                ProviderConfig::S3Compatible {
                    endpoint,
                    region,
                    bucket,
                    access_key_id,
                    secret_access_key,
                    session_token,
                    allow_http,
                } => ProviderConfig::S3Compatible {
                    endpoint: endpoint.clone(),
                    region: region.clone(),
                    bucket: bucket.clone(),
                    access_key_id: access_key_id.clone(),
                    secret_access_key: secret_access_key.clone(),
                    session_token: session_token.clone(),
                    allow_http: *allow_http,
                },
                ProviderConfig::Gcs {
                    bucket,
                    service_account_json,
                    endpoint,
                    allow_http,
                } => ProviderConfig::Gcs {
                    bucket: bucket.clone(),
                    service_account_json: service_account_json.clone(),
                    endpoint: endpoint.clone(),
                    allow_http: *allow_http,
                },
                ProviderConfig::Azure {
                    account,
                    container,
                    access_key,
                    endpoint,
                    allow_http,
                } => ProviderConfig::Azure {
                    account: account.clone(),
                    container: container.clone(),
                    access_key: access_key.clone(),
                    endpoint: endpoint.clone(),
                    allow_http: *allow_http,
                },
            },
            limits: self.limits,
        }
    }

    fn into_config(self) -> ObjectStorageConfig {
        ObjectStorageConfig {
            provider: self.provider,
            limits: self.limits,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadConfig {
    scanner: ClamdScannerConfig,
    reconciler: ReconcilerSerdeConfig,
    policy: BrowserUploadPolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconcilerSerdeConfig {
    lease_owner: String,
    claim_batch: u16,
    #[serde(with = "humantime_serde")]
    lease_duration: Duration,
    #[serde(with = "humantime_serde")]
    work_timeout: Duration,
    #[serde(with = "humantime_serde")]
    finalization_margin: Duration,
    #[serde(with = "humantime_serde")]
    poll_interval: Duration,
    max_attempts: u16,
    #[serde(with = "humantime_serde")]
    initial_retry: Duration,
    #[serde(with = "humantime_serde")]
    max_retry: Duration,
    #[serde(with = "humantime_serde")]
    orphan_grace: Duration,
}

impl PasswordConfig {
    fn worker_concurrency(&self) -> Result<NonZeroUsize, StartupError> {
        let concurrency = self.max_concurrency.get();
        if concurrency > MAX_PASSWORD_WORKER_CONCURRENCY {
            return Err(StartupError::PasswordWorkerConcurrency);
        }
        let aggregate_memory_kib = u64::from(self.policy.memory_kib)
            .checked_mul(
                u64::try_from(concurrency).map_err(|_| StartupError::PasswordWorkerConcurrency)?,
            )
            .ok_or(StartupError::PasswordWorkerConcurrency)?;
        if aggregate_memory_kib > MAX_PASSWORD_WORKER_MEMORY_KIB {
            return Err(StartupError::PasswordWorkerConcurrency);
        }
        Ok(self.max_concurrency)
    }

    fn validate(&self) -> Result<(), StartupError> {
        let _max_concurrency = self.worker_concurrency()?;
        let active_pepper = PasswordPepper::new(self.pepper.version, self.pepper.secret.clone())?;
        let _policy = PasswordPolicy::new(self.policy, active_pepper, Vec::new())?;
        let _provider = PasswordLoginProvider::new(self.login_provider.clone())?;
        Ok(())
    }

    fn build(self) -> Result<(PasswordWorker, PasswordLoginProvider), StartupError> {
        let max_concurrency = self.worker_concurrency()?;
        let active_pepper = PasswordPepper::new(self.pepper.version, self.pepper.secret)?;
        let policy = PasswordPolicy::new(self.policy, active_pepper, Vec::new())?;
        let engine = PasswordEngine::new(policy)?;
        let worker = PasswordWorker::new(engine, max_concurrency);
        let provider = PasswordLoginProvider::new(self.login_provider)?;
        Ok((worker, provider))
    }
}

impl RealtimeConfig {
    fn websocket_config(&self) -> Result<WebSocketConfig, StartupError> {
        WebSocketConfig::new(&self.trusted_origins).map_err(StartupError::WebSocketConfig)
    }
}

impl ReconcilerSerdeConfig {
    fn build(&self) -> ReconcilerConfig {
        ReconcilerConfig {
            lease_owner: self.lease_owner.clone(),
            claim_batch: self.claim_batch,
            lease_duration: self.lease_duration,
            work_timeout: self.work_timeout,
            finalization_margin: self.finalization_margin,
            poll_interval: self.poll_interval,
            max_attempts: self.max_attempts,
            initial_retry: self.initial_retry,
            max_retry: self.max_retry,
            orphan_grace: self.orphan_grace,
        }
    }
}

impl UploadConfig {
    fn validate(
        &self,
        tenancy: &TenancyConfig,
        object_storage: &RuntimeObjectStorageConfig,
        deployment: DeploymentEnvironment,
    ) -> Result<(), StartupError> {
        tenancy.validate()?;
        if !tenancy.enabled {
            return Err(BrowserUploadBuildError::Tenancy(TenancyStoreError::Disabled).into());
        }
        let object_storage = object_storage.as_config();
        object_storage.validate(deployment)?;
        let _scanner = ClamdScanner::new(self.scanner)?;
        self.reconciler.build().validate()?;

        let credential_window = self
            .policy
            .direct_upload_expires_in
            .checked_add(Duration::from_secs(30))
            .ok_or(BrowserUploadBuildError::UploadPolicy)?;
        if self.policy.direct_upload_expires_in.is_zero()
            || self.policy.direct_upload_expires_in.subsec_nanos() != 0
            || self.policy.direct_upload_expires_in > object_storage.limits.max_signed_url_expiry
            || self.policy.pending_upload_ttl < credential_window
            || self.policy.pending_upload_ttl > Duration::from_secs(24 * 60 * 60)
        {
            return Err(BrowserUploadBuildError::UploadPolicy.into());
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
        let _static_delivery = self.static_delivery.clone().validate()?;
        let _health = HealthBuilder::new(build_metadata()?, self.health)?;
        let _idempotency_store = PostgresIdempotencyStore::new(self.idempotency)?;
        let _cursor_key = cursor_signing_key(&self.pagination)?;
        let _openapi = self.openapi.validate()?;
        self.outbound_http.validate()?;
        self.webhooks_inbound.validate()?;
        if !self.auth.session.enabled {
            return Err(SessionConfigError::Disabled.into());
        }
        if !self.auth.jwt.enabled {
            return Err(JwtBuildError::Disabled.into());
        }
        self.auth.session.validate_for(environment.deployment())?;
        self.auth.jwt.validate_for(environment.deployment())?;
        self.auth.password.validate()?;
        let _websocket = self.realtime.websocket_config()?;
        self.uploads.validate(
            &self.tenancy,
            &self.object_storage,
            environment.deployment(),
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
    #[error("inbound webhook configuration failed: {0}")]
    Webhooks(#[from] WebhookConfigError),
    #[error("inbound webhook service composition failed: {0}")]
    WebhooksBuild(#[from] ReceiveBuildError),
    #[error("enabled inbound webhooks require at least one exact domain handler")]
    WebhookHandlersMissing,
    #[error("inbound webhook processor task code is invalid: {0}")]
    WebhookTaskCode(#[from] InvalidErrorCode),
    #[error("password policy configuration failed: {0}")]
    PasswordPolicy(#[from] PasswordPolicyError),
    #[error("password worker initialization failed: {0}")]
    Password(#[from] PasswordError),
    #[error("password worker concurrency or aggregate memory exceeds its hard bound")]
    PasswordWorkerConcurrency,
    #[error("password login provider configuration failed: {0}")]
    PasswordLoginProvider(#[from] PasswordLoginProviderError),
    #[error("browser authorization identifier is invalid: {0}")]
    BrowserAuthorizationIdentifier(#[from] IdentifierError),
    #[error("browser authorization policy is invalid: {0}")]
    BrowserAuthorizationPolicy(#[from] PolicyError),
    #[error("browser authentication composition failed: {0}")]
    BrowserAuth(#[from] BrowserAuthBuildError),
    #[error("browser realtime transport configuration failed: {0}")]
    WebSocketConfig(#[from] WebSocketConfigError),
    #[error("browser realtime composition failed: {0}")]
    BrowserRealtime(#[from] BrowserRealtimeBuildError),
    #[error("browser tenancy configuration failed: {0}")]
    Tenancy(#[from] TenancyConfigError),
    #[error("browser object-storage configuration failed: {0}")]
    ObjectStorage(#[from] BlobStoreError),
    #[error("browser upload workflow configuration failed: {0}")]
    UploadWorkflow(#[from] UploadError),
    #[error("browser upload composition failed: {0}")]
    BrowserUploads(#[from] BrowserUploadBuildError),
    #[error("browser session configuration failed: {0}")]
    SessionConfig(#[from] SessionConfigError),
    #[error("authenticated identity composition failed: {0}")]
    IdentityComposition(#[from] AuthenticatedIdentityBuildError),
    #[error("JWT verifier configuration failed: {0}")]
    JwtConfig(#[from] JwtConfigError),
    #[error("JWT verifier initialization failed: {0}")]
    Jwt(#[from] JwtBuildError),
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
    #[error("browser realtime delivery did not drain before its deadline")]
    RealtimeShutdownDeadline,
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
            Self::Webhooks(_)
            | Self::WebhooksBuild(_)
            | Self::WebhookHandlersMissing
            | Self::WebhookTaskCode(_) => "STARTUP_WEBHOOKS_INBOUND",
            Self::PasswordPolicy(_)
            | Self::Password(_)
            | Self::PasswordWorkerConcurrency
            | Self::PasswordLoginProvider(_)
            | Self::BrowserAuthorizationIdentifier(_)
            | Self::BrowserAuthorizationPolicy(_)
            | Self::BrowserAuth(_) => "STARTUP_BROWSER_AUTH",
            Self::SessionConfig(_) | Self::IdentityComposition(_) => "STARTUP_SESSION_CONFIG",
            Self::WebSocketConfig(_) | Self::BrowserRealtime(_) => "STARTUP_BROWSER_REALTIME",
            Self::Tenancy(_)
            | Self::ObjectStorage(_)
            | Self::UploadWorkflow(_)
            | Self::BrowserUploads(_) => "STARTUP_BROWSER_UPLOADS",
            Self::JwtConfig(_) | Self::Jwt(_) => "STARTUP_JWT",
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
            Self::RealtimeShutdownDeadline => "SHUTDOWN_BROWSER_REALTIME_DEADLINE",
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
    let telemetry = omnius_telemetry::bootstrap(&config.telemetry)?;
    let span = telemetry.service_span();
    let telemetry_flush_timeout = config.server.telemetry_flush_timeout;
    let result = run_application(config, environment).instrument(span).await;

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
    config.validate_composition(environment)?;

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

fn build_identity_routes(
    pool: &PostgresPool,
    session_config: &SessionConfig,
    jwt_verifier: Option<JwtVerifier>,
    deployment: DeploymentEnvironment,
) -> Result<Router, StartupError> {
    Ok(authenticated_identity_router(
        AuthenticatedIdentityState::new(pool.clone(), session_config.clone(), jwt_verifier),
        deployment,
    )?)
}

struct BrowserRuntime {
    routes: Router,
    realtime: BrowserRealtime<BasicPolicy>,
    upload_reconciler: UploadReconciler,
}

fn build_browser_authorization() -> Result<BrowserAuthorization, StartupError> {
    let action = Action::new("browser:privileged")?;
    let resource_kind = ResourceKind::new("browser_session")?;
    let deny_unless_explicit =
        AuthorizationService::new(BasicPolicy::new(PolicyMatrix::new(Vec::new())?));
    Ok(BrowserAuthorization::new(
        deny_unless_explicit,
        action,
        resource_kind,
    ))
}

async fn build_browser_runtime(
    pool: PostgresPool,
    session_config: SessionConfig,
    password_config: PasswordConfig,
    realtime_config: RealtimeConfig,
    tenancy_config: TenancyConfig,
    object_storage_config: RuntimeObjectStorageConfig,
    upload_config: UploadConfig,
    deployment: DeploymentEnvironment,
    url_policy: &OutboundUrlPolicy,
) -> Result<BrowserRuntime, StartupError> {
    let object_storage_config = object_storage_config.into_config();
    let (password_worker, login_provider) = password_config.build()?;
    let auth_state = BrowserAuthState::new(
        pool.clone(),
        session_config,
        password_worker,
        login_provider,
        build_browser_authorization()?,
        realtime_config.trusted_origins.clone(),
    );
    let identity = Arc::new(BrowserSessionRealtimeIdentity::new(&auth_state));
    let realtime = BrowserRealtime::with_basic_policy(
        identity,
        BrowserRealtimeConfig::new(
            RegistryConfig::default(),
            DeliveryQueueConfig::default(),
            FanoutRouterConfig::default(),
            realtime_config.websocket_config()?,
            SseConfig::default(),
        ),
    )?;

    let UploadConfig {
        scanner,
        reconciler,
        policy,
    } = upload_config;
    let uploads = assemble_browser_uploads(
        pool,
        &tenancy_config,
        object_storage_config,
        scanner,
        reconciler.build(),
        policy,
        deployment,
        url_policy,
    )
    .await?;
    let upload_routes = protected_browser_router(
        &auth_state,
        deployment,
        browser_upload_router(uploads.state),
    )?;
    let routes = browser_auth_router(auth_state, deployment)?
        .merge(realtime.router())
        .merge(upload_routes);
    Ok(BrowserRuntime {
        routes,
        realtime,
        upload_reconciler: uploads.reconciler,
    })
}

fn build_webhook_service(
    config: &WebhookConfig,
    pool: &PostgresPool,
) -> Result<InboundWebhookService, StartupError> {
    let receipts: Arc<dyn ReceiptRepository> = Arc::new(PostgresReceiptStore::new(pool.clone()));
    Ok(InboundWebhookService::new(
        config.build_registry()?,
        receipts,
        ReceiveLimits {
            max_body_bytes: config.max_body_bytes,
            max_header_count: config.max_header_count,
            max_header_bytes: config.max_header_bytes,
            max_safe_payload_bytes: config.max_safe_payload_bytes,
        },
        config.retention,
    )?)
}

fn reference_webhook_handlers() -> Result<HandlerRegistry, StartupError> {
    let handlers = HandlerRegistry::default();
    if handlers.is_empty() {
        return Err(StartupError::WebhookHandlersMissing);
    }
    Ok(handlers)
}

fn build_webhook_processor(
    config: &WebhookConfig,
    pool: &PostgresPool,
) -> Result<WebhookProcessor, StartupError> {
    let handlers = reference_webhook_handlers()?;
    let handler: Arc<dyn WebhookHandler> = Arc::new(handlers);
    Ok(WebhookProcessor::new(
        PostgresReceiptStore::new(pool.clone()),
        handler,
        config.processing,
    )?)
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
    machine_callbacks: Option<Router>,
    static_delivery: Option<StaticDelivery>,
}

struct HttpApplication {
    router: Router,
    header_read_timeout: Duration,
}

impl HttpComposition {
    fn finish(self, browser_routes: Router) -> Result<HttpApplication, StartupError> {
        let Self {
            shell,
            application_routes,
            machine_callbacks,
            static_delivery,
        } = self;
        let header_read_timeout = shell.header_read_timeout();
        let mut router = shell.apply(application_routes.merge(browser_routes))?;
        if let Some(callbacks) = machine_callbacks {
            router = router.merge(shell.apply_machine_callbacks(callbacks));
        }
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
    environment: EnvironmentArg,
    pool: &PostgresPool,
    jwt_verifier: Option<JwtVerifier>,
    health: &HealthService,
    static_delivery: Option<StaticDelivery>,
) -> Result<HttpComposition, StartupError> {
    let shell = HttpShell::new(config.http.clone())?;
    let idempotency_store = PostgresIdempotencyStore::new(config.idempotency)?;
    let cursor_codec = CursorCodec::new(cursor_signing_key(&config.pagination)?);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let state = ReferenceApiState::new(pool.clone(), cursor_codec, idempotency_store, clock);
    let identity_routes = build_identity_routes(
        pool,
        &config.auth.session,
        jwt_verifier,
        environment.deployment(),
    )?;
    let catalog = openapi_catalog(config.openapi)?;
    let application_routes = health
        .public_router()
        .merge(metadata_router())
        .merge(reference_router(state))
        .merge(identity_routes)
        .merge(catalog.router());
    let machine_callbacks = if config.webhooks_inbound.enabled {
        Some(webhook_router(build_webhook_service(
            &config.webhooks_inbound,
            pool,
        )?))
    } else {
        None
    };
    Ok(HttpComposition {
        shell,
        application_routes,
        machine_callbacks,
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
    let jwt_verifier =
        JwtVerifier::initialize(&config.auth.jwt, deployment, outbound_clients).await?;

    let health = build_health_service(&config, &pool, static_delivery.as_ref())?;
    let webhook_processor = if config.webhooks_inbound.enabled {
        Some(build_webhook_processor(&config.webhooks_inbound, &pool)?)
    } else {
        None
    };
    let http_composition = build_http_composition(
        &config,
        environment,
        &pool,
        Some(jwt_verifier),
        &health,
        static_delivery,
    )?;
    let url_policy = OutboundUrlPolicy::new(config.outbound_http.url_policy.clone())?;
    let BrowserRuntime {
        routes,
        realtime,
        upload_reconciler,
    } = build_browser_runtime(
        pool.clone(),
        config.auth.session,
        config.auth.password,
        config.realtime,
        config.tenancy,
        config.object_storage,
        config.uploads,
        deployment,
        &url_policy,
    )
    .await?;
    let HttpApplication {
        router,
        header_read_timeout,
    } = http_composition.finish(routes)?;
    let listener = TcpListener::bind(listen_address)
        .await
        .map_err(|_| StartupError::Bind)?;
    let bound_address = listener.local_addr().map_err(|_| StartupError::Bind)?;
    let mut signals = TerminationSignals::new().map_err(|_| StartupError::Signal)?;

    let mut supervisor = Supervisor::new();
    supervisor.register(health.supervised_refresh_task())?;
    supervisor.register(upload_reconciler.task_spec())?;
    if let Some(processor) = webhook_processor {
        supervisor.register(processor_task(processor)?)?;
    }
    let supervisor = supervisor.start()?;
    let control = supervisor.control();
    let listener_drain = CancellationToken::new();
    let graceful_drain = listener_drain.clone();
    let mut server = Box::pin(serve_http(
        listener,
        router,
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

    health.begin_drain_with(&control, || realtime.begin_drain());
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
            () = time::sleep(listener_shutdown_timeout) => {
                control.force_cancel();
                listener_timed_out = true;
            }
        }
    }
    drop(server);

    let (realtime_drain, report) = if forced {
        (None, supervisor.shutdown().await)
    } else {
        let (realtime_drain, report) = tokio::join!(realtime.drain(), supervisor.shutdown());
        (Some(realtime_drain), report)
    };
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
    if realtime_drain.is_some_and(|outcome| outcome.deadline_expired) {
        return Err(StartupError::RealtimeShutdownDeadline);
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
                let (stream, peer_address) = accepted?;
                connections.spawn(serve_connection(
                    stream,
                    peer_address,
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
    peer_address: SocketAddr,
    app: Router,
    header_read_timeout: Duration,
    draining: CancellationToken,
) -> Result<(), ConnectionError> {
    let mut builder = AutoBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout);
    let app = app.layer(Extension(ConnectInfo(peer_address)));
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

#[cfg(test)]
mod webhook_composition_tests {
    use super::*;

    #[test]
    fn enabled_reference_webhooks_fail_closed_without_domain_handlers() {
        assert!(matches!(
            reference_webhook_handlers(),
            Err(StartupError::WebhookHandlersMissing)
        ));
    }
}
