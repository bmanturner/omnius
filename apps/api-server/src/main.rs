//! PostgreSQL-backed reference API composition.

use std::{
    collections::BTreeSet,
    io::{self, IsTerminal as _, Read as _},
    net::SocketAddr,
    num::NonZeroUsize,
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use axum::{Extension, Router, extract::ConnectInfo};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Parser, Subcommand, ValueEnum};
use garde::Validate;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as AutoBuilder,
    service::TowerToHyperService,
};
use omnius_api_server::{
    ReferenceApiState,
    account_auth::{
        AccountAuthBuildError, AccountAuthState, AccountAuthStateInput, AccountMailPresentation,
        account_auth_router, account_invitation_router, canonical_email,
    },
    api_key_auth::{
        ApiKeyManagementBuildError, ApiKeyManagementState, AuthenticatedIdentityBuildError,
        CanonicalPrincipalState, api_key_management_router, canonical_identity_route,
        protected_principal_router,
    },
    browser_auth::{
        BrowserAuthBuildError, BrowserAuthState, BrowserAuthorization, PasswordLoginProvider,
        PasswordLoginProviderError, browser_auth_router,
    },
    browser_tenancy::{BrowserTenancyState, browser_tenancy_router},
    metadata_router,
    oauth_provider::{
        OAuthAdminAdapterInput, OAuthProviderBuildError, OAuthProviderBuildInput,
        OAuthProviderRuntime, OAuthRateLimiters, build_oauth_admin_adapter, build_oauth_provider,
    },
    openapi_catalog, reference_router,
};
use omnius_auth_api_key::{ApiKeyConfig, ApiKeyConfigError, ApiKeyStore, ApiKeyStoreError};
use omnius_auth_core::{SessionConfig, SessionConfigError};
use omnius_auth_jwt::{JwtBuildError, JwtConfig, JwtConfigError, JwtVerifier};
use omnius_auth_oauth_server::{
    AuthorizationServerConfig, AuthorizationServerConfigError, ClientId, TokenEndpointAuthMethod,
    ValidatedAuthorizationServerConfig,
};
use omnius_auth_password::{
    InvitationIssueRequest, InvitationTokenError, InvitationTokenPepper,
    OsInvitationTokenGenerator, PasswordEngine, PasswordError, PasswordPepper, PasswordPolicy,
    PasswordPolicyConfig, PasswordPolicyError, PasswordStoreError, PasswordWorker,
    PostgresPasswordStore, RegistrationMode, RegistrationPolicy, RegistrationPolicyConfig,
    RegistrationPolicyError,
};
use omnius_auth_session_postgres::session_store_health_check;
use omnius_authz_basic::{
    Action, AuthorizationService, BasicPolicy, IdentifierError, PolicyError, PolicyMatrix,
    ResourceKind,
};
use omnius_config::{
    ConfigLoadError, ConfigLoader, DeploymentEnvironment, ExposeSecret as _, SecretString,
};
use omnius_core::{BuildMetadata, BuildMetadataInput, ErrorCode, SchemaCompatibility, SystemClock};
use omnius_email::{
    CustomHeaderPolicy, EmailConfig, EmailError, EmailLimits, EmailProviderConfig, EmailService,
    MailboxAddress, TemplateConfig,
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
use omnius_openapi::{OpenApiConfig, OpenApiError};
use omnius_outbound_http::{
    BuildError as OutboundBuildError, ConfigError as OutboundConfigError, OutboundHttpClients,
    OutboundHttpConfig,
};
use omnius_pagination::{CursorCodec, CursorSigningKey, CursorSigningKeyError};
use omnius_postgres::{PostgresConfig, PostgresConfigError, PostgresError, PostgresPool};
use omnius_rate_limit_local::{
    LocalRateLimitConfigError, LocalRateLimitPolicy, LocalRateLimiter, RateLimitIdentityKind,
    RateLimitOperation,
};
use omnius_runtime::{Criticality, RegisterError, StartError, Supervisor, TaskSpec};
use omnius_telemetry::{TelemetryConfig, TelemetryError, TelemetryGuard};
use omnius_tenancy::{TenancyConfig, TenancyConfigError, TenancyStore, TenancyStoreError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    task::{JoinError, JoinSet},
    time,
};
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;
use url::Url;
use uuid::Uuid;

type ConnectionError = Box<dyn std::error::Error + Send + Sync>;

const SERVICE_NAME: &str = "api-reference";
const PROFILE: &str = "oauth-provider";
const MAX_PASSWORD_WORKER_CONCURRENCY: usize = 16;
const MAX_PASSWORD_WORKER_MEMORY_KIB: u64 = 1024 * 1024;
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
const SCHEMA: SchemaCompatibility = SchemaCompatibility {
    minimum: "2026082301",
    maximum: "2026082802",
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthConfig {
    session: SessionConfig,
    jwt: JwtConfig,
    password: PasswordConfig,
    registration: RegistrationConfig,
    api_key: ApiKeyApplicationConfig,
    authorization_server: AuthorizationServerConfig,
    oauth_rate_limit: OAuthRateLimitConfig,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthRateLimitConfig {
    authorize: OAuthRateLimitPolicyConfig,
    token: OAuthRateLimitPolicyConfig,
    register: OAuthRateLimitPolicyConfig,
    revoke: OAuthRateLimitPolicyConfig,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthRateLimitPolicyConfig {
    #[serde(with = "humantime_serde")]
    replenish_every: Duration,
    burst_size: u32,
    identity_buckets: u32,
}

impl OAuthRateLimitConfig {
    fn build(self) -> Result<OAuthRateLimiters, LocalRateLimitConfigError> {
        Ok(OAuthRateLimiters {
            authorize: self.authorize.build(RateLimitOperation::OAuthAuthorize)?,
            token: self.token.build(RateLimitOperation::OAuthToken)?,
            register: self
                .register
                .build(RateLimitOperation::OAuthClientRegistration)?,
            revoke: self.revoke.build(RateLimitOperation::OAuthRevoke)?,
        })
    }
}

impl OAuthRateLimitPolicyConfig {
    fn build(
        self,
        operation: RateLimitOperation,
    ) -> Result<LocalRateLimiter, LocalRateLimitConfigError> {
        LocalRateLimiter::new(
            operation,
            RateLimitIdentityKind::OAuthClientIp,
            LocalRateLimitPolicy {
                replenish_every: self.replenish_every,
                burst_size: self.burst_size,
                identity_buckets: self.identity_buckets,
            },
        )
    }
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
struct ApiKeyApplicationConfig {
    enabled: bool,
    pepper: SecretString,
    max_scopes: usize,
    #[serde(with = "humantime_serde")]
    max_key_lifetime: Duration,
    #[serde(with = "humantime_serde")]
    last_used_write_interval: Duration,
}

impl ApiKeyApplicationConfig {
    fn validate(&self) -> Result<(), StartupError> {
        if !self.enabled || !canonical_api_key_pepper(&self.pepper) {
            return Err(StartupError::ApiKeyPepper);
        }
        self.store_config().validate()?;
        Ok(())
    }

    fn build(self) -> Result<ApiKeyConfig, StartupError> {
        if !self.enabled || !canonical_api_key_pepper(&self.pepper) {
            return Err(StartupError::ApiKeyPepper);
        }
        let config = ApiKeyConfig {
            enabled: self.enabled,
            pepper: self.pepper,
            max_scopes: self.max_scopes,
            max_key_lifetime: self.max_key_lifetime,
            last_used_write_interval: self.last_used_write_interval,
        };
        config.validate()?;
        Ok(config)
    }

    fn store_config(&self) -> ApiKeyConfig {
        ApiKeyConfig {
            enabled: self.enabled,
            pepper: self.pepper.clone(),
            max_scopes: self.max_scopes,
            max_key_lifetime: self.max_key_lifetime,
            last_used_write_interval: self.last_used_write_interval,
        }
    }
}

fn canonical_api_key_pepper(pepper: &SecretString) -> bool {
    let source = pepper.expose_secret().as_bytes();
    let mut decoded = [0_u8; 33];
    let decoded_len = URL_SAFE_NO_PAD.decode_slice(source, &mut decoded).ok();
    let mut canonical = [0_u8; 44];
    let encoded_len = decoded_len.and_then(|length| {
        (length == 32)
            .then(|| {
                URL_SAFE_NO_PAD
                    .encode_slice(&decoded[..length], &mut canonical)
                    .ok()
            })
            .flatten()
    });
    let valid = encoded_len == Some(source.len()) && &canonical[..source.len()] == source;
    decoded.fill(0);
    canonical.fill(0);
    valid
}
fn validate_local_identity_provider(
    password_provider: &str,
    registration_provider: &str,
) -> Result<(), StartupError> {
    if password_provider != registration_provider {
        return Err(StartupError::LocalIdentityProviderMismatch);
    }
    if Url::parse(password_provider).is_ok()
        || password_provider.starts_with("//")
        || password_provider.contains("://")
    {
        return Err(StartupError::LocalIdentityProviderUrl);
    }
    Ok(())
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationConfig {
    mode: Option<RegistrationMode>,
    #[serde(default = "default_local_identity_provider")]
    local_identity_provider: String,
    #[serde(default = "default_invitation_ttl", with = "humantime_serde")]
    invitation_ttl: Duration,
    public_app_url: Option<Url>,
    invitation_token_pepper: SecretString,
    #[serde(default = "default_account_response_floor", with = "humantime_serde")]
    response_floor: Duration,
}

fn default_local_identity_provider() -> String {
    "email".to_owned()
}

const fn default_invitation_ttl() -> Duration {
    Duration::from_hours(168)
}

const fn default_account_response_floor() -> Duration {
    Duration::from_millis(500)
}

impl RegistrationConfig {
    fn policy_config(&self) -> RegistrationPolicyConfig {
        RegistrationPolicyConfig {
            mode: self.mode,
            local_identity_provider: self.local_identity_provider.clone(),
            invitation_ttl: self.invitation_ttl,
            public_app_url: self.public_app_url.clone(),
        }
    }

    fn validate(
        &self,
        deployment: DeploymentEnvironment,
        password_policy: &PasswordPolicy,
    ) -> Result<RegistrationPolicy, StartupError> {
        let policy = self
            .policy_config()
            .validate_for(deployment, password_policy)?;
        let _pepper = InvitationTokenPepper::parse(self.invitation_token_pepper.clone())?;
        if !(Duration::from_millis(500)..=Duration::from_secs(5)).contains(&self.response_floor) {
            return Err(StartupError::AccountResponseFloor);
        }
        Ok(policy)
    }

    fn build(
        self,
        deployment: DeploymentEnvironment,
        password_policy: &PasswordPolicy,
    ) -> Result<(RegistrationPolicy, InvitationTokenPepper, Duration), StartupError> {
        let policy = self
            .policy_config()
            .validate_for(deployment, password_policy)?;
        let pepper = InvitationTokenPepper::parse(self.invitation_token_pepper)?;
        if !(Duration::from_millis(500)..=Duration::from_secs(5)).contains(&self.response_floor) {
            return Err(StartupError::AccountResponseFloor);
        }
        Ok((policy, pepper, self.response_floor))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountEmailConfig {
    from: MailboxAddress,
    provider: EmailProviderConfig,
    templates: TemplateConfig,
    #[serde(default)]
    custom_headers: CustomHeaderPolicy,
    #[serde(default)]
    limits: EmailLimits,
}

impl AccountEmailConfig {
    fn into_email_config(self) -> (EmailConfig, MailboxAddress) {
        (
            EmailConfig {
                provider: self.provider,
                templates: self.templates,
                custom_headers: self.custom_headers,
                limits: self.limits,
            },
            self.from,
        )
    }

    fn validate_templates(&self) -> Result<(), StartupError> {
        let configured: BTreeSet<&str> = self
            .templates
            .allowed_templates
            .iter()
            .map(omnius_email::TemplateName::as_str)
            .collect();
        let required: BTreeSet<&str> = AccountMailPresentation::required_templates()
            .into_iter()
            .collect();
        if configured != required {
            return Err(StartupError::AccountEmailTemplates);
        }
        Ok(())
    }
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

    fn policy(&self) -> Result<PasswordPolicy, StartupError> {
        let active_pepper = PasswordPepper::new(self.pepper.version, self.pepper.secret.clone())?;
        PasswordPolicy::new(self.policy, active_pepper, Vec::new())
            .map_err(StartupError::PasswordPolicy)
    }

    fn validate(&self) -> Result<PasswordPolicy, StartupError> {
        let _max_concurrency = self.worker_concurrency()?;
        let policy = self.policy()?;
        let _provider = PasswordLoginProvider::new(self.login_provider.clone())?;
        Ok(policy)
    }

    fn build(
        self,
    ) -> Result<(PasswordWorker, PasswordLoginProvider, PasswordPolicy), StartupError> {
        let max_concurrency = self.worker_concurrency()?;
        let policy = self.policy()?;
        let login_provider = PasswordLoginProvider::new(self.login_provider)?;
        let worker = PasswordWorker::new(PasswordEngine::new(policy.clone())?, max_concurrency);
        Ok((worker, login_provider, policy))
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
        self.tenancy.validate()?;
        if !self.tenancy.enabled {
            return Err(TenancyStoreError::Disabled.into());
        }
        if !self.auth.session.enabled {
            return Err(SessionConfigError::Disabled.into());
        }
        self.auth.session.validate_for(environment.deployment())?;
        if self.auth.jwt.enabled {
            self.auth.jwt.validate_for(environment.deployment())?;
        }
        let authorization_server = self
            .auth
            .authorization_server
            .build_for(environment.deployment(), ::time::OffsetDateTime::now_utc())?
            .ok_or(StartupError::AuthorizationServerDisabled)?;
        let public_app_url = self
            .auth
            .registration
            .public_app_url
            .as_ref()
            .ok_or(StartupError::AuthorizationUiOrigin)?;
        let issuer = Url::parse(authorization_server.issuer().as_str())
            .map_err(|_| StartupError::AuthorizationUiOrigin)?;
        if public_app_url.origin() != issuer.origin() {
            return Err(StartupError::AuthorizationUiOrigin);
        }
        let _oauth_rate_limits = self.auth.oauth_rate_limit.build()?;
        self.auth.api_key.validate()?;
        let password_policy = self.auth.password.validate()?;
        let _registration = self
            .auth
            .registration
            .validate(environment.deployment(), &password_policy)?;
        validate_local_identity_provider(
            &self.auth.password.login_provider,
            &self.auth.registration.local_identity_provider,
        )?;
        self.email.validate_templates()?;
        let _mail = AccountMailPresentation::new(self.email.from.clone())?;
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
    #[error("API-key configuration failed: {0}")]
    ApiKeyConfig(#[from] ApiKeyConfigError),
    #[error("API-key pepper must be canonical unpadded base64url encoding of exactly 32 bytes")]
    ApiKeyPepper,
    #[error("API-key store construction failed: {0}")]
    ApiKeyStore(#[from] ApiKeyStoreError),
    #[error("API-key management policy construction failed: {0}")]
    ApiKeyManagement(#[from] ApiKeyManagementBuildError),
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
    #[error("account registration policy configuration failed: {0}")]
    RegistrationPolicy(#[from] RegistrationPolicyError),
    #[error("registration invitation secret configuration failed: {0}")]
    InvitationToken(#[from] InvitationTokenError),
    #[error("account discovery response floor is invalid")]
    AccountResponseFloor,
    #[error("account email configuration or delivery failed: {0}")]
    AccountEmail(#[from] EmailError),
    #[error("account email template allowlist must contain exactly the three account templates")]
    AccountEmailTemplates,
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
    #[error("registration identity provider must exactly match the password login provider")]
    LocalIdentityProviderMismatch,
    #[error("local identity provider namespaces must not be URL-shaped")]
    LocalIdentityProviderUrl,
    #[error("browser tenancy configuration failed: {0}")]
    Tenancy(#[from] TenancyConfigError),
    #[error("browser tenancy store composition failed: {0}")]
    TenancyStore(#[from] TenancyStoreError),
    #[error("browser session configuration failed: {0}")]
    SessionConfig(#[from] SessionConfigError),
    #[error("authenticated identity composition failed: {0}")]
    IdentityComposition(#[from] AuthenticatedIdentityBuildError),
    #[error("JWT verifier configuration failed: {0}")]
    JwtConfig(#[from] JwtConfigError),
    #[error("JWT verifier initialization failed: {0}")]
    Jwt(#[from] JwtBuildError),
    #[error("authorization-server configuration failed: {0}")]
    AuthorizationServerConfig(#[from] AuthorizationServerConfigError),
    #[error("authorization-server composition failed: {0}")]
    OAuthProvider(#[from] OAuthProviderBuildError),
    #[error("authorization-server rate-limit configuration failed: {0}")]
    OAuthRateLimit(#[from] LocalRateLimitConfigError),
    #[error("oauth-provider profile requires the authorization server to be enabled")]
    AuthorizationServerDisabled,
    #[error("authorization UI origin must exactly match the configured issuer origin")]
    AuthorizationUiOrigin,
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
            Self::Idempotency(_) => "STARTUP_IDEMPOTENCY",
            Self::Pagination(_) => "STARTUP_PAGINATION",
            Self::OpenApi(_) => "STARTUP_OPENAPI",
            Self::OutboundConfig(_) | Self::OutboundBuild(_) => "STARTUP_OUTBOUND_HTTP",
            Self::PasswordPolicy(_)
            | Self::Password(_)
            | Self::PasswordWorkerConcurrency
            | Self::PasswordLoginProvider(_)
            | Self::BrowserAuthorizationIdentifier(_)
            | Self::BrowserAuthorizationPolicy(_)
            | Self::BrowserAuth(_)
            | Self::SessionConfig(_)
            | Self::IdentityComposition(_) => "STARTUP_BROWSER_AUTH",
            Self::RegistrationPolicy(_)
            | Self::InvitationToken(_)
            | Self::AccountResponseFloor
            | Self::AccountEmail(_)
            | Self::AccountEmailTemplates
            | Self::AccountAuth(_)
            | Self::AccountMailDelivery
            | Self::LocalIdentityProviderMismatch
            | Self::LocalIdentityProviderUrl => "STARTUP_ACCOUNT_AUTH",
            Self::RegistrationInviteMode
            | Self::RegistrationInviteInput
            | Self::RegistrationInviteDatabase
            | Self::RegistrationInviteStore(_)
            | Self::RegistrationInviteTimestamp => "REGISTRATION_INVITATION",
            Self::ApiKeyConfig(_)
            | Self::ApiKeyPepper
            | Self::ApiKeyStore(_)
            | Self::ApiKeyManagement(_) => "STARTUP_API_KEY",
            Self::Tenancy(_) | Self::TenancyStore(_) => "STARTUP_TENANCY",
            Self::JwtConfig(_) | Self::Jwt(_) => "STARTUP_JWT",
            Self::AuthorizationServerConfig(_)
            | Self::OAuthProvider(_)
            | Self::OAuthRateLimit(_)
            | Self::AuthorizationServerDisabled
            | Self::AuthorizationUiOrigin => "STARTUP_OAUTH_PROVIDER",
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
    validate_local_identity_provider(
        &config.auth.password.login_provider,
        &config.auth.registration.local_identity_provider,
    )?;
    let (password_worker, _login_provider, password_policy) = config.auth.password.build()?;
    let (registration, invitation_pepper, response_floor) = config
        .auth
        .registration
        .build(deployment, &password_policy)?;
    if registration.mode() != RegistrationMode::InviteOnly {
        return Err(StartupError::RegistrationInviteMode);
    }
    let (email, mail) = build_account_email(config.email, deployment)?;
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
        let adapter = build_oauth_admin_adapter(OAuthAdminAdapterInput {
            config: Arc::new(validated),
            pool: pool.clone(),
            outbound_http: Arc::new(OutboundHttpClients::new(&config.outbound_http)?),
            session_config: config.auth.session,
            local_identity_provider: config.auth.registration.local_identity_provider,
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
        let adapter = build_oauth_admin_adapter(OAuthAdminAdapterInput {
            config: Arc::new(validated),
            pool: pool.clone(),
            outbound_http: Arc::new(OutboundHttpClients::new(&config.outbound_http)?),
            session_config: config.auth.session,
            local_identity_provider: config.auth.registration.local_identity_provider,
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
    config
        .auth
        .authorization_server
        .build_for(deployment, ::time::OffsetDateTime::now_utc())?
        .ok_or(StartupError::AuthorizationServerDisabled)
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

struct BrowserRuntime {
    routes: Router,
    email: EmailService,
    oauth_cleanup_task: TaskSpec,
}

struct BrowserRuntimeInputs {
    pool: PostgresPool,
    session_config: SessionConfig,
    jwt_verifier: Option<JwtVerifier>,
    authorization_server: ValidatedAuthorizationServerConfig,
    outbound_http: Arc<OutboundHttpClients>,
    oauth_rate_limits: OAuthRateLimiters,
    api_key_config: ApiKeyApplicationConfig,
    password_config: PasswordConfig,
    registration_config: RegistrationConfig,
    email_config: AccountEmailConfig,
    trusted_origins: Vec<String>,
    idempotency_config: IdempotencyConfig,
    pagination_config: PaginationConfig,
    tenancy_config: TenancyConfig,
    deployment: DeploymentEnvironment,
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

struct ProtectedRouteComponents {
    api_key_store: ApiKeyStore,
    api_key_management: ApiKeyManagementState,
    tenancy_routes: Router,
    cursor_codec: CursorCodec,
}

impl ProtectedRouteComponents {
    fn build(
        pool: &PostgresPool,
        api_key_config: ApiKeyApplicationConfig,
        tenancy_config: &TenancyConfig,
        pagination_config: &PaginationConfig,
    ) -> Result<Self, StartupError> {
        let api_key_config = api_key_config.build()?;
        let api_key_store = ApiKeyStore::new(pool.clone(), &api_key_config)?;
        let tenancy_store = TenancyStore::new(pool.clone(), tenancy_config)?;
        let tenancy_routes =
            browser_tenancy_router(BrowserTenancyState::new(tenancy_store.clone()));
        let cursor_codec = CursorCodec::new(cursor_signing_key(pagination_config)?);
        let api_key_management =
            ApiKeyManagementState::new(api_key_store.clone(), tenancy_store, cursor_codec.clone())?;
        Ok(Self {
            api_key_store,
            api_key_management,
            tenancy_routes,
            cursor_codec,
        })
    }
}

fn build_browser_runtime(inputs: BrowserRuntimeInputs) -> Result<BrowserRuntime, StartupError> {
    let BrowserRuntimeInputs {
        pool,
        session_config,
        jwt_verifier,
        authorization_server,
        outbound_http,
        oauth_rate_limits,
        api_key_config,
        password_config,
        registration_config,
        email_config,
        trusted_origins,
        idempotency_config,
        pagination_config: pagination,
        tenancy_config: tenancy,
        deployment,
    } = inputs;
    validate_local_identity_provider(
        &password_config.login_provider,
        &registration_config.local_identity_provider,
    )?;
    let protected = ProtectedRouteComponents::build(&pool, api_key_config, &tenancy, &pagination)?;
    let authorization_ui = registration_config
        .public_app_url
        .clone()
        .ok_or(StartupError::AuthorizationUiOrigin)?;
    let local_identity_provider = registration_config.local_identity_provider.clone();
    let (password_worker, login_provider, password_policy) = password_config.build()?;
    let (registration, invitation_pepper, response_floor) =
        registration_config.build(deployment, &password_policy)?;
    let (email, mail) = build_account_email(email_config, deployment)?;
    let auth_state = BrowserAuthState::new(
        pool.clone(),
        session_config.clone(),
        password_worker.clone(),
        login_provider,
        build_browser_authorization()?,
        trusted_origins.clone(),
    );
    let OAuthProviderRuntime {
        routes: oauth_routes,
        resource_verifier,
        cleanup_task: oauth_cleanup_task,
        adapter: _oauth_adapter,
    } = build_oauth_provider(OAuthProviderBuildInput {
        config: authorization_server,
        pool: pool.clone(),
        outbound_http,
        session_config: session_config.clone(),
        browser_auth: auth_state.clone(),
        local_identity_provider,
        authorization_ui,
        deployment,
        rate_limits: oauth_rate_limits,
    })?;
    let principal_state = CanonicalPrincipalState::new(
        pool.clone(),
        session_config.clone(),
        jwt_verifier,
        Some(protected.api_key_store),
    )
    .with_trusted_origins(trusted_origins)
    .with_oauth_resource_verifier(resource_verifier);
    let account_state = AccountAuthState::new(AccountAuthStateInput {
        pool: pool.clone(),
        session_config,
        password_worker,
        registration,
        invitation_pepper,
        response_floor,
        email: email.clone(),
        mail,
    })?;
    let invitation_routes = account_invitation_router(account_state.clone());
    let account_routes = account_auth_router(account_state, &auth_state, deployment)?;
    let reference_state = ReferenceApiState::new(
        pool,
        protected.cursor_codec,
        PostgresIdempotencyStore::new(idempotency_config)?,
        Arc::new(SystemClock),
    );
    let protected_routes = protected_principal_router(
        principal_state,
        deployment,
        canonical_identity_route()
            .merge(api_key_management_router(protected.api_key_management))
            .merge(invitation_routes)
            .merge(protected.tenancy_routes)
            .merge(reference_router(reference_state)),
    )?;
    let routes = browser_auth_router(auth_state, deployment)?
        .merge(account_routes)
        .merge(oauth_routes)
        .merge(protected_routes);
    Ok(BrowserRuntime {
        routes,
        email,
        oauth_cleanup_task,
    })
}

fn build_account_email(
    config: AccountEmailConfig,
    deployment: DeploymentEnvironment,
) -> Result<(EmailService, AccountMailPresentation), StartupError> {
    config.validate_templates()?;
    let (config, from) = config.into_email_config();
    let service = EmailService::build(config, deployment)?;
    let presentation = AccountMailPresentation::new(from)?;
    Ok((service, presentation))
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
        .merge(metadata_router())
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
    let authorization_server = validated_authorization_server(&config, deployment)?;
    let oauth_rate_limits = config.auth.oauth_rate_limit.build()?;
    let outbound_clients = Arc::new(outbound_clients);
    let jwt_verifier = if config.auth.jwt.enabled {
        Some(
            JwtVerifier::initialize(
                &config.auth.jwt,
                deployment,
                outbound_clients.as_ref().clone(),
            )
            .await?,
        )
    } else {
        None
    };

    let health = build_health_service(&config, &pool, static_delivery.as_ref())?;
    let http_composition = build_http_composition(&config, &health, static_delivery)?;
    let trusted_origins = config.http.trusted_origins.clone();
    let BrowserRuntime {
        routes,
        email,
        oauth_cleanup_task,
    } = build_browser_runtime(BrowserRuntimeInputs {
        pool: pool.clone(),
        session_config: config.auth.session,
        jwt_verifier,
        authorization_server,
        outbound_http: Arc::clone(&outbound_clients),
        oauth_rate_limits,
        api_key_config: config.auth.api_key,
        password_config: config.auth.password,
        registration_config: config.auth.registration,
        email_config: config.email,
        trusted_origins,
        idempotency_config: config.idempotency,
        pagination_config: config.pagination,
        tenancy_config: config.tenancy,
        deployment,
    })?;
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
    let listener = TcpListener::bind(listen_address)
        .await
        .map_err(|_| StartupError::Bind)?;
    let bound_address = listener.local_addr().map_err(|_| StartupError::Bind)?;
    let mut signals = TerminationSignals::new().map_err(|_| StartupError::Signal)?;

    let mut supervisor = Supervisor::new();
    supervisor.register(health.supervised_refresh_task())?;
    supervisor.register(oauth_cleanup_task)?;
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
    let connection =
        builder.serve_connection_with_upgrades(TokioIo::new(stream), TowerToHyperService::new(app));
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
mod composition_tests {
    use super::*;

    #[test]
    fn api_key_pepper_accepts_canonical_256_bit_base64url() {
        assert!(canonical_api_key_pepper(&SecretString::from(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        )));
    }

    #[test]
    fn production_registration_requires_explicit_mode_and_https_public_url()
    -> Result<(), Box<dyn std::error::Error>> {
        let password_policy = PasswordPolicy::default_unpeppered()?;
        let omitted_mode: RegistrationConfig = serde_json::from_str(
            r#"{
                "local_identity_provider":"email",
                "invitation_ttl":"7d",
                "public_app_url":"https://app.example.test",
                "invitation_token_pepper":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }"#,
        )?;
        assert!(matches!(
            omitted_mode.validate(DeploymentEnvironment::Production, &password_policy),
            Err(StartupError::RegistrationPolicy(
                RegistrationPolicyError::ProductionModeRequired
            ))
        ));

        let insecure_url: RegistrationConfig = serde_json::from_str(
            r#"{
                "mode":"invite_only",
                "local_identity_provider":"email",
                "invitation_ttl":"7d",
                "public_app_url":"http://app.example.test",
                "invitation_token_pepper":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }"#,
        )?;
        assert!(matches!(
            insecure_url.validate(DeploymentEnvironment::Production, &password_policy),
            Err(StartupError::RegistrationPolicy(
                RegistrationPolicyError::InvalidPublicAppUrl
            ))
        ));
        Ok(())
    }

    #[test]
    fn registration_configuration_rejects_unknown_fields_and_invalid_secret()
    -> Result<(), Box<dyn std::error::Error>> {
        let unknown = serde_json::from_str::<RegistrationConfig>(
            r#"{
                "mode":"disabled",
                "local_identity_provider":"email",
                "invitation_ttl":"7d",
                "public_app_url":"https://app.example.test",
                "invitation_token_pepper":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "fallback_mode":"self_service"
            }"#,
        );
        assert!(unknown.is_err());
        let invalid: RegistrationConfig = serde_json::from_str(
            r#"{
                "mode":"disabled",
                "local_identity_provider":"email",
                "invitation_ttl":"7d",
                "public_app_url":"https://app.example.test",
                "invitation_token_pepper":"not-a-secret"
            }"#,
        )?;
        assert!(matches!(
            invalid.validate(
                DeploymentEnvironment::Test,
                &PasswordPolicy::default_unpeppered()?
            ),
            Err(StartupError::InvitationToken(_))
        ));
        Ok(())
    }
    #[test]
    fn api_key_configuration_requires_enabled_canonical_256_bit_pepper_and_strict_bounds()
    -> Result<(), Box<dyn std::error::Error>> {
        let valid: ApiKeyApplicationConfig = serde_json::from_str(
            r#"{
                "enabled":true,
                "pepper":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "max_scopes":32,
                "max_key_lifetime":"90d",
                "last_used_write_interval":"5m"
            }"#,
        )?;
        assert!(valid.validate().is_ok());

        let padded: ApiKeyApplicationConfig = serde_json::from_str(
            r#"{
                "enabled":true,
                "pepper":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "max_scopes":32,
                "max_key_lifetime":"90d",
                "last_used_write_interval":"5m"
            }"#,
        )?;
        assert!(matches!(padded.validate(), Err(StartupError::ApiKeyPepper)));

        let disabled: ApiKeyApplicationConfig = serde_json::from_str(
            r#"{
                "enabled":false,
                "pepper":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "max_scopes":32,
                "max_key_lifetime":"90d",
                "last_used_write_interval":"5m"
            }"#,
        )?;
        assert!(matches!(
            disabled.validate(),
            Err(StartupError::ApiKeyPepper)
        ));

        let unknown = serde_json::from_str::<ApiKeyApplicationConfig>(
            r#"{
                "enabled":true,
                "pepper":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "max_scopes":32,
                "max_key_lifetime":"90d",
                "last_used_write_interval":"5m",
                "legacy_overlap":"1h"
            }"#,
        );
        assert!(unknown.is_err());
        Ok(())
    }

    #[test]
    fn local_identity_provider_must_match_and_must_not_be_url_shaped() {
        assert!(validate_local_identity_provider("email", "email").is_ok());
        assert!(matches!(
            validate_local_identity_provider("email", "local-email"),
            Err(StartupError::LocalIdentityProviderMismatch)
        ));
        for provider in [
            "https://identity.example.test",
            "mailto:accounts@example.test",
            "//identity.example.test",
        ] {
            assert!(matches!(
                validate_local_identity_provider(provider, provider),
                Err(StartupError::LocalIdentityProviderUrl)
            ));
        }
    }
}
