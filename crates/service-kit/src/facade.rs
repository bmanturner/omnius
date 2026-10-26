//! Facade modules re-exporting selected provider APIs for generated process glue.

/// Configuration loading APIs used by generated process glue.
pub mod config {
    pub use omnius_config::{ConfigLoadError, ConfigLoader, DeploymentEnvironment, SecretString};
}

/// Health lifecycle APIs used by generated process glue.
pub mod health {
    pub use omnius_health::{HealthBuilder, HealthConfig, HealthService};
}

/// HTTP shell APIs used by generated process glue.
#[cfg(feature = "http")]
pub mod http {
    pub use omnius_http::{
        ConditionalHeaderError, FieldError, HttpShell, HttpShellConfig, IfMatch, ProblemDetails,
        StaticDelivery, StaticDeliveryConfig, VersionEtag,
    };

    /// HTTP server lifecycle APIs used by generated process glue.
    pub mod server {
        pub use omnius_http::server::{
            ConnectionMode, HttpServer, HttpServerConfig, PeerAddressMode,
        };
    }
}

/// Runtime supervision APIs used by generated process glue.
pub mod runtime {
    pub use omnius_runtime::{RegisterError, StartError, Supervisor, TaskSpec, TerminationSignals};
}

/// Telemetry lifecycle APIs used by generated process glue.
#[cfg(feature = "telemetry")]
pub mod telemetry {
    pub use omnius_telemetry::{TelemetryConfig, TelemetryError, TelemetryGuard, bootstrap};
}

#[cfg(feature = "idempotency")]
pub mod idempotency {
    //! Selected idempotency provider API.

    pub use omnius_idempotency::{
        ClaimOutcome, IdempotencyConfig, IdempotencyConfigError, IdempotencyKey,
        IdempotencyKeyError, IdempotencyOperation, IdempotencyOperationError, IdempotencyRequest,
        IdempotencyScope, IdempotencyScopeValue, IdempotencyScopeValueError, IdempotencyStoreError,
        PostgresIdempotencyStore, RequestFingerprint, RequestFingerprintError, SafeResponse,
        SafeResponseError,
    };
}

/// Outbound HTTP client policy exposed to application factories and tests.
#[cfg(feature = "outbound-http")]
pub mod outbound_http {
    pub use omnius_outbound_http::{
        ApprovedUrl, BoundedResponse, BuildError, ConfigError, HeaderMap, Method,
        OutboundByteStream, OutboundHttpClients, OutboundHttpConfig, OutboundHttpError,
        OutboundRequest, OutboundRequestBuilder, OutboundResponse, OutboundUrlPolicy,
        OutboundUrlPolicyConfig, PolicyClass, ProxyPolicy, Resolver, ResolverError, ResolverFuture,
        StatusCode, StreamingResponse, SystemResolver, Url,
    };
}

/// Authentication primitives exposed to application-owned handlers.
#[cfg(feature = "auth-core")]
pub mod auth {
    #[cfg(feature = "test-support")]
    pub use omnius_auth_core::testing;
    pub use omnius_auth_core::{
        AssuranceLevel, AuthMethod, IdentityIdError, Principal, PrincipalError, PrincipalKind,
        Scope, ScopeError, SessionCleanup, SessionConfig, SessionConfigError, SessionMetadata,
        SessionRegistration, SessionSameSite, SessionStoreKind, SessionValidation, SubjectId,
        TenantId, hash_user_agent,
    };
}

/// Reusable authenticated HTTP composition exposed to application factories.
#[cfg(feature = "auth-http")]
pub mod auth_http {
    #[cfg(feature = "auth-api-key")]
    pub use omnius_auth_http::{
        API_KEY_MANAGEMENT_OPERATIONS, API_KEY_MANAGEMENT_ROUTE_IDS, ApiKeyApplicationConfig,
        api_key_management_openapi_contribution,
    };
    pub use omnius_auth_http::{
        AUTH_HTTP_OPERATIONS, AccountEmailConfig, AuthenticatedHttpBuildError,
        AuthenticatedHttpConfig, AuthenticatedHttpConfigError, AuthenticatedHttpInput,
        AuthenticatedHttpRuntime, AuthenticatedHttpRuntimeParts, PasswordConfig,
        PasswordPepperConfig, RegistrationConfig, RegistrationMode, auth_http_operations_for,
        auth_openapi_contribution, auth_openapi_contribution_for, build_authenticated_http,
    };
    pub use omnius_auth_http::{account_auth, api_key_auth, browser_auth};
}

/// `OpenAPI` composition and validation APIs exposed to application contracts.
#[cfg(feature = "openapi")]
pub mod openapi {
    pub use omnius_openapi::{
        BreakingChange, BreakingChangeKind, DEFAULT_MAX_DOCUMENT_BYTES, ExpectedOperation,
        MAX_DOCUMENT_BYTES, OPENAPI_DOCS_PATH, OPENAPI_DOCUMENT_PATH, OpenApiCatalog,
        OpenApiConfig, OpenApiDiffError, OpenApiError, breaking_changes, deterministic_json,
        deterministic_json_value, validate_document, validate_json_value,
        validate_operation_coverage, validate_operation_coverage_value,
    };
}

#[cfg(feature = "migrations")]
pub mod migrations {
    //! Selected migration provider API.

    pub use omnius_migrations::{
        APPLICATION_MIGRATION_MAXIMUM, APPLICATION_MIGRATION_MINIMUM, ApplicationMigrations,
        CURRENT_SCHEMA_VERSION, FRAMEWORK_SCHEMA_HEAD, FRAMEWORK_SCHEMA_MINIMUM, MIGRATOR,
        MigrationCommand, MigrationCommandOutput, MigrationConfig, MigrationConfigError,
        MigrationError, MigrationRunner, MigrationStatus, Migrator, PreparedMigrations,
        SchemaVersionRange, framework_schema_compatibility, prepare_migrations,
    };
    pub use omnius_migrations_macros::migrate;
}

#[doc(hidden)]
#[cfg(feature = "migrations")]
pub mod migrate {
    //! SQLx migration types used by the hygienic embedding macro.

    pub use sqlx::migrate::{MigrateError, Migration, MigrationSource, MigrationType, Migrator};
}

#[cfg(feature = "postgres")]
pub mod postgres {
    //! Selected PostgreSQL provider API.

    pub use omnius_postgres::{
        PostgresConfig, PostgresConfigError, PostgresConnection, PostgresError, PostgresPool,
        PostgresPoolStats, PostgresTlsMode, PostgresTransactionRunner, RetryableSqlState,
        RetryableTransactionError, TransactionIsolation, TransactionRetryConfig,
        TransactionRetryConfigError, TransactionRunError, sqlx,
    };
}

#[cfg(feature = "test-support")]
pub mod test_support {
    //! Selected integration-test support API.

    pub use omnius_test_support::{
        CleanDirectory, ContainerFixtureError, DeterministicRandom, MinioFixture,
        NatsCoreFanoutRoleFixture, NatsFixture, NatsRoleFixture, PostgresFixture,
        PrincipalMismatch, ProfileCommand, ProfileGenerationHarness, ProfileHarnessError,
        ProviderFake, ProviderFakeError, ProviderMock, ProviderMockGuard, ProviderRequest,
        ProviderResponse, RedisFixture, TEST_PROFILE_ENV, TestClient, TestClock, TestClockError,
        TestConfigBuilder, TestIdError, TestIds, TestPrincipalFactory, TestServer, TestServerError,
        ensure_principal_matches, provider_matchers,
    };
}
