//! Generated canonical module contracts and feature-gated dispatch.
//!
//! Regenerate with `cargo xtask specs generate`; do not edit by hand.

/// Closed application-owned requirements accepted by the module graph.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApplicationRequirement {
    /// `admin.authority-resolver`.
    AdminAuthorityResolver,
    /// `admin.operation-handler`.
    AdminOperationHandler,
    /// `auth.authenticated-runtime`.
    AuthAuthenticatedRuntime,
    /// `auth.redis-session-runtime`.
    AuthRedisSessionRuntime,
    /// `auth-oidc.runtime`.
    AuthOidcRuntime,
    /// `auth.oauth-runtime`.
    AuthOauthRuntime,
    /// `auth-webauthn.runtime`.
    AuthWebAuthnRuntime,
    /// `auth-totp.runtime`.
    AuthTotpRuntime,
    /// `billing.provider`.
    BillingProvider,
    /// `feature-flags.exposure-recorder`.
    FeatureFlagsExposureRecorder,
    /// `feature-flags.provider`.
    FeatureFlagsProvider,
    /// `graphql.request-data-injector`.
    GraphqlRequestDataInjector,
    /// `graphql.schema`.
    GraphqlSchema,
    /// `grpc.application-service`.
    GrpcApplicationService,
    /// `grpc.authenticator`.
    GrpcAuthenticator,
    /// `grpc.method-policies`.
    GrpcMethodPolicies,
    /// `inbox.consumers`.
    InboxConsumers,
    /// `jobs.handlers`.
    JobsHandlers,
    /// `llm.evaluation-repository`.
    LlmEvaluationRepository,
    /// `llm.media-authorization`.
    LlmMediaAuthorization,
    /// `llm.media-scanner`.
    LlmMediaScanner,
    /// `llm.tool-audit`.
    LlmToolAudit,
    /// `llm.tool-authorization`.
    LlmToolAuthorization,
    /// `mcp.apps-ports`.
    McpAppsPorts,
    /// `mcp.bearer-authenticator`.
    McpBearerAuthenticator,
    /// `mcp.cancellation-runtime`.
    McpCancellationRuntime,
    /// `mcp.capability-executor`.
    McpCapabilityExecutor,
    /// `mcp.capability-registry`.
    McpCapabilityRegistry,
    /// `mcp.enterprise-ports`.
    McpEnterprisePorts,
    /// `mcp.subscription-authorizer`.
    McpSubscriptionAuthorizer,
    /// `mcp.subscription-delivery`.
    McpSubscriptionDelivery,
    /// `mcp.subscription-repository`.
    McpSubscriptionRepository,
    /// `mcp.subscription-runtime`.
    McpSubscriptionRuntime,
    /// `mcp.task-payload-protector`.
    McpTaskPayloadProtector,
    /// `outbox.publisher`.
    OutboxPublisher,
    /// `privacy.authorizer`.
    PrivacyAuthorizer,
    /// `privacy.consent-policy`.
    PrivacyConsentPolicy,
    /// `privacy.inventory-adapters`.
    PrivacyInventoryAdapters,
    /// `privacy.inventory-manifest`.
    PrivacyInventoryManifest,
    /// `privacy.lifecycle-handler`.
    PrivacyLifecycleHandler,
    /// `privacy.moderation-policy`.
    PrivacyModerationPolicy,
    /// `realtime.event-handler`.
    RealtimeEventHandler,
    /// `realtime.fanout-authorizer`.
    RealtimeFanoutAuthorizer,
    /// `realtime.identity-revalidator`.
    RealtimeIdentityRevalidator,
    /// `scheduler.envelope-factory`.
    SchedulerEnvelopeFactory,
    /// `search.index-schema`.
    SearchIndexSchema,
    /// `search.projection-resolver`.
    SearchProjectionResolver,
    /// `search.reauthorizer`.
    SearchReauthorizer,
    /// `uploads.authorization`.
    UploadsAuthorization,
    /// `uploads.workflow`.
    UploadsWorkflow,
    /// `webhooks-inbound.handlers`.
    WebhooksInboundHandlers,
    /// `webhooks-inbound.provider-adapters`.
    WebhooksInboundProviderAdapters,
    /// `webhooks-svix.replay-admission`.
    WebhooksSvixReplayAdmission,
}

impl ApplicationRequirement {
    /// Every application requirement accepted by the module graph.
    pub const ALL: &[Self] = &[
        Self::AdminAuthorityResolver,
        Self::AdminOperationHandler,
        Self::AuthAuthenticatedRuntime,
        Self::AuthRedisSessionRuntime,
        Self::AuthOidcRuntime,
        Self::AuthOauthRuntime,
        Self::AuthWebAuthnRuntime,
        Self::AuthTotpRuntime,
        Self::BillingProvider,
        Self::FeatureFlagsExposureRecorder,
        Self::FeatureFlagsProvider,
        Self::GraphqlRequestDataInjector,
        Self::GraphqlSchema,
        Self::GrpcApplicationService,
        Self::GrpcAuthenticator,
        Self::GrpcMethodPolicies,
        Self::InboxConsumers,
        Self::JobsHandlers,
        Self::LlmEvaluationRepository,
        Self::LlmMediaAuthorization,
        Self::LlmMediaScanner,
        Self::LlmToolAudit,
        Self::LlmToolAuthorization,
        Self::McpAppsPorts,
        Self::McpBearerAuthenticator,
        Self::McpCancellationRuntime,
        Self::McpCapabilityExecutor,
        Self::McpCapabilityRegistry,
        Self::McpEnterprisePorts,
        Self::McpSubscriptionAuthorizer,
        Self::McpSubscriptionDelivery,
        Self::McpSubscriptionRepository,
        Self::McpSubscriptionRuntime,
        Self::McpTaskPayloadProtector,
        Self::OutboxPublisher,
        Self::PrivacyAuthorizer,
        Self::PrivacyConsentPolicy,
        Self::PrivacyInventoryAdapters,
        Self::PrivacyInventoryManifest,
        Self::PrivacyLifecycleHandler,
        Self::PrivacyModerationPolicy,
        Self::RealtimeEventHandler,
        Self::RealtimeFanoutAuthorizer,
        Self::RealtimeIdentityRevalidator,
        Self::SchedulerEnvelopeFactory,
        Self::SearchIndexSchema,
        Self::SearchProjectionResolver,
        Self::SearchReauthorizer,
        Self::UploadsAuthorization,
        Self::UploadsWorkflow,
        Self::WebhooksInboundHandlers,
        Self::WebhooksInboundProviderAdapters,
        Self::WebhooksSvixReplayAdmission,
    ];

    /// Returns the canonical diagnostic identifier.
    #[must_use = "use the canonical identifier when reporting this requirement"]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AdminAuthorityResolver => "admin.authority-resolver",
            Self::AdminOperationHandler => "admin.operation-handler",
            Self::AuthAuthenticatedRuntime => "auth.authenticated-runtime",
            Self::AuthRedisSessionRuntime => "auth.redis-session-runtime",
            Self::AuthOidcRuntime => "auth-oidc.runtime",
            Self::AuthOauthRuntime => "auth.oauth-runtime",
            Self::AuthWebAuthnRuntime => "auth-webauthn.runtime",
            Self::AuthTotpRuntime => "auth-totp.runtime",
            Self::BillingProvider => "billing.provider",
            Self::FeatureFlagsExposureRecorder => "feature-flags.exposure-recorder",
            Self::FeatureFlagsProvider => "feature-flags.provider",
            Self::GraphqlRequestDataInjector => "graphql.request-data-injector",
            Self::GraphqlSchema => "graphql.schema",
            Self::GrpcApplicationService => "grpc.application-service",
            Self::GrpcAuthenticator => "grpc.authenticator",
            Self::GrpcMethodPolicies => "grpc.method-policies",
            Self::InboxConsumers => "inbox.consumers",
            Self::JobsHandlers => "jobs.handlers",
            Self::LlmEvaluationRepository => "llm.evaluation-repository",
            Self::LlmMediaAuthorization => "llm.media-authorization",
            Self::LlmMediaScanner => "llm.media-scanner",
            Self::LlmToolAudit => "llm.tool-audit",
            Self::LlmToolAuthorization => "llm.tool-authorization",
            Self::McpAppsPorts => "mcp.apps-ports",
            Self::McpBearerAuthenticator => "mcp.bearer-authenticator",
            Self::McpCancellationRuntime => "mcp.cancellation-runtime",
            Self::McpCapabilityExecutor => "mcp.capability-executor",
            Self::McpCapabilityRegistry => "mcp.capability-registry",
            Self::McpEnterprisePorts => "mcp.enterprise-ports",
            Self::McpSubscriptionAuthorizer => "mcp.subscription-authorizer",
            Self::McpSubscriptionDelivery => "mcp.subscription-delivery",
            Self::McpSubscriptionRepository => "mcp.subscription-repository",
            Self::McpSubscriptionRuntime => "mcp.subscription-runtime",
            Self::McpTaskPayloadProtector => "mcp.task-payload-protector",
            Self::OutboxPublisher => "outbox.publisher",
            Self::PrivacyAuthorizer => "privacy.authorizer",
            Self::PrivacyConsentPolicy => "privacy.consent-policy",
            Self::PrivacyInventoryAdapters => "privacy.inventory-adapters",
            Self::PrivacyInventoryManifest => "privacy.inventory-manifest",
            Self::PrivacyLifecycleHandler => "privacy.lifecycle-handler",
            Self::PrivacyModerationPolicy => "privacy.moderation-policy",
            Self::RealtimeEventHandler => "realtime.event-handler",
            Self::RealtimeFanoutAuthorizer => "realtime.fanout-authorizer",
            Self::RealtimeIdentityRevalidator => "realtime.identity-revalidator",
            Self::SchedulerEnvelopeFactory => "scheduler.envelope-factory",
            Self::SearchIndexSchema => "search.index-schema",
            Self::SearchProjectionResolver => "search.projection-resolver",
            Self::SearchReauthorizer => "search.reauthorizer",
            Self::UploadsAuthorization => "uploads.authorization",
            Self::UploadsWorkflow => "uploads.workflow",
            Self::WebhooksInboundHandlers => "webhooks-inbound.handlers",
            Self::WebhooksInboundProviderAdapters => "webhooks-inbound.provider-adapters",
            Self::WebhooksSvixReplayAdmission => "webhooks-svix.replay-admission",
        }
    }
}

/// Canonical runtime contract for one catalog module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedModuleContract {
    /// Stable module ID.
    pub module: &'static str,
    /// Whether configuration may disable this compiled module.
    pub runtime_toggle: bool,
    /// Declared route IDs.
    pub routes: &'static [&'static str],
    /// Declared background-task IDs.
    pub tasks: &'static [&'static str],
    /// Declared health-check IDs.
    pub health_checks: &'static [&'static str],
    /// Application-owned contributions required by this module.
    pub application_requirements: &'static [ApplicationRequirement],
}

#[cfg(any(feature = "core", test))]
#[rustfmt::skip]
pub(crate) const COMPILED_MODULES: &[&str] = &[
    #[cfg(feature = "core")]
    "core",
    #[cfg(feature = "config")]
    "config",
    #[cfg(feature = "telemetry")]
    "telemetry",
    #[cfg(feature = "runtime")]
    "runtime",
    #[cfg(feature = "http")]
    "http",
    #[cfg(feature = "health")]
    "health",
    #[cfg(feature = "postgres")]
    "postgres",
    #[cfg(feature = "migrations")]
    "migrations",
    #[cfg(feature = "validation")]
    "validation",
    #[cfg(feature = "openapi")]
    "openapi",
    #[cfg(feature = "idempotency")]
    "idempotency",
    #[cfg(feature = "outbound-http")]
    "outbound-http",
    #[cfg(feature = "redis-core")]
    "redis-core",
    #[cfg(feature = "cache-local")]
    "cache-local",
    #[cfg(feature = "cache-redis")]
    "cache-redis",
    #[cfg(feature = "rate-limit-local")]
    "rate-limit-local",
    #[cfg(feature = "rate-limit-redis")]
    "rate-limit-redis",
    #[cfg(feature = "auth-core")]
    "auth-core",
    #[cfg(feature = "auth-password")]
    "auth-password",
    #[cfg(feature = "auth-session-postgres")]
    "auth-session-postgres",
    #[cfg(feature = "auth-session-redis")]
    "auth-session-redis",
    #[cfg(feature = "auth-jwt")]
    "auth-jwt",
    #[cfg(feature = "auth-oidc")]
    "auth-oidc",
    #[cfg(feature = "auth-api-key")]
    "auth-api-key",
    #[cfg(feature = "auth-webauthn")]
    "auth-webauthn",
    #[cfg(feature = "auth-totp")]
    "auth-totp",
    #[cfg(feature = "authz-basic")]
    "authz-basic",
    #[cfg(feature = "authz-cedar")]
    "authz-cedar",
    #[cfg(feature = "tenancy")]
    "tenancy",
    #[cfg(feature = "audit")]
    "audit",
    #[cfg(feature = "auth-oauth-server")]
    "auth-oauth-server",
    #[cfg(feature = "admin")]
    "admin",
    #[cfg(feature = "jobs-core")]
    "jobs-core",
    #[cfg(feature = "jobs-apalis-redis")]
    "jobs-apalis-redis",
    #[cfg(feature = "jobs-pgmq")]
    "jobs-pgmq",
    #[cfg(feature = "outbox")]
    "outbox",
    #[cfg(feature = "inbox")]
    "inbox",
    #[cfg(feature = "scheduler")]
    "scheduler",
    #[cfg(feature = "events-nats")]
    "events-nats",
    #[cfg(feature = "events-redis-ephemeral")]
    "events-redis-ephemeral",
    #[cfg(feature = "realtime-core")]
    "realtime-core",
    #[cfg(feature = "sse")]
    "sse",
    #[cfg(feature = "websockets")]
    "websockets",
    #[cfg(feature = "object-storage")]
    "object-storage",
    #[cfg(feature = "email")]
    "email",
    #[cfg(feature = "notifications")]
    "notifications",
    #[cfg(feature = "webhooks-svix")]
    "webhooks-svix",
    #[cfg(feature = "webhooks-inbound")]
    "webhooks-inbound",
    #[cfg(feature = "feature-flags")]
    "feature-flags",
    #[cfg(feature = "search-meilisearch")]
    "search-meilisearch",
    #[cfg(feature = "billing")]
    "billing",
    #[cfg(feature = "graphql")]
    "graphql",
    #[cfg(feature = "grpc")]
    "grpc",
    #[cfg(feature = "localization")]
    "localization",
    #[cfg(feature = "data-lifecycle")]
    "data-lifecycle",
    #[cfg(feature = "consent")]
    "consent",
    #[cfg(feature = "moderation")]
    "moderation",
    #[cfg(feature = "web-sdk-core")]
    "web-sdk-core",
    #[cfg(feature = "web-auth")]
    "web-auth",
    #[cfg(feature = "web-authorization")]
    "web-authorization",
    #[cfg(feature = "web-react")]
    "web-react",
    #[cfg(feature = "web-feature-flags")]
    "web-feature-flags",
    #[cfg(feature = "web-forms")]
    "web-forms",
    #[cfg(feature = "web-local-state")]
    "web-local-state",
    #[cfg(feature = "web-realtime")]
    "web-realtime",
    #[cfg(feature = "web-static")]
    "web-static",
    #[cfg(feature = "web-tenancy")]
    "web-tenancy",
    #[cfg(feature = "web-uploads")]
    "web-uploads",
    #[cfg(feature = "agent-capability-registry")]
    "agent-capability-registry",
    #[cfg(feature = "llm-core")]
    "llm-core",
    #[cfg(feature = "llm-conversations")]
    "llm-conversations",
    #[cfg(feature = "llm-media")]
    "llm-media",
    #[cfg(feature = "llm-prompt-catalog")]
    "llm-prompt-catalog",
    #[cfg(feature = "llm-provider-rig")]
    "llm-provider-rig",
    #[cfg(feature = "llm-embeddings")]
    "llm-embeddings",
    #[cfg(feature = "llm-provider-bedrock")]
    "llm-provider-bedrock",
    #[cfg(feature = "llm-provider-vertex")]
    "llm-provider-vertex",
    #[cfg(feature = "llm-routing")]
    "llm-routing",
    #[cfg(feature = "llm-safety-policy")]
    "llm-safety-policy",
    #[cfg(feature = "llm-streaming")]
    "llm-streaming",
    #[cfg(feature = "llm-structured-output")]
    "llm-structured-output",
    #[cfg(feature = "llm-http-api")]
    "llm-http-api",
    #[cfg(feature = "llm-tool-runtime")]
    "llm-tool-runtime",
    #[cfg(feature = "llm-usage-ledger")]
    "llm-usage-ledger",
    #[cfg(feature = "llm-budgeting")]
    "llm-budgeting",
    #[cfg(feature = "mcp-server-core")]
    "mcp-server-core",
    #[cfg(feature = "mcp-elicitation")]
    "mcp-elicitation",
    #[cfg(feature = "mcp-prompts")]
    "mcp-prompts",
    #[cfg(feature = "mcp-resources")]
    "mcp-resources",
    #[cfg(feature = "mcp-skills")]
    "mcp-skills",
    #[cfg(feature = "mcp-subscriptions-local")]
    "mcp-subscriptions-local",
    #[cfg(feature = "mcp-subscriptions-nats")]
    "mcp-subscriptions-nats",
    #[cfg(feature = "mcp-subscriptions-redis")]
    "mcp-subscriptions-redis",
    #[cfg(feature = "mcp-tasks")]
    "mcp-tasks",
    #[cfg(feature = "mcp-tools")]
    "mcp-tools",
    #[cfg(feature = "mcp-apps")]
    "mcp-apps",
    #[cfg(feature = "mcp-transport-http")]
    "mcp-transport-http",
    #[cfg(feature = "mcp-auth-oauth")]
    "mcp-auth-oauth",
    #[cfg(feature = "mcp-auth-client-credentials")]
    "mcp-auth-client-credentials",
    #[cfg(feature = "mcp-auth-enterprise")]
    "mcp-auth-enterprise",
    #[cfg(feature = "web-llm")]
    "web-llm",
];

#[rustfmt::skip]
pub(crate) const COMPILED_CONTRACTS: &[SelectedModuleContract] = &[
    #[cfg(feature = "core")]
    SelectedModuleContract {
        module: "core",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "config")]
    SelectedModuleContract {
        module: "config",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "telemetry")]
    SelectedModuleContract {
        module: "telemetry",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "runtime")]
    SelectedModuleContract {
        module: "runtime",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "http")]
    SelectedModuleContract {
        module: "http",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "health")]
    SelectedModuleContract {
        module: "health",
        runtime_toggle: false,
        routes: &["/live", "/ready", "/startup", "/version"],
        tasks: &["health-cache-refresh"],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "postgres")]
    SelectedModuleContract {
        module: "postgres",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &["postgres-connectivity"],
        application_requirements: &[],
    },
    #[cfg(feature = "migrations")]
    SelectedModuleContract {
        module: "migrations",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "validation")]
    SelectedModuleContract {
        module: "validation",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "openapi")]
    SelectedModuleContract {
        module: "openapi",
        runtime_toggle: true,
        routes: &["/openapi.json", "/docs"],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "idempotency")]
    SelectedModuleContract {
        module: "idempotency",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "outbound-http")]
    SelectedModuleContract {
        module: "outbound-http",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "redis-core")]
    SelectedModuleContract {
        module: "redis-core",
        runtime_toggle: true,
        routes: &[],
        tasks: &["redis-health-probe"],
        health_checks: &["redis-connectivity"],
        application_requirements: &[ApplicationRequirement::RealtimeEventHandler],
    },
    #[cfg(feature = "cache-local")]
    SelectedModuleContract {
        module: "cache-local",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "cache-redis")]
    SelectedModuleContract {
        module: "cache-redis",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "rate-limit-local")]
    SelectedModuleContract {
        module: "rate-limit-local",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "rate-limit-redis")]
    SelectedModuleContract {
        module: "rate-limit-redis",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "auth-core")]
    SelectedModuleContract {
        module: "auth-core",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "auth-password")]
    SelectedModuleContract {
        module: "auth-password",
        runtime_toggle: true,
        routes: &["/auth/login", "/auth/logout", "/auth/register", "/auth/email/verification/request", "/auth/email/verification/complete", "/auth/password/change", "/auth/password/reset/request", "/auth/password/reset/complete", "/auth/registration-invitations", "/auth/registration-invitations/{invitation_id}"],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::AuthAuthenticatedRuntime],
    },
    #[cfg(feature = "auth-session-postgres")]
    SelectedModuleContract {
        module: "auth-session-postgres",
        runtime_toggle: true,
        routes: &["/auth/sessions", "/auth/sessions/{device_id}"],
        tasks: &["session-cleanup"],
        health_checks: &["session-store"],
        application_requirements: &[ApplicationRequirement::AuthAuthenticatedRuntime],
    },
    #[cfg(feature = "auth-session-redis")]
    SelectedModuleContract {
        module: "auth-session-redis",
        runtime_toggle: true,
        routes: &["/auth/sessions", "/auth/sessions/{id}"],
        tasks: &["session-cleanup"],
        health_checks: &["session-store"],
        application_requirements: &[ApplicationRequirement::AuthRedisSessionRuntime],
    },
    #[cfg(feature = "auth-jwt")]
    SelectedModuleContract {
        module: "auth-jwt",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "auth-oidc")]
    SelectedModuleContract {
        module: "auth-oidc",
        runtime_toggle: true,
        routes: &["/auth/oidc/{provider}/start", "/auth/oidc/{provider}/callback"],
        tasks: &["oidc-pending-authorization-cleanup"],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::AuthOidcRuntime],
    },
    #[cfg(feature = "auth-api-key")]
    SelectedModuleContract {
        module: "auth-api-key",
        runtime_toggle: true,
        routes: &["/auth/service-accounts", "/auth/service-accounts/{service_account_id}", "/auth/service-accounts/{service_account_id}/api-keys", "/auth/api-keys/{api_key_id}/rotate", "/auth/api-keys/{api_key_id}"],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::AuthAuthenticatedRuntime],
    },
    #[cfg(feature = "auth-webauthn")]
    SelectedModuleContract {
        module: "auth-webauthn",
        runtime_toggle: true,
        routes: &["/auth/passkeys", "/auth/passkeys/register/start", "/auth/passkeys/register/finish", "/auth/passkeys/authenticate/start", "/auth/passkeys/authenticate/finish"],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::AuthWebAuthnRuntime],
    },
    #[cfg(feature = "auth-totp")]
    SelectedModuleContract {
        module: "auth-totp",
        runtime_toggle: true,
        routes: &["/auth/mfa/totp/enroll", "/auth/mfa/totp/confirm", "/auth/mfa/totp/disable"],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::AuthTotpRuntime],
    },
    #[cfg(feature = "authz-basic")]
    SelectedModuleContract {
        module: "authz-basic",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "authz-cedar")]
    SelectedModuleContract {
        module: "authz-cedar",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "tenancy")]
    SelectedModuleContract {
        module: "tenancy",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "audit")]
    SelectedModuleContract {
        module: "audit",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "auth-oauth-server")]
    SelectedModuleContract {
        module: "auth-oauth-server",
        runtime_toggle: false,
        routes: &["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration", "/.well-known/oauth-protected-resource", "/oauth/jwks.json", "/oauth/authorize", "/oauth/authorize/interaction", "/oauth/authorize/decision", "/oauth/token", "/oauth/register", "/oauth/revoke", "/oauth/grants", "/oauth/grants/{grant_id}", "/oauth/userinfo", "/oauth/logout"],
        tasks: &["oauth-protocol-state-cleanup"],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::AuthOauthRuntime],
    },
    #[cfg(feature = "admin")]
    SelectedModuleContract {
        module: "admin",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::AdminAuthorityResolver, ApplicationRequirement::AdminOperationHandler],
    },
    #[cfg(feature = "jobs-core")]
    SelectedModuleContract {
        module: "jobs-core",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::JobsHandlers],
    },
    #[cfg(feature = "jobs-apalis-redis")]
    SelectedModuleContract {
        module: "jobs-apalis-redis",
        runtime_toggle: true,
        routes: &[],
        tasks: &["job-worker"],
        health_checks: &["job-backend"],
        application_requirements: &[ApplicationRequirement::JobsHandlers],
    },
    #[cfg(feature = "jobs-pgmq")]
    SelectedModuleContract {
        module: "jobs-pgmq",
        runtime_toggle: true,
        routes: &[],
        tasks: &["job-worker"],
        health_checks: &["job-backend"],
        application_requirements: &[ApplicationRequirement::JobsHandlers],
    },
    #[cfg(feature = "outbox")]
    SelectedModuleContract {
        module: "outbox",
        runtime_toggle: true,
        routes: &[],
        tasks: &["outbox-relay"],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::OutboxPublisher],
    },
    #[cfg(feature = "inbox")]
    SelectedModuleContract {
        module: "inbox",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::InboxConsumers],
    },
    #[cfg(feature = "scheduler")]
    SelectedModuleContract {
        module: "scheduler",
        runtime_toggle: true,
        routes: &[],
        tasks: &["scheduler"],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::SchedulerEnvelopeFactory],
    },
    #[cfg(feature = "events-nats")]
    SelectedModuleContract {
        module: "events-nats",
        runtime_toggle: true,
        routes: &[],
        tasks: &["nats-consumers"],
        health_checks: &["nats-jetstream"],
        application_requirements: &[ApplicationRequirement::RealtimeEventHandler],
    },
    #[cfg(feature = "events-redis-ephemeral")]
    SelectedModuleContract {
        module: "events-redis-ephemeral",
        runtime_toggle: true,
        routes: &[],
        tasks: &["redis-pubsub-listener"],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::RealtimeEventHandler],
    },
    #[cfg(feature = "realtime-core")]
    SelectedModuleContract {
        module: "realtime-core",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::RealtimeFanoutAuthorizer, ApplicationRequirement::RealtimeIdentityRevalidator, ApplicationRequirement::RealtimeEventHandler],
    },
    #[cfg(feature = "sse")]
    SelectedModuleContract {
        module: "sse",
        runtime_toggle: true,
        routes: &["/realtime/events"],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::RealtimeFanoutAuthorizer, ApplicationRequirement::RealtimeIdentityRevalidator, ApplicationRequirement::RealtimeEventHandler],
    },
    #[cfg(feature = "websockets")]
    SelectedModuleContract {
        module: "websockets",
        runtime_toggle: true,
        routes: &["/realtime/ws"],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::RealtimeFanoutAuthorizer, ApplicationRequirement::RealtimeIdentityRevalidator, ApplicationRequirement::RealtimeEventHandler],
    },
    #[cfg(feature = "object-storage")]
    SelectedModuleContract {
        module: "object-storage",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &["object-store"],
        application_requirements: &[ApplicationRequirement::UploadsWorkflow, ApplicationRequirement::UploadsAuthorization],
    },
    #[cfg(feature = "email")]
    SelectedModuleContract {
        module: "email",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &["email-provider"],
        application_requirements: &[ApplicationRequirement::JobsHandlers],
    },
    #[cfg(feature = "notifications")]
    SelectedModuleContract {
        module: "notifications",
        runtime_toggle: true,
        routes: &[],
        tasks: &["notification-orchestrator"],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::JobsHandlers, ApplicationRequirement::OutboxPublisher],
    },
    #[cfg(feature = "webhooks-svix")]
    SelectedModuleContract {
        module: "webhooks-svix",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &["svix"],
        application_requirements: &[ApplicationRequirement::WebhooksSvixReplayAdmission],
    },
    #[cfg(feature = "webhooks-inbound")]
    SelectedModuleContract {
        module: "webhooks-inbound",
        runtime_toggle: true,
        routes: &["/webhooks/inbound/{provider}"],
        tasks: &["inbound-webhook-processor"],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::WebhooksInboundProviderAdapters, ApplicationRequirement::WebhooksInboundHandlers],
    },
    #[cfg(feature = "feature-flags")]
    SelectedModuleContract {
        module: "feature-flags",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::FeatureFlagsProvider, ApplicationRequirement::FeatureFlagsExposureRecorder],
    },
    #[cfg(feature = "search-meilisearch")]
    SelectedModuleContract {
        module: "search-meilisearch",
        runtime_toggle: true,
        routes: &[],
        tasks: &["search-indexer"],
        health_checks: &["search-provider"],
        application_requirements: &[ApplicationRequirement::SearchIndexSchema, ApplicationRequirement::SearchReauthorizer, ApplicationRequirement::SearchProjectionResolver],
    },
    #[cfg(feature = "billing")]
    SelectedModuleContract {
        module: "billing",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &["billing-provider"],
        application_requirements: &[ApplicationRequirement::BillingProvider],
    },
    #[cfg(feature = "graphql")]
    SelectedModuleContract {
        module: "graphql",
        runtime_toggle: true,
        routes: &["/graphql"],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::GraphqlSchema, ApplicationRequirement::GraphqlRequestDataInjector],
    },
    #[cfg(feature = "grpc")]
    SelectedModuleContract {
        module: "grpc",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::GrpcApplicationService, ApplicationRequirement::GrpcAuthenticator, ApplicationRequirement::GrpcMethodPolicies],
    },
    #[cfg(feature = "localization")]
    SelectedModuleContract {
        module: "localization",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "data-lifecycle")]
    SelectedModuleContract {
        module: "data-lifecycle",
        runtime_toggle: true,
        routes: &[],
        tasks: &["retention-worker"],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::PrivacyInventoryManifest, ApplicationRequirement::PrivacyInventoryAdapters, ApplicationRequirement::PrivacyAuthorizer, ApplicationRequirement::PrivacyLifecycleHandler],
    },
    #[cfg(feature = "consent")]
    SelectedModuleContract {
        module: "consent",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::PrivacyConsentPolicy],
    },
    #[cfg(feature = "moderation")]
    SelectedModuleContract {
        module: "moderation",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::PrivacyModerationPolicy],
    },
    #[cfg(feature = "web-sdk-core")]
    SelectedModuleContract {
        module: "web-sdk-core",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "web-auth")]
    SelectedModuleContract {
        module: "web-auth",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "web-authorization")]
    SelectedModuleContract {
        module: "web-authorization",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "web-react")]
    SelectedModuleContract {
        module: "web-react",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "web-feature-flags")]
    SelectedModuleContract {
        module: "web-feature-flags",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "web-forms")]
    SelectedModuleContract {
        module: "web-forms",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "web-local-state")]
    SelectedModuleContract {
        module: "web-local-state",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "web-realtime")]
    SelectedModuleContract {
        module: "web-realtime",
        runtime_toggle: false,
        routes: &[],
        tasks: &["browser connection lifecycle"],
        health_checks: &["runtime transport metadata"],
        application_requirements: &[ApplicationRequirement::RealtimeFanoutAuthorizer, ApplicationRequirement::RealtimeIdentityRevalidator, ApplicationRequirement::RealtimeEventHandler],
    },
    #[cfg(feature = "web-static")]
    SelectedModuleContract {
        module: "web-static",
        runtime_toggle: false,
        routes: &["GET/HEAD /assets/*", "GET/HEAD <spa-fallback>"],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "web-tenancy")]
    SelectedModuleContract {
        module: "web-tenancy",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "web-uploads")]
    SelectedModuleContract {
        module: "web-uploads",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::UploadsWorkflow, ApplicationRequirement::UploadsAuthorization],
    },
    #[cfg(feature = "agent-capability-registry")]
    SelectedModuleContract {
        module: "agent-capability-registry",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "llm-core")]
    SelectedModuleContract {
        module: "llm-core",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "llm-conversations")]
    SelectedModuleContract {
        module: "llm-conversations",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "llm-media")]
    SelectedModuleContract {
        module: "llm-media",
        runtime_toggle: false,
        routes: &[],
        tasks: &["llm-media-reconciliation"],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::LlmMediaScanner, ApplicationRequirement::LlmMediaAuthorization],
    },
    #[cfg(feature = "llm-prompt-catalog")]
    SelectedModuleContract {
        module: "llm-prompt-catalog",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "llm-provider-rig")]
    SelectedModuleContract {
        module: "llm-provider-rig",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &["configured-provider-route-availability"],
        application_requirements: &[ApplicationRequirement::LlmToolAuthorization],
    },
    #[cfg(feature = "llm-embeddings")]
    SelectedModuleContract {
        module: "llm-embeddings",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "llm-provider-bedrock")]
    SelectedModuleContract {
        module: "llm-provider-bedrock",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &["bedrock-route-availability"],
        application_requirements: &[ApplicationRequirement::LlmToolAuthorization],
    },
    #[cfg(feature = "llm-provider-vertex")]
    SelectedModuleContract {
        module: "llm-provider-vertex",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &["vertex-route-availability"],
        application_requirements: &[ApplicationRequirement::LlmToolAuthorization],
    },
    #[cfg(feature = "llm-routing")]
    SelectedModuleContract {
        module: "llm-routing",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &["required-route-availability"],
        application_requirements: &[ApplicationRequirement::LlmToolAuthorization],
    },
    #[cfg(feature = "llm-safety-policy")]
    SelectedModuleContract {
        module: "llm-safety-policy",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "llm-streaming")]
    SelectedModuleContract {
        module: "llm-streaming",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "llm-structured-output")]
    SelectedModuleContract {
        module: "llm-structured-output",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "llm-http-api")]
    SelectedModuleContract {
        module: "llm-http-api",
        runtime_toggle: false,
        routes: &["GET /api/ai/routes", "POST /api/ai/responses", "POST /api/ai/responses/stream", "POST /api/ai/jobs", "GET /api/ai/jobs/{job_id}", "DELETE /api/ai/jobs/{job_id}", "GET /api/ai/jobs/{job_id}/result", "POST /api/ai/conversations", "GET /api/ai/conversations/{conversation_id}", "DELETE /api/ai/conversations/{conversation_id}", "GET /api/ai/conversations/{conversation_id}/messages", "POST /api/ai/conversations/{conversation_id}/messages", "PATCH /api/ai/conversations/{conversation_id}/messages/{message_id}", "DELETE /api/ai/conversations/{conversation_id}/messages/{message_id}", "GET /api/ai/conversations/{conversation_id}/provider-state/{state_id}", "PUT /api/ai/conversations/{conversation_id}/provider-state/{state_id}", "DELETE /api/ai/conversations/{conversation_id}/provider-state/{state_id}"],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::LlmToolAuthorization, ApplicationRequirement::LlmToolAudit, ApplicationRequirement::LlmMediaScanner, ApplicationRequirement::LlmMediaAuthorization],
    },
    #[cfg(feature = "llm-tool-runtime")]
    SelectedModuleContract {
        module: "llm-tool-runtime",
        runtime_toggle: false,
        routes: &[],
        tasks: &["tool-approval-expiry"],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::LlmToolAuthorization, ApplicationRequirement::LlmToolAudit],
    },
    #[cfg(feature = "llm-usage-ledger")]
    SelectedModuleContract {
        module: "llm-usage-ledger",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "llm-budgeting")]
    SelectedModuleContract {
        module: "llm-budgeting",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "mcp-server-core")]
    SelectedModuleContract {
        module: "mcp-server-core",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::McpCapabilityRegistry],
    },
    #[cfg(feature = "mcp-elicitation")]
    SelectedModuleContract {
        module: "mcp-elicitation",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "mcp-prompts")]
    SelectedModuleContract {
        module: "mcp-prompts",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "mcp-resources")]
    SelectedModuleContract {
        module: "mcp-resources",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "mcp-skills")]
    SelectedModuleContract {
        module: "mcp-skills",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "mcp-subscriptions-local")]
    SelectedModuleContract {
        module: "mcp-subscriptions-local",
        runtime_toggle: false,
        routes: &[],
        tasks: &["mcp-subscription-backplane"],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::McpSubscriptionRepository, ApplicationRequirement::McpSubscriptionAuthorizer, ApplicationRequirement::McpSubscriptionRuntime, ApplicationRequirement::McpSubscriptionDelivery],
    },
    #[cfg(feature = "mcp-subscriptions-nats")]
    SelectedModuleContract {
        module: "mcp-subscriptions-nats",
        runtime_toggle: false,
        routes: &[],
        tasks: &["mcp-subscription-backplane"],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::McpSubscriptionRepository, ApplicationRequirement::McpSubscriptionAuthorizer, ApplicationRequirement::McpSubscriptionRuntime, ApplicationRequirement::McpSubscriptionDelivery],
    },
    #[cfg(feature = "mcp-subscriptions-redis")]
    SelectedModuleContract {
        module: "mcp-subscriptions-redis",
        runtime_toggle: false,
        routes: &[],
        tasks: &["mcp-subscription-backplane"],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::McpSubscriptionRepository, ApplicationRequirement::McpSubscriptionAuthorizer, ApplicationRequirement::McpSubscriptionRuntime, ApplicationRequirement::McpSubscriptionDelivery],
    },
    #[cfg(feature = "mcp-tasks")]
    SelectedModuleContract {
        module: "mcp-tasks",
        runtime_toggle: false,
        routes: &[],
        tasks: &["mcp-task-expiry"],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::McpTaskPayloadProtector, ApplicationRequirement::McpCancellationRuntime, ApplicationRequirement::McpCapabilityExecutor],
    },
    #[cfg(feature = "mcp-tools")]
    SelectedModuleContract {
        module: "mcp-tools",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "mcp-apps")]
    SelectedModuleContract {
        module: "mcp-apps",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::McpAppsPorts],
    },
    #[cfg(feature = "mcp-transport-http")]
    SelectedModuleContract {
        module: "mcp-transport-http",
        runtime_toggle: false,
        routes: &["POST /mcp"],
        tasks: &[],
        health_checks: &["mcp-http-dispatch"],
        application_requirements: &[ApplicationRequirement::McpBearerAuthenticator],
    },
    #[cfg(feature = "mcp-auth-oauth")]
    SelectedModuleContract {
        module: "mcp-auth-oauth",
        runtime_toggle: false,
        routes: &["GET /.well-known/oauth-protected-resource"],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::McpBearerAuthenticator],
    },
    #[cfg(feature = "mcp-auth-client-credentials")]
    SelectedModuleContract {
        module: "mcp-auth-client-credentials",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
    #[cfg(feature = "mcp-auth-enterprise")]
    SelectedModuleContract {
        module: "mcp-auth-enterprise",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[ApplicationRequirement::McpEnterprisePorts],
    },
    #[cfg(feature = "web-llm")]
    SelectedModuleContract {
        module: "web-llm",
        runtime_toggle: false,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: &[],
    },
];

#[cfg(any(feature = "core", test))]
#[rustfmt::skip]
fn is_known_module(module: &str) -> bool {
    matches!(
        module,
        "core" | "config" | "telemetry"
        | "runtime" | "http" | "health"
        | "postgres" | "migrations" | "validation"
        | "openapi" | "idempotency" | "outbound-http"
        | "redis-core" | "cache-local" | "cache-redis"
        | "rate-limit-local" | "rate-limit-redis" | "auth-core"
        | "auth-password" | "auth-session-postgres" | "auth-session-redis"
        | "auth-jwt" | "auth-oidc" | "auth-api-key"
        | "auth-webauthn" | "auth-totp" | "authz-basic"
        | "authz-cedar" | "tenancy" | "audit"
        | "auth-oauth-server" | "admin" | "jobs-core"
        | "jobs-apalis-redis" | "jobs-pgmq" | "outbox"
        | "inbox" | "scheduler" | "events-nats"
        | "events-redis-ephemeral" | "realtime-core" | "sse"
        | "websockets" | "object-storage" | "email"
        | "notifications" | "webhooks-svix" | "webhooks-inbound"
        | "feature-flags" | "search-meilisearch" | "billing"
        | "graphql" | "grpc" | "localization"
        | "data-lifecycle" | "consent" | "moderation"
        | "web-sdk-core" | "web-auth" | "web-authorization"
        | "web-react" | "web-feature-flags" | "web-forms"
        | "web-local-state" | "web-realtime" | "web-static"
        | "web-tenancy" | "web-uploads" | "agent-capability-registry"
        | "llm-core" | "llm-conversations" | "llm-media"
        | "llm-prompt-catalog" | "llm-provider-rig" | "llm-embeddings"
        | "llm-provider-bedrock" | "llm-provider-vertex" | "llm-routing"
        | "llm-safety-policy" | "llm-streaming" | "llm-structured-output"
        | "llm-http-api" | "llm-tool-runtime" | "llm-usage-ledger"
        | "llm-budgeting" | "mcp-server-core" | "mcp-elicitation"
        | "mcp-prompts" | "mcp-resources" | "mcp-skills"
        | "mcp-subscriptions-local" | "mcp-subscriptions-nats" | "mcp-subscriptions-redis"
        | "mcp-tasks" | "mcp-tools" | "mcp-apps"
        | "mcp-transport-http" | "mcp-auth-oauth" | "mcp-auth-client-credentials"
        | "mcp-auth-enterprise" | "web-llm"
    )
}

#[cfg(any(feature = "core", test))]
pub(crate) fn canonical_contract(
    module: &'static str,
) -> Result<&'static SelectedModuleContract, crate::CompositionError> {
    if let Some(contract) = COMPILED_CONTRACTS
        .iter()
        .find(|contract| contract.module == module)
    {
        return Ok(contract);
    }
    if is_known_module(module) {
        Err(crate::CompositionError::FeatureNotEnabled { module })
    } else {
        Err(crate::CompositionError::UnknownModule { module })
    }
}

#[cfg(any(feature = "core", test))]
pub(crate) fn validate_selection(
    modules: &'static [&'static str],
) -> Result<(), crate::CompositionError> {
    for &module in modules {
        canonical_contract(module)?;
    }
    if modules != COMPILED_MODULES {
        return Err(crate::CompositionError::SelectionMismatch);
    }
    Ok(())
}

#[cfg(any(feature = "core", test))]
#[rustfmt::skip]
fn is_registrarless_module(module: &str) -> bool {
    matches!(
        module,
        "validation" | "redis-core" | "cache-local"
        | "cache-redis" | "rate-limit-redis" | "auth-core"
        | "auth-password" | "auth-session-postgres" | "auth-session-redis"
        | "auth-jwt" | "auth-api-key" | "authz-basic"
        | "authz-cedar" | "tenancy" | "audit"
        | "auth-oauth-server" | "admin" | "jobs-core"
        | "search-meilisearch" | "billing" | "graphql"
        | "grpc" | "localization" | "data-lifecycle"
        | "consent" | "moderation" | "web-sdk-core"
        | "web-auth" | "web-authorization" | "web-react"
        | "web-feature-flags" | "web-forms" | "web-local-state"
        | "web-realtime" | "web-tenancy" | "web-uploads"
        | "agent-capability-registry" | "llm-core" | "llm-conversations"
        | "llm-prompt-catalog" | "llm-embeddings" | "llm-safety-policy"
        | "llm-streaming" | "llm-structured-output" | "llm-usage-ledger"
        | "llm-budgeting" | "mcp-elicitation" | "mcp-prompts"
        | "mcp-resources" | "mcp-skills" | "mcp-tools"
        | "mcp-apps" | "mcp-auth-client-credentials" | "mcp-auth-enterprise"
        | "web-llm"
    )
}

#[cfg(any(feature = "core", test))]
#[rustfmt::skip]
fn register_selected_module(
    #[cfg(feature = "core")]
    builder: &mut crate::AppCompositionBuilder<'_>,
    #[cfg(not(feature = "core"))]
    _: &mut crate::AppCompositionBuilder<'_>,
    module: &'static str,
) -> Result<(), crate::CompositionError> {
    match module {
        #[cfg(feature = "core")] "core" => crate::modules::core::register(builder),
        #[cfg(feature = "config")] "config" => crate::modules::config::register(builder),
        #[cfg(feature = "telemetry")] "telemetry" => crate::modules::telemetry::register(builder),
        #[cfg(feature = "runtime")] "runtime" => crate::modules::runtime::register(builder),
        #[cfg(feature = "http")] "http" => crate::modules::http::register(builder),
        #[cfg(feature = "health")] "health" => crate::modules::health::register(builder),
        #[cfg(feature = "postgres")] "postgres" => crate::modules::postgres::register(builder),
        #[cfg(feature = "migrations")] "migrations" => crate::modules::migrations::register(builder),
        #[cfg(feature = "openapi")] "openapi" => crate::modules::openapi::register(builder),
        #[cfg(feature = "idempotency")] "idempotency" => crate::modules::idempotency::register(builder),
        #[cfg(feature = "outbound-http")] "outbound-http" => crate::modules::outbound_http::register(builder),
        #[cfg(feature = "rate-limit-local")] "rate-limit-local" => crate::modules::rate_limit_local::register(builder),
        #[cfg(feature = "auth-oidc")] "auth-oidc" => crate::modules::auth_oidc::register(builder),
        #[cfg(feature = "auth-webauthn")] "auth-webauthn" => crate::modules::auth_webauthn::register(builder),
        #[cfg(feature = "auth-totp")] "auth-totp" => crate::modules::auth_totp::register(builder),
        #[cfg(feature = "jobs-apalis-redis")] "jobs-apalis-redis" => crate::modules::jobs_apalis_redis::register(builder),
        #[cfg(feature = "jobs-pgmq")] "jobs-pgmq" => crate::modules::jobs_pgmq::register(builder),
        #[cfg(feature = "outbox")] "outbox" => crate::modules::outbox::register(builder),
        #[cfg(feature = "inbox")] "inbox" => crate::modules::inbox::register(builder),
        #[cfg(feature = "scheduler")] "scheduler" => crate::modules::scheduler::register(builder),
        #[cfg(feature = "events-nats")] "events-nats" => crate::modules::events_nats::register(builder),
        #[cfg(feature = "events-redis-ephemeral")] "events-redis-ephemeral" => crate::modules::events_redis_ephemeral::register(builder),
        #[cfg(feature = "realtime-core")] "realtime-core" => crate::modules::realtime_core::register(builder),
        #[cfg(feature = "sse")] "sse" => crate::modules::sse::register(builder),
        #[cfg(feature = "websockets")] "websockets" => crate::modules::websockets::register(builder),
        #[cfg(feature = "object-storage")] "object-storage" => crate::modules::object_storage::register(builder),
        #[cfg(feature = "email")] "email" => crate::modules::email::register(builder),
        #[cfg(feature = "notifications")] "notifications" => crate::modules::notifications::register(builder),
        #[cfg(feature = "webhooks-svix")] "webhooks-svix" => crate::modules::webhooks_svix::register(builder),
        #[cfg(feature = "webhooks-inbound")] "webhooks-inbound" => crate::modules::webhooks_inbound::register(builder),
        #[cfg(feature = "feature-flags")] "feature-flags" => crate::modules::feature_flags::register(builder),
        #[cfg(feature = "web-static")] "web-static" => crate::modules::web_static::register(builder),
        #[cfg(feature = "llm-media")] "llm-media" => crate::modules::llm_media::register(builder),
        #[cfg(feature = "llm-provider-rig")] "llm-provider-rig" => crate::modules::llm_provider_rig::register(builder),
        #[cfg(feature = "llm-provider-bedrock")] "llm-provider-bedrock" => crate::modules::llm_provider_bedrock::register(builder),
        #[cfg(feature = "llm-provider-vertex")] "llm-provider-vertex" => crate::modules::llm_provider_vertex::register(builder),
        #[cfg(feature = "llm-routing")] "llm-routing" => crate::modules::llm_routing::register(builder),
        #[cfg(feature = "llm-http-api")] "llm-http-api" => crate::modules::llm_http_api::register(builder),
        #[cfg(feature = "llm-tool-runtime")] "llm-tool-runtime" => crate::modules::llm_tool_runtime::register(builder),
        #[cfg(feature = "mcp-server-core")] "mcp-server-core" => crate::modules::mcp_server_core::register(builder),
        #[cfg(feature = "mcp-subscriptions-local")] "mcp-subscriptions-local" => crate::modules::mcp_subscriptions_local::register(builder),
        #[cfg(feature = "mcp-subscriptions-nats")] "mcp-subscriptions-nats" => crate::modules::mcp_subscriptions_nats::register(builder),
        #[cfg(feature = "mcp-subscriptions-redis")] "mcp-subscriptions-redis" => crate::modules::mcp_subscriptions_redis::register(builder),
        #[cfg(feature = "mcp-tasks")] "mcp-tasks" => crate::modules::mcp_tasks::register(builder),
        #[cfg(feature = "mcp-transport-http")] "mcp-transport-http" => crate::modules::mcp_transport_http::register(builder),
        #[cfg(feature = "mcp-auth-oauth")] "mcp-auth-oauth" => crate::modules::mcp_auth_oauth::register(builder),
        _ if is_registrarless_module(module) => Ok(()),
        _ => Err(crate::CompositionError::SelectionMismatch),
    }
}

#[cfg(any(feature = "core", test))]
pub(crate) fn register_selected(
    builder: &mut crate::AppCompositionBuilder<'_>,
) -> Result<(), crate::CompositionError> {
    let selected = builder.input.modules;
    validate_selection(selected)?;
    for &module in selected {
        register_selected_module(builder, module)?;
    }
    #[cfg(feature = "http")]
    crate::modules::http::finalize(builder)?;
    Ok(())
}
