//! Selection-driven application builder populated by static registrars.

#[cfg(any(feature = "core", test))]
use std::collections::{BTreeMap, BTreeSet};

#[cfg(any(feature = "core", test))]
use crate::ApplicationContributions;
#[cfg(feature = "http")]
use crate::ApplicationExtension;
#[cfg(feature = "rate-limit-local")]
use crate::ApplicationRateLimitConfig;
#[cfg(any(feature = "core", test))]
use crate::CompositionError;
#[cfg(feature = "openapi")]
use crate::ExpectedOperation;
#[cfg(any(
    feature = "llm-provider-rig",
    feature = "llm-provider-bedrock",
    feature = "llm-provider-vertex",
    feature = "llm-routing"
))]
use crate::HealthRuntime;
#[cfg(any(
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats"
))]
use crate::TaskRuntime;
#[cfg(any(feature = "core", test, feature = "openapi"))]
use crate::catalog;
#[cfg(any(feature = "core", test))]
use crate::{
    ApplicationRequirement, ComposedApplication, CompositionInput, SelectedModuleContract,
    ShutdownHook,
};

#[cfg(any(feature = "core", test))]
/// Selection-driven application builder populated by static registrars.
pub struct AppCompositionBuilder<'a> {
    pub(crate) input: CompositionInput,
    pub(crate) contributions: &'a mut ApplicationContributions,
    pub(crate) application_requirements: BTreeMap<ApplicationRequirement, bool>,
    #[cfg(feature = "rate-limit-local")]
    pub(crate) application_rate_limiter: Option<omnius_rate_limit_local::LocalRateLimiter>,
    pub(crate) routers: Vec<axum::Router>,
    pub(crate) health_specs: Vec<omnius_health::HealthCheckSpec>,
    pub(crate) health_runtime: bool,
    pub(crate) task_specs: Vec<omnius_runtime::TaskSpec>,
    pub(crate) shutdown_hooks: Vec<ShutdownHook>,
    #[cfg(feature = "openapi")]
    pub(crate) openapi_fragments: Vec<serde_json::Value>,
    #[cfg(feature = "openapi")]
    pub(crate) expected_operations: Vec<ExpectedOperation>,
    pub(crate) route_ids: BTreeSet<&'static str>,
    pub(crate) health_ids: BTreeSet<&'static str>,
    pub(crate) task_ids: BTreeSet<&'static str>,
    pub(crate) public_operations: BTreeSet<&'static str>,
    pub(crate) capabilities: BTreeMap<&'static str, bool>,
}

#[cfg(any(feature = "core", test))]
impl<'a> AppCompositionBuilder<'a> {
    /// Creates a builder for one resolved profile and application boundary.
    #[must_use]
    pub fn new(input: CompositionInput, contributions: &'a mut ApplicationContributions) -> Self {
        let mut builder = Self {
            input,
            contributions,
            application_requirements: BTreeMap::new(),
            #[cfg(feature = "rate-limit-local")]
            application_rate_limiter: None,
            routers: Vec::new(),
            health_runtime: false,
            health_specs: Vec::new(),
            task_specs: Vec::new(),
            shutdown_hooks: Vec::new(),
            #[cfg(feature = "openapi")]
            openapi_fragments: Vec::new(),
            #[cfg(feature = "openapi")]
            expected_operations: Vec::new(),
            route_ids: BTreeSet::new(),
            health_ids: BTreeSet::new(),
            task_ids: BTreeSet::new(),
            public_operations: BTreeSet::new(),
            capabilities: BTreeMap::new(),
        };
        for requirement in ApplicationRequirement::ALL {
            if let Some(present) = builder.requirement_present(*requirement) {
                builder
                    .application_requirements
                    .insert(*requirement, present);
            }
        }
        builder
    }

    /// Executes the generated prerequisite-first registrar list.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] when a registrar cannot construct its
    /// selected contribution.
    pub fn register_selected(&mut self) -> Result<(), CompositionError> {
        catalog::register_selected(self)
    }

    #[cfg(feature = "core")]
    /// Records truthful compile/runtime capability availability.
    pub(crate) fn register_capability(
        &mut self,
        module: &'static str,
    ) -> Result<(), CompositionError> {
        let runtime_available = !self.input.runtime_disabled_modules.contains(&module);
        if self
            .capabilities
            .insert(module, runtime_available)
            .is_some()
        {
            return Err(CompositionError::DuplicateRegistration {
                kind: "capability",
                id: module,
            });
        }
        Ok(())
    }

    #[cfg(any(
        feature = "rate-limit-local",
        feature = "web-static",
        feature = "jobs-apalis-redis",
        feature = "jobs-pgmq",
        feature = "outbox",
        feature = "inbox",
        feature = "scheduler",
        feature = "events-nats",
        feature = "events-redis-ephemeral",
        feature = "realtime-core",
        feature = "sse",
        feature = "websockets",
        feature = "object-storage",
        feature = "email",
        feature = "notifications",
        feature = "webhooks-svix",
        feature = "webhooks-inbound",
        feature = "feature-flags",
        feature = "auth-http",
        feature = "auth-oidc",
        feature = "auth-webauthn",
        feature = "auth-totp",
        feature = "mcp-server-core",
        feature = "mcp-transport-http",
        feature = "mcp-auth-oauth",
        feature = "mcp-subscriptions-local",
        feature = "mcp-subscriptions-redis",
        feature = "mcp-subscriptions-nats",
        feature = "mcp-tasks",
        feature = "llm-provider-rig",
        feature = "llm-provider-bedrock",
        feature = "llm-provider-vertex",
        feature = "llm-routing",
        feature = "llm-tool-runtime",
        feature = "llm-media",
        feature = "llm-http-api"
    ))]
    pub(crate) fn runtime_available(&self, module: &str) -> bool {
        !self.input.runtime_disabled_modules.contains(&module)
    }

    #[cfg(feature = "http")]
    pub(crate) fn take_application_extension(
        &mut self,
    ) -> Result<ApplicationExtension, CompositionError> {
        self.contributions.application_extension.take().ok_or(
            CompositionError::MissingContribution {
                module: "http",
                contribution: "application.extension",
            },
        )
    }

    #[cfg(feature = "rate-limit-local")]
    pub(crate) fn application_rate_limit(
        &self,
        module: &'static str,
    ) -> Result<ApplicationRateLimitConfig, CompositionError> {
        self.contributions
            .application_rate_limit
            .ok_or(CompositionError::MissingContribution {
                module,
                contribution: "application.rate-limit",
            })
    }

    #[cfg(feature = "rate-limit-local")]
    pub(crate) fn register_application_rate_limiter(
        &mut self,
        limiter: omnius_rate_limit_local::LocalRateLimiter,
    ) -> Result<(), CompositionError> {
        if self.application_rate_limiter.replace(limiter).is_some() {
            return Err(CompositionError::DuplicateRegistration {
                kind: "runtime",
                id: "application-rate-limiter",
            });
        }
        Ok(())
    }

    #[cfg(feature = "rate-limit-local")]
    pub(crate) fn application_rate_limiter(
        &self,
    ) -> Option<omnius_rate_limit_local::LocalRateLimiter> {
        self.application_rate_limiter.clone()
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn postgres_pool(
        &self,
        module: &'static str,
    ) -> Result<&omnius_postgres::PostgresPool, CompositionError> {
        self.contributions
            .postgres_pool
            .as_ref()
            .ok_or(CompositionError::MissingContribution {
                module,
                contribution: "postgres.pool",
            })
    }

    #[cfg(feature = "outbound-http")]
    pub(crate) fn register_outbound_http(&mut self) -> Result<(), CompositionError> {
        self.register_capability("outbound-http")?;
        self.contributions
            .outbound_http
            .as_ref()
            .ok_or(CompositionError::MissingContribution {
                module: "outbound-http",
                contribution: "outbound-http.clients",
            })?;
        Ok(())
    }

    #[cfg(feature = "idempotency")]
    pub(crate) fn idempotency_store(
        &self,
        module: &'static str,
    ) -> Result<omnius_idempotency::PostgresIdempotencyStore, CompositionError> {
        self.contributions
            .idempotency_store
            .ok_or(CompositionError::MissingContribution {
                module,
                contribution: "idempotency.store",
            })
    }
    fn admin_auth_requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            #[cfg(any(feature = "admin", test))]
            ApplicationRequirement::AdminAuthorityResolver => self
                .contributions
                .admin
                .as_ref()
                .map(|runtime| runtime.authority_resolver.is_some()),
            #[cfg(any(feature = "admin", test))]
            ApplicationRequirement::AdminOperationHandler => self
                .contributions
                .admin
                .as_ref()
                .map(|runtime| runtime.operation_handler.is_some()),
            #[cfg(any(feature = "auth-http", test))]
            ApplicationRequirement::AuthAuthenticatedRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.authenticated_http.is_some()),
            #[cfg(any(feature = "auth-session-redis", test))]
            ApplicationRequirement::AuthRedisSessionRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.redis_session.is_some()),
            #[cfg(any(feature = "auth-oidc", test))]
            ApplicationRequirement::AuthOidcRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.oidc.is_some()),
            #[cfg(any(feature = "auth-oauth-server", test))]
            ApplicationRequirement::AuthOauthRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.oauth.is_some()),
            #[cfg(any(feature = "auth-webauthn", test))]
            ApplicationRequirement::AuthWebAuthnRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.webauthn.is_some()),
            #[cfg(any(feature = "auth-totp", test))]
            ApplicationRequirement::AuthTotpRuntime => self
                .contributions
                .auth
                .as_ref()
                .map(|runtime| runtime.totp.is_some()),
            _ => None,
        }
    }

    fn service_requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            #[cfg(any(feature = "billing", test))]
            ApplicationRequirement::BillingProvider => self
                .contributions
                .billing
                .as_ref()
                .map(|runtime| runtime.provider.is_some()),
            #[cfg(any(feature = "feature-flags", test))]
            ApplicationRequirement::FeatureFlagsExposureRecorder => self
                .contributions
                .feature_flags
                .as_ref()
                .map(|runtime| runtime.exposure_recorder.is_some()),
            #[cfg(any(feature = "feature-flags", test))]
            ApplicationRequirement::FeatureFlagsProvider => self
                .contributions
                .feature_flags
                .as_ref()
                .map(|runtime| runtime.provider.is_some()),
            #[cfg(any(feature = "graphql", test))]
            ApplicationRequirement::GraphqlRequestDataInjector => self
                .contributions
                .graphql
                .as_ref()
                .map(|runtime| runtime.request_data_injector.is_some()),
            #[cfg(any(feature = "graphql", test))]
            ApplicationRequirement::GraphqlSchema => self
                .contributions
                .graphql
                .as_ref()
                .map(|runtime| runtime.schema.is_some()),
            #[cfg(any(feature = "grpc", test))]
            ApplicationRequirement::GrpcApplicationService => self
                .contributions
                .grpc
                .as_ref()
                .map(|runtime| runtime.application_service.is_some()),
            #[cfg(any(feature = "grpc", test))]
            ApplicationRequirement::GrpcAuthenticator => self
                .contributions
                .grpc
                .as_ref()
                .map(|runtime| runtime.authenticator.is_some()),
            #[cfg(any(feature = "grpc", test))]
            ApplicationRequirement::GrpcMethodPolicies => self
                .contributions
                .grpc
                .as_ref()
                .map(|runtime| runtime.method_policies.is_some()),
            #[cfg(any(feature = "inbox", test))]
            ApplicationRequirement::InboxConsumers => self
                .contributions
                .inbox
                .as_ref()
                .map(|runtime| runtime.consumers.is_some()),
            #[cfg(any(feature = "jobs-core", test))]
            ApplicationRequirement::JobsHandlers => self
                .contributions
                .jobs
                .as_ref()
                .map(|runtime| !runtime.is_empty()),
            _ => None,
        }
    }

    fn llm_requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            #[cfg(test)]
            ApplicationRequirement::LlmEvaluationRepository => self
                .contributions
                .llm
                .as_ref()
                .map(|runtime| runtime.evaluation_repository.is_some()),
            #[cfg(any(feature = "llm-media", feature = "llm-http-api", test))]
            ApplicationRequirement::LlmMediaAuthorization => self
                .contributions
                .llm
                .as_ref()
                .map(|runtime| runtime.media_authorization.is_some()),
            #[cfg(any(feature = "llm-media", feature = "llm-http-api", test))]
            ApplicationRequirement::LlmMediaScanner => self
                .contributions
                .llm
                .as_ref()
                .map(|runtime| runtime.media_scanner.is_some()),
            #[cfg(any(feature = "llm-tool-runtime", feature = "llm-http-api", test))]
            ApplicationRequirement::LlmToolAudit => self
                .contributions
                .llm
                .as_ref()
                .map(|runtime| runtime.tool_audit.is_some()),
            #[cfg(any(
                feature = "llm-provider-rig",
                feature = "llm-tool-runtime",
                feature = "llm-http-api",
                test
            ))]
            ApplicationRequirement::LlmToolAuthorization => self
                .contributions
                .llm
                .as_ref()
                .map(|runtime| runtime.tool_authorization.is_some()),
            _ => None,
        }
    }

    fn mcp_core_requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            #[cfg(any(feature = "mcp-apps", test))]
            ApplicationRequirement::McpAppsPorts => self
                .contributions
                .mcp_apps
                .as_ref()
                .map(|runtime| runtime.ports.is_some()),
            #[cfg(any(feature = "mcp-transport-http", test))]
            ApplicationRequirement::McpBearerAuthenticator => self
                .contributions
                .mcp_auth
                .as_ref()
                .map(|runtime| runtime.bearer_authenticator.is_some()),
            #[cfg(any(feature = "mcp-tasks", test))]
            ApplicationRequirement::McpCancellationRuntime => self
                .contributions
                .mcp_tasks
                .as_ref()
                .map(|runtime| runtime.cancellation_runtime.is_some()),
            #[cfg(any(feature = "mcp-tasks", test))]
            ApplicationRequirement::McpCapabilityExecutor => self
                .contributions
                .mcp_tasks
                .as_ref()
                .map(|runtime| runtime.capability_executor.is_some()),
            #[cfg(any(feature = "mcp-server-core", test))]
            ApplicationRequirement::McpCapabilityRegistry => self
                .contributions
                .mcp_core
                .as_ref()
                .map(|runtime| runtime.capability_registry.is_some()),
            #[cfg(any(feature = "mcp-auth-enterprise", test))]
            ApplicationRequirement::McpEnterprisePorts => self
                .contributions
                .mcp_enterprise
                .as_ref()
                .map(|runtime| runtime.ports.is_some()),
            _ => None,
        }
    }

    fn mcp_work_requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            #[cfg(any(
                feature = "mcp-subscriptions-local",
                feature = "mcp-subscriptions-redis",
                feature = "mcp-subscriptions-nats",
                test
            ))]
            ApplicationRequirement::McpSubscriptionAuthorizer => self
                .contributions
                .mcp_subscriptions
                .as_ref()
                .map(|runtime| runtime.authorizer.is_some()),
            #[cfg(any(
                feature = "mcp-subscriptions-local",
                feature = "mcp-subscriptions-redis",
                feature = "mcp-subscriptions-nats",
                test
            ))]
            ApplicationRequirement::McpSubscriptionDelivery => self
                .contributions
                .mcp_subscriptions
                .as_ref()
                .map(|runtime| runtime.delivery.is_some()),
            #[cfg(any(
                feature = "mcp-subscriptions-local",
                feature = "mcp-subscriptions-redis",
                feature = "mcp-subscriptions-nats",
                test
            ))]
            ApplicationRequirement::McpSubscriptionRepository => self
                .contributions
                .mcp_subscriptions
                .as_ref()
                .map(|runtime| runtime.repository.is_some()),
            #[cfg(any(
                feature = "mcp-subscriptions-local",
                feature = "mcp-subscriptions-redis",
                feature = "mcp-subscriptions-nats",
                test
            ))]
            ApplicationRequirement::McpSubscriptionRuntime => self
                .contributions
                .mcp_subscriptions
                .as_ref()
                .map(|runtime| runtime.runtime.is_some()),
            #[cfg(any(feature = "mcp-tasks", test))]
            ApplicationRequirement::McpTaskPayloadProtector => self
                .contributions
                .mcp_tasks
                .as_ref()
                .map(|runtime| runtime.payload_protector.is_some()),
            _ => None,
        }
    }

    fn data_requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            #[cfg(any(feature = "outbox", test))]
            ApplicationRequirement::OutboxPublisher => self
                .contributions
                .outbox
                .as_ref()
                .map(|runtime| runtime.publisher.is_some()),
            #[cfg(any(feature = "data-lifecycle", test))]
            ApplicationRequirement::PrivacyAuthorizer => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.authorizer.is_some()),
            #[cfg(any(feature = "consent", test))]
            ApplicationRequirement::PrivacyConsentPolicy => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.consent_policy.is_some()),
            #[cfg(any(feature = "data-lifecycle", test))]
            ApplicationRequirement::PrivacyInventoryAdapters => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.inventory_adapters.is_some()),
            #[cfg(any(feature = "data-lifecycle", test))]
            ApplicationRequirement::PrivacyInventoryManifest => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.inventory_manifest.is_some()),
            #[cfg(any(feature = "data-lifecycle", test))]
            ApplicationRequirement::PrivacyLifecycleHandler => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.lifecycle_handler.is_some()),
            #[cfg(any(feature = "moderation", test))]
            ApplicationRequirement::PrivacyModerationPolicy => self
                .contributions
                .privacy
                .as_ref()
                .map(|runtime| runtime.moderation_policy.is_some()),
            _ => None,
        }
    }

    fn delivery_requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            #[cfg(any(
                feature = "redis-core",
                feature = "events-nats",
                feature = "realtime-core",
                test
            ))]
            ApplicationRequirement::RealtimeEventHandler => self
                .contributions
                .realtime
                .as_ref()
                .map(|runtime| runtime.event_handler.is_some()),
            #[cfg(any(feature = "realtime-core", test))]
            ApplicationRequirement::RealtimeFanoutAuthorizer => self
                .contributions
                .realtime
                .as_ref()
                .map(|runtime| runtime.fanout_authorizer.is_some()),
            #[cfg(any(feature = "realtime-core", test))]
            ApplicationRequirement::RealtimeIdentityRevalidator => self
                .contributions
                .realtime
                .as_ref()
                .map(|runtime| runtime.identity_revalidator.is_some()),
            #[cfg(any(feature = "scheduler", test))]
            ApplicationRequirement::SchedulerEnvelopeFactory => self
                .contributions
                .scheduler
                .as_ref()
                .map(|runtime| runtime.envelope_factory.is_some()),
            #[cfg(any(feature = "search-meilisearch", test))]
            ApplicationRequirement::SearchIndexSchema => self
                .contributions
                .search
                .as_ref()
                .map(|runtime| runtime.index_schema.is_some()),
            #[cfg(any(feature = "search-meilisearch", test))]
            ApplicationRequirement::SearchProjectionResolver => self
                .contributions
                .search
                .as_ref()
                .map(|runtime| runtime.projection_resolver.is_some()),
            #[cfg(any(feature = "search-meilisearch", test))]
            ApplicationRequirement::SearchReauthorizer => self
                .contributions
                .search
                .as_ref()
                .map(|runtime| runtime.reauthorizer.is_some()),
            #[cfg(any(feature = "object-storage", test))]
            ApplicationRequirement::UploadsAuthorization => self
                .contributions
                .uploads
                .as_ref()
                .map(|runtime| runtime.authorization.is_some()),
            #[cfg(any(feature = "object-storage", test))]
            ApplicationRequirement::UploadsWorkflow => self
                .contributions
                .uploads
                .as_ref()
                .map(|runtime| runtime.workflow.is_some()),
            #[cfg(any(feature = "webhooks-inbound", test))]
            ApplicationRequirement::WebhooksInboundHandlers => self
                .contributions
                .webhooks_inbound
                .as_ref()
                .map(|runtime| runtime.handlers.is_some()),
            #[cfg(any(feature = "webhooks-inbound", test))]
            ApplicationRequirement::WebhooksInboundProviderAdapters => self
                .contributions
                .webhooks_inbound
                .as_ref()
                .map(|runtime| runtime.provider_adapters.is_some()),
            #[cfg(any(feature = "webhooks-svix", test))]
            ApplicationRequirement::WebhooksSvixReplayAdmission => self
                .contributions
                .webhooks_svix
                .as_ref()
                .map(|runtime| runtime.replay_admission.is_some()),
            _ => None,
        }
    }

    fn requirement_present(&self, requirement: ApplicationRequirement) -> Option<bool> {
        match requirement {
            ApplicationRequirement::AdminAuthorityResolver
            | ApplicationRequirement::AdminOperationHandler
            | ApplicationRequirement::AuthAuthenticatedRuntime
            | ApplicationRequirement::AuthRedisSessionRuntime
            | ApplicationRequirement::AuthOidcRuntime
            | ApplicationRequirement::AuthOauthRuntime
            | ApplicationRequirement::AuthWebAuthnRuntime
            | ApplicationRequirement::AuthTotpRuntime => {
                self.admin_auth_requirement_present(requirement)
            }
            ApplicationRequirement::BillingProvider
            | ApplicationRequirement::FeatureFlagsExposureRecorder
            | ApplicationRequirement::FeatureFlagsProvider
            | ApplicationRequirement::GraphqlRequestDataInjector
            | ApplicationRequirement::GraphqlSchema
            | ApplicationRequirement::GrpcApplicationService
            | ApplicationRequirement::GrpcAuthenticator
            | ApplicationRequirement::GrpcMethodPolicies
            | ApplicationRequirement::InboxConsumers
            | ApplicationRequirement::JobsHandlers => self.service_requirement_present(requirement),
            ApplicationRequirement::LlmEvaluationRepository
            | ApplicationRequirement::LlmMediaAuthorization
            | ApplicationRequirement::LlmMediaScanner
            | ApplicationRequirement::LlmToolAudit
            | ApplicationRequirement::LlmToolAuthorization => {
                self.llm_requirement_present(requirement)
            }
            ApplicationRequirement::McpAppsPorts
            | ApplicationRequirement::McpBearerAuthenticator
            | ApplicationRequirement::McpCancellationRuntime
            | ApplicationRequirement::McpCapabilityExecutor
            | ApplicationRequirement::McpCapabilityRegistry
            | ApplicationRequirement::McpEnterprisePorts => {
                self.mcp_core_requirement_present(requirement)
            }
            ApplicationRequirement::McpSubscriptionAuthorizer
            | ApplicationRequirement::McpSubscriptionDelivery
            | ApplicationRequirement::McpSubscriptionRepository
            | ApplicationRequirement::McpSubscriptionRuntime
            | ApplicationRequirement::McpTaskPayloadProtector => {
                self.mcp_work_requirement_present(requirement)
            }
            ApplicationRequirement::OutboxPublisher
            | ApplicationRequirement::PrivacyAuthorizer
            | ApplicationRequirement::PrivacyConsentPolicy
            | ApplicationRequirement::PrivacyInventoryAdapters
            | ApplicationRequirement::PrivacyInventoryManifest
            | ApplicationRequirement::PrivacyLifecycleHandler
            | ApplicationRequirement::PrivacyModerationPolicy => {
                self.data_requirement_present(requirement)
            }
            ApplicationRequirement::RealtimeEventHandler
            | ApplicationRequirement::RealtimeFanoutAuthorizer
            | ApplicationRequirement::RealtimeIdentityRevalidator
            | ApplicationRequirement::SchedulerEnvelopeFactory
            | ApplicationRequirement::SearchIndexSchema
            | ApplicationRequirement::SearchProjectionResolver
            | ApplicationRequirement::SearchReauthorizer
            | ApplicationRequirement::UploadsAuthorization
            | ApplicationRequirement::UploadsWorkflow
            | ApplicationRequirement::WebhooksInboundHandlers
            | ApplicationRequirement::WebhooksInboundProviderAdapters
            | ApplicationRequirement::WebhooksSvixReplayAdmission => {
                self.delivery_requirement_present(requirement)
            }
        }
    }

    /// Validates one generated application requirement against its exact typed field.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::MissingContribution`] when the required
    /// runtime family is unavailable, or [`CompositionError::ContractMismatch`]
    /// when that family exists without the required typed port.
    pub fn require(
        &self,
        module: &'static str,
        requirement: ApplicationRequirement,
    ) -> Result<(), CompositionError> {
        match self.application_requirements.get(&requirement).copied() {
            None => Err(CompositionError::MissingContribution {
                module,
                contribution: requirement.as_str(),
            }),
            Some(false) => Err(CompositionError::ContractMismatch {
                kind: "application-requirement",
                id: requirement.as_str(),
            }),
            Some(true) => Ok(()),
        }
    }

    #[cfg(any(
        feature = "web-static",
        feature = "jobs-apalis-redis",
        feature = "jobs-pgmq",
        feature = "outbox",
        feature = "inbox",
        feature = "scheduler",
        feature = "events-nats",
        feature = "events-redis-ephemeral",
        feature = "realtime-core",
        feature = "sse",
        feature = "websockets",
        feature = "object-storage",
        feature = "email",
        feature = "notifications",
        feature = "webhooks-svix",
        feature = "webhooks-inbound",
        feature = "feature-flags",
        feature = "auth-http",
        feature = "auth-oidc",
        feature = "auth-webauthn",
        feature = "auth-totp",
        feature = "mcp-server-core",
        feature = "mcp-transport-http",
        feature = "mcp-auth-oauth",
        feature = "mcp-subscriptions-local",
        feature = "mcp-subscriptions-redis",
        feature = "mcp-subscriptions-nats",
        feature = "mcp-tasks",
        feature = "llm-provider-rig",
        feature = "llm-provider-bedrock",
        feature = "llm-provider-vertex",
        feature = "llm-routing",
        feature = "llm-tool-runtime",
        feature = "llm-media",
        feature = "llm-http-api"
    ))]
    fn prepare_module(&mut self, module: &'static str) -> Result<bool, CompositionError> {
        self.register_capability(module)?;
        if !self.runtime_available(module) {
            return Ok(false);
        }
        if let Some(contract) = self
            .input
            .contracts
            .iter()
            .find(|contract| contract.module == module)
        {
            for requirement in contract.application_requirements {
                self.require(module, *requirement)?;
            }
        }
        Ok(true)
    }

    #[cfg(any(
        feature = "web-static",
        feature = "jobs-apalis-redis",
        feature = "jobs-pgmq",
        feature = "outbox",
        feature = "scheduler",
        feature = "events-nats",
        feature = "events-redis-ephemeral",
        feature = "sse",
        feature = "websockets",
        feature = "object-storage",
        feature = "email",
        feature = "notifications",
        feature = "webhooks-svix",
        feature = "webhooks-inbound",
        feature = "auth-http",
        feature = "auth-oidc",
        feature = "auth-webauthn",
        feature = "auth-totp",
        feature = "mcp-transport-http",
        feature = "mcp-auth-oauth",
        feature = "mcp-subscriptions-local",
        feature = "mcp-subscriptions-redis",
        feature = "mcp-subscriptions-nats",
        feature = "mcp-tasks",
        feature = "llm-provider-rig",
        feature = "llm-provider-bedrock",
        feature = "llm-provider-vertex",
        feature = "llm-routing",
        feature = "llm-tool-runtime",
        feature = "llm-media",
        feature = "llm-http-api"
    ))]
    fn missing_runtime(module: &'static str) -> CompositionError {
        CompositionError::ContractMismatch {
            kind: "runtime",
            id: module,
        }
    }

    #[cfg(feature = "web-static")]
    pub(crate) fn register_web_static(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("web-static")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .web_static_output
            .take()
            .ok_or_else(|| Self::missing_runtime("web-static"))?;
        self.register_router(
            runtime.router,
            &["GET/HEAD /assets/*", "GET/HEAD <spa-fallback>"],
        )
    }

    #[cfg(feature = "jobs-apalis-redis")]
    pub(crate) fn register_jobs_apalis_redis(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("jobs-apalis-redis")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .jobs_apalis_redis_output
            .take()
            .ok_or_else(|| Self::missing_runtime("jobs-apalis-redis"))?;
        self.register_task("job-worker", runtime.worker)?;
        self.register_health("job-backend", runtime.readiness)
    }

    #[cfg(feature = "jobs-pgmq")]
    pub(crate) fn register_jobs_pgmq(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("jobs-pgmq")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .jobs_pgmq_output
            .take()
            .ok_or_else(|| Self::missing_runtime("jobs-pgmq"))?;
        self.register_task("job-worker", runtime.worker)?;
        self.register_health("job-backend", runtime.readiness)
    }

    #[cfg(feature = "outbox")]
    pub(crate) fn register_outbox(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("outbox")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .outbox_output
            .take()
            .ok_or_else(|| Self::missing_runtime("outbox"))?;
        self.register_task("outbox-relay", runtime.task)
    }

    #[cfg(feature = "inbox")]
    pub(crate) fn register_inbox(&mut self) -> Result<(), CompositionError> {
        self.prepare_module("inbox").map(|_| ())
    }

    #[cfg(feature = "scheduler")]
    pub(crate) fn register_scheduler(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("scheduler")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .scheduler_output
            .take()
            .ok_or_else(|| Self::missing_runtime("scheduler"))?;
        self.register_task("scheduler", runtime.task)
    }

    #[cfg(feature = "events-nats")]
    pub(crate) fn register_events_nats(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("events-nats")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .events_nats_output
            .take()
            .ok_or_else(|| Self::missing_runtime("events-nats"))?;
        self.register_task("nats-consumers", runtime.task)?;
        self.register_health("nats-jetstream", runtime.health)
    }

    #[cfg(feature = "events-redis-ephemeral")]
    pub(crate) fn register_events_redis(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("events-redis-ephemeral")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .events_redis_output
            .take()
            .ok_or_else(|| Self::missing_runtime("events-redis-ephemeral"))?;
        self.register_task("redis-pubsub-listener", runtime.task)
    }

    #[cfg(feature = "realtime-core")]
    pub(crate) fn register_realtime_core(&mut self) -> Result<(), CompositionError> {
        self.prepare_module("realtime-core").map(|_| ())
    }

    #[cfg(feature = "sse")]
    pub(crate) fn register_sse(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("sse")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .sse_output
            .take()
            .ok_or_else(|| Self::missing_runtime("sse"))?;
        self.register_router(runtime.router, &["/realtime/events"])
    }

    #[cfg(feature = "websockets")]
    pub(crate) fn register_websockets(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("websockets")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .websockets_output
            .take()
            .ok_or_else(|| Self::missing_runtime("websockets"))?;
        self.register_router(runtime.router, &["/realtime/ws"])
    }

    #[cfg(feature = "object-storage")]
    pub(crate) fn register_object_storage(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("object-storage")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .object_storage_output
            .take()
            .ok_or_else(|| Self::missing_runtime("object-storage"))?;
        self.register_health("object-store", runtime.health)
    }

    #[cfg(feature = "auth-http")]
    pub(crate) fn register_auth_http(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("auth-http")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .auth
            .as_mut()
            .and_then(|runtime| runtime.authenticated_http.take())
            .ok_or_else(|| Self::missing_runtime("auth-http"))?;
        let route_ids = runtime.route_ids();
        let operations = runtime.expected_operations();
        let health = runtime.session_health_check(std::time::Duration::from_secs(5));
        let parts = runtime.into_parts();
        #[cfg(feature = "rate-limit-local")]
        let router = match self.application_rate_limiter() {
            Some(limiter) => crate::modules::rate_limit_local::apply(parts.router, &limiter),
            None => parts.router,
        };
        #[cfg(not(feature = "rate-limit-local"))]
        let router = parts.router;
        self.register_router(router, route_ids)?;
        self.register_health("session-store", health)?;
        self.register_task("session-cleanup", parts.session_cleanup_task)?;
        self.register_expected_operations(operations)?;
        self.register_openapi_fragment(parts.openapi);
        Ok(())
    }

    #[cfg(feature = "email")]
    pub(crate) fn register_email(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("email")? {
            return Ok(());
        }
        let email_job_name = <omnius_email::SendEmailJob as omnius_jobs_core::Job>::NAME;
        let email_job_version = <omnius_email::SendEmailJob as omnius_jobs_core::Job>::VERSION;
        self.contributions
            .jobs
            .as_ref()
            .and_then(|jobs| jobs.handler(email_job_name, email_job_version))
            .ok_or_else(|| Self::missing_runtime("email"))?;
        let runtime = self
            .contributions
            .email_output
            .take()
            .ok_or_else(|| Self::missing_runtime("email"))?;
        self.register_health("email-provider", runtime.health)?;
        self.register_shutdown_hook(runtime.shutdown)
    }

    #[cfg(feature = "notifications")]
    pub(crate) fn register_notifications(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("notifications")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .notifications_output
            .take()
            .ok_or_else(|| Self::missing_runtime("notifications"))?;
        self.register_task("notification-orchestrator", runtime.task)
    }

    #[cfg(feature = "webhooks-svix")]
    pub(crate) fn register_webhooks_svix(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("webhooks-svix")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .webhooks_svix_output
            .take()
            .ok_or_else(|| Self::missing_runtime("webhooks-svix"))?;
        self.register_health("svix", runtime.health)
    }

    #[cfg(feature = "webhooks-inbound")]
    pub(crate) fn register_webhooks_inbound(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("webhooks-inbound")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .webhooks_inbound_output
            .take()
            .ok_or_else(|| Self::missing_runtime("webhooks-inbound"))?;
        self.register_router(runtime.router, &["/webhooks/inbound/{provider}"])?;
        self.register_task("inbound-webhook-processor", runtime.task)
    }

    #[cfg(feature = "feature-flags")]
    pub(crate) fn register_feature_flags(&mut self) -> Result<(), CompositionError> {
        self.prepare_module("feature-flags").map(|_| ())
    }

    #[cfg(feature = "auth-oidc")]
    pub(crate) fn register_auth_oidc(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("auth-oidc")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .auth_oidc_output
            .take()
            .ok_or_else(|| Self::missing_runtime("auth-oidc"))?;
        self.register_router(
            runtime.router,
            &[
                "/auth/oidc/{provider}/start",
                "/auth/oidc/{provider}/callback",
            ],
        )?;
        self.register_task("oidc-pending-authorization-cleanup", runtime.task)
    }

    #[cfg(feature = "auth-webauthn")]
    pub(crate) fn register_auth_webauthn(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("auth-webauthn")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .auth_webauthn_output
            .take()
            .ok_or_else(|| Self::missing_runtime("auth-webauthn"))?;
        self.register_router(
            runtime.router,
            &[
                "/auth/passkeys",
                "/auth/passkeys/register/start",
                "/auth/passkeys/register/finish",
                "/auth/passkeys/authenticate/start",
                "/auth/passkeys/authenticate/finish",
            ],
        )
    }

    #[cfg(feature = "auth-totp")]
    pub(crate) fn register_auth_totp(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("auth-totp")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .auth_totp_output
            .take()
            .ok_or_else(|| Self::missing_runtime("auth-totp"))?;
        self.register_router(
            runtime.router,
            &[
                "/auth/mfa/totp/enroll",
                "/auth/mfa/totp/confirm",
                "/auth/mfa/totp/disable",
            ],
        )
    }

    #[cfg(feature = "mcp-server-core")]
    pub(crate) fn register_mcp_core(&mut self) -> Result<(), CompositionError> {
        self.prepare_module("mcp-server-core").map(|_| ())
    }

    #[cfg(feature = "mcp-transport-http")]
    pub(crate) fn register_mcp_http(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("mcp-transport-http")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .mcp_http_output
            .take()
            .ok_or_else(|| Self::missing_runtime("mcp-transport-http"))?;
        self.register_router(runtime.router, &["POST /mcp"])?;
        self.register_health("mcp-http-dispatch", runtime.health)?;
        self.register_public_operation("mcp.dispatch")
    }

    #[cfg(feature = "mcp-auth-oauth")]
    pub(crate) fn register_mcp_auth_oauth(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("mcp-auth-oauth")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .mcp_auth_oauth_output
            .take()
            .ok_or_else(|| Self::missing_runtime("mcp-auth-oauth"))?;
        self.register_router(
            runtime.router,
            &["GET /.well-known/oauth-protected-resource"],
        )?;
        self.register_public_operation("mcp.oauthProtectedResourceMetadata")
    }

    #[cfg(feature = "mcp-subscriptions-local")]
    pub(crate) fn register_mcp_subscriptions_local(&mut self) -> Result<(), CompositionError> {
        self.register_mcp_subscription_output("mcp-subscriptions-local", |c| {
            c.mcp_subscriptions_local_output.take()
        })
    }

    #[cfg(feature = "mcp-subscriptions-redis")]
    pub(crate) fn register_mcp_subscriptions_redis(&mut self) -> Result<(), CompositionError> {
        self.register_mcp_subscription_output("mcp-subscriptions-redis", |c| {
            c.mcp_subscriptions_redis_output.take()
        })
    }

    #[cfg(feature = "mcp-subscriptions-nats")]
    pub(crate) fn register_mcp_subscriptions_nats(&mut self) -> Result<(), CompositionError> {
        self.register_mcp_subscription_output("mcp-subscriptions-nats", |c| {
            c.mcp_subscriptions_nats_output.take()
        })
    }

    #[cfg(any(
        feature = "mcp-subscriptions-local",
        feature = "mcp-subscriptions-redis",
        feature = "mcp-subscriptions-nats"
    ))]
    fn register_mcp_subscription_output(
        &mut self,
        module: &'static str,
        take: impl FnOnce(&mut ApplicationContributions) -> Option<TaskRuntime>,
    ) -> Result<(), CompositionError> {
        if !self.prepare_module(module)? {
            return Ok(());
        }
        let runtime = take(self.contributions).ok_or_else(|| Self::missing_runtime(module))?;
        self.register_task("mcp-subscription-backplane", runtime.task)
    }

    #[cfg(feature = "mcp-tasks")]
    pub(crate) fn register_mcp_tasks(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("mcp-tasks")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .mcp_tasks_output
            .take()
            .ok_or_else(|| Self::missing_runtime("mcp-tasks"))?;
        self.register_task("mcp-task-expiry", runtime.task)
    }

    #[cfg(feature = "llm-provider-rig")]
    pub(crate) fn register_llm_provider_rig(&mut self) -> Result<(), CompositionError> {
        self.register_llm_health_output(
            "llm-provider-rig",
            "configured-provider-route-availability",
            |c| c.llm_provider_rig_output.take(),
        )
    }

    #[cfg(feature = "llm-provider-bedrock")]
    pub(crate) fn register_llm_provider_bedrock(&mut self) -> Result<(), CompositionError> {
        self.register_llm_health_output("llm-provider-bedrock", "bedrock-route-availability", |c| {
            c.llm_provider_bedrock_output.take()
        })
    }

    #[cfg(feature = "llm-provider-vertex")]
    pub(crate) fn register_llm_provider_vertex(&mut self) -> Result<(), CompositionError> {
        self.register_llm_health_output("llm-provider-vertex", "vertex-route-availability", |c| {
            c.llm_provider_vertex_output.take()
        })
    }

    #[cfg(feature = "llm-routing")]
    pub(crate) fn register_llm_routing(&mut self) -> Result<(), CompositionError> {
        self.register_llm_health_output("llm-routing", "required-route-availability", |c| {
            c.llm_routing_output.take()
        })
    }

    #[cfg(any(
        feature = "llm-provider-rig",
        feature = "llm-provider-bedrock",
        feature = "llm-provider-vertex",
        feature = "llm-routing"
    ))]
    fn register_llm_health_output(
        &mut self,
        module: &'static str,
        health_id: &'static str,
        take: impl FnOnce(&mut ApplicationContributions) -> Option<HealthRuntime>,
    ) -> Result<(), CompositionError> {
        if !self.prepare_module(module)? {
            return Ok(());
        }
        let runtime = take(self.contributions).ok_or_else(|| Self::missing_runtime(module))?;
        self.register_health(health_id, runtime.health)
    }

    #[cfg(feature = "llm-tool-runtime")]
    pub(crate) fn register_llm_tool_runtime(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("llm-tool-runtime")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .llm_tool_runtime_output
            .take()
            .ok_or_else(|| Self::missing_runtime("llm-tool-runtime"))?;
        self.register_task("tool-approval-expiry", runtime.task)
    }

    #[cfg(feature = "llm-media")]
    pub(crate) fn register_llm_media(&mut self) -> Result<(), CompositionError> {
        if !self.prepare_module("llm-media")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .llm_media_output
            .take()
            .ok_or_else(|| Self::missing_runtime("llm-media"))?;
        self.register_task("llm-media-reconciliation", runtime.task)
    }

    #[cfg(feature = "llm-http-api")]
    pub(crate) fn register_llm_http_api(&mut self) -> Result<(), CompositionError> {
        const ROUTES: &[&str] = &[
            "GET /api/ai/routes",
            "POST /api/ai/responses",
            "POST /api/ai/responses/stream",
            "POST /api/ai/jobs",
            "GET /api/ai/jobs/{job_id}",
            "DELETE /api/ai/jobs/{job_id}",
            "GET /api/ai/jobs/{job_id}/result",
            "POST /api/ai/conversations",
            "GET /api/ai/conversations/{conversation_id}",
            "DELETE /api/ai/conversations/{conversation_id}",
            "GET /api/ai/conversations/{conversation_id}/messages",
            "POST /api/ai/conversations/{conversation_id}/messages",
            "PATCH /api/ai/conversations/{conversation_id}/messages/{message_id}",
            "DELETE /api/ai/conversations/{conversation_id}/messages/{message_id}",
            "GET /api/ai/conversations/{conversation_id}/provider-state/{state_id}",
            "PUT /api/ai/conversations/{conversation_id}/provider-state/{state_id}",
            "DELETE /api/ai/conversations/{conversation_id}/provider-state/{state_id}",
        ];
        const OPERATIONS: &[&str] = &[
            "aiRoutesList",
            "aiResponseCreate",
            "aiResponseStream",
            "aiJobSubmit",
            "aiJobGet",
            "aiJobCancel",
            "aiJobResult",
            "aiConversationCreate",
            "aiConversationGet",
            "aiConversationDelete",
            "aiConversationMessagesList",
            "aiConversationMessageAppend",
            "aiConversationMessageUpdate",
            "aiConversationMessageDelete",
            "aiConversationProviderStateGet",
            "aiConversationProviderStatePut",
            "aiConversationProviderStateDelete",
        ];
        if !self.prepare_module("llm-http-api")? {
            return Ok(());
        }
        let runtime = self
            .contributions
            .llm_http_api_output
            .take()
            .ok_or_else(|| Self::missing_runtime("llm-http-api"))?;
        self.register_router(runtime.router, ROUTES)?;
        for operation in OPERATIONS {
            self.register_public_operation(operation)?;
        }
        Ok(())
    }

    /// Mounts a router and records exactly the route IDs it serves.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::DuplicateRegistration`] if any route ID was
    /// already registered.
    pub fn register_router(
        &mut self,
        router: axum::Router,
        route_ids: &'static [&'static str],
    ) -> Result<(), CompositionError> {
        insert_ids(&mut self.route_ids, "route", route_ids)?;
        self.routers.push(router);
        Ok(())
    }

    /// Registers one cached health check and its catalog ID.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::DuplicateRegistration`] if `id` was already
    /// registered as a health check.
    pub fn register_health(
        &mut self,
        id: &'static str,
        spec: omnius_health::HealthCheckSpec,
    ) -> Result<(), CompositionError> {
        if !self.health_ids.insert(id) {
            return Err(CompositionError::DuplicateRegistration { kind: "health", id });
        }
        self.health_specs.push(spec);
        Ok(())
    }

    /// Registers one supervised task and its catalog ID.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::DuplicateRegistration`] if `id` was already
    /// registered as a task.
    pub fn register_task(
        &mut self,
        id: &'static str,
        spec: omnius_runtime::TaskSpec,
    ) -> Result<(), CompositionError> {
        if !self.task_ids.insert(id) {
            return Err(CompositionError::DuplicateRegistration { kind: "task", id });
        }
        self.task_specs.push(spec);
        Ok(())
    }
    /// Maximum number of application-owned shutdown hooks.
    pub const MAX_SHUTDOWN_HOOKS: usize = 32;

    /// Registers one bounded named asynchronous shutdown action.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::DuplicateRegistration`] for duplicate names
    /// or [`CompositionError::CapacityExceeded`] when the fixed bound is full.
    pub fn register_shutdown_hook(&mut self, hook: ShutdownHook) -> Result<(), CompositionError> {
        if self.shutdown_hooks.len() == Self::MAX_SHUTDOWN_HOOKS {
            return Err(CompositionError::CapacityExceeded {
                kind: "shutdown-hook",
                maximum: Self::MAX_SHUTDOWN_HOOKS,
            });
        }
        if self
            .shutdown_hooks
            .iter()
            .any(|existing| existing.name == hook.name)
        {
            return Err(CompositionError::DuplicateRegistration {
                kind: "shutdown-hook",
                id: hook.name,
            });
        }
        self.shutdown_hooks.push(hook);
        Ok(())
    }

    #[cfg(feature = "health")]
    pub(crate) fn register_health_runtime(&mut self) -> Result<(), CompositionError> {
        const ROUTES: &[&str] = &["/live", "/ready", "/startup", "/version"];
        const TASKS: &[&str] = &["health-cache-refresh"];

        if self.health_runtime {
            return Err(CompositionError::DuplicateRegistration {
                kind: "runtime",
                id: "health",
            });
        }
        insert_ids(&mut self.route_ids, "route", ROUTES)?;
        insert_ids(&mut self.task_ids, "task", TASKS)?;
        self.health_runtime = true;
        Ok(())
    }

    /// Records one public operation served by a mounted composition router.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::DuplicateRegistration`] if `operation` was
    /// already registered.
    pub fn register_public_operation(
        &mut self,
        operation: &'static str,
    ) -> Result<(), CompositionError> {
        if !self.public_operations.insert(operation) {
            return Err(CompositionError::DuplicateRegistration {
                kind: "operation",
                id: operation,
            });
        }
        Ok(())
    }

    #[cfg(feature = "openapi")]
    pub(crate) fn register_expected_operations(
        &mut self,
        operations: &[ExpectedOperation],
    ) -> Result<(), CompositionError> {
        for operation in operations {
            self.register_public_operation(operation.operation_id)?;
        }
        self.expected_operations.extend_from_slice(operations);
        Ok(())
    }

    #[cfg(feature = "openapi")]
    pub(crate) fn register_openapi_fragment(&mut self, fragment: serde_json::Value) {
        self.openapi_fragments.push(fragment);
    }

    #[cfg(feature = "openapi")]
    pub(crate) fn install_openapi_catalog(
        &mut self,
        mut document: serde_json::Value,
    ) -> Result<(), CompositionError> {
        const ROUTES: &[&str] = &["/openapi.json", "/docs"];

        let enabled = self.input.contracts.iter().any(|contract| {
            contract.module == "openapi"
                && (!contract.runtime_toggle
                    || !self
                        .input
                        .runtime_disabled_modules
                        .contains(&contract.module))
        });
        if !enabled {
            return Ok(());
        }
        let config =
            self.contributions
                .openapi_config
                .ok_or(CompositionError::MissingContribution {
                    module: "openapi",
                    contribution: "openapi.config",
                })?;
        if !config.document_route_enabled || !config.docs_route_enabled {
            return Err(CompositionError::InvalidConfiguration { module: "openapi" });
        }
        for fragment in &self.openapi_fragments {
            merge_openapi_fragment(&mut document, fragment)?;
        }
        omnius_openapi::validate_operation_coverage_value(&document, &self.expected_operations)
            .map_err(|error| CompositionError::construction("openapi", error))?;
        let catalog = omnius_openapi::OpenApiCatalog::try_from_value(document, config)
            .map_err(|error| CompositionError::construction("openapi", error))?;
        self.register_router(catalog.router(), ROUTES)
    }

    /// Validates application requirements and catalog-to-runtime registration.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] for missing application policy, duplicate
    /// registrations, or any declared route/task/health contract that was not
    /// actually registered.
    pub fn finish(self) -> Result<ComposedApplication, CompositionError> {
        let builder = self;
        for contract in builder.input.contracts {
            let enabled = !contract.runtime_toggle
                || !builder
                    .input
                    .runtime_disabled_modules
                    .contains(&contract.module);
            if !enabled {
                continue;
            }
            for requirement in contract.application_requirements {
                builder.require(contract.module, *requirement)?;
            }
        }
        validate_contract_ids(
            builder.input.contracts,
            builder.input.runtime_disabled_modules,
            "route",
            |contract| contract.routes,
            &builder.route_ids,
        )?;
        validate_contract_ids(
            builder.input.contracts,
            builder.input.runtime_disabled_modules,
            "task",
            |contract| contract.tasks,
            &builder.task_ids,
        )?;
        validate_contract_ids(
            builder.input.contracts,
            builder.input.runtime_disabled_modules,
            "health",
            |contract| contract.health_checks,
            &builder.health_ids,
        )?;
        let router = builder
            .routers
            .into_iter()
            .fold(axum::Router::new(), axum::Router::merge);
        Ok(ComposedApplication {
            router,
            health_runtime: builder.health_runtime,
            health_specs: builder.health_specs,
            task_specs: builder.task_specs,
            shutdown_hooks: builder.shutdown_hooks,
            public_operations: builder.public_operations,
            capabilities: builder.capabilities,
        })
    }
}
#[cfg(feature = "openapi")]
fn merge_openapi_fragment(
    document: &mut serde_json::Value,
    fragment: &serde_json::Value,
) -> Result<(), CompositionError> {
    let target = document
        .as_object_mut()
        .ok_or(CompositionError::InvalidConfiguration { module: "openapi" })?;
    let source = fragment
        .as_object()
        .ok_or(CompositionError::InvalidConfiguration { module: "openapi" })?;
    for section in ["paths", "components"] {
        let Some(source_section) = source.get(section).and_then(serde_json::Value::as_object)
        else {
            continue;
        };
        let target_section = target
            .entry(section)
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
            .as_object_mut()
            .ok_or(CompositionError::InvalidConfiguration { module: "openapi" })?;
        merge_openapi_object(target_section, source_section)?;
    }
    Ok(())
}

#[cfg(feature = "openapi")]
fn merge_openapi_object(
    target: &mut serde_json::Map<String, serde_json::Value>,
    source: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), CompositionError> {
    for (key, value) in source {
        if target.get(key) == Some(value) {
            continue;
        }
        if let Some(existing) = target.get_mut(key) {
            let target_nested = existing
                .as_object_mut()
                .ok_or(CompositionError::InvalidConfiguration { module: "openapi" })?;
            let source_nested = value
                .as_object()
                .ok_or(CompositionError::InvalidConfiguration { module: "openapi" })?;
            merge_openapi_object(target_nested, source_nested)?;
        } else {
            target.insert(key.clone(), value.clone());
        }
    }
    Ok(())
}

#[cfg(any(feature = "core", test))]
fn insert_ids(
    target: &mut BTreeSet<&'static str>,
    kind: &'static str,
    ids: &'static [&'static str],
) -> Result<(), CompositionError> {
    for id in ids {
        if !target.insert(id) {
            return Err(CompositionError::DuplicateRegistration { kind, id });
        }
    }
    Ok(())
}

#[cfg(any(feature = "core", test))]
fn validate_contract_ids(
    contracts: &'static [SelectedModuleContract],
    disabled_modules: &'static [&'static str],
    kind: &'static str,
    ids: impl Fn(&SelectedModuleContract) -> &'static [&'static str],
    registered: &BTreeSet<&'static str>,
) -> Result<(), CompositionError> {
    for contract in contracts {
        if contract.runtime_toggle && disabled_modules.contains(&contract.module) {
            continue;
        }
        for id in ids(contract) {
            if !registered.contains(id) {
                return Err(CompositionError::ContractMismatch { kind, id });
            }
        }
    }
    Ok(())
}
