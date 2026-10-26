#[cfg(all(feature = "http", feature = "rate-limit-local"))]
use std::time::Duration;
use std::{future::Future, pin::Pin, sync::Arc};

#[cfg(feature = "http")]
use axum::Router;
#[cfg(feature = "http")]
use serde::Deserialize;

use super::*;

struct ContractProbe;

impl AdminAuthorityResolverPort for ContractProbe {
    fn authorizes(&self, principal: &str, action: &str) -> bool {
        !principal.is_empty() && !action.is_empty()
    }
}
impl AdminOperationHandlerPort for ContractProbe {
    fn execute(&self, operation: &str) -> bool {
        !operation.is_empty()
    }
}
impl RedisSessionRuntimePort for ContractProbe {
    fn session_is_live(&self, session_id: &str) -> bool {
        !session_id.is_empty()
    }
}
impl OidcRuntimePort for ContractProbe {
    fn supports_provider(&self, provider: &str) -> bool {
        !provider.is_empty()
    }
}
impl OauthRuntimePort for ContractProbe {
    fn authorizes_client_scope(&self, client_id: &str, scope: &str) -> bool {
        !client_id.is_empty() && !scope.is_empty()
    }
}
impl WebauthnRuntimePort for ContractProbe {
    fn accepts_origin(&self, origin: &str) -> bool {
        origin.starts_with("https://")
    }
}
impl TotpRuntimePort for ContractProbe {
    fn verifies_code(&self, subject: &str, code: &str) -> bool {
        !subject.is_empty() && code.len() == 6
    }
}
impl omnius_jobs_core::JobHandler for ContractProbe {
    fn job_name(&self) -> &'static str {
        "contract.probe"
    }

    fn job_version(&self) -> u16 {
        1
    }

    fn metrics_prefix(&self) -> &'static str {
        "contract_probe"
    }

    fn runbook(&self) -> &'static str {
        "runbooks/contract-probe"
    }

    fn handle(
        &self,
        _envelope: omnius_jobs_core::EncodedJobEnvelope,
        _context: omnius_jobs_core::DeliveryContext,
    ) -> Pin<Box<dyn Future<Output = omnius_jobs_core::HandlerOutcome> + Send + '_>> {
        Box::pin(async { omnius_jobs_core::HandlerOutcome::Succeeded })
    }
}
impl OutboxPublisherPort for ContractProbe {
    fn publish(&self, event_id: &str, payload: &[u8]) -> bool {
        !event_id.is_empty() && !payload.is_empty()
    }
}
impl InboxConsumersPort for ContractProbe {
    fn consume(&self, message_name: &str, payload: &[u8]) -> bool {
        !message_name.is_empty() && !payload.is_empty()
    }
}
impl SchedulerEnvelopeFactoryPort for ContractProbe {
    fn envelope(&self, schedule_id: &str, occurrence: u64) -> Option<Vec<u8>> {
        (!schedule_id.is_empty()).then(|| occurrence.to_be_bytes().to_vec())
    }
}
impl RealtimeFanoutAuthorizerPort for ContractProbe {
    fn authorizes_fanout(&self, subject: &str, topic: &str) -> bool {
        !subject.is_empty() && !topic.is_empty()
    }
}
impl RealtimeIdentityRevalidatorPort for ContractProbe {
    fn identity_is_live(&self, subject: &str) -> bool {
        !subject.is_empty()
    }
}
impl RealtimeEventHandlerPort for ContractProbe {
    fn handle_event(&self, event_name: &str, payload: &[u8]) -> bool {
        !event_name.is_empty() && !payload.is_empty()
    }
}
impl UploadWorkflowPort for ContractProbe {
    fn advance(&self, upload_id: &str, transition: &str) -> bool {
        !upload_id.is_empty() && !transition.is_empty()
    }
}
impl UploadAuthorizationPort for ContractProbe {
    fn authorizes_upload(&self, subject: &str, upload_id: &str, operation: &str) -> bool {
        !subject.is_empty() && !upload_id.is_empty() && !operation.is_empty()
    }
}
impl WebhooksSvixReplayAdmissionPort for ContractProbe {
    fn admit_replay(&self, event_id: &str) -> bool {
        !event_id.is_empty()
    }
}
impl WebhooksInboundProviderAdaptersPort for ContractProbe {
    fn supports_provider(&self, provider: &str) -> bool {
        !provider.is_empty()
    }
}
impl WebhooksInboundHandlersPort for ContractProbe {
    fn handle_webhook(&self, provider: &str, event_id: &str, payload: &[u8]) -> bool {
        !provider.is_empty() && !event_id.is_empty() && !payload.is_empty()
    }
}
impl FeatureFlagProviderPort for ContractProbe {
    fn enabled(&self, flag: &str, subject: &str) -> bool {
        !flag.is_empty() && !subject.is_empty()
    }
}
impl FeatureFlagExposureRecorderPort for ContractProbe {
    fn record_exposure(&self, flag: &str, subject: &str, _enabled: bool) -> bool {
        !flag.is_empty() && !subject.is_empty()
    }
}
impl SearchIndexSchemaPort for ContractProbe {
    fn schema_digest(&self, index: &str) -> Option<String> {
        (!index.is_empty()).then(|| "digest".to_owned())
    }
}
impl SearchReauthorizerPort for ContractProbe {
    fn reauthorize(&self, subject: &str, source_id: &str) -> bool {
        !subject.is_empty() && !source_id.is_empty()
    }
}
impl SearchProjectionResolverPort for ContractProbe {
    fn projection(&self, source_id: &str) -> Option<Vec<u8>> {
        (!source_id.is_empty()).then(|| source_id.as_bytes().to_vec())
    }
}
impl BillingProviderPort for ContractProbe {
    fn execute_billing(&self, account_id: &str, operation: &str) -> bool {
        !account_id.is_empty() && !operation.is_empty()
    }
}
impl GraphqlSchemaPort for ContractProbe {
    fn declares_field(&self, field: &str) -> bool {
        !field.is_empty()
    }
}
impl GraphqlRequestDataInjectorPort for ContractProbe {
    fn inject_request_data(&self, subject: &str) -> bool {
        !subject.is_empty()
    }
}
impl GrpcApplicationServicePort for ContractProbe {
    fn execute_method(&self, method: &str, payload: &[u8]) -> bool {
        !method.is_empty() && !payload.is_empty()
    }
}
impl GrpcAuthenticatorPort for ContractProbe {
    fn authenticate_metadata(&self, authorization: &str) -> Option<String> {
        (!authorization.is_empty()).then(|| "subject".to_owned())
    }
}
impl GrpcMethodPoliciesPort for ContractProbe {
    fn authorizes_method(&self, subject: &str, method: &str) -> bool {
        !subject.is_empty() && !method.is_empty()
    }
}
impl PrivacyInventoryManifestPort for ContractProbe {
    fn manifest_digest(&self) -> String {
        "manifest-digest".to_owned()
    }
}
impl PrivacyInventoryAdaptersPort for ContractProbe {
    fn inventory(&self, data_class: &str) -> Option<Vec<u8>> {
        (!data_class.is_empty()).then(|| data_class.as_bytes().to_vec())
    }
}
impl PrivacyAuthorizerPort for ContractProbe {
    fn authorizes_privacy(&self, subject: &str, operation: &str) -> bool {
        !subject.is_empty() && !operation.is_empty()
    }
}
impl PrivacyLifecycleHandlerPort for ContractProbe {
    fn execute_lifecycle(&self, request_id: &str, operation: &str) -> bool {
        !request_id.is_empty() && !operation.is_empty()
    }
}
impl PrivacyConsentPolicyPort for ContractProbe {
    fn has_consent(&self, subject: &str, purpose: &str) -> bool {
        !subject.is_empty() && !purpose.is_empty()
    }
}
impl PrivacyModerationPolicyPort for ContractProbe {
    fn permits_content(&self, subject: &str, content: &[u8]) -> bool {
        !subject.is_empty() && !content.is_empty()
    }
}
impl LlmToolAuthorizationPort for ContractProbe {
    fn authorizes_tool(&self, subject: &str, tool: &str) -> bool {
        !subject.is_empty() && !tool.is_empty()
    }
}
impl LlmToolAuditPort for ContractProbe {
    fn record_tool_outcome(&self, invocation_id: &str, _succeeded: bool) -> bool {
        !invocation_id.is_empty()
    }
}
impl LlmMediaScannerPort for ContractProbe {
    fn scans_clean(&self, media_id: &str, bytes: &[u8]) -> bool {
        !media_id.is_empty() && !bytes.is_empty()
    }
}
impl LlmMediaAuthorizationPort for ContractProbe {
    fn authorizes_media(&self, subject: &str, media_id: &str, operation: &str) -> bool {
        !subject.is_empty() && !media_id.is_empty() && !operation.is_empty()
    }
}
impl LlmEvaluationRepositoryPort for ContractProbe {
    fn store_evaluation(&self, evaluation_id: &str, report: &[u8]) -> bool {
        !evaluation_id.is_empty() && !report.is_empty()
    }
}
impl McpCapabilityRegistryPort for ContractProbe {
    fn contains_capability(&self, capability: &str) -> bool {
        !capability.is_empty()
    }
}
impl McpBearerAuthenticatorPort for ContractProbe {
    fn authenticate_bearer(&self, credential: &str) -> Option<String> {
        (!credential.is_empty()).then(|| "subject".to_owned())
    }
}
impl McpEnterprisePorts for ContractProbe {
    fn authorizes_enterprise(&self, subject: &str, operation: &str) -> bool {
        !subject.is_empty() && !operation.is_empty()
    }
}
impl McpSubscriptionRepositoryPort for ContractProbe {
    fn store_subscription(&self, subscription_id: &str) -> bool {
        !subscription_id.is_empty()
    }
}
impl McpSubscriptionAuthorizerPort for ContractProbe {
    fn authorizes_subscription(&self, subject: &str, task_id: &str) -> bool {
        !subject.is_empty() && !task_id.is_empty()
    }
}
impl McpSubscriptionRuntimePort for ContractProbe {
    fn arm_subscription(&self, subscription_id: &str) -> bool {
        !subscription_id.is_empty()
    }
}
impl McpSubscriptionDeliveryPort for ContractProbe {
    fn deliver_subscription(&self, subscription_id: &str, frame: &[u8]) -> bool {
        !subscription_id.is_empty() && !frame.is_empty()
    }
}
impl McpTaskPayloadProtectorPort for ContractProbe {
    fn seal_payload(&self, task_id: &str, payload: &[u8]) -> Option<Vec<u8>> {
        (!task_id.is_empty() && !payload.is_empty()).then(|| payload.to_vec())
    }
}
impl McpCancellationRuntimePort for ContractProbe {
    fn cancel_task(&self, task_id: &str) -> bool {
        !task_id.is_empty()
    }
}
impl McpCapabilityExecutorPort for ContractProbe {
    fn execute_capability(&self, capability: &str, payload: &[u8]) -> bool {
        !capability.is_empty() && !payload.is_empty()
    }
}
impl McpAppsPorts for ContractProbe {
    fn admit_app_action(&self, app_id: &str, action: &str) -> bool {
        !app_id.is_empty() && !action.is_empty()
    }
}

fn present_admin_auth(
    requirement: ApplicationRequirement,
    probe: Arc<ContractProbe>,
) -> ApplicationContributions {
    match requirement {
        ApplicationRequirement::AdminAuthorityResolver => ApplicationContributions::new()
            .with_admin_runtime(AdminRuntime::default().with_authority_resolver(probe)),
        ApplicationRequirement::AdminOperationHandler => ApplicationContributions::new()
            .with_admin_runtime(AdminRuntime::default().with_operation_handler(probe)),
        ApplicationRequirement::AuthAuthenticatedRuntime => {
            unreachable!("concrete authenticated HTTP construction has focused integration tests")
        }
        ApplicationRequirement::AuthRedisSessionRuntime => ApplicationContributions::new()
            .with_auth_runtime(AuthRuntime::default().with_redis_session_runtime(probe)),
        ApplicationRequirement::AuthOidcRuntime => ApplicationContributions::new()
            .with_auth_runtime(AuthRuntime::default().with_oidc_runtime(probe)),
        ApplicationRequirement::AuthOauthRuntime => ApplicationContributions::new()
            .with_auth_runtime(AuthRuntime::default().with_oauth_runtime(probe)),
        ApplicationRequirement::AuthWebAuthnRuntime => ApplicationContributions::new()
            .with_auth_runtime(AuthRuntime::default().with_webauthn_runtime(probe)),
        ApplicationRequirement::AuthTotpRuntime => ApplicationContributions::new()
            .with_auth_runtime(AuthRuntime::default().with_totp_runtime(probe)),
        _ => unreachable!("admin/auth requirement family dispatch must be exact"),
    }
}

#[expect(
    clippy::expect_used,
    reason = "single fixed handler insertion in test fixture"
)]
fn present_service(
    requirement: ApplicationRequirement,
    probe: Arc<ContractProbe>,
) -> ApplicationContributions {
    match requirement {
        ApplicationRequirement::BillingProvider => ApplicationContributions::new()
            .with_billing_runtime(BillingRuntime::default().with_provider(probe)),
        ApplicationRequirement::FeatureFlagsExposureRecorder => ApplicationContributions::new()
            .with_feature_flags_runtime(
                FeatureFlagsRuntime::default().with_exposure_recorder(probe),
            ),
        ApplicationRequirement::FeatureFlagsProvider => ApplicationContributions::new()
            .with_feature_flags_runtime(FeatureFlagsRuntime::default().with_provider(probe)),
        ApplicationRequirement::GraphqlRequestDataInjector => ApplicationContributions::new()
            .with_graphql_runtime(GraphqlRuntime::default().with_request_data_injector(probe)),
        ApplicationRequirement::GraphqlSchema => ApplicationContributions::new()
            .with_graphql_runtime(GraphqlRuntime::default().with_schema(probe)),
        ApplicationRequirement::GrpcApplicationService => ApplicationContributions::new()
            .with_grpc_runtime(GrpcRuntime::default().with_application_service(probe)),
        ApplicationRequirement::GrpcAuthenticator => ApplicationContributions::new()
            .with_grpc_runtime(GrpcRuntime::default().with_authenticator(probe)),
        ApplicationRequirement::GrpcMethodPolicies => ApplicationContributions::new()
            .with_grpc_runtime(GrpcRuntime::default().with_method_policies(probe)),
        ApplicationRequirement::InboxConsumers => ApplicationContributions::new()
            .with_inbox_runtime(InboxRuntime::default().with_consumers(probe)),
        ApplicationRequirement::JobsHandlers => ApplicationContributions::new().with_jobs_runtime(
            JobsRuntime::default()
                .with_handler(probe)
                .expect("probe handler must be unique"),
        ),
        _ => unreachable!("service requirement family dispatch must be exact"),
    }
}

fn present_llm(
    requirement: ApplicationRequirement,
    probe: Arc<ContractProbe>,
) -> ApplicationContributions {
    match requirement {
        ApplicationRequirement::LlmEvaluationRepository => ApplicationContributions::new()
            .with_llm_runtime(LlmRuntime::default().with_evaluation_repository(probe)),
        ApplicationRequirement::LlmMediaAuthorization => ApplicationContributions::new()
            .with_llm_runtime(LlmRuntime::default().with_media_authorization(probe)),
        ApplicationRequirement::LlmMediaScanner => ApplicationContributions::new()
            .with_llm_runtime(LlmRuntime::default().with_media_scanner(probe)),
        ApplicationRequirement::LlmToolAudit => ApplicationContributions::new()
            .with_llm_runtime(LlmRuntime::default().with_tool_audit(probe)),
        ApplicationRequirement::LlmToolAuthorization => ApplicationContributions::new()
            .with_llm_runtime(LlmRuntime::default().with_tool_authorization(probe)),
        _ => unreachable!("LLM requirement family dispatch must be exact"),
    }
}

fn present_mcp_core(
    requirement: ApplicationRequirement,
    probe: Arc<ContractProbe>,
) -> ApplicationContributions {
    match requirement {
        ApplicationRequirement::McpAppsPorts => ApplicationContributions::new()
            .with_mcp_apps_runtime(McpAppsRuntime::default().with_ports(probe)),
        ApplicationRequirement::McpBearerAuthenticator => ApplicationContributions::new()
            .with_mcp_auth_runtime(McpAuthRuntime::default().with_bearer_authenticator(probe)),
        ApplicationRequirement::McpCancellationRuntime => ApplicationContributions::new()
            .with_mcp_tasks_runtime(McpTasksRuntime::default().with_cancellation_runtime(probe)),
        ApplicationRequirement::McpCapabilityExecutor => ApplicationContributions::new()
            .with_mcp_tasks_runtime(McpTasksRuntime::default().with_capability_executor(probe)),
        ApplicationRequirement::McpCapabilityRegistry => ApplicationContributions::new()
            .with_mcp_core_runtime(McpCoreRuntime::default().with_capability_registry(probe)),
        ApplicationRequirement::McpEnterprisePorts => ApplicationContributions::new()
            .with_mcp_enterprise_runtime(McpEnterpriseRuntime::default().with_ports(probe)),
        _ => unreachable!("MCP core requirement family dispatch must be exact"),
    }
}

fn present_mcp_work(
    requirement: ApplicationRequirement,
    probe: Arc<ContractProbe>,
) -> ApplicationContributions {
    match requirement {
        ApplicationRequirement::McpSubscriptionAuthorizer => ApplicationContributions::new()
            .with_mcp_subscriptions_runtime(
                McpSubscriptionsRuntime::default().with_authorizer(probe),
            ),
        ApplicationRequirement::McpSubscriptionDelivery => ApplicationContributions::new()
            .with_mcp_subscriptions_runtime(
                McpSubscriptionsRuntime::default().with_delivery(probe),
            ),
        ApplicationRequirement::McpSubscriptionRepository => ApplicationContributions::new()
            .with_mcp_subscriptions_runtime(
                McpSubscriptionsRuntime::default().with_repository(probe),
            ),
        ApplicationRequirement::McpSubscriptionRuntime => ApplicationContributions::new()
            .with_mcp_subscriptions_runtime(McpSubscriptionsRuntime::default().with_runtime(probe)),
        ApplicationRequirement::McpTaskPayloadProtector => ApplicationContributions::new()
            .with_mcp_tasks_runtime(McpTasksRuntime::default().with_payload_protector(probe)),
        _ => unreachable!("MCP work requirement family dispatch must be exact"),
    }
}

fn present_data(
    requirement: ApplicationRequirement,
    probe: Arc<ContractProbe>,
) -> ApplicationContributions {
    match requirement {
        ApplicationRequirement::OutboxPublisher => ApplicationContributions::new()
            .with_outbox_runtime(OutboxRuntime::default().with_publisher(probe)),
        ApplicationRequirement::PrivacyAuthorizer => ApplicationContributions::new()
            .with_privacy_runtime(PrivacyRuntime::default().with_authorizer(probe)),
        ApplicationRequirement::PrivacyConsentPolicy => ApplicationContributions::new()
            .with_privacy_runtime(PrivacyRuntime::default().with_consent_policy(probe)),
        ApplicationRequirement::PrivacyInventoryAdapters => ApplicationContributions::new()
            .with_privacy_runtime(PrivacyRuntime::default().with_inventory_adapters(probe)),
        ApplicationRequirement::PrivacyInventoryManifest => ApplicationContributions::new()
            .with_privacy_runtime(PrivacyRuntime::default().with_inventory_manifest(probe)),
        ApplicationRequirement::PrivacyLifecycleHandler => ApplicationContributions::new()
            .with_privacy_runtime(PrivacyRuntime::default().with_lifecycle_handler(probe)),
        ApplicationRequirement::PrivacyModerationPolicy => ApplicationContributions::new()
            .with_privacy_runtime(PrivacyRuntime::default().with_moderation_policy(probe)),
        _ => unreachable!("data requirement family dispatch must be exact"),
    }
}

fn present_delivery(
    requirement: ApplicationRequirement,
    probe: Arc<ContractProbe>,
) -> ApplicationContributions {
    match requirement {
        ApplicationRequirement::RealtimeEventHandler => ApplicationContributions::new()
            .with_realtime_runtime(RealtimeRuntime::default().with_event_handler(probe)),
        ApplicationRequirement::RealtimeFanoutAuthorizer => ApplicationContributions::new()
            .with_realtime_runtime(RealtimeRuntime::default().with_fanout_authorizer(probe)),
        ApplicationRequirement::RealtimeIdentityRevalidator => ApplicationContributions::new()
            .with_realtime_runtime(RealtimeRuntime::default().with_identity_revalidator(probe)),
        ApplicationRequirement::SchedulerEnvelopeFactory => ApplicationContributions::new()
            .with_scheduler_runtime(SchedulerRuntime::default().with_envelope_factory(probe)),
        ApplicationRequirement::SearchIndexSchema => ApplicationContributions::new()
            .with_search_runtime(SearchRuntime::default().with_index_schema(probe)),
        ApplicationRequirement::SearchProjectionResolver => ApplicationContributions::new()
            .with_search_runtime(SearchRuntime::default().with_projection_resolver(probe)),
        ApplicationRequirement::SearchReauthorizer => ApplicationContributions::new()
            .with_search_runtime(SearchRuntime::default().with_reauthorizer(probe)),
        ApplicationRequirement::UploadsAuthorization => ApplicationContributions::new()
            .with_uploads_runtime(UploadsRuntime::default().with_authorization(probe)),
        ApplicationRequirement::UploadsWorkflow => ApplicationContributions::new()
            .with_uploads_runtime(UploadsRuntime::default().with_workflow(probe)),
        ApplicationRequirement::WebhooksInboundHandlers => ApplicationContributions::new()
            .with_webhooks_inbound_runtime(WebhooksInboundRuntime::default().with_handlers(probe)),
        ApplicationRequirement::WebhooksInboundProviderAdapters => ApplicationContributions::new()
            .with_webhooks_inbound_runtime(
                WebhooksInboundRuntime::default().with_provider_adapters(probe),
            ),
        ApplicationRequirement::WebhooksSvixReplayAdmission => ApplicationContributions::new()
            .with_webhooks_svix_runtime(
                WebhooksSvixRuntime::default().with_replay_admission(probe),
            ),
        _ => unreachable!("delivery requirement family dispatch must be exact"),
    }
}

fn present(requirement: ApplicationRequirement) -> ApplicationContributions {
    let probe = Arc::new(ContractProbe);
    match requirement {
        ApplicationRequirement::AdminAuthorityResolver
        | ApplicationRequirement::AdminOperationHandler
        | ApplicationRequirement::AuthAuthenticatedRuntime
        | ApplicationRequirement::AuthRedisSessionRuntime
        | ApplicationRequirement::AuthOidcRuntime
        | ApplicationRequirement::AuthOauthRuntime
        | ApplicationRequirement::AuthWebAuthnRuntime
        | ApplicationRequirement::AuthTotpRuntime => present_admin_auth(requirement, probe),
        ApplicationRequirement::BillingProvider
        | ApplicationRequirement::FeatureFlagsExposureRecorder
        | ApplicationRequirement::FeatureFlagsProvider
        | ApplicationRequirement::GraphqlRequestDataInjector
        | ApplicationRequirement::GraphqlSchema
        | ApplicationRequirement::GrpcApplicationService
        | ApplicationRequirement::GrpcAuthenticator
        | ApplicationRequirement::GrpcMethodPolicies
        | ApplicationRequirement::InboxConsumers
        | ApplicationRequirement::JobsHandlers => present_service(requirement, probe),
        ApplicationRequirement::LlmEvaluationRepository
        | ApplicationRequirement::LlmMediaAuthorization
        | ApplicationRequirement::LlmMediaScanner
        | ApplicationRequirement::LlmToolAudit
        | ApplicationRequirement::LlmToolAuthorization => present_llm(requirement, probe),
        ApplicationRequirement::McpAppsPorts
        | ApplicationRequirement::McpBearerAuthenticator
        | ApplicationRequirement::McpCancellationRuntime
        | ApplicationRequirement::McpCapabilityExecutor
        | ApplicationRequirement::McpCapabilityRegistry
        | ApplicationRequirement::McpEnterprisePorts => present_mcp_core(requirement, probe),
        ApplicationRequirement::McpSubscriptionAuthorizer
        | ApplicationRequirement::McpSubscriptionDelivery
        | ApplicationRequirement::McpSubscriptionRepository
        | ApplicationRequirement::McpSubscriptionRuntime
        | ApplicationRequirement::McpTaskPayloadProtector => present_mcp_work(requirement, probe),
        ApplicationRequirement::OutboxPublisher
        | ApplicationRequirement::PrivacyAuthorizer
        | ApplicationRequirement::PrivacyConsentPolicy
        | ApplicationRequirement::PrivacyInventoryAdapters
        | ApplicationRequirement::PrivacyInventoryManifest
        | ApplicationRequirement::PrivacyLifecycleHandler
        | ApplicationRequirement::PrivacyModerationPolicy => present_data(requirement, probe),
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
            present_delivery(requirement, probe)
        }
    }
}

fn malformed(requirement: ApplicationRequirement) -> ApplicationContributions {
    match requirement {
        ApplicationRequirement::AdminAuthorityResolver
        | ApplicationRequirement::AdminOperationHandler => {
            ApplicationContributions::new().with_admin_runtime(AdminRuntime::default())
        }
        ApplicationRequirement::AuthAuthenticatedRuntime
        | ApplicationRequirement::AuthRedisSessionRuntime
        | ApplicationRequirement::AuthOidcRuntime
        | ApplicationRequirement::AuthOauthRuntime
        | ApplicationRequirement::AuthWebAuthnRuntime
        | ApplicationRequirement::AuthTotpRuntime => {
            ApplicationContributions::new().with_auth_runtime(AuthRuntime::default())
        }
        ApplicationRequirement::BillingProvider => {
            ApplicationContributions::new().with_billing_runtime(BillingRuntime::default())
        }
        ApplicationRequirement::FeatureFlagsExposureRecorder
        | ApplicationRequirement::FeatureFlagsProvider => ApplicationContributions::new()
            .with_feature_flags_runtime(FeatureFlagsRuntime::default()),
        ApplicationRequirement::GraphqlRequestDataInjector
        | ApplicationRequirement::GraphqlSchema => {
            ApplicationContributions::new().with_graphql_runtime(GraphqlRuntime::default())
        }
        ApplicationRequirement::GrpcApplicationService
        | ApplicationRequirement::GrpcAuthenticator
        | ApplicationRequirement::GrpcMethodPolicies => {
            ApplicationContributions::new().with_grpc_runtime(GrpcRuntime::default())
        }
        ApplicationRequirement::InboxConsumers => {
            ApplicationContributions::new().with_inbox_runtime(InboxRuntime::default())
        }
        ApplicationRequirement::JobsHandlers => {
            ApplicationContributions::new().with_jobs_runtime(JobsRuntime::default())
        }
        ApplicationRequirement::LlmEvaluationRepository
        | ApplicationRequirement::LlmMediaAuthorization
        | ApplicationRequirement::LlmMediaScanner
        | ApplicationRequirement::LlmToolAudit
        | ApplicationRequirement::LlmToolAuthorization => {
            ApplicationContributions::new().with_llm_runtime(LlmRuntime::default())
        }
        ApplicationRequirement::McpAppsPorts => {
            ApplicationContributions::new().with_mcp_apps_runtime(McpAppsRuntime::default())
        }
        ApplicationRequirement::McpBearerAuthenticator => {
            ApplicationContributions::new().with_mcp_auth_runtime(McpAuthRuntime::default())
        }
        ApplicationRequirement::McpCapabilityRegistry => {
            ApplicationContributions::new().with_mcp_core_runtime(McpCoreRuntime::default())
        }
        ApplicationRequirement::McpEnterprisePorts => ApplicationContributions::new()
            .with_mcp_enterprise_runtime(McpEnterpriseRuntime::default()),
        ApplicationRequirement::McpSubscriptionAuthorizer
        | ApplicationRequirement::McpSubscriptionDelivery
        | ApplicationRequirement::McpSubscriptionRepository
        | ApplicationRequirement::McpSubscriptionRuntime => ApplicationContributions::new()
            .with_mcp_subscriptions_runtime(McpSubscriptionsRuntime::default()),
        ApplicationRequirement::McpCancellationRuntime
        | ApplicationRequirement::McpCapabilityExecutor
        | ApplicationRequirement::McpTaskPayloadProtector => {
            ApplicationContributions::new().with_mcp_tasks_runtime(McpTasksRuntime::default())
        }
        ApplicationRequirement::OutboxPublisher => {
            ApplicationContributions::new().with_outbox_runtime(OutboxRuntime::default())
        }
        ApplicationRequirement::PrivacyAuthorizer
        | ApplicationRequirement::PrivacyConsentPolicy
        | ApplicationRequirement::PrivacyInventoryAdapters
        | ApplicationRequirement::PrivacyInventoryManifest
        | ApplicationRequirement::PrivacyLifecycleHandler
        | ApplicationRequirement::PrivacyModerationPolicy => {
            ApplicationContributions::new().with_privacy_runtime(PrivacyRuntime::default())
        }
        ApplicationRequirement::RealtimeEventHandler
        | ApplicationRequirement::RealtimeFanoutAuthorizer
        | ApplicationRequirement::RealtimeIdentityRevalidator => {
            ApplicationContributions::new().with_realtime_runtime(RealtimeRuntime::default())
        }
        ApplicationRequirement::SchedulerEnvelopeFactory => {
            ApplicationContributions::new().with_scheduler_runtime(SchedulerRuntime::default())
        }
        ApplicationRequirement::SearchIndexSchema
        | ApplicationRequirement::SearchProjectionResolver
        | ApplicationRequirement::SearchReauthorizer => {
            ApplicationContributions::new().with_search_runtime(SearchRuntime::default())
        }
        ApplicationRequirement::UploadsAuthorization | ApplicationRequirement::UploadsWorkflow => {
            ApplicationContributions::new().with_uploads_runtime(UploadsRuntime::default())
        }
        ApplicationRequirement::WebhooksInboundHandlers
        | ApplicationRequirement::WebhooksInboundProviderAdapters => {
            ApplicationContributions::new()
                .with_webhooks_inbound_runtime(WebhooksInboundRuntime::default())
        }
        ApplicationRequirement::WebhooksSvixReplayAdmission => ApplicationContributions::new()
            .with_webhooks_svix_runtime(WebhooksSvixRuntime::default()),
    }
}

fn input(
    contracts: &'static [SelectedModuleContract],
    disabled: &'static [&'static str],
) -> CompositionInput {
    CompositionInput {
        profile: "contract-test",
        modules: &["contract-test-module"],
        providers: &[],
        contracts,
        runtime_disabled_modules: disabled,
    }
}

#[test]
fn every_requirement_has_one_typed_present_missing_and_malformed_path() {
    for requirement in ApplicationRequirement::ALL {
        if matches!(
            requirement,
            ApplicationRequirement::AuthAuthenticatedRuntime
        ) {
            continue;
        }
        let mut missing = ApplicationContributions::new();
        let missing_builder = AppCompositionBuilder::new(input(&[], &[]), &mut missing);
        assert_eq!(
            missing_builder.require("contract-test-module", *requirement),
            Err(CompositionError::MissingContribution {
                module: "contract-test-module",
                contribution: requirement.as_str(),
            })
        );

        let mut supplied = present(*requirement);
        let supplied_builder = AppCompositionBuilder::new(input(&[], &[]), &mut supplied);
        assert_eq!(
            supplied_builder.require("contract-test-module", *requirement),
            Ok(())
        );

        let mut grouped = malformed(*requirement);
        let grouped_builder = AppCompositionBuilder::new(input(&[], &[]), &mut grouped);
        assert_eq!(
            grouped_builder.require("contract-test-module", *requirement),
            Err(CompositionError::ContractMismatch {
                kind: "application-requirement",
                id: requirement.as_str(),
            })
        );
    }
}

#[test]
fn jobs_runtime_indexes_exact_unique_handler_identity() -> Result<(), JobsRuntimeError> {
    let runtime = JobsRuntime::default().with_handler(Arc::new(ContractProbe))?;
    assert!(runtime.handler("contract.probe", 1).is_some());
    assert!(runtime.handler("contract.probe", 2).is_none());
    assert!(matches!(
        runtime.with_handler(Arc::new(ContractProbe)),
        Err(JobsRuntimeError::DuplicateHandler {
            job_name: "contract.probe",
            version: 1,
        })
    ));
    Ok(())
}

#[test]
fn authenticated_requirement_fails_closed_without_concrete_http_runtime() {
    let mut contributions =
        ApplicationContributions::new().with_auth_runtime(AuthRuntime::default());
    let builder = AppCompositionBuilder::new(input(&[], &[]), &mut contributions);
    assert_eq!(
        builder.require(
            "auth-http",
            ApplicationRequirement::AuthAuthenticatedRuntime,
        ),
        Err(CompositionError::ContractMismatch {
            kind: "application-requirement",
            id: ApplicationRequirement::AuthAuthenticatedRuntime.as_str(),
        })
    );
}

#[test]
fn requirement_snapshot_survives_runtime_registration_consumption() {
    let requirement = ApplicationRequirement::JobsHandlers;
    let mut contributions = present(requirement);
    let builder = AppCompositionBuilder::new(input(&[], &[]), &mut contributions);
    assert_eq!(
        builder.require("jobs", requirement),
        Ok(()),
        "precondition: supplied requirement is present"
    );

    builder.contributions.jobs = None;
    assert_eq!(builder.require("jobs", requirement), Ok(()));
}

#[test]
fn disabled_runtime_toggles_skip_every_dormant_requirement() {
    const CONTRACTS: &[SelectedModuleContract] = &[SelectedModuleContract {
        module: "contract-test-module",
        runtime_toggle: true,
        routes: &[],
        tasks: &[],
        health_checks: &[],
        application_requirements: ApplicationRequirement::ALL,
    }];
    let mut contributions = ApplicationContributions::new();
    let builder = AppCompositionBuilder::new(
        input(CONTRACTS, &["contract-test-module"]),
        &mut contributions,
    );
    assert_eq!(builder.finish().map(|_| ()), Ok(()));
}
#[cfg(feature = "postgres")]
#[test]
fn application_runtime_reports_a_missing_postgres_pool() {
    assert!(matches!(
        ApplicationRuntime::default().postgres_pool(),
        Err(ApplicationExtensionError::MissingPostgresPool)
    ));
}

#[cfg(feature = "idempotency")]
#[test]
fn application_runtime_reports_a_missing_idempotency_store() {
    assert!(matches!(
        ApplicationRuntime::default().idempotency_store(),
        Err(ApplicationExtensionError::MissingIdempotencyStore)
    ));
}

#[cfg(feature = "http")]
use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
#[cfg(feature = "http")]
use tower::ServiceExt as _;

#[cfg(feature = "http")]
const APPLICATION_ROUTES: &[&str] = &["/application"];
#[cfg(feature = "http")]
const APPLICATION_OPERATIONS: &[ExpectedOperation] = &[ExpectedOperation::new(
    "get",
    "/application",
    "getApplication",
    "application",
)];
#[cfg(feature = "openapi")]
const OPENAPI_CONTRACTS: &[SelectedModuleContract] = &[SelectedModuleContract {
    module: "openapi",
    runtime_toggle: true,
    routes: &["/openapi.json", "/docs"],
    tasks: &[],
    health_checks: &[],
    application_requirements: &[],
}];

#[cfg(feature = "http")]
fn application_document() -> serde_json::Value {
    serde_json::json!({
        "openapi": "3.1.0",
        "info": {"title": "application", "version": "1.0.0"},
        "paths": {
            "/application": {
                "get": {
                    "operationId": "getApplication",
                    "tags": ["application"],
                    "security": [],
                    "responses": {
                        "204": {"description": "application"},
                        "400": {
                            "description": "invalid request",
                            "content": {
                                "application/problem+json": {
                                    "schema": {
                                        "type": "object",
                                        "required": [
                                            "type",
                                            "title",
                                            "status",
                                            "code",
                                            "request_id"
                                        ],
                                        "properties": {
                                            "type": {"type": "string"},
                                            "title": {"type": "string"},
                                            "status": {"type": "integer"},
                                            "code": {"type": "string"},
                                            "request_id": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    })
}

#[cfg(feature = "http")]
fn application_extension() -> ApplicationExtension {
    ApplicationExtension::new(
        Router::new().route("/application", get(|| async { StatusCode::NO_CONTENT })),
        APPLICATION_ROUTES,
        application_document(),
        APPLICATION_OPERATIONS,
    )
}

#[cfg(feature = "http")]
async fn resolved_application_contributions()
-> Result<ApplicationContributions, ApplicationFactoryError> {
    ApplicationContributions::new()
        .with_application_extension(|_| Ok(application_extension()))
        .with_selected_runtime(
            SelectedRuntime::default(),
            serde_json::json!({}),
            omnius_config::DeploymentEnvironment::Test,
        )
        .await
}

#[cfg(feature = "http")]
#[test]
fn http_finalization_requires_an_application_extension() {
    let mut contributions = ApplicationContributions::new();
    let mut builder = AppCompositionBuilder::new(input(&[], &[]), &mut contributions);

    assert_eq!(
        modules::http::finalize(&mut builder),
        Err(CompositionError::MissingContribution {
            module: "http",
            contribution: "application.extension",
        })
    );
}

#[cfg(feature = "http")]
#[tokio::test]
async fn application_extension_factory_is_last_wins_and_one_shot() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let first_calls = Arc::new(AtomicUsize::new(0));
    let second_calls = Arc::new(AtomicUsize::new(0));
    let first_factory_calls = Arc::clone(&first_calls);
    let second_factory_calls = Arc::clone(&second_calls);
    let contributions = ApplicationContributions::new()
        .with_application_extension(move |_| {
            first_factory_calls.fetch_add(1, Ordering::Relaxed);
            Ok(application_extension())
        })
        .with_application_extension(move |_| {
            second_factory_calls.fetch_add(1, Ordering::Relaxed);
            Ok(application_extension())
        })
        .with_selected_runtime(
            SelectedRuntime::default(),
            serde_json::json!({}),
            omnius_config::DeploymentEnvironment::Test,
        )
        .await;

    assert!(contributions.is_ok());
    assert_eq!(
        (
            first_calls.load(Ordering::Relaxed),
            second_calls.load(Ordering::Relaxed)
        ),
        (0, 1)
    );
}

#[cfg(feature = "http")]
#[test]
fn application_runtime_deserializes_strict_config_exactly_once()
-> Result<(), ApplicationConfigError> {
    #[derive(Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct SecretConfig {
        secret: String,
    }

    let mut runtime = ApplicationRuntime {
        application_config: Some(serde_json::json!({"secret": "do-not-clone-or-print"})),
        deployment: omnius_config::DeploymentEnvironment::Test,
        #[cfg(feature = "postgres")]
        postgres_pool: None,
        #[cfg(feature = "idempotency")]
        idempotency_store: None,
        #[cfg(feature = "outbound-http")]
        outbound_http: None,
    };
    let config: SecretConfig = runtime.deserialize_application()?;
    assert_eq!(config.secret, "do-not-clone-or-print");
    assert!(matches!(
        runtime.deserialize_application::<SecretConfig>(),
        Err(ApplicationConfigError::AlreadyDeserialized)
    ));

    let mut invalid = ApplicationRuntime {
        application_config: Some(serde_json::json!({"secret": "do-not-print", "unexpected": true})),
        deployment: omnius_config::DeploymentEnvironment::Test,
        #[cfg(feature = "postgres")]
        postgres_pool: None,
        #[cfg(feature = "idempotency")]
        idempotency_store: None,
        #[cfg(feature = "outbound-http")]
        outbound_http: None,
    };
    let result = invalid.deserialize_application::<SecretConfig>();
    let Err(error) = result else {
        panic!("unknown application keys must fail");
    };
    assert!(!error.to_string().contains("do-not-print"));
    Ok(())
}

#[cfg(feature = "http")]
#[tokio::test]
async fn asynchronous_application_factory_failure_is_propagated() {
    let result = ApplicationContributions::new()
        .with_application_factory(|_| async {
            Err::<ApplicationContributions, ApplicationFactoryError>(
                std::io::Error::other("factory failed").into(),
            )
        })
        .with_selected_runtime(
            SelectedRuntime::default(),
            serde_json::json!({}),
            omnius_config::DeploymentEnvironment::Test,
        )
        .await;

    let Err(error) = result else {
        panic!("application factory failure must abort composition");
    };
    assert_eq!(error.to_string(), "factory failed");
}

#[cfg(all(feature = "http", feature = "outbound-http"))]
#[tokio::test]
async fn asynchronous_application_factory_receives_outbound_and_installs_extension()
-> Result<(), ApplicationFactoryError> {
    let clients = omnius_outbound_http::OutboundHttpClients::new(
        &omnius_outbound_http::OutboundHttpConfig::default(),
    )?;
    let runtime = SelectedRuntime {
        outbound_http: Some(Arc::new(clients)),
        ..SelectedRuntime::default()
    };
    let mut contributions = ApplicationContributions::new()
        .with_application_factory(|runtime| async move {
            let _clients = runtime.outbound_http()?;
            Ok(ApplicationContributions::new()
                .with_application_extension_runtime(application_extension()))
        })
        .with_selected_runtime(
            runtime,
            serde_json::json!({}),
            omnius_config::DeploymentEnvironment::Test,
        )
        .await?;
    let mut builder = AppCompositionBuilder::new(input(&[], &[]), &mut contributions);
    modules::http::finalize(&mut builder)?;
    let response = builder
        .finish()?
        .into_runtime_parts()
        .router
        .oneshot(Request::get("/application").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    Ok(())
}

#[cfg(all(feature = "http", feature = "idempotency"))]
#[tokio::test]
async fn application_extension_factory_receives_selected_resources()
-> Result<(), ApplicationFactoryError> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let received = Arc::new(AtomicBool::new(false));
    let factory_received = Arc::clone(&received);
    let store = omnius_idempotency::PostgresIdempotencyStore::new(
        omnius_idempotency::IdempotencyConfig::default(),
    )?;
    let runtime = SelectedRuntime {
        idempotency_store: Some(store),
        ..SelectedRuntime::default()
    };

    let _contributions = ApplicationContributions::new()
        .with_application_extension(move |runtime| {
            let _store = runtime.idempotency_store()?;
            factory_received.store(true, Ordering::Relaxed);
            Ok(application_extension())
        })
        .with_selected_runtime(
            runtime,
            serde_json::json!({}),
            omnius_config::DeploymentEnvironment::Test,
        )
        .await?;

    assert!(received.load(Ordering::Relaxed));
    Ok(())
}

#[cfg(feature = "http")]
#[tokio::test]
async fn http_finalization_mounts_the_application_router_once()
-> Result<(), ApplicationFactoryError> {
    let mut contributions = resolved_application_contributions().await?;
    let mut builder = AppCompositionBuilder::new(input(&[], &[]), &mut contributions);
    modules::http::finalize(&mut builder)?;
    let second = modules::http::finalize(&mut builder);
    let router = builder.finish()?.into_runtime_parts().router;
    let response = router
        .oneshot(Request::get("/application").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        second,
        Err(CompositionError::MissingContribution {
            module: "http",
            contribution: "application.extension",
        })
    );
    Ok(())
}

#[cfg(all(feature = "http", not(feature = "openapi")))]
#[tokio::test]
async fn http_mounts_the_application_when_openapi_is_not_compiled()
-> Result<(), ApplicationFactoryError> {
    let mut contributions = resolved_application_contributions().await?;
    let mut builder = AppCompositionBuilder::new(input(&[], &[]), &mut contributions);
    modules::http::finalize(&mut builder)?;
    let router = builder.finish()?.into_runtime_parts().router;
    let response = router
        .oneshot(Request::get("/application").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    Ok(())
}

#[cfg(all(feature = "http", feature = "rate-limit-local"))]
#[tokio::test]
async fn http_finalization_applies_the_recorded_local_limiter()
-> Result<(), ApplicationFactoryError> {
    let mut contributions = ApplicationContributions::new()
        .with_application_rate_limit(ApplicationRateLimitConfig {
            enabled: true,
            replenish_every: Duration::from_secs(60),
            burst_size: 1,
            identity_buckets: 16,
        })
        .with_application_extension(|_| Ok(application_extension()))
        .with_selected_runtime(
            SelectedRuntime::default(),
            serde_json::json!({}),
            omnius_config::DeploymentEnvironment::Test,
        )
        .await?;
    let mut builder = AppCompositionBuilder::new(input(&[], &[]), &mut contributions);
    modules::rate_limit_local::register(&mut builder)?;
    modules::http::finalize(&mut builder)?;
    let router = builder.finish()?.into_runtime_parts().router;
    let request =
        || {
            let mut request = Request::get("/application").body(Body::empty())?;
            request.extensions_mut().insert(axum::extract::ConnectInfo(
                std::net::SocketAddr::from(([127, 0, 0, 1], 3000)),
            ));
            request
                .extensions_mut()
                .insert(omnius_core::RequestId::new());
            Ok::<_, axum::http::Error>(request)
        };
    let first = router.clone().oneshot(request()?).await?;
    let second = router.oneshot(request()?).await?;

    assert_eq!(
        (first.status(), second.status()),
        (StatusCode::NO_CONTENT, StatusCode::TOO_MANY_REQUESTS)
    );
    Ok(())
}

#[cfg(all(feature = "openapi", not(feature = "idempotency")))]
#[tokio::test]
async fn openapi_installs_from_the_extension_without_idempotency()
-> Result<(), ApplicationFactoryError> {
    let runtime = SelectedRuntime::for_in_process_tests();
    let mut contributions = ApplicationContributions::new()
        .with_application_extension(|_| Ok(application_extension()))
        .with_selected_runtime(
            runtime,
            serde_json::json!({}),
            omnius_config::DeploymentEnvironment::Test,
        )
        .await?;
    let mut builder = AppCompositionBuilder::new(input(OPENAPI_CONTRACTS, &[]), &mut contributions);
    modules::http::finalize(&mut builder)?;
    let application = builder.finish()?;
    assert!(application.public_operations().contains("getApplication"));
    let router = application.into_runtime_parts().router;
    let response = router
        .oneshot(Request::get("/openapi.json").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[cfg(feature = "openapi")]
#[tokio::test]
async fn extension_document_must_cover_its_declared_operations() {
    const MISMATCHED: &[ExpectedOperation] = &[ExpectedOperation::new(
        "get",
        "/application",
        "renamedApplication",
        "application",
    )];

    let runtime = SelectedRuntime::for_in_process_tests();
    let contributions = ApplicationContributions::new()
        .with_application_extension(|_| {
            Ok(ApplicationExtension::new(
                Router::new(),
                APPLICATION_ROUTES,
                application_document(),
                MISMATCHED,
            ))
        })
        .with_selected_runtime(
            runtime,
            serde_json::json!({}),
            omnius_config::DeploymentEnvironment::Test,
        )
        .await;
    let Ok(mut contributions) = contributions else {
        panic!("application extension factory must succeed");
    };
    let mut builder = AppCompositionBuilder::new(input(OPENAPI_CONTRACTS, &[]), &mut contributions);

    assert_eq!(
        modules::http::finalize(&mut builder),
        Err(CompositionError::InvalidConfiguration { module: "openapi" })
    );
}

#[cfg(all(feature = "http", feature = "idempotency"))]
#[tokio::test]
async fn idempotency_registers_only_its_store_and_no_reference_routes()
-> Result<(), ApplicationFactoryError> {
    let store = omnius_idempotency::PostgresIdempotencyStore::new(
        omnius_idempotency::IdempotencyConfig::default(),
    )?;
    let runtime = SelectedRuntime {
        idempotency_store: Some(store),
        ..SelectedRuntime::default()
    };
    let mut contributions = ApplicationContributions::new()
        .with_application_extension(|_| Ok(application_extension()))
        .with_selected_runtime(
            runtime,
            serde_json::json!({}),
            omnius_config::DeploymentEnvironment::Test,
        )
        .await?;
    let mut builder = AppCompositionBuilder::new(input(&[], &[]), &mut contributions);
    modules::idempotency::register(&mut builder)?;
    modules::http::finalize(&mut builder)?;
    let router = builder.finish()?.into_runtime_parts().router;
    let response = router
        .oneshot(Request::get("/reference-records").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}
