//! Application-owned port traits for selected modules.
//!
//! These traits are requirement-presence markers: composition only checks that
//! the application supplied an implementation for a selected module's
//! requirement (for example `runtime.authority_resolver.is_some()`); service-kit
//! never invokes their methods. The `bool` and `&str` signatures are therefore
//! intentionally minimal and are not a runtime error or data contract.

/// Resolves current administrative authority for an exact principal and action.
pub trait AdminAuthorityResolverPort: Send + Sync {
    /// Returns `true` only when current authority permits the action.
    fn authorizes(&self, principal: &str, action: &str) -> bool;
}

/// Executes one closed administrative operation.
pub trait AdminOperationHandlerPort: Send + Sync {
    /// Executes the named closed operation and reports whether it completed.
    fn execute(&self, operation: &str) -> bool;
}

/// Revalidates one Redis-backed session.
pub trait RedisSessionRuntimePort: Send + Sync {
    /// Returns whether the session is live and current.
    fn session_is_live(&self, session_id: &str) -> bool;
}

/// Starts and completes an OIDC authorization flow.
pub trait OidcRuntimePort: Send + Sync {
    /// Returns whether the provider is configured for authorization.
    fn supports_provider(&self, provider: &str) -> bool;
}

/// Applies application OAuth authorization-server policy.
pub trait OauthRuntimePort: Send + Sync {
    /// Returns whether the client may request the exact scope.
    fn authorizes_client_scope(&self, client_id: &str, scope: &str) -> bool;
}

/// Executes `WebAuthn` registration and authentication ceremonies.
pub trait WebauthnRuntimePort: Send + Sync {
    /// Returns whether the relying party accepts this origin.
    fn accepts_origin(&self, origin: &str) -> bool;
}

/// Applies TOTP enrollment and verification policy.
pub trait TotpRuntimePort: Send + Sync {
    /// Verifies one code for the canonical subject.
    fn verifies_code(&self, subject: &str, code: &str) -> bool;
}

/// Publishes one durable outbox event.
pub trait OutboxPublisherPort: Send + Sync {
    /// Publishes the canonical event and reports durable provider acceptance.
    fn publish(&self, event_id: &str, payload: &[u8]) -> bool;
}

/// Dispatches one durable inbox message.
pub trait InboxConsumersPort: Send + Sync {
    /// Consumes the named message and reports durable completion.
    fn consume(&self, message_name: &str, payload: &[u8]) -> bool;
}

/// Creates a fresh typed envelope for a scheduled occurrence.
pub trait SchedulerEnvelopeFactoryPort: Send + Sync {
    /// Builds canonical encoded envelope bytes for the occurrence.
    fn envelope(&self, schedule_id: &str, occurrence: u64) -> Option<Vec<u8>>;
}

/// Authorizes one realtime fan-out decision.
pub trait RealtimeFanoutAuthorizerPort: Send + Sync {
    /// Returns whether the subject may receive the exact topic.
    fn authorizes_fanout(&self, subject: &str, topic: &str) -> bool;
}

/// Revalidates realtime identity before delivery.
pub trait RealtimeIdentityRevalidatorPort: Send + Sync {
    /// Returns whether the subject is still live for this connection.
    fn identity_is_live(&self, subject: &str) -> bool;
}

/// Handles one canonical realtime event.
pub trait RealtimeEventHandlerPort: Send + Sync {
    /// Handles the named event and reports completion.
    fn handle_event(&self, event_name: &str, payload: &[u8]) -> bool;
}

/// Owns upload workflow state transitions.
pub trait UploadWorkflowPort: Send + Sync {
    /// Advances the upload and returns whether the transition committed.
    fn advance(&self, upload_id: &str, transition: &str) -> bool;
}

/// Authorizes one upload operation.
pub trait UploadAuthorizationPort: Send + Sync {
    /// Returns whether the subject may perform the operation.
    fn authorizes_upload(&self, subject: &str, upload_id: &str, operation: &str) -> bool;
}

/// Admits one durable Svix replay.
pub trait WebhooksSvixReplayAdmissionPort: Send + Sync {
    /// Returns whether the replay was durably admitted.
    fn admit_replay(&self, event_id: &str) -> bool;
}

/// Selects a verified inbound webhook provider adapter.
pub trait WebhooksInboundProviderAdaptersPort: Send + Sync {
    /// Returns whether a concrete adapter owns the provider ID.
    fn supports_provider(&self, provider: &str) -> bool;
}

/// Dispatches verified inbound webhook events.
pub trait WebhooksInboundHandlersPort: Send + Sync {
    /// Handles the verified provider event.
    fn handle_webhook(&self, provider: &str, event_id: &str, payload: &[u8]) -> bool;
}

/// Evaluates one feature flag using application-owned provider state.
pub trait FeatureFlagProviderPort: Send + Sync {
    /// Returns the provider decision for the subject.
    fn enabled(&self, flag: &str, subject: &str) -> bool;
}

/// Records one durable feature exposure.
pub trait FeatureFlagExposureRecorderPort: Send + Sync {
    /// Records the exposure and reports durable acceptance.
    fn record_exposure(&self, flag: &str, subject: &str, enabled: bool) -> bool;
}

/// Declares the stable application search schema.
pub trait SearchIndexSchemaPort: Send + Sync {
    /// Returns the immutable schema digest for an index.
    fn schema_digest(&self, index: &str) -> Option<String>;
}

/// Reauthorizes one search result against current source state.
pub trait SearchReauthorizerPort: Send + Sync {
    /// Returns whether the subject may still observe the source.
    fn reauthorize(&self, subject: &str, source_id: &str) -> bool;
}

/// Resolves an authoritative search projection.
pub trait SearchProjectionResolverPort: Send + Sync {
    /// Returns canonical projection bytes for the source.
    fn projection(&self, source_id: &str) -> Option<Vec<u8>>;
}

/// Executes one billing-provider operation.
pub trait BillingProviderPort: Send + Sync {
    /// Returns whether the provider durably accepted the operation.
    fn execute_billing(&self, account_id: &str, operation: &str) -> bool;
}

/// Supplies the closed application GraphQL schema.
pub trait GraphqlSchemaPort: Send + Sync {
    /// Returns whether the schema declares the field.
    fn declares_field(&self, field: &str) -> bool;
}

/// Injects canonical application request data into GraphQL execution.
pub trait GraphqlRequestDataInjectorPort: Send + Sync {
    /// Returns whether request data was attached for the subject.
    fn inject_request_data(&self, subject: &str) -> bool;
}

/// Executes one application gRPC method.
pub trait GrpcApplicationServicePort: Send + Sync {
    /// Executes the method and reports completion.
    fn execute_method(&self, method: &str, payload: &[u8]) -> bool;
}

/// Authenticates gRPC transport metadata.
pub trait GrpcAuthenticatorPort: Send + Sync {
    /// Returns the canonical subject for accepted authorization metadata.
    fn authenticate_metadata(&self, authorization: &str) -> Option<String>;
}

/// Authorizes one canonical gRPC method.
pub trait GrpcMethodPoliciesPort: Send + Sync {
    /// Returns whether the subject may call the method.
    fn authorizes_method(&self, subject: &str, method: &str) -> bool;
}

/// Supplies the immutable privacy inventory manifest.
pub trait PrivacyInventoryManifestPort: Send + Sync {
    /// Returns the immutable manifest digest.
    fn manifest_digest(&self) -> String;
}

/// Reads application-owned privacy inventory data.
pub trait PrivacyInventoryAdaptersPort: Send + Sync {
    /// Returns canonical inventory bytes for the data class.
    fn inventory(&self, data_class: &str) -> Option<Vec<u8>>;
}

/// Authorizes one privacy operation.
pub trait PrivacyAuthorizerPort: Send + Sync {
    /// Returns whether the subject may perform the operation.
    fn authorizes_privacy(&self, subject: &str, operation: &str) -> bool;
}

/// Executes one privacy lifecycle request.
pub trait PrivacyLifecycleHandlerPort: Send + Sync {
    /// Executes the request and reports durable completion.
    fn execute_lifecycle(&self, request_id: &str, operation: &str) -> bool;
}

/// Applies application consent policy.
pub trait PrivacyConsentPolicyPort: Send + Sync {
    /// Returns whether current consent covers the purpose.
    fn has_consent(&self, subject: &str, purpose: &str) -> bool;
}

/// Applies application moderation policy.
pub trait PrivacyModerationPolicyPort: Send + Sync {
    /// Returns whether bounded content passes moderation.
    fn permits_content(&self, subject: &str, content: &[u8]) -> bool;
}

/// Authorizes one LLM tool invocation.
pub trait LlmToolAuthorizationPort: Send + Sync {
    /// Returns whether the subject may invoke the tool.
    fn authorizes_tool(&self, subject: &str, tool: &str) -> bool;
}

/// Records one durable LLM tool audit outcome.
pub trait LlmToolAuditPort: Send + Sync {
    /// Records the terminal outcome and reports durable acceptance.
    fn record_tool_outcome(&self, invocation_id: &str, succeeded: bool) -> bool;
}

/// Scans one complete media object.
pub trait LlmMediaScannerPort: Send + Sync {
    /// Returns whether the complete object is clean.
    fn scans_clean(&self, media_id: &str, bytes: &[u8]) -> bool;
}

/// Authorizes one LLM media operation.
pub trait LlmMediaAuthorizationPort: Send + Sync {
    /// Returns whether the subject may perform the operation.
    fn authorizes_media(&self, subject: &str, media_id: &str, operation: &str) -> bool;
}

/// Stores and reads persistent LLM evaluation reports.
pub trait LlmEvaluationRepositoryPort: Send + Sync {
    /// Returns whether the evaluation report was durably stored.
    fn store_evaluation(&self, evaluation_id: &str, report: &[u8]) -> bool;
}

/// Resolves the canonical MCP capability registry.
pub trait McpCapabilityRegistryPort: Send + Sync {
    /// Returns whether the capability is currently declared.
    fn contains_capability(&self, capability: &str) -> bool;
}

/// Authenticates one MCP bearer credential.
pub trait McpBearerAuthenticatorPort: Send + Sync {
    /// Returns the canonical subject only for a valid credential.
    fn authenticate_bearer(&self, credential: &str) -> Option<String>;
}

/// Supplies the complete enterprise MCP trust boundary.
pub trait McpEnterprisePorts: Send + Sync {
    /// Returns whether live enterprise state authorizes the operation.
    fn authorizes_enterprise(&self, subject: &str, operation: &str) -> bool;
}

/// Stores MCP subscription state.
pub trait McpSubscriptionRepositoryPort: Send + Sync {
    /// Returns whether the subscription was durably stored.
    fn store_subscription(&self, subscription_id: &str) -> bool;
}

/// Authorizes MCP subscription operations.
pub trait McpSubscriptionAuthorizerPort: Send + Sync {
    /// Returns whether the subject may subscribe to the task.
    fn authorizes_subscription(&self, subject: &str, task_id: &str) -> bool;
}

/// Arms MCP subscription lifecycle callbacks.
pub trait McpSubscriptionRuntimePort: Send + Sync {
    /// Returns whether lifecycle handling was armed.
    fn arm_subscription(&self, subscription_id: &str) -> bool;
}

/// Delivers MCP subscription frames.
pub trait McpSubscriptionDeliveryPort: Send + Sync {
    /// Returns whether the frame was accepted for delivery.
    fn deliver_subscription(&self, subscription_id: &str, frame: &[u8]) -> bool;
}

/// Protects MCP task payloads.
pub trait McpTaskPayloadProtectorPort: Send + Sync {
    /// Seals a payload into authenticated bytes.
    fn seal_payload(&self, task_id: &str, payload: &[u8]) -> Option<Vec<u8>>;
}

/// Coordinates live MCP task cancellation.
pub trait McpCancellationRuntimePort: Send + Sync {
    /// Returns whether the active task generation was cancelled.
    fn cancel_task(&self, task_id: &str) -> bool;
}

/// Executes one MCP capability for a durable task.
pub trait McpCapabilityExecutorPort: Send + Sync {
    /// Executes the capability and reports completion.
    fn execute_capability(&self, capability: &str, payload: &[u8]) -> bool;
}

/// Supplies complete MCP Apps lifecycle, artifact, and messaging ports.
pub trait McpAppsPorts: Send + Sync {
    /// Returns whether the app action was durably admitted.
    fn admit_app_action(&self, app_id: &str, action: &str) -> bool;
}
