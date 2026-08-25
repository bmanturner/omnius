use std::time::Duration;

use futures::future::BoxFuture;

use crate::{
    ApplicationId, ApplicationRecord, ApplicationSpec, DeliveryStatus, EndpointId, EndpointRecord,
    EndpointSpec, EventType, IdempotencyKey, MessageId, ProviderError, PublishReceipt,
    PublishRequest, ReplayAdmissionRequest, ReplayCompletion, ReplayLease, ReplayRequest,
    ReplayTask, ReplayTaskBinding, ReplayTaskId, SigningSecret,
};

/// Required durable replay-admission boundary.
///
/// Production implementations must atomically enforce one active replay per application/endpoint,
/// reject overlapping windows across replicas, apply bounded tenant budgets and cooldown, and make
/// lease/task authorization survive process restarts. Reserving the same fingerprint must be
/// idempotent so an ambiguous provider result can be reconciled with the same provider key.
///
/// Implementations must retain completed records for their cooldown/audit policy rather than
/// deleting them. This crate intentionally provides no permissive production implementation.
///
/// Binding, rejection release, and terminal completion must also be idempotent.
pub trait ReplayAdmission: Send + Sync + 'static {
    /// Atomically reserves or idempotently recovers the canonical replay request.
    fn reserve<'a>(
        &'a self,
        request: &'a ReplayAdmissionRequest,
    ) -> BoxFuture<'a, Result<ReplayLease, ProviderError>>;

    /// Atomically persists the provider task binding for a reserved lease.
    fn bind_task<'a>(
        &'a self,
        lease: &'a ReplayLease,
        task_id: &'a ReplayTaskId,
    ) -> BoxFuture<'a, Result<ReplayTaskBinding, ProviderError>>;

    /// Authorizes a task status lookup from durable application-scoped state.
    fn authorize_task<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        task_id: &'a ReplayTaskId,
    ) -> BoxFuture<'a, Result<ReplayTaskBinding, ProviderError>>;

    /// Releases a lease only after a definitive pre-dispatch or provider 4xx rejection.
    ///
    /// Conflict and rate-limit responses are ambiguous and must retain the lease.
    fn release_rejected<'a>(
        &'a self,
        lease: &'a ReplayLease,
    ) -> BoxFuture<'a, Result<(), ProviderError>>;

    /// Durably records a terminal provider result and begins the configured cooldown.
    fn complete<'a>(
        &'a self,
        binding: &'a ReplayTaskBinding,
        completion: ReplayCompletion,
    ) -> BoxFuture<'a, Result<(), ProviderError>>;
}

/// Narrow provider boundary implemented by the pinned Svix SDK adapter and fixed-capacity fake.
///
/// Svix credentials, SDK clients, response bodies, delivery URLs, and provider model types never
/// cross this boundary.
pub trait WebhookProvider: Send + Sync + 'static {
    /// Publishes one canonical public event envelope.
    fn publish<'a>(
        &'a self,
        request: PublishRequest<'a>,
    ) -> BoxFuture<'a, Result<PublishReceipt, ProviderError>>;

    /// Gets or creates the stable local application mapping.
    fn application_get_or_create<'a>(
        &'a self,
        spec: &'a ApplicationSpec,
    ) -> BoxFuture<'a, Result<ApplicationRecord, ProviderError>>;

    /// Creates a stable local endpoint mapping from a centrally approved URL capability.
    fn endpoint_create<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        spec: EndpointSpec,
    ) -> BoxFuture<'a, Result<EndpointRecord, ProviderError>>;

    /// Replaces mutable endpoint data from a newly approved URL capability.
    fn endpoint_update<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        spec: EndpointSpec,
    ) -> BoxFuture<'a, Result<EndpointRecord, ProviderError>>;

    /// Reads safe endpoint status without returning its delivery URL.
    fn endpoint_status<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        endpoint_id: &'a EndpointId,
    ) -> BoxFuture<'a, Result<EndpointRecord, ProviderError>>;

    /// Enables or disables delivery for an endpoint.
    fn endpoint_set_enabled<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        endpoint_id: &'a EndpointId,
        enabled: bool,
    ) -> BoxFuture<'a, Result<EndpointRecord, ProviderError>>;

    /// Deletes an endpoint.
    fn endpoint_delete<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        endpoint_id: &'a EndpointId,
    ) -> BoxFuture<'a, Result<(), ProviderError>>;

    /// Retrieves an endpoint signing secret in a redacted wrapper.
    fn signing_secret<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        endpoint_id: &'a EndpointId,
    ) -> BoxFuture<'a, Result<SigningSecret, ProviderError>>;

    /// Rotates an endpoint signing secret with a bounded grace period and deterministic key.
    fn rotate_signing_secret<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        endpoint_id: &'a EndpointId,
        grace_period: Duration,
        idempotency_key: &'a IdempotencyKey,
    ) -> BoxFuture<'a, Result<(), ProviderError>>;

    /// Returns bounded response-body-free delivery attempts for one message.
    fn delivery_status<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<DeliveryStatus, ProviderError>>;

    /// Starts a provider-managed replay task.
    fn replay_start<'a>(
        &'a self,
        request: &'a ReplayRequest,
    ) -> BoxFuture<'a, Result<ReplayTask, ProviderError>>;

    /// Reads one provider-managed replay task within the bound application scope.
    fn replay_status<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        task_id: &'a ReplayTaskId,
    ) -> BoxFuture<'a, Result<ReplayTask, ProviderError>>;

    /// Sends a provider-managed schema example using a deterministic key.
    fn send_test_event<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        endpoint_id: &'a EndpointId,
        event_type: &'a EventType,
        idempotency_key: &'a IdempotencyKey,
    ) -> BoxFuture<'a, Result<PublishReceipt, ProviderError>>;

    /// Performs a bounded provider health probe.
    fn health(&self) -> BoxFuture<'_, Result<(), ProviderError>>;
}
