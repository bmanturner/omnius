use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use omnius_mcp_server_core::{
    McpRequestContext,
    sdk::{McpAdapterFuture, McpSubscriptionAdapter},
};
use rmcp::{ErrorData, model::SubscriptionFilter, service::SubscriptionContext};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use crate::{
    BoundedDeliveryQueue, CloseReason, DeliveryFrame, RequestedEventClass, SubscribeRequest,
    SubscriptionAcknowledgement, SubscriptionClosed, SubscriptionError, SubscriptionId,
    SubscriptionStart, TaskId, TaskSnapshot, TaskSubscriptionService,
};

/// Request metadata key carrying the Tasks extension's exact snapshot-subscription request.
pub const TASK_SUBSCRIPTION_REQUEST_META_KEY: &str = "io.modelcontextprotocol/tasks/subscription";

/// A task subscription frame with no replay or transport durability claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskSubscriptionBridgeFrame {
    /// The domain service accepted and durably claimed the exact request.
    Acknowledged(SubscriptionAcknowledgement),
    /// A complete, currently authorized task snapshot.
    TaskSnapshot(TaskSnapshot),
    /// The domain service closed the stream.
    Closed(SubscriptionClosed),
}

/// Redacted failure from a transport-owned task notification bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TaskSubscriptionFrameSinkError {
    /// The bridge cannot establish or use the required task notification route.
    #[error("task subscription frame sink is unavailable")]
    Unavailable,
    /// The response stream disconnected.
    #[error("task subscription frame sink disconnected")]
    Disconnected,
}

/// One response-stream-scoped task notification sink.
#[async_trait]
pub trait BoundTaskSubscriptionFrameSink: Send + Sync {
    /// Delivers one typed frame without changing its subscription association.
    async fn send(
        &self,
        frame: TaskSubscriptionBridgeFrame,
    ) -> Result<(), TaskSubscriptionFrameSinkError>;

    /// Waits until the response stream is no longer usable.
    async fn disconnected(&self);
}

/// Required contribution for routing task frames missing from RMCP 3.1.4's native sink.
pub trait TaskSubscriptionFrameSink: Send + Sync {
    /// Binds a typed task frame sink to one established RMCP listen request.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the transport cannot provide a real task notification route.
    fn bind(
        &self,
        context: &SubscriptionContext,
    ) -> Result<Box<dyn BoundTaskSubscriptionFrameSink>, TaskSubscriptionFrameSinkError>;
}

/// Cloneable graceful-drain handle shared with application lifecycle supervision.
#[derive(Clone)]
pub struct TaskSubscriptionDrainHandle {
    service: TaskSubscriptionService,
    cancellation: CancellationToken,
}

impl TaskSubscriptionDrainHandle {
    /// Signals every adapter listen loop and gracefully drains all service subscriptions.
    ///
    /// # Errors
    ///
    /// Returns [`SubscriptionError::Runtime`] when the authoritative runtime clock is unavailable.
    pub async fn drain(&self) -> Result<(), SubscriptionError> {
        let now_ms = self.service.now_ms().await?;
        self.cancellation.cancel();
        self.service.drain_all(now_ms).await;
        Ok(())
    }

    /// Returns whether graceful drain has been requested.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

impl std::fmt::Debug for TaskSubscriptionDrainHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaskSubscriptionDrainHandle")
            .field("is_draining", &self.is_draining())
            .finish_non_exhaustive()
    }
}

/// Exact RMCP subscription adapter over the authorized task subscription domain.
///
/// The selected [`crate::SelectedBackplaneReceiver`] is deliberately not owned here. Application
/// supervision must continue to own and run that move-only receiver through
/// [`TaskSubscriptionService::run_backplane`].
#[derive(Clone)]
pub struct TaskSubscriptionRmcpAdapter {
    service: TaskSubscriptionService,
    delivery: BoundedDeliveryQueue,
    frame_sink: Option<Arc<dyn TaskSubscriptionFrameSink>>,
    drain: TaskSubscriptionDrainHandle,
}

impl TaskSubscriptionRmcpAdapter {
    /// Creates a fail-closed adapter without RMCP task notification routing.
    ///
    /// `delivery` must be the same queue installed as the service's delivery port. The adapter
    /// remains unavailable until [`Self::with_frame_sink`] supplies a real transport bridge.
    #[must_use]
    pub fn new(service: TaskSubscriptionService, delivery: BoundedDeliveryQueue) -> Self {
        let drain = TaskSubscriptionDrainHandle {
            service: service.clone(),
            cancellation: CancellationToken::new(),
        };
        Self {
            service,
            delivery,
            frame_sink: None,
            drain,
        }
    }

    /// Installs the required transport contribution for `notifications/tasks` frames.
    #[must_use]
    pub fn with_frame_sink(mut self, frame_sink: Arc<dyn TaskSubscriptionFrameSink>) -> Self {
        self.frame_sink = Some(frame_sink);
        self
    }

    /// Returns the application-owned graceful-drain handle.
    #[must_use]
    pub fn drain_handle(&self) -> TaskSubscriptionDrainHandle {
        self.drain.clone()
    }

    async fn listen_inner(&self, context: SubscriptionContext) -> Result<(), ErrorData> {
        if self.drain.is_draining() {
            return Err(subscription_unavailable());
        }
        if !is_exact_native_filter(context.requested())
            || !is_exact_native_filter(context.accepted())
        {
            return Err(invalid_subscription_request());
        }
        let frame_sink = self
            .frame_sink
            .as_ref()
            .ok_or_else(subscription_unavailable)?;
        let request_context = context
            .request_context()
            .extensions
            .get::<McpRequestContext>()
            .cloned()
            .ok_or_else(invalid_subscription_request)?;
        let request = decode_request(&context)?;
        let bound_sink = frame_sink
            .bind(&context)
            .map_err(|_| subscription_unavailable())?;

        let lease = self
            .service
            .subscribe(&request_context, request)
            .await
            .map_err(map_subscription_error)?;
        let subscription_id = lease.subscription_id;
        let mut stream = match self.delivery.take_stream(&subscription_id) {
            Ok(stream) => stream,
            Err(_) => {
                cancel_failed(&self.service, &subscription_id).await;
                return Err(subscription_unavailable());
            }
        };
        let drain_signal = self.drain.cancellation.clone();
        let mut draining = drain_signal.is_cancelled();

        loop {
            tokio::select! {
                () = context.cancelled() => {
                    let now_ms = self.service.now_ms().await.map_err(map_subscription_error)?;
                    self.service
                        .cancel(&subscription_id, CloseReason::Cancelled, now_ms, false)
                        .await;
                    return Ok(());
                }
                () = drain_signal.cancelled(), if !draining => {
                    draining = true;
                }
                () = bound_sink.disconnected() => {
                    drop(stream);
                    disconnect(&self.service, &subscription_id).await;
                    return Err(subscription_unavailable());
                }
                frame = stream.next() => {
                    let Some(frame) = frame else {
                        drop(stream);
                        disconnect(&self.service, &subscription_id).await;
                        return Err(subscription_unavailable());
                    };
                    let terminal = matches!(frame, DeliveryFrame::Closed(_));
                    let bridge_frame = match bridge_frame(frame) {
                        Ok(frame) => frame,
                        Err(()) => {
                            cancel_failed(&self.service, &subscription_id).await;
                            return Err(subscription_unavailable());
                        }
                    };
                    if bound_sink.send(bridge_frame).await.is_err() {
                        drop(stream);
                        disconnect(&self.service, &subscription_id).await;
                        return Err(subscription_unavailable());
                    }
                    if terminal {
                        return Ok(());
                    }
                }
            }
        }
    }
}

impl std::fmt::Debug for TaskSubscriptionRmcpAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaskSubscriptionRmcpAdapter")
            .field("has_frame_sink", &self.frame_sink.is_some())
            .field("drain", &self.drain)
            .finish_non_exhaustive()
    }
}

impl McpSubscriptionAdapter for TaskSubscriptionRmcpAdapter {
    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        (self.frame_sink.is_some()
            && !self.drain.is_draining()
            && is_exact_native_filter(requested))
        .then(SubscriptionFilter::new)
    }

    fn listen(&self, context: SubscriptionContext) -> McpAdapterFuture<'_, ()> {
        Box::pin(async move { self.listen_inner(context).await })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireTaskSubscriptionRequest {
    task_ids: Vec<String>,
    event_classes: Vec<WireTaskEventClass>,
    ttl_ms: u64,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum WireTaskEventClass {
    TaskSnapshots,
}

fn decode_request(context: &SubscriptionContext) -> Result<SubscribeRequest, ErrorData> {
    let value = context
        .request_context()
        .meta
        .get(TASK_SUBSCRIPTION_REQUEST_META_KEY)
        .cloned()
        .ok_or_else(invalid_subscription_request)?;
    let wire: WireTaskSubscriptionRequest =
        serde_json::from_value(value).map_err(|_| invalid_subscription_request())?;
    if wire.task_ids.is_empty()
        || wire.ttl_ms == 0
        || wire.event_classes.as_slice() != [WireTaskEventClass::TaskSnapshots]
    {
        return Err(invalid_subscription_request());
    }

    let mut unique = BTreeSet::new();
    let mut task_ids = Vec::with_capacity(wire.task_ids.len());
    for task_id in wire.task_ids {
        let task_id = TaskId::new(task_id).map_err(|_| invalid_subscription_request())?;
        if !unique.insert(task_id.clone()) {
            return Err(invalid_subscription_request());
        }
        task_ids.push(task_id);
    }

    Ok(SubscribeRequest {
        task_ids,
        event_classes: vec![RequestedEventClass::TaskSnapshots],
        ttl_ms: wire.ttl_ms,
        start: SubscriptionStart::Initial {
            idempotency_key: None,
        },
    })
}

fn is_exact_native_filter(filter: &SubscriptionFilter) -> bool {
    filter.tools_list_changed.is_none()
        && filter.prompts_list_changed.is_none()
        && filter.resources_list_changed.is_none()
        && filter.resource_subscriptions.is_none()
}

fn bridge_frame(frame: DeliveryFrame) -> Result<TaskSubscriptionBridgeFrame, ()> {
    match frame {
        DeliveryFrame::Acknowledged(acknowledgement) => {
            Ok(TaskSubscriptionBridgeFrame::Acknowledged(acknowledgement))
        }
        DeliveryFrame::TaskSnapshot {
            replayed: false,
            snapshot,
            ..
        } => Ok(TaskSubscriptionBridgeFrame::TaskSnapshot(snapshot)),
        DeliveryFrame::Closed(closed) => Ok(TaskSubscriptionBridgeFrame::Closed(closed)),
        DeliveryFrame::TaskSnapshot { replayed: true, .. } | DeliveryFrame::ReplayGap { .. } => {
            Err(())
        }
    }
}

async fn cancel_failed(service: &TaskSubscriptionService, subscription_id: &SubscriptionId) {
    if let Ok(now_ms) = service.now_ms().await {
        service
            .cancel(subscription_id, CloseReason::Failed, now_ms, false)
            .await;
    }
}

async fn disconnect(service: &TaskSubscriptionService, subscription_id: &SubscriptionId) {
    if let Ok(now_ms) = service.now_ms().await {
        service.disconnect(subscription_id, now_ms).await;
    }
}

fn map_subscription_error(error: SubscriptionError) -> ErrorData {
    match error {
        SubscriptionError::NotNegotiated
        | SubscriptionError::InvalidRequestContext
        | SubscriptionError::NoSupportedEventClass
        | SubscriptionError::InvalidTaskFilter
        | SubscriptionError::InvalidTtl
        | SubscriptionError::Unauthorized
        | SubscriptionError::TaskNotFound
        | SubscriptionError::AlreadyActive
        | SubscriptionError::IdentifierReused
        | SubscriptionError::InvalidReconnect => invalid_subscription_request(),
        SubscriptionError::BackplaneUnavailable
        | SubscriptionError::ExpiredDuringSetup
        | SubscriptionError::Expired
        | SubscriptionError::Repository
        | SubscriptionError::Authorization
        | SubscriptionError::Runtime
        | SubscriptionError::Delivery
        | SubscriptionError::SlowConsumer
        | SubscriptionError::Disconnected
        | SubscriptionError::InvalidConfiguration
        | SubscriptionError::CapacityExceeded => subscription_unavailable(),
    }
}

fn invalid_subscription_request() -> ErrorData {
    ErrorData::invalid_params("task subscription request is invalid", None)
}

fn subscription_unavailable() -> ErrorData {
    ErrorData::internal_error("task subscription is unavailable", None)
}
