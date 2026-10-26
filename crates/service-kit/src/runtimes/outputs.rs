//! Module runtime outputs (routers, tasks, health checks) and shutdown hooks.

use std::error::Error;
use std::future::Future;
use std::pin::Pin;

/// Runtime output for one optional router.
#[cfg(any(
    feature = "sse",
    feature = "websockets",
    feature = "auth-webauthn",
    feature = "auth-totp",
    feature = "mcp-auth-oauth",
    feature = "llm-http-api",
))]
pub struct RouterRuntime {
    pub(crate) router: axum::Router,
}

#[cfg(any(
    feature = "sse",
    feature = "websockets",
    feature = "auth-webauthn",
    feature = "auth-totp",
    feature = "mcp-auth-oauth",
    feature = "llm-http-api",
))]
impl RouterRuntime {
    /// Creates a named module router output.
    #[must_use]
    pub fn new(router: axum::Router) -> Self {
        Self { router }
    }
}

/// Runtime output for one supervised task.
#[cfg(any(
    feature = "outbox",
    feature = "scheduler",
    feature = "events-redis-ephemeral",
    feature = "notifications",
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    feature = "mcp-tasks",
    feature = "llm-tool-runtime",
    feature = "llm-media",
))]
pub struct TaskRuntime {
    pub(crate) task: omnius_runtime::TaskSpec,
}

#[cfg(any(
    feature = "outbox",
    feature = "scheduler",
    feature = "events-redis-ephemeral",
    feature = "notifications",
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    feature = "mcp-tasks",
    feature = "llm-tool-runtime",
    feature = "llm-media",
))]
impl TaskRuntime {
    /// Creates a named module task output.
    #[must_use]
    pub fn new(task: omnius_runtime::TaskSpec) -> Self {
        Self { task }
    }
}

/// Runtime output for one health check.
#[cfg(any(
    feature = "object-storage",
    feature = "email",
    feature = "webhooks-svix",
    feature = "llm-provider-rig",
    feature = "llm-provider-bedrock",
    feature = "llm-provider-vertex",
    feature = "llm-routing",
))]
pub struct HealthRuntime {
    pub(crate) health: omnius_health::HealthCheckSpec,
}

#[cfg(any(
    feature = "object-storage",
    feature = "email",
    feature = "webhooks-svix",
    feature = "llm-provider-rig",
    feature = "llm-provider-bedrock",
    feature = "llm-provider-vertex",
    feature = "llm-routing",
))]
impl HealthRuntime {
    /// Creates a named module health output.
    #[must_use]
    pub fn new(health: omnius_health::HealthCheckSpec) -> Self {
        Self { health }
    }
}

/// Boxed failure returned by one application shutdown hook.
pub type ShutdownError = Box<dyn Error + Send + Sync + 'static>;

type ShutdownFuture = Pin<Box<dyn Future<Output = Result<(), ShutdownError>> + Send + 'static>>;

/// Named one-shot asynchronous application shutdown action.
pub struct ShutdownHook {
    pub(crate) name: &'static str,
    pub(crate) callback: Box<dyn FnOnce() -> ShutdownFuture + Send + 'static>,
}

impl ShutdownHook {
    /// Creates a named one-shot shutdown action.
    #[must_use]
    pub fn new<F, Fut>(name: &'static str, callback: F) -> Self
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), ShutdownError>> + Send + 'static,
    {
        Self {
            name,
            callback: Box::new(move || Box::pin(callback())),
        }
    }

    /// Returns the fixed-cardinality diagnostic name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Invokes the one-shot action.
    ///
    /// # Errors
    ///
    /// Returns the hook's application-owned shutdown failure.
    pub async fn run(self) -> Result<(), ShutdownError> {
        (self.callback)().await
    }
}

/// Runtime outputs for a task-backed provider with readiness.
#[cfg(feature = "events-nats")]
pub struct TaskHealthRuntime {
    pub(crate) task: omnius_runtime::TaskSpec,
    pub(crate) health: omnius_health::HealthCheckSpec,
}

#[cfg(feature = "events-nats")]
impl TaskHealthRuntime {
    /// Creates task and health outputs.
    #[must_use]
    pub fn new(task: omnius_runtime::TaskSpec, health: omnius_health::HealthCheckSpec) -> Self {
        Self { task, health }
    }
}

/// Runtime outputs for a routed background processor.
#[cfg(any(feature = "webhooks-inbound", feature = "auth-oidc"))]
pub struct RouterTaskRuntime {
    pub(crate) router: axum::Router,
    pub(crate) task: omnius_runtime::TaskSpec,
}

#[cfg(any(feature = "webhooks-inbound", feature = "auth-oidc"))]
impl RouterTaskRuntime {
    /// Creates router and task outputs.
    #[must_use]
    pub fn new(router: axum::Router, task: omnius_runtime::TaskSpec) -> Self {
        Self { router, task }
    }
}

/// Runtime outputs for an authenticated router with readiness.
#[cfg(feature = "mcp-transport-http")]
pub struct RouterHealthRuntime {
    pub(crate) router: axum::Router,
    pub(crate) health: omnius_health::HealthCheckSpec,
}

#[cfg(feature = "mcp-transport-http")]
impl RouterHealthRuntime {
    /// Creates router and health outputs.
    #[must_use]
    pub fn new(router: axum::Router, health: omnius_health::HealthCheckSpec) -> Self {
        Self { router, health }
    }
}
