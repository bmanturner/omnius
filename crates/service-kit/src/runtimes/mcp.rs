//! Application-owned MCP runtime wrappers.

#[cfg(any(feature = "mcp-apps", test))]
use crate::ports::McpAppsPorts;
#[cfg(any(feature = "mcp-transport-http", test))]
use crate::ports::McpBearerAuthenticatorPort;
#[cfg(any(feature = "mcp-tasks", test))]
use crate::ports::McpCancellationRuntimePort;
#[cfg(any(feature = "mcp-tasks", test))]
use crate::ports::McpCapabilityExecutorPort;
#[cfg(any(feature = "mcp-server-core", test))]
use crate::ports::McpCapabilityRegistryPort;
#[cfg(any(feature = "mcp-auth-enterprise", test))]
use crate::ports::McpEnterprisePorts;
#[cfg(any(
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    test
))]
use crate::ports::McpSubscriptionAuthorizerPort;
#[cfg(any(
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    test
))]
use crate::ports::McpSubscriptionDeliveryPort;
#[cfg(any(
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    test
))]
use crate::ports::McpSubscriptionRepositoryPort;
#[cfg(any(
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    test
))]
use crate::ports::McpSubscriptionRuntimePort;
#[cfg(any(feature = "mcp-tasks", test))]
use crate::ports::McpTaskPayloadProtectorPort;

/// Application-owned MCP core contract.
#[derive(Default)]
#[cfg(any(feature = "mcp-server-core", test))]
pub struct McpCoreRuntime {
    pub(crate) capability_registry: Option<std::sync::Arc<dyn McpCapabilityRegistryPort>>,
}

#[cfg(any(feature = "mcp-server-core", test))]
impl McpCoreRuntime {
    port_setter!(
        with_capability_registry,
        capability_registry,
        dyn McpCapabilityRegistryPort
    );
}

/// Application-owned MCP authentication contract.
#[derive(Default)]
#[cfg(any(feature = "mcp-transport-http", test))]
pub struct McpAuthRuntime {
    pub(crate) bearer_authenticator: Option<std::sync::Arc<dyn McpBearerAuthenticatorPort>>,
}

#[cfg(any(feature = "mcp-transport-http", test))]
impl McpAuthRuntime {
    port_setter!(
        with_bearer_authenticator,
        bearer_authenticator,
        dyn McpBearerAuthenticatorPort
    );
}

/// Application-owned MCP enterprise contract.
#[derive(Default)]
#[cfg(any(feature = "mcp-auth-enterprise", test))]
pub struct McpEnterpriseRuntime {
    pub(crate) ports: Option<std::sync::Arc<dyn McpEnterprisePorts>>,
}

#[cfg(any(feature = "mcp-auth-enterprise", test))]
impl McpEnterpriseRuntime {
    port_setter!(with_ports, ports, dyn McpEnterprisePorts);
}

/// Application-owned MCP subscription contract.
#[derive(Default)]
#[cfg(any(
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    test
))]
pub struct McpSubscriptionsRuntime {
    pub(crate) repository: Option<std::sync::Arc<dyn McpSubscriptionRepositoryPort>>,
    pub(crate) authorizer: Option<std::sync::Arc<dyn McpSubscriptionAuthorizerPort>>,
    pub(crate) runtime: Option<std::sync::Arc<dyn McpSubscriptionRuntimePort>>,
    pub(crate) delivery: Option<std::sync::Arc<dyn McpSubscriptionDeliveryPort>>,
}

#[cfg(any(
    feature = "mcp-subscriptions-local",
    feature = "mcp-subscriptions-redis",
    feature = "mcp-subscriptions-nats",
    test
))]
impl McpSubscriptionsRuntime {
    port_setter!(
        with_repository,
        repository,
        dyn McpSubscriptionRepositoryPort
    );
    port_setter!(
        with_authorizer,
        authorizer,
        dyn McpSubscriptionAuthorizerPort
    );
    port_setter!(with_runtime, runtime, dyn McpSubscriptionRuntimePort);
    port_setter!(with_delivery, delivery, dyn McpSubscriptionDeliveryPort);
}

/// Application-owned durable MCP task contract.
#[derive(Default)]
#[cfg(any(feature = "mcp-tasks", test))]
pub struct McpTasksRuntime {
    pub(crate) payload_protector: Option<std::sync::Arc<dyn McpTaskPayloadProtectorPort>>,
    pub(crate) cancellation_runtime: Option<std::sync::Arc<dyn McpCancellationRuntimePort>>,
    pub(crate) capability_executor: Option<std::sync::Arc<dyn McpCapabilityExecutorPort>>,
}

#[cfg(any(feature = "mcp-tasks", test))]
impl McpTasksRuntime {
    port_setter!(
        with_payload_protector,
        payload_protector,
        dyn McpTaskPayloadProtectorPort
    );
    port_setter!(
        with_cancellation_runtime,
        cancellation_runtime,
        dyn McpCancellationRuntimePort
    );
    port_setter!(
        with_capability_executor,
        capability_executor,
        dyn McpCapabilityExecutorPort
    );
}

/// Application-owned MCP Apps contract.
#[derive(Default)]
#[cfg(any(feature = "mcp-apps", test))]
pub struct McpAppsRuntime {
    pub(crate) ports: Option<std::sync::Arc<dyn McpAppsPorts>>,
}

#[cfg(any(feature = "mcp-apps", test))]
impl McpAppsRuntime {
    port_setter!(with_ports, ports, dyn McpAppsPorts);
}
