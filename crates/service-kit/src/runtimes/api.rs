//! Application-owned GraphQL, gRPC, and static-delivery runtime wrappers.

#[cfg(any(feature = "graphql", test))]
use crate::ports::GraphqlRequestDataInjectorPort;
#[cfg(any(feature = "graphql", test))]
use crate::ports::GraphqlSchemaPort;
#[cfg(any(feature = "grpc", test))]
use crate::ports::GrpcApplicationServicePort;
#[cfg(any(feature = "grpc", test))]
use crate::ports::GrpcAuthenticatorPort;
#[cfg(any(feature = "grpc", test))]
use crate::ports::GrpcMethodPoliciesPort;

/// Application-owned GraphQL contract.
#[derive(Default)]
#[cfg(any(feature = "graphql", test))]
pub struct GraphqlRuntime {
    pub(crate) schema: Option<std::sync::Arc<dyn GraphqlSchemaPort>>,
    pub(crate) request_data_injector: Option<std::sync::Arc<dyn GraphqlRequestDataInjectorPort>>,
}

#[cfg(any(feature = "graphql", test))]
impl GraphqlRuntime {
    port_setter!(with_schema, schema, dyn GraphqlSchemaPort);
    port_setter!(
        with_request_data_injector,
        request_data_injector,
        dyn GraphqlRequestDataInjectorPort
    );
}

/// Application-owned gRPC contract.
#[derive(Default)]
#[cfg(any(feature = "grpc", test))]
pub struct GrpcRuntime {
    pub(crate) application_service: Option<std::sync::Arc<dyn GrpcApplicationServicePort>>,
    pub(crate) authenticator: Option<std::sync::Arc<dyn GrpcAuthenticatorPort>>,
    pub(crate) method_policies: Option<std::sync::Arc<dyn GrpcMethodPoliciesPort>>,
}

#[cfg(any(feature = "grpc", test))]
impl GrpcRuntime {
    port_setter!(
        with_application_service,
        application_service,
        dyn GrpcApplicationServicePort
    );
    port_setter!(with_authenticator, authenticator, dyn GrpcAuthenticatorPort);
    port_setter!(
        with_method_policies,
        method_policies,
        dyn GrpcMethodPoliciesPort
    );
}

/// Validated static-delivery runtime.
#[cfg(feature = "web-static")]
pub struct WebStaticRuntime {
    pub(crate) router: axum::Router,
}

#[cfg(feature = "web-static")]
impl WebStaticRuntime {
    /// Creates a runtime from the validated delivery router.
    #[must_use]
    pub fn new(router: axum::Router) -> Self {
        Self { router }
    }
}
