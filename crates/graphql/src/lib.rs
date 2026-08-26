//! Bounded `async-graphql` HTTP transport for application-owned schemas.
//!
//! The crate deliberately owns transport policy rather than product semantics. [`graphql_router`]
//! builds a schema with fixed depth and complexity limits, disables subscriptions, applies an
//! optional persisted-operation allowlist, and installs request-scoped canonical identity,
//! authorization, deadline, and cancellation data. Application resolvers should only translate
//! `GraphQL` inputs and delegate to injected application services.
//!
//! [`AuthorizedBatchLoader`] is the provided `DataLoader`-compatible seam. It calls an injected
//! [`ApplicationQueryService`], authorizes every returned object through the canonical
//! [`AuthorizationService`], and exposes only allowed objects. A typical composition injects the
//! per-request loader through [`RequestDataInjector`]:
//!
//! ```ignore
//! let router = graphql_router(query, mutation, config, move |request, request_context| {
//!     let batch_item_limit = request_context.batch_item_limit();
//!     let loader = AuthorizedBatchLoader::new(
//!         service.clone(),
//!         authorizer.clone(),
//!         read_action.clone(),
//!         request_context,
//!         batch_item_limit,
//!     )
//!     .into_data_loader();
//!     request.data(loader)
//! })?;
//! ```
//!
//! Only `POST /graphql` is exposed. `GraphQL` subscription operations receive a stable error that
//! directs clients to the separately composed realtime transport; this crate never upgrades to a
//! subscription protocol.

#![forbid(unsafe_code)]

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    future::Future,
    hash::Hash,
    io,
    ops::Deref,
    sync::Arc,
    time::{Duration, Instant},
};

use async_graphql::{
    ContextSelectionSet, EmptySubscription, ErrorExtensionValues, ErrorExtensions, ObjectType,
    OutputType, Positioned, Request, Response, Schema, ServerError, ServerResult, Value,
    dataloader::{DataLoader, Loader},
    parser::types::{
        Directive, DocumentOperations, ExecutableDocument, Field, OperationDefinition,
        OperationType, Selection,
    },
    registry,
    resolver_utils::resolve_list,
};
use async_graphql_value::Value as InputValue;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, State, rejection::JsonRejection},
    http::{
        StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE},
    },
    response::{IntoResponse, Response as HttpResponse},
    routing::post,
};
use rsk_auth_core::{Principal, TenantId};
use rsk_authz_basic::{
    Action, AuthorizationContext, AuthorizationProvider, AuthorizationService, Decision, Resource,
};
use rsk_core::RequestId;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

/// Reserved `GraphQL` HTTP endpoint.
pub const GRAPHQL_PATH: &str = "/graphql";
/// Default maximum `GraphQL` selection depth.
pub const DEFAULT_MAX_DEPTH: usize = 12;
/// Default maximum calculated `GraphQL` operation complexity.
pub const DEFAULT_MAX_COMPLEXITY: usize = 200;
/// Default maximum length of an input or output `GraphQL` list.
pub const DEFAULT_MAX_LIST_ITEMS: usize = 100;
/// Default maximum request body size.
pub const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024;
/// Default maximum serialized response size.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Default execution deadline.
pub const DEFAULT_EXECUTION_TIMEOUT: Duration = Duration::from_secs(5);
/// Default validation recursion bound, aligned with the parser's fixed bound.
pub const DEFAULT_MAX_RECURSIVE_DEPTH: usize = 64;
/// Largest accepted `GraphQL` selection depth.
pub const MAX_DEPTH: usize = 64;
/// Largest accepted calculated `GraphQL` complexity.
pub const MAX_COMPLEXITY: usize = 100_000;
/// Largest accepted `GraphQL` list length.
pub const MAX_LIST_ITEMS: usize = 1_000;
/// Largest accepted `GraphQL` request body.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Largest accepted serialized response size.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Largest accepted execution deadline.
pub const MAX_EXECUTION_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest validation recursion bound, aligned with `async-graphql`'s fixed parser bound.
pub const MAX_RECURSIVE_DEPTH: usize = 64;
/// Largest number of persisted operations in one allowlist.
pub const MAX_PERSISTED_OPERATIONS: usize = 10_000;
/// Largest UTF-8 query text accepted in one persisted operation.
pub const MAX_PERSISTED_OPERATION_BYTES: usize = 64 * 1024;

const MIN_BODY_BYTES: usize = 256;
const MIN_RESPONSE_BYTES: usize = 256;
const PUBLIC_ERROR_MESSAGE: &str = "GraphQL request failed";
const REALTIME_HANDOFF_MESSAGE: &str = "Subscriptions use the realtime transport";
const CODE_GRAPHQL_REQUEST_FAILED: &str = "GRAPHQL_REQUEST_FAILED";
const CODE_INVALID_REQUEST: &str = "INVALID_GRAPHQL_REQUEST";
const CODE_UNAUTHENTICATED: &str = "UNAUTHENTICATED";
const CODE_AUTHORIZATION_CONTEXT_REQUIRED: &str = "AUTHORIZATION_CONTEXT_REQUIRED";
const CODE_BODY_TOO_LARGE: &str = "REQUEST_BODY_TOO_LARGE";
const CODE_RESPONSE_TOO_LARGE: &str = "GRAPHQL_RESPONSE_TOO_LARGE";
const CODE_PERSISTED_REQUIRED: &str = "PERSISTED_OPERATION_REQUIRED";
const CODE_PERSISTED_NOT_ALLOWED: &str = "PERSISTED_OPERATION_NOT_ALLOWED";
const CODE_SUBSCRIPTION_NOT_SUPPORTED: &str = "SUBSCRIPTION_NOT_SUPPORTED";
const CODE_LIST_LIMIT_EXCEEDED: &str = "LIST_LIMIT_EXCEEDED";
const CODE_REQUEST_TIMEOUT: &str = "REQUEST_TIMEOUT";

/// Runtime class used to enforce production-safe introspection policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEnvironment {
    /// Production runtime; introspection cannot be enabled.
    Production,
    /// Development runtime.
    Development,
    /// Test runtime.
    Test,
}

/// Whether the `GraphQL` schema accepts introspection fields.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IntrospectionPolicy {
    /// Reject introspection fields.
    Disabled,
    /// Permit introspection outside production.
    Enabled,
}

/// A validated SHA-256 persisted-operation allowlist.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(transparent)]
pub struct PersistedOperationAllowlist(BTreeMap<String, String>);

impl PersistedOperationAllowlist {
    /// Builds an allowlist and calculates the lowercase SHA-256 identifier for each operation.
    ///
    /// # Errors
    ///
    /// Returns [`PersistedOperationError`] for an empty or excessive allowlist, an empty query,
    /// an excessive query, or a SHA-256 collision between distinct query texts.
    pub fn new<I, S>(operations: I) -> Result<Self, PersistedOperationError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut entries = BTreeMap::new();
        for (index, operation) in operations.into_iter().enumerate() {
            if index >= MAX_PERSISTED_OPERATIONS {
                return Err(PersistedOperationError::TooManyOperations);
            }
            let operation = operation.into();
            validate_operation_text(&operation)?;
            let hash = operation_hash(&operation);
            if let Some(previous) = entries.insert(hash, operation.clone())
                && previous != operation
            {
                return Err(PersistedOperationError::HashCollision);
            }
        }
        let allowlist = Self(entries);
        allowlist.validate()?;
        Ok(allowlist)
    }

    /// Returns the operation registered for `sha256_hash`.
    #[must_use]
    pub fn get(&self, sha256_hash: &str) -> Option<&str> {
        self.0.get(sha256_hash).map(String::as_str)
    }

    /// Returns the number of allowlisted operations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the allowlist contains no operations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn validate(&self) -> Result<(), PersistedOperationError> {
        if self.0.is_empty() {
            return Err(PersistedOperationError::EmptyAllowlist);
        }
        if self.0.len() > MAX_PERSISTED_OPERATIONS {
            return Err(PersistedOperationError::TooManyOperations);
        }
        for (hash, operation) in &self.0 {
            validate_operation_text(operation)?;
            if !valid_sha256_hash(hash) {
                return Err(PersistedOperationError::InvalidHash);
            }
            if operation_hash(operation) != *hash {
                return Err(PersistedOperationError::HashMismatch);
            }
        }
        Ok(())
    }
}

/// Optional persisted-operation enforcement.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case", tag = "mode", content = "operations")]
pub enum PersistedOperationPolicy {
    /// Accept bounded ad hoc `GraphQL` documents.
    #[default]
    Disabled,
    /// Require a known SHA-256 operation identifier.
    Allowlist(PersistedOperationAllowlist),
}

impl PersistedOperationPolicy {
    /// Creates an allowlist policy from canonical operation texts.
    ///
    /// # Errors
    ///
    /// Returns [`PersistedOperationError`] when the allowlist is invalid.
    pub fn allowlist<I, S>(operations: I) -> Result<Self, PersistedOperationError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        PersistedOperationAllowlist::new(operations).map(Self::Allowlist)
    }

    fn validate(&self) -> Result<(), PersistedOperationError> {
        match self {
            Self::Disabled => Ok(()),
            Self::Allowlist(allowlist) => allowlist.validate(),
        }
    }

    fn resolve(&self, request: &mut Request) -> Result<(), RequestRejection> {
        match self {
            Self::Disabled => {
                if request.query.trim().is_empty() {
                    Err(RequestRejection::InvalidRequest)
                } else {
                    Ok(())
                }
            }
            Self::Allowlist(allowlist) => {
                let hash = persisted_operation_hash(request)?
                    .ok_or(RequestRejection::PersistedOperationRequired)?;
                let operation = allowlist
                    .get(&hash)
                    .ok_or(RequestRejection::PersistedOperationNotAllowed)?;
                if !request.query.is_empty() && request.query != operation {
                    return Err(RequestRejection::PersistedOperationNotAllowed);
                }
                operation.clone_into(&mut request.query);
                Ok(())
            }
        }
    }
}

/// Failure to construct a persisted-operation allowlist.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PersistedOperationError {
    /// The allowlist had no operations.
    #[error("persisted-operation allowlist must not be empty")]
    EmptyAllowlist,
    /// The allowlist exceeded its fixed operation bound.
    #[error("persisted-operation allowlist exceeds its operation limit")]
    TooManyOperations,
    /// An operation had no query text.
    #[error("persisted operation must not be empty")]
    EmptyOperation,
    /// An operation exceeded its fixed byte bound.
    #[error("persisted operation exceeds its byte limit")]
    OperationTooLong,
    /// A configured operation identifier was not lowercase SHA-256 hexadecimal.
    #[error("persisted-operation identifier is invalid")]
    InvalidHash,
    /// A configured identifier did not match its operation text.
    #[error("persisted-operation identifier does not match its operation")]
    HashMismatch,
    /// Distinct operation texts produced the same identifier.
    #[error("persisted-operation identifier collision")]
    HashCollision,
}

/// Calculates the lowercase SHA-256 identifier used by persisted operations.
#[must_use]
pub fn operation_hash(operation: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(operation.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Bounded `GraphQL` transport settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct GraphqlConfig {
    /// Runtime class used to make production introspection fail closed.
    pub environment: RuntimeEnvironment,
    /// Introspection policy; production accepts only [`IntrospectionPolicy::Disabled`].
    pub introspection: IntrospectionPolicy,
    /// Maximum selection depth.
    pub max_depth: usize,
    /// Maximum calculated operation complexity.
    pub max_complexity: usize,
    /// Maximum length of every input and output list.
    pub max_list_items: usize,
    /// Maximum request body bytes consumed by the JSON extractor.
    pub max_body_bytes: usize,
    /// Maximum bytes in the fully serialized JSON response.
    pub max_response_bytes: usize,
    /// Maximum recursive validation depth; never exceeds the parser's fixed bound.
    pub max_recursive_depth: usize,
    /// Total resolver execution deadline.
    #[serde(with = "humantime_serde")]
    pub execution_timeout: Duration,
    /// Optional SHA-256 persisted-operation enforcement.
    pub persisted_operations: PersistedOperationPolicy,
}

impl Default for GraphqlConfig {
    fn default() -> Self {
        Self {
            environment: RuntimeEnvironment::Production,
            introspection: IntrospectionPolicy::Disabled,
            max_depth: DEFAULT_MAX_DEPTH,
            max_complexity: DEFAULT_MAX_COMPLEXITY,
            max_list_items: DEFAULT_MAX_LIST_ITEMS,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_recursive_depth: DEFAULT_MAX_RECURSIVE_DEPTH,
            execution_timeout: DEFAULT_EXECUTION_TIMEOUT,
            persisted_operations: PersistedOperationPolicy::Disabled,
        }
    }
}

impl GraphqlConfig {
    /// Validates every configured bound and the production introspection invariant.
    ///
    /// # Errors
    ///
    /// Returns [`GraphqlBuildError`] for zero or excessive bounds, enabled production
    /// introspection, or an invalid persisted-operation allowlist.
    pub fn validate(&self) -> Result<(), GraphqlBuildError> {
        validate_bound("max_depth", self.max_depth, MAX_DEPTH)?;
        validate_bound("max_complexity", self.max_complexity, MAX_COMPLEXITY)?;
        validate_bound("max_list_items", self.max_list_items, MAX_LIST_ITEMS)?;
        if self.max_body_bytes < MIN_BODY_BYTES {
            return Err(GraphqlBuildError::LimitTooSmall("max_body_bytes"));
        }
        if self.max_body_bytes > MAX_BODY_BYTES {
            return Err(GraphqlBuildError::LimitTooLarge("max_body_bytes"));
        }
        if self.max_response_bytes < MIN_RESPONSE_BYTES {
            return Err(GraphqlBuildError::LimitTooSmall("max_response_bytes"));
        }
        if self.max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(GraphqlBuildError::LimitTooLarge("max_response_bytes"));
        }
        validate_bound(
            "max_recursive_depth",
            self.max_recursive_depth,
            MAX_RECURSIVE_DEPTH,
        )?;
        if self.execution_timeout.is_zero() {
            return Err(GraphqlBuildError::LimitTooSmall("execution_timeout"));
        }
        if self.execution_timeout > MAX_EXECUTION_TIMEOUT {
            return Err(GraphqlBuildError::LimitTooLarge("execution_timeout"));
        }
        if self.environment == RuntimeEnvironment::Production
            && self.introspection == IntrospectionPolicy::Enabled
        {
            return Err(GraphqlBuildError::ProductionIntrospection);
        }
        self.persisted_operations.validate()?;
        Ok(())
    }
}

/// Failure to build a bounded `GraphQL` transport.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GraphqlBuildError {
    /// A configured limit was zero or below its safe minimum.
    #[error("GraphQL limit is below its safe minimum: {0}")]
    LimitTooSmall(&'static str),
    /// A configured limit exceeded its fixed maximum.
    #[error("GraphQL limit exceeds its fixed maximum: {0}")]
    LimitTooLarge(&'static str),
    /// Production configuration attempted to enable introspection.
    #[error("GraphQL introspection cannot be enabled in production")]
    ProductionIntrospection,
    /// The persisted-operation policy was invalid.
    #[error(transparent)]
    PersistedOperation(#[from] PersistedOperationError),
}

/// Canonical request facts propagated to application services and batch loaders.
#[derive(Clone, Debug)]
pub struct GraphqlRequestContext {
    principal: Arc<Principal>,
    authorization_context: Arc<AuthorizationContext>,
    tenant_id: Option<TenantId>,
    batch_item_limit: BatchItemLimit,
    request_id: RequestId,
    deadline: Instant,
    cancellation: CancellationToken,
}

impl GraphqlRequestContext {
    fn new(
        principal: Principal,
        authorization_context: AuthorizationContext,
        request_id: RequestId,
        batch_item_limit: BatchItemLimit,
        execution_timeout: Duration,
    ) -> Self {
        let tenant_id = principal.tenant_id;
        Self {
            principal: Arc::new(principal),
            authorization_context: Arc::new(authorization_context),
            tenant_id,
            batch_item_limit,
            request_id,
            deadline: Instant::now() + execution_timeout,
            cancellation: CancellationToken::new(),
        }
    }

    /// Returns the canonical authenticated principal.
    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Returns the canonical tenant carried by the principal, when present.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<TenantId> {
        self.tenant_id
    }

    /// Returns the validated list and application-service batch bound for this request.
    #[must_use]
    pub const fn batch_item_limit(&self) -> BatchItemLimit {
        self.batch_item_limit
    }

    /// Returns the authoritative authorization context installed by application composition.
    #[must_use]
    pub fn authorization_context(&self) -> &AuthorizationContext {
        &self.authorization_context
    }

    /// Returns the canonical request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the absolute execution deadline.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Returns the duration remaining before the execution deadline.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// Returns the token cancelled on timeout or when the HTTP request future is dropped.
    #[must_use]
    pub const fn cancellation_token(&self) -> &CancellationToken {
        &self.cancellation
    }
}

/// Adds application-owned services and request-scoped `DataLoader`s to a `GraphQL` request.
///
/// The transport has already inserted `Arc<GraphqlRequestContext>` when this method runs. The
/// injector must not authenticate or authorize: it only attaches already-composed services.
pub trait RequestDataInjector: Send + Sync + 'static {
    /// Adds application-owned request data.
    fn inject(&self, request: Request, context: Arc<GraphqlRequestContext>) -> Request;
}

impl<F> RequestDataInjector for F
where
    F: Fn(Request, Arc<GraphqlRequestContext>) -> Request + Send + Sync + 'static,
{
    fn inject(&self, request: Request, context: Arc<GraphqlRequestContext>) -> Request {
        self(request, context)
    }
}

/// One application-service result paired with authoritative resource facts.
#[derive(Clone, Debug)]
pub struct QueryObject<V> {
    resource: Resource,
    value: V,
}

impl<V> QueryObject<V> {
    /// Binds an application value to the resource facts used for per-object authorization.
    #[must_use]
    pub const fn new(resource: Resource, value: V) -> Self {
        Self { resource, value }
    }

    /// Returns the resource facts used for authorization.
    #[must_use]
    pub const fn resource(&self) -> &Resource {
        &self.resource
    }

    /// Returns the application value.
    #[must_use]
    pub const fn value(&self) -> &V {
        &self.value
    }

    /// Consumes the wrapper and returns the application value.
    #[must_use]
    pub fn into_value(self) -> V {
        self.value
    }
}

/// Application-owned batch query boundary used by [`AuthorizedBatchLoader`].
///
/// Implementations receive the canonical principal, tenant, authorization context, deadline, and
/// cancellation token through [`GraphqlRequestContext`]. Provider-specific failures are mapped to
/// a stable transport error and are never returned to `GraphQL` clients.
pub trait ApplicationQueryService<K>: Send + Sync + 'static
where
    K: Send + Sync + Hash + Eq + Clone + 'static,
{
    /// Application output exposed by a resolver after authorization.
    type Value: Send + Sync + Clone + 'static;
    /// Application-service failure, retained only inside the application boundary.
    type Error: Send + Sync + 'static;

    /// Loads application values and their authoritative resource facts in one bounded batch.
    fn load<'a>(
        &'a self,
        context: &'a GraphqlRequestContext,
        keys: &'a [K],
    ) -> impl Future<Output = Result<HashMap<K, QueryObject<Self::Value>>, Self::Error>> + Send + 'a;
}

/// Validated non-zero upper bound for one application-service batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchItemLimit(usize);

impl BatchItemLimit {
    /// Validates a batch bound against the transport-wide list maximum.
    ///
    /// # Errors
    ///
    /// Returns [`BatchItemLimitError`] when `value` is zero or exceeds [`MAX_LIST_ITEMS`].
    pub const fn new(value: usize) -> Result<Self, BatchItemLimitError> {
        if value == 0 {
            return Err(BatchItemLimitError::Zero);
        }
        if value > MAX_LIST_ITEMS {
            return Err(BatchItemLimitError::TooLarge);
        }
        Ok(Self(value))
    }

    /// Returns the validated batch bound.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl TryFrom<usize> for BatchItemLimit {
    type Error = BatchItemLimitError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Invalid application-service batch bound.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BatchItemLimitError {
    /// A batch bound must be non-zero.
    #[error("GraphQL batch item limit must be greater than zero")]
    Zero,
    /// A batch bound exceeded the transport-wide list maximum.
    #[error("GraphQL batch item limit exceeds its fixed maximum")]
    TooLarge,
}

/// A list collected without allocating beyond the validated `GraphQL` list bound.
///
/// Application resolvers returning lists should use this type with
/// [`GraphqlRequestContext::batch_item_limit`]. The response walk remains a fail-closed backstop
/// for third-party output types, while this wrapper prevents an oversized iterator from first
/// materializing an unbounded `Vec`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedList<T>(Vec<T>);

impl<T> BoundedList<T> {
    /// Collects at most `limit` items from an iterator.
    ///
    /// The collector retains no more than `limit` elements. It reads at most one additional item
    /// to detect an oversized result.
    ///
    /// # Errors
    ///
    /// Returns [`ListLimitError`] when the iterator contains more than `limit` items.
    pub fn try_collect<I>(values: I, limit: BatchItemLimit) -> Result<Self, ListLimitError>
    where
        I: IntoIterator<Item = T>,
    {
        let mut values = values.into_iter();
        let mut items = Vec::with_capacity(values.size_hint().0.min(limit.get()));
        for value in &mut values {
            if items.len() == limit.get() {
                return Err(ListLimitError);
            }
            items.push(value);
        }
        Ok(Self(items))
    }

    /// Returns the bounded values as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Consumes the wrapper into its already-bounded vector.
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T> Deref for BoundedList<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: OutputType> OutputType for BoundedList<T> {
    fn type_name() -> Cow<'static, str> {
        Cow::Owned(format!("[{}]", T::qualified_type_name()))
    }

    fn qualified_type_name() -> String {
        format!("[{}]!", T::qualified_type_name())
    }

    fn create_type_info(registry: &mut registry::Registry) -> String {
        T::create_type_info(registry);
        Self::qualified_type_name()
    }

    async fn resolve(
        &self,
        context: &ContextSelectionSet<'_>,
        field: &Positioned<Field>,
    ) -> ServerResult<Value> {
        resolve_list(context, field, &self.0, Some(self.0.len())).await
    }
}

/// A resolver attempted to produce more than the validated `GraphQL` list bound.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GraphQL list limit exceeded")]
pub struct ListLimitError;

impl ErrorExtensions for ListLimitError {
    fn extend(&self) -> async_graphql::Error {
        async_graphql::Error::new(self.to_string()).extend_with(|_, extensions| {
            extensions.set("code", CODE_LIST_LIMIT_EXCEEDED);
        })
    }
}

/// Stable `DataLoader` failure safe to pass through a resolver before response sanitization.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BatchLoadError {
    /// The batch exceeded its configured bound.
    #[error("GraphQL batch exceeds its item limit")]
    TooManyItems,
    /// The request was cancelled.
    #[error("GraphQL request was cancelled")]
    Cancelled,
    /// The request deadline elapsed.
    #[error("GraphQL request deadline elapsed")]
    DeadlineExceeded,
    /// The application query service failed.
    #[error("application query is unavailable")]
    ServiceUnavailable,
}

/// `DataLoader` seam that authorizes every application-service result before exposure.
pub struct AuthorizedBatchLoader<S, P> {
    service: Arc<S>,
    authorizer: Arc<AuthorizationService<P>>,
    action: Action,
    context: Arc<GraphqlRequestContext>,
    max_batch_items: BatchItemLimit,
}

impl<S, P> AuthorizedBatchLoader<S, P> {
    /// Creates a request-scoped authorized loader with a validated item bound.
    #[must_use]
    pub fn new(
        service: Arc<S>,
        authorizer: Arc<AuthorizationService<P>>,
        action: Action,
        context: Arc<GraphqlRequestContext>,
        max_batch_items: BatchItemLimit,
    ) -> Self {
        Self {
            service,
            authorizer,
            action,
            context,
            max_batch_items,
        }
    }

    /// Wraps this request-scoped loader in an `async-graphql` `DataLoader` with the same batch bound.
    #[must_use]
    pub fn into_data_loader(self) -> DataLoader<Self> {
        let max_batch_items = self.max_batch_items.get();
        DataLoader::new(self, tokio::spawn).max_batch_size(max_batch_items)
    }
}

impl<K, S, P> Loader<K> for AuthorizedBatchLoader<S, P>
where
    K: Send + Sync + Hash + Eq + Clone + 'static,
    S: ApplicationQueryService<K>,
    P: AuthorizationProvider + Send + Sync + 'static,
{
    type Value = S::Value;
    type Error = BatchLoadError;

    async fn load(&self, keys: &[K]) -> Result<HashMap<K, Self::Value>, Self::Error> {
        if keys.len() > self.max_batch_items.get() {
            return Err(BatchLoadError::TooManyItems);
        }
        if self.context.cancellation_token().is_cancelled() {
            return Err(BatchLoadError::Cancelled);
        }
        if self.context.remaining().is_zero() {
            return Err(BatchLoadError::DeadlineExceeded);
        }

        let cancellation = self.context.cancellation_token().clone();
        let deadline = tokio::time::Instant::from_std(self.context.deadline());
        let loaded = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(BatchLoadError::Cancelled),
            () = tokio::time::sleep_until(deadline) => return Err(BatchLoadError::DeadlineExceeded),
            result = self.service.load(&self.context, keys) => {
                result.map_err(|_| BatchLoadError::ServiceUnavailable)?
            }
        };

        if self.context.cancellation_token().is_cancelled() {
            return Err(BatchLoadError::Cancelled);
        }
        if self.context.remaining().is_zero() {
            return Err(BatchLoadError::DeadlineExceeded);
        }

        Ok(loaded
            .into_iter()
            .filter_map(|(key, object)| {
                let decision = self.authorizer.authorize(
                    self.context.principal(),
                    &self.action,
                    object.resource(),
                    self.context.authorization_context(),
                );
                (decision == Decision::Allow).then(|| (key, object.into_value()))
            })
            .collect())
    }
}

/// Fully built `GraphQL` schema and HTTP transport state.
pub struct GraphqlTransport<Query, Mutation, Injector> {
    state: GraphqlState<Query, Mutation, Injector>,
}

impl<Query, Mutation, Injector> GraphqlTransport<Query, Mutation, Injector>
where
    Query: ObjectType + 'static,
    Mutation: ObjectType + 'static,
    Injector: RequestDataInjector,
{
    /// Builds a bounded schema with `EmptySubscription` and validated transport policy.
    ///
    /// # Errors
    ///
    /// Returns [`GraphqlBuildError`] when the configuration is unsafe.
    pub fn new(
        query: Query,
        mutation: Mutation,
        config: GraphqlConfig,
        injector: Injector,
    ) -> Result<Self, GraphqlBuildError> {
        config.validate()?;
        let batch_item_limit = BatchItemLimit(config.max_list_items);
        let mut builder = Schema::build(query, mutation, EmptySubscription)
            .limit_depth(config.max_depth)
            .limit_complexity(config.max_complexity)
            .limit_recursive_depth(config.max_recursive_depth);
        if config.introspection == IntrospectionPolicy::Disabled {
            builder = builder.disable_introspection();
        }
        Ok(Self {
            state: GraphqlState {
                schema: builder.finish(),
                config,
                batch_item_limit,
                injector: Arc::new(injector),
            },
        })
    }

    /// Returns the bounded schema for registration or schema export.
    #[must_use]
    pub const fn schema(&self) -> &Schema<Query, Mutation, EmptySubscription> {
        &self.state.schema
    }

    /// Builds a stateless `Axum` router exposing only `POST /graphql`.
    pub fn into_router(self) -> Router {
        let max_body_bytes = self.state.config.max_body_bytes;
        Router::new()
            .route(
                GRAPHQL_PATH,
                post(execute_graphql::<Query, Mutation, Injector>),
            )
            .layer(DefaultBodyLimit::max(max_body_bytes))
            .with_state(self.state)
    }
}

/// Builds a bounded `GraphQL` schema and returns an `Axum` `POST /graphql` router.
///
/// Application composition must install canonical [`Principal`] and [`AuthorizationContext`]
/// request extensions before this router. The `injector` adds application services and `DataLoader`s
/// after the transport creates [`GraphqlRequestContext`].
///
/// # Errors
///
/// Returns [`GraphqlBuildError`] when the configuration is unsafe.
pub fn graphql_router<Query, Mutation, Injector>(
    query: Query,
    mutation: Mutation,
    config: GraphqlConfig,
    injector: Injector,
) -> Result<Router, GraphqlBuildError>
where
    Query: ObjectType + 'static,
    Mutation: ObjectType + 'static,
    Injector: RequestDataInjector,
{
    GraphqlTransport::new(query, mutation, config, injector).map(GraphqlTransport::into_router)
}

struct GraphqlState<Query, Mutation, Injector> {
    schema: Schema<Query, Mutation, EmptySubscription>,
    config: GraphqlConfig,
    batch_item_limit: BatchItemLimit,
    injector: Arc<Injector>,
}

impl<Query, Mutation, Injector> Clone for GraphqlState<Query, Mutation, Injector> {
    fn clone(&self) -> Self {
        Self {
            schema: self.schema.clone(),
            config: self.config.clone(),
            batch_item_limit: self.batch_item_limit,
            injector: Arc::clone(&self.injector),
        }
    }
}

async fn execute_graphql<Query, Mutation, Injector>(
    State(state): State<GraphqlState<Query, Mutation, Injector>>,
    principal: Option<Extension<Principal>>,
    authorization_context: Option<Extension<AuthorizationContext>>,
    request_id: Option<Extension<RequestId>>,
    body: Result<Json<Request>, JsonRejection>,
) -> HttpResponse
where
    Query: ObjectType + 'static,
    Mutation: ObjectType + 'static,
    Injector: RequestDataInjector,
{
    let request_id = request_id.map_or_else(RequestId::new, |Extension(value)| value);
    let Some(Extension(principal)) = principal else {
        return error_http_response(
            StatusCode::UNAUTHORIZED,
            CODE_UNAUTHENTICATED,
            request_id,
            state.config.max_response_bytes,
        );
    };
    let Some(Extension(authorization_context)) = authorization_context else {
        return error_http_response(
            StatusCode::FORBIDDEN,
            CODE_AUTHORIZATION_CONTEXT_REQUIRED,
            request_id,
            state.config.max_response_bytes,
        );
    };
    let Json(mut request) = match body {
        Ok(request) => request,
        Err(rejection) => {
            let status = rejection.status();
            let code = if status == StatusCode::PAYLOAD_TOO_LARGE {
                CODE_BODY_TOO_LARGE
            } else {
                CODE_INVALID_REQUEST
            };
            return error_http_response(status, code, request_id, state.config.max_response_bytes);
        }
    };

    if let Err(rejection) = prepare_request(&state.config, &mut request) {
        return error_http_response(
            StatusCode::OK,
            rejection.code(),
            request_id,
            state.config.max_response_bytes,
        );
    }

    let context = Arc::new(GraphqlRequestContext::new(
        principal,
        authorization_context,
        request_id,
        state.batch_item_limit,
        state.config.execution_timeout,
    ));
    let _cancel_on_drop = CancelOnDrop(context.cancellation_token().clone());
    request.extensions.clear();
    let request = request.data(Arc::clone(&context));
    let request = state.injector.inject(request, Arc::clone(&context));
    let execution_deadline = tokio::time::Instant::from_std(context.deadline());
    let response = if let Ok(response) =
        tokio::time::timeout_at(execution_deadline, state.schema.execute(request)).await
    {
        response
    } else {
        context.cancellation_token().cancel();
        graphql_error(CODE_REQUEST_TIMEOUT)
    };

    finalize_graphql_http_response(
        StatusCode::OK,
        response,
        request_id,
        &state.config,
        context.deadline(),
    )
}

struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestRejection {
    InvalidRequest,
    IntrospectionDisabled,
    PersistedOperationRequired,
    PersistedOperationNotAllowed,
    SubscriptionNotSupported,
    ListLimitExceeded,
}

impl RequestRejection {
    const fn code(self) -> &'static str {
        match self {
            Self::IntrospectionDisabled => CODE_GRAPHQL_REQUEST_FAILED,
            Self::InvalidRequest => CODE_INVALID_REQUEST,
            Self::PersistedOperationRequired => CODE_PERSISTED_REQUIRED,
            Self::PersistedOperationNotAllowed => CODE_PERSISTED_NOT_ALLOWED,
            Self::SubscriptionNotSupported => CODE_SUBSCRIPTION_NOT_SUPPORTED,
            Self::ListLimitExceeded => CODE_LIST_LIMIT_EXCEEDED,
        }
    }
}

fn prepare_request(config: &GraphqlConfig, request: &mut Request) -> Result<(), RequestRejection> {
    config.persisted_operations.resolve(request)?;
    if !const_values_within_limit(request.variables.values(), config.max_list_items) {
        return Err(RequestRejection::ListLimitExceeded);
    }

    let operation_name = request.operation_name.clone();
    let document = request
        .parsed_query()
        .map_err(|_| RequestRejection::InvalidRequest)?;
    let operation = selected_operation(document, operation_name.as_deref())?;
    if operation.ty == OperationType::Subscription {
        return Err(RequestRejection::SubscriptionNotSupported);
    }
    let inspection = inspect_document(document, config.max_list_items);
    if config.introspection == IntrospectionPolicy::Disabled && inspection.contains_introspection {
        return Err(RequestRejection::IntrospectionDisabled);
    }
    if !inspection.values_within_limit {
        return Err(RequestRejection::ListLimitExceeded);
    }
    Ok(())
}

fn selected_operation<'a>(
    document: &'a ExecutableDocument,
    operation_name: Option<&str>,
) -> Result<&'a OperationDefinition, RequestRejection> {
    match &document.operations {
        DocumentOperations::Single(operation) => {
            if operation_name.is_some() {
                Err(RequestRejection::InvalidRequest)
            } else {
                Ok(&operation.node)
            }
        }
        DocumentOperations::Multiple(operations) => match operation_name {
            Some(name) => operations
                .get(name)
                .map(|operation| &operation.node)
                .ok_or(RequestRejection::InvalidRequest),
            None if operations.len() == 1 => operations
                .values()
                .next()
                .map(|operation| &operation.node)
                .ok_or(RequestRejection::InvalidRequest),
            None => Err(RequestRejection::InvalidRequest),
        },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DocumentInspection {
    values_within_limit: bool,
    contains_introspection: bool,
}

fn inspect_document(document: &ExecutableDocument, limit: usize) -> DocumentInspection {
    let mut values = Vec::new();
    let mut const_values = Vec::new();
    let mut selections = Vec::new();
    let mut contains_introspection = false;
    for (_, operation) in document.operations.iter() {
        for variable in &operation.node.variable_definitions {
            if let Some(default) = &variable.node.default_value {
                const_values.push(&default.node);
            }
            push_directive_values(&variable.node.directives, &mut values);
        }
        push_directive_values(&operation.node.directives, &mut values);
        selections.extend(
            operation
                .node
                .selection_set
                .node
                .items
                .iter()
                .map(|selection| &selection.node),
        );
    }
    for fragment in document.fragments.values() {
        push_directive_values(&fragment.node.directives, &mut values);
        selections.extend(
            fragment
                .node
                .selection_set
                .node
                .items
                .iter()
                .map(|selection| &selection.node),
        );
    }

    while let Some(selection) = selections.pop() {
        match selection {
            Selection::Field(field) => {
                values.extend(field.node.arguments.iter().map(|(_, value)| &value.node));
                contains_introspection |=
                    matches!(field.node.name.node.as_str(), "__schema" | "__type");
                push_directive_values(&field.node.directives, &mut values);
                selections.extend(
                    field
                        .node
                        .selection_set
                        .node
                        .items
                        .iter()
                        .map(|selection| &selection.node),
                );
            }
            Selection::FragmentSpread(spread) => {
                push_directive_values(&spread.node.directives, &mut values);
            }
            Selection::InlineFragment(fragment) => {
                push_directive_values(&fragment.node.directives, &mut values);
                selections.extend(
                    fragment
                        .node
                        .selection_set
                        .node
                        .items
                        .iter()
                        .map(|selection| &selection.node),
                );
            }
        }
    }

    DocumentInspection {
        values_within_limit: input_values_within_limit(values, limit)
            && const_values_within_limit(const_values, limit),
        contains_introspection,
    }
}

fn push_directive_values<'a>(
    directives: &'a [Positioned<Directive>],
    values: &mut Vec<&'a InputValue>,
) {
    values.extend(
        directives
            .iter()
            .flat_map(|directive| directive.node.arguments.iter())
            .map(|(_, value)| &value.node),
    );
}

fn input_values_within_limit<'a>(
    values: impl IntoIterator<Item = &'a InputValue>,
    limit: usize,
) -> bool {
    let mut pending = values.into_iter().collect::<Vec<_>>();
    while let Some(value) = pending.pop() {
        match value {
            InputValue::List(items) => {
                if items.len() > limit {
                    return false;
                }
                pending.extend(items);
            }
            InputValue::Object(items) => pending.extend(items.values()),
            InputValue::Variable(_)
            | InputValue::Null
            | InputValue::Number(_)
            | InputValue::String(_)
            | InputValue::Boolean(_)
            | InputValue::Binary(_)
            | InputValue::Enum(_) => {}
        }
    }
    true
}

fn const_values_within_limit<'a>(
    values: impl IntoIterator<Item = &'a Value>,
    limit: usize,
) -> bool {
    let mut pending = values.into_iter().collect::<Vec<_>>();
    while let Some(value) = pending.pop() {
        match value {
            Value::List(items) => {
                if items.len() > limit {
                    return false;
                }
                pending.extend(items);
            }
            Value::Object(items) => pending.extend(items.values()),
            Value::Null
            | Value::Number(_)
            | Value::String(_)
            | Value::Boolean(_)
            | Value::Binary(_)
            | Value::Enum(_) => {}
        }
    }
    true
}

fn response_lists_within_limit(value: &Value, limit: usize) -> bool {
    const_values_within_limit([value], limit)
}

fn persisted_operation_hash(request: &Request) -> Result<Option<String>, RequestRejection> {
    let Some(value) = request.extensions.get("persistedQuery") else {
        return Ok(None);
    };
    let Value::Object(fields) = value else {
        return Err(RequestRejection::PersistedOperationNotAllowed);
    };
    let valid_version = matches!(
        fields.get("version"),
        Some(Value::Number(version)) if version.as_u64() == Some(1)
    );
    let Some(Value::String(hash)) = fields.get("sha256Hash") else {
        return Err(RequestRejection::PersistedOperationNotAllowed);
    };
    if !valid_version || !valid_sha256_hash(hash) {
        return Err(RequestRejection::PersistedOperationNotAllowed);
    }
    Ok(Some(hash.clone()))
}

fn validate_operation_text(operation: &str) -> Result<(), PersistedOperationError> {
    if operation.trim().is_empty() {
        return Err(PersistedOperationError::EmptyOperation);
    }
    if operation.len() > MAX_PERSISTED_OPERATION_BYTES {
        return Err(PersistedOperationError::OperationTooLong);
    }
    Ok(())
}

fn valid_sha256_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_bound(
    name: &'static str,
    value: usize,
    maximum: usize,
) -> Result<(), GraphqlBuildError> {
    if value == 0 {
        return Err(GraphqlBuildError::LimitTooSmall(name));
    }
    if value > maximum {
        return Err(GraphqlBuildError::LimitTooLarge(name));
    }
    Ok(())
}

fn error_http_response(
    status: StatusCode,
    code: &'static str,
    request_id: RequestId,
    max_response_bytes: usize,
) -> HttpResponse {
    serialized_http_response(
        status,
        encode_error_body(code, request_id, max_response_bytes),
    )
}

fn graphql_error(code: &'static str) -> Response {
    let message = public_message(code);
    let mut error = ServerError::new(message, None);
    let mut extensions = ErrorExtensionValues::default();
    extensions.set("code", code);
    error.extensions = Some(extensions);
    Response::from_errors(vec![error])
}

fn finalize_graphql_http_response(
    status: StatusCode,
    response: Response,
    request_id: RequestId,
    config: &GraphqlConfig,
    deadline: Instant,
) -> HttpResponse {
    let response = if Instant::now() >= deadline {
        graphql_error(CODE_REQUEST_TIMEOUT)
    } else if response_lists_within_limit(&response.data, config.max_list_items) {
        response
    } else {
        graphql_error(CODE_LIST_LIMIT_EXCEEDED)
    };
    let response = if Instant::now() >= deadline {
        graphql_error(CODE_REQUEST_TIMEOUT)
    } else {
        response
    };
    let response = sanitize_response(response, request_id);
    if Instant::now() >= deadline {
        return serialized_http_response(
            status,
            encode_error_body(CODE_REQUEST_TIMEOUT, request_id, config.max_response_bytes),
        );
    }

    let encoded = encode_bounded_response(&response, config.max_response_bytes);
    let body = if Instant::now() >= deadline {
        encode_error_body(CODE_REQUEST_TIMEOUT, request_id, config.max_response_bytes)
    } else {
        match encoded {
            Ok(body) => body,
            Err(ResponseEncodeError::TooLarge) => encode_error_body(
                CODE_RESPONSE_TOO_LARGE,
                request_id,
                config.max_response_bytes,
            ),
            Err(ResponseEncodeError::Serialization) => encode_error_body(
                CODE_GRAPHQL_REQUEST_FAILED,
                request_id,
                config.max_response_bytes,
            ),
        }
    };
    serialized_http_response(status, body)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseEncodeError {
    TooLarge,
    Serialization,
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    max_bytes: usize,
    limit_exceeded: bool,
}

impl BoundedJsonWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max_bytes.min(8 * 1024)),
            max_bytes,
            limit_exceeded: false,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl io::Write for BoundedJsonWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let remaining = self.max_bytes.saturating_sub(self.bytes.len());
        if input.len() > remaining {
            self.limit_exceeded = true;
            return Err(io::Error::other(
                "serialized GraphQL response exceeds its byte limit",
            ));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_bounded_response(
    response: &Response,
    max_response_bytes: usize,
) -> Result<Vec<u8>, ResponseEncodeError> {
    let mut writer = BoundedJsonWriter::new(max_response_bytes);
    match serde_json::to_writer(&mut writer, response) {
        Ok(()) => Ok(writer.into_bytes()),
        Err(_) if writer.limit_exceeded => Err(ResponseEncodeError::TooLarge),
        Err(_) => Err(ResponseEncodeError::Serialization),
    }
}

fn encode_error_body(
    code: &'static str,
    request_id: RequestId,
    max_response_bytes: usize,
) -> Vec<u8> {
    let response = sanitize_response(graphql_error(code), request_id);
    encode_bounded_response(&response, max_response_bytes).unwrap_or_else(|_| {
        let message = public_message(code);
        format!(
            r#"{{"errors":[{{"message":"{message}","extensions":{{"code":"{code}","requestId":"{request_id}"}}}}]}}"#
        )
        .into_bytes()
    })
}

fn serialized_http_response(status: StatusCode, body: Vec<u8>) -> HttpResponse {
    let mut http_response = (status, body).into_response();
    http_response.headers_mut().insert(
        CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    http_response.headers_mut().insert(
        CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    http_response
}

fn sanitize_response(mut response: Response, request_id: RequestId) -> Response {
    for error in &mut response.errors {
        let code = error
            .extensions
            .as_ref()
            .and_then(|extensions| extensions.get("code"))
            .and_then(|value| {
                let Value::String(code) = value else {
                    return None;
                };
                public_error_code(code)
            })
            .unwrap_or(CODE_GRAPHQL_REQUEST_FAILED);
        public_message(code).clone_into(&mut error.message);
        error.source = None;
        let mut extensions = ErrorExtensionValues::default();
        extensions.set("code", code);
        extensions.set("requestId", request_id.to_string());
        error.extensions = Some(extensions);
    }
    response
}

fn public_error_code(code: &str) -> Option<&'static str> {
    match code {
        CODE_INVALID_REQUEST => Some(CODE_INVALID_REQUEST),
        CODE_UNAUTHENTICATED => Some(CODE_UNAUTHENTICATED),
        CODE_AUTHORIZATION_CONTEXT_REQUIRED => Some(CODE_AUTHORIZATION_CONTEXT_REQUIRED),
        CODE_BODY_TOO_LARGE => Some(CODE_BODY_TOO_LARGE),
        CODE_RESPONSE_TOO_LARGE => Some(CODE_RESPONSE_TOO_LARGE),
        CODE_PERSISTED_REQUIRED => Some(CODE_PERSISTED_REQUIRED),
        CODE_PERSISTED_NOT_ALLOWED => Some(CODE_PERSISTED_NOT_ALLOWED),
        CODE_SUBSCRIPTION_NOT_SUPPORTED => Some(CODE_SUBSCRIPTION_NOT_SUPPORTED),
        CODE_LIST_LIMIT_EXCEEDED => Some(CODE_LIST_LIMIT_EXCEEDED),
        CODE_REQUEST_TIMEOUT => Some(CODE_REQUEST_TIMEOUT),
        _ => None,
    }
}

fn public_message(code: &str) -> &'static str {
    match code {
        CODE_UNAUTHENTICATED => "Authentication is required",
        CODE_AUTHORIZATION_CONTEXT_REQUIRED => "Authorization context is required",
        CODE_BODY_TOO_LARGE => "GraphQL request body is too large",
        CODE_RESPONSE_TOO_LARGE => "GraphQL response exceeds its byte limit",
        CODE_PERSISTED_REQUIRED => "A persisted operation is required",
        CODE_PERSISTED_NOT_ALLOWED => "The persisted operation is not allowed",
        CODE_SUBSCRIPTION_NOT_SUPPORTED => REALTIME_HANDOFF_MESSAGE,
        CODE_LIST_LIMIT_EXCEEDED => "GraphQL list limit exceeded",
        CODE_REQUEST_TIMEOUT => "GraphQL request deadline elapsed",
        _ => PUBLIC_ERROR_MESSAGE,
    }
}
