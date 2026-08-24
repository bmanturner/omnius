//! Transactional, append-only PostgreSQL audit records and typed security-event names.
//!
//! [`PostgresAuditSink`] owns neither a pool nor a transaction. Callers append on their own
//! connection or explicit transaction so the audit record and protected business effect commit or
//! roll back together. The sink never queues or spawns delivery work.
//!
//! The schema/migration owner is a trusted administrative principal. Production deployments that
//! need DDL-resistant history should run the application as a separate non-owner role with only
//! the required `INSERT` and read privileges.

use std::{collections::BTreeMap, fmt, str::FromStr, time::Instant};

use rsk_auth_core::{SubjectId, TenantId};
use rsk_authz_basic::{Action, ResourceKind};
use rsk_core::{CausationId, CorrelationId, RequestId};
use rsk_postgres::{RetryableSqlState, RetryableTransactionError};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::{Uuid, Variant, Version};

const MAX_IDENTIFIER_BYTES: usize = 128;

const INSERT_AUDIT_EVENT: &str = r"
    INSERT INTO public.audit_events (
        id, occurred_at, event_type, actor_kind, actor_subject_id, subject_id,
        impersonator_subject_id, effective_tenant_id, action, resource_kind, resource_id,
        outcome, request_id, correlation_id, causation_id, reason, metadata
    )
    VALUES (
        $1, $2, $3, $4, $5, $6,
        $7, $8, $9, $10, $11,
        $12, $13, $14, $15, $16, $17
    )
";

/// An audit event identifier was not an RFC-compatible `UUIDv7` value.
///
/// This error intentionally carries none of the rejected identifier.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("audit event identifier must be a UUIDv7 value")]
pub struct AuditEventIdError;

/// The time-ordered identity of one immutable audit record.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AuditEventId(Uuid);

impl AuditEventId {
    /// Generates a new `UUIDv7` audit identity.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Restores a validated audit identity.
    ///
    /// # Errors
    ///
    /// Returns [`AuditEventIdError`] unless `value` is an RFC-compatible `UUIDv7`.
    pub fn from_uuid(value: Uuid) -> Result<Self, AuditEventIdError> {
        if value.get_version() == Some(Version::SortRand) && value.get_variant() == Variant::RFC4122
        {
            Ok(Self(value))
        } else {
            Err(AuditEventIdError)
        }
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for AuditEventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Default for AuditEventId {
    fn default() -> Self {
        Self::new()
    }
}

/// A bounded audit identifier was invalid.
///
/// Errors are stable and deliberately omit rejected values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuditIdentifierError {
    /// The identifier was empty.
    #[error("audit identifier must not be empty")]
    Empty,
    /// The identifier exceeded 128 bytes.
    #[error("audit identifier exceeds 128 bytes")]
    TooLong,
    /// The identifier was outside the portable audit grammar.
    #[error("audit identifier contains an invalid character")]
    InvalidCharacter,
}

fn validate_identifier(value: &str) -> Result<(), AuditIdentifierError> {
    if value.is_empty() {
        return Err(AuditIdentifierError::Empty);
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(AuditIdentifierError::TooLong);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'_' | b'-'))
    {
        return Err(AuditIdentifierError::InvalidCharacter);
    }
    Ok(())
}

macro_rules! audit_identifier {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validates and owns the portable identifier.
            ///
            /// # Errors
            ///
            /// Returns [`AuditIdentifierError`] for an empty, oversized, or non-portable value.
            pub fn new(value: impl Into<String>) -> Result<Self, AuditIdentifierError> {
                let value = value.into();
                validate_identifier(&value)?;
                Ok(Self(value))
            }

            /// Returns the validated identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = AuditIdentifierError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = AuditIdentifierError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

audit_identifier!(AuditEventType, "A stable name classifying an audit event.");
audit_identifier!(
    AuditResourceId,
    "A bounded, non-secret application identifier for the affected resource."
);
audit_identifier!(
    AuditReasonCode,
    "A stable machine-readable explanation for an audit outcome."
);

/// Safe, predefined authentication and identity security-event names.
///
/// Outcomes and reasons belong in their dedicated fields rather than being encoded into names.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityEventName {
    /// An interactive or non-interactive login attempt.
    Login,
    /// An authenticated logout.
    Logout,
    /// A session was created.
    SessionCreated,
    /// A session was refreshed.
    SessionRefreshed,
    /// A session was revoked.
    SessionRevoked,
    /// A session expired.
    SessionExpired,
    /// A password was changed.
    PasswordChanged,
    /// Password recovery was requested.
    PasswordRecoveryRequested,
    /// Password recovery was completed.
    PasswordRecoveryCompleted,
    /// An external identity was linked.
    IdentityLinked,
    /// An external identity was unlinked.
    IdentityUnlinked,
    /// An API key was created.
    ApiKeyCreated,
    /// An API key was rotated.
    ApiKeyRotated,
    /// An API key was revoked.
    ApiKeyRevoked,
    /// An MFA factor was enrolled.
    MfaEnrolled,
    /// An MFA challenge was verified.
    MfaVerified,
    /// An MFA factor was disabled.
    MfaDisabled,
    /// An MFA recovery code was used.
    MfaRecoveryCodeUsed,
    /// A passkey was registered.
    PasskeyRegistered,
    /// A passkey authenticated a subject.
    PasskeyAuthenticated,
    /// A passkey was removed.
    PasskeyRemoved,
    /// Refresh-token reuse was detected.
    RefreshReuseDetected,
    /// An administrator performed an identity action.
    AdministrativeIdentityAction,
    /// An administrator started acting as another human user.
    ImpersonationStarted,
    /// An administrator stopped acting as another human user.
    ImpersonationEnded,
}

impl SecurityEventName {
    /// Returns the stable persisted event name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Login => "security.login",
            Self::Logout => "security.logout",
            Self::SessionCreated => "security.session.created",
            Self::SessionRefreshed => "security.session.refreshed",
            Self::SessionRevoked => "security.session.revoked",
            Self::SessionExpired => "security.session.expired",
            Self::PasswordChanged => "security.password.changed",
            Self::PasswordRecoveryRequested => "security.password_recovery.requested",
            Self::PasswordRecoveryCompleted => "security.password_recovery.completed",
            Self::IdentityLinked => "security.identity.linked",
            Self::IdentityUnlinked => "security.identity.unlinked",
            Self::ApiKeyCreated => "security.api_key.created",
            Self::ApiKeyRotated => "security.api_key.rotated",
            Self::ApiKeyRevoked => "security.api_key.revoked",
            Self::MfaEnrolled => "security.mfa.enrolled",
            Self::MfaVerified => "security.mfa.verified",
            Self::MfaDisabled => "security.mfa.disabled",
            Self::MfaRecoveryCodeUsed => "security.mfa.recovery_code_used",
            Self::PasskeyRegistered => "security.passkey.registered",
            Self::PasskeyAuthenticated => "security.passkey.authenticated",
            Self::PasskeyRemoved => "security.passkey.removed",
            Self::RefreshReuseDetected => "security.refresh_reuse_detected",
            Self::AdministrativeIdentityAction => "security.admin.identity_action",
            Self::ImpersonationStarted => "security.admin.impersonation.started",
            Self::ImpersonationEnded => "security.admin.impersonation.ended",
        }
    }
}

impl From<SecurityEventName> for AuditEventType {
    fn from(value: SecurityEventName) -> Self {
        Self(value.as_str().to_owned())
    }
}

/// The persisted class of an audit actor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuditActorKind {
    /// Infrastructure or trusted application code without a subject identity.
    System,
    /// An unauthenticated caller without a subject identity.
    Anonymous,
    /// An authenticated human user.
    User,
    /// An authenticated service account.
    ServiceAccount,
}

impl AuditActorKind {
    /// Returns the stable database representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Anonymous => "anonymous",
            Self::User => "user",
            Self::ServiceAccount => "service_account",
        }
    }
}

/// A coherent audit actor whose kind determines whether a subject identity is present.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditActor {
    /// Infrastructure or trusted application code.
    System,
    /// An unauthenticated caller.
    Anonymous,
    /// An authenticated human user.
    User(SubjectId),
    /// An authenticated service account.
    ServiceAccount(SubjectId),
}

impl AuditActor {
    /// Returns the actor class.
    #[must_use]
    pub const fn kind(self) -> AuditActorKind {
        match self {
            Self::System => AuditActorKind::System,
            Self::Anonymous => AuditActorKind::Anonymous,
            Self::User(_) => AuditActorKind::User,
            Self::ServiceAccount(_) => AuditActorKind::ServiceAccount,
        }
    }

    /// Returns the actor subject for user and service-account actors.
    #[must_use]
    pub const fn subject_id(self) -> Option<SubjectId> {
        match self {
            Self::System | Self::Anonymous => None,
            Self::User(subject_id) | Self::ServiceAccount(subject_id) => Some(subject_id),
        }
    }
}

/// The explicit authorization scope of an audit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditScope {
    /// An event not authorized within a tenant.
    Global,
    /// An event authorized within the named effective tenant.
    Tenant(TenantId),
}

impl AuditScope {
    const fn tenant_id(self) -> Option<TenantId> {
        match self {
            Self::Global => None,
            Self::Tenant(tenant_id) => Some(tenant_id),
        }
    }
}

/// An impersonator was incoherent with the effective actor.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("audit impersonation requires distinct human-user identities")]
pub struct AuditImpersonationError;

/// The result of the audited action.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuditOutcome {
    /// The action completed successfully.
    Succeeded,
    /// Policy or authentication denied the action.
    Denied,
    /// The action was allowed to run but failed.
    Failed,
}

impl AuditOutcome {
    /// Returns the stable database representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }
}

/// A closed, typed vocabulary of non-secret audit metadata fields.
///
/// New variants require an explicit security review; callers cannot provide arbitrary keys or
/// text. Bounded attempt counts and booleans are the only supported values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditMetadataField {
    /// A bounded ordinal attempt count.
    Attempt(u8),
    /// Whether a result came from a cache.
    Cached(bool),
    /// Whether a human participated interactively.
    Interactive(bool),
}

impl AuditMetadataField {
    const fn into_entry(self) -> (&'static str, AuditMetadataValue) {
        match self {
            Self::Attempt(value) => ("attempt", AuditMetadataValue::Integer(value)),
            Self::Cached(value) => ("cached", AuditMetadataValue::Boolean(value)),
            Self::Interactive(value) => ("interactive", AuditMetadataValue::Boolean(value)),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(untagged)]
enum AuditMetadataValue {
    Boolean(bool),
    Integer(u8),
}

/// Safe metadata construction failed.
///
/// The error is value-free so display and debug output cannot leak metadata.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuditMetadataError {
    /// The same typed field appeared more than once.
    #[error("audit metadata contains a duplicate field")]
    DuplicateField,
}

/// A normalized, closed-vocabulary audit metadata object.
#[derive(Clone, Eq, PartialEq)]
pub struct AuditMetadata {
    entries: BTreeMap<&'static str, AuditMetadataValue>,
}

impl AuditMetadata {
    /// Returns an empty valid metadata object.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Starts a typed metadata builder.
    #[must_use]
    pub const fn builder() -> AuditMetadataBuilder {
        AuditMetadataBuilder::new()
    }

    /// Builds normalized metadata from typed fields.
    ///
    /// # Errors
    ///
    /// Returns [`AuditMetadataError::DuplicateField`] when a field appears twice.
    pub fn try_from_fields<I>(fields: I) -> Result<Self, AuditMetadataError>
    where
        I: IntoIterator<Item = AuditMetadataField>,
    {
        let mut builder = AuditMetadataBuilder::new();
        for field in fields {
            builder = builder.insert(field)?;
        }
        Ok(builder.build())
    }

    /// Returns the number of fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Reports whether the object has no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for AuditMetadata {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for AuditMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditMetadata")
            .field("field_count", &self.entries.len())
            .finish()
    }
}

/// Incremental construction for a typed [`AuditMetadata`] object.
#[derive(Clone, Default)]
pub struct AuditMetadataBuilder {
    entries: BTreeMap<&'static str, AuditMetadataValue>,
}

impl fmt::Debug for AuditMetadataBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditMetadataBuilder")
            .field("field_count", &self.entries.len())
            .finish()
    }
}

impl AuditMetadataBuilder {
    /// Creates an empty metadata builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Adds one field from the closed metadata vocabulary.
    ///
    /// # Errors
    ///
    /// Returns [`AuditMetadataError::DuplicateField`] when the field is already present.
    pub fn insert(mut self, field: AuditMetadataField) -> Result<Self, AuditMetadataError> {
        let (key, value) = field.into_entry();
        if self.entries.insert(key, value).is_some() {
            return Err(AuditMetadataError::DuplicateField);
        }
        Ok(self)
    }

    /// Finalizes the normalized object.
    #[must_use]
    pub fn build(self) -> AuditMetadata {
        AuditMetadata {
            entries: self.entries,
        }
    }
}

/// One complete immutable audit record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    id: AuditEventId,
    occurred_at: OffsetDateTime,
    event_type: AuditEventType,
    actor: AuditActor,
    subject_id: Option<SubjectId>,
    impersonator_subject_id: Option<SubjectId>,
    effective_tenant_id: Option<TenantId>,
    action: Action,
    resource_kind: ResourceKind,
    resource_id: Option<AuditResourceId>,
    outcome: AuditOutcome,
    request_id: Option<RequestId>,
    correlation_id: Option<CorrelationId>,
    causation_id: Option<CausationId>,
    reason: Option<AuditReasonCode>,
    metadata: AuditMetadata,
}

impl AuditEvent {
    /// Starts a typed builder with every required field.
    ///
    /// `event_type` accepts either a validated [`AuditEventType`] or a typed
    /// [`SecurityEventName`]. Callers must choose a global or tenant scope explicitly. The
    /// generated ID is `UUIDv7`.
    #[must_use]
    pub fn builder(
        event_type: impl Into<AuditEventType>,
        occurred_at: OffsetDateTime,
        actor: AuditActor,
        scope: AuditScope,
        action: Action,
        resource_kind: ResourceKind,
        outcome: AuditOutcome,
    ) -> AuditEventBuilder {
        AuditEventBuilder {
            id: AuditEventId::new(),
            occurred_at,
            event_type: event_type.into(),
            actor,
            subject_id: None,
            impersonator_subject_id: None,
            effective_tenant_id: scope.tenant_id(),
            action,
            resource_kind,
            resource_id: None,
            outcome,
            request_id: None,
            correlation_id: None,
            causation_id: None,
            reason: None,
            metadata: AuditMetadata::empty(),
        }
    }

    /// Returns the immutable event identity.
    #[must_use]
    pub const fn id(&self) -> AuditEventId {
        self.id
    }

    /// Returns when the event occurred.
    #[must_use]
    pub const fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    /// Returns the event classification.
    #[must_use]
    pub const fn event_type(&self) -> &AuditEventType {
        &self.event_type
    }

    /// Returns the effective actor.
    #[must_use]
    pub const fn actor(&self) -> AuditActor {
        self.actor
    }

    /// Returns the separately affected subject, if any.
    #[must_use]
    pub const fn subject_id(&self) -> Option<SubjectId> {
        self.subject_id
    }

    /// Returns the separately recorded impersonator, if any.
    #[must_use]
    pub const fn impersonator_subject_id(&self) -> Option<SubjectId> {
        self.impersonator_subject_id
    }

    /// Returns the effective tenant, if any.
    #[must_use]
    pub const fn effective_tenant_id(&self) -> Option<TenantId> {
        self.effective_tenant_id
    }

    /// Returns the audited action.
    #[must_use]
    pub const fn action(&self) -> &Action {
        &self.action
    }

    /// Returns the affected resource class.
    #[must_use]
    pub const fn resource_kind(&self) -> &ResourceKind {
        &self.resource_kind
    }

    /// Returns the bounded resource identity, if any.
    #[must_use]
    pub const fn resource_id(&self) -> Option<&AuditResourceId> {
        self.resource_id.as_ref()
    }

    /// Returns the audited result.
    #[must_use]
    pub const fn outcome(&self) -> AuditOutcome {
        self.outcome
    }

    /// Returns the request identity, if any.
    #[must_use]
    pub const fn request_id(&self) -> Option<RequestId> {
        self.request_id
    }

    /// Returns the cross-transport correlation identity, if any.
    #[must_use]
    pub const fn correlation_id(&self) -> Option<CorrelationId> {
        self.correlation_id
    }

    /// Returns the causing work identity, if any.
    #[must_use]
    pub const fn causation_id(&self) -> Option<CausationId> {
        self.causation_id
    }

    /// Returns the stable reason, if any.
    #[must_use]
    pub const fn reason(&self) -> Option<&AuditReasonCode> {
        self.reason.as_ref()
    }

    /// Returns the safe scalar metadata object.
    #[must_use]
    pub const fn metadata(&self) -> &AuditMetadata {
        &self.metadata
    }
}

/// Builder for optional audit fields after all required fields are supplied.
#[derive(Clone, Debug)]
pub struct AuditEventBuilder {
    id: AuditEventId,
    occurred_at: OffsetDateTime,
    event_type: AuditEventType,
    actor: AuditActor,
    subject_id: Option<SubjectId>,
    impersonator_subject_id: Option<SubjectId>,
    effective_tenant_id: Option<TenantId>,
    action: Action,
    resource_kind: ResourceKind,
    resource_id: Option<AuditResourceId>,
    outcome: AuditOutcome,
    request_id: Option<RequestId>,
    correlation_id: Option<CorrelationId>,
    causation_id: Option<CausationId>,
    reason: Option<AuditReasonCode>,
    metadata: AuditMetadata,
}

impl AuditEventBuilder {
    /// Uses a previously validated event identity, primarily when accepting a caller-created event.
    #[must_use]
    pub const fn id(mut self, id: AuditEventId) -> Self {
        self.id = id;
        self
    }

    /// Records the subject affected by the action independently of the actor.
    #[must_use]
    pub const fn subject_id(mut self, subject_id: SubjectId) -> Self {
        self.subject_id = Some(subject_id);
        self
    }

    /// Records the distinct human user who is impersonating the effective user actor.
    ///
    /// # Errors
    ///
    /// Returns [`AuditImpersonationError`] unless the effective actor is a different human user.
    pub fn impersonator_subject_id(
        mut self,
        subject_id: SubjectId,
    ) -> Result<Self, AuditImpersonationError> {
        match self.actor {
            AuditActor::User(actor_subject_id) if actor_subject_id != subject_id => {
                self.impersonator_subject_id = Some(subject_id);
                Ok(self)
            }
            AuditActor::System
            | AuditActor::Anonymous
            | AuditActor::User(_)
            | AuditActor::ServiceAccount(_) => Err(AuditImpersonationError),
        }
    }

    /// Records a bounded application resource identity.
    #[must_use]
    pub fn resource_id(mut self, resource_id: AuditResourceId) -> Self {
        self.resource_id = Some(resource_id);
        self
    }

    /// Records the request identity.
    #[must_use]
    pub const fn request_id(mut self, request_id: RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Records the cross-transport correlation identity.
    #[must_use]
    pub const fn correlation_id(mut self, correlation_id: CorrelationId) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Records the causing work identity.
    #[must_use]
    pub const fn causation_id(mut self, causation_id: CausationId) -> Self {
        self.causation_id = Some(causation_id);
        self
    }

    /// Records a bounded machine-readable reason.
    #[must_use]
    pub fn reason(mut self, reason: AuditReasonCode) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Replaces the default empty metadata with a validated scalar object.
    #[must_use]
    pub fn metadata(mut self, metadata: AuditMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Finalizes the immutable event. No validation is deferred to this step.
    #[must_use]
    pub fn build(self) -> AuditEvent {
        AuditEvent {
            id: self.id,
            occurred_at: self.occurred_at,
            event_type: self.event_type,
            actor: self.actor,
            subject_id: self.subject_id,
            impersonator_subject_id: self.impersonator_subject_id,
            effective_tenant_id: self.effective_tenant_id,
            action: self.action,
            resource_kind: self.resource_kind,
            resource_id: self.resource_id,
            outcome: self.outcome,
            request_id: self.request_id,
            correlation_id: self.correlation_id,
            causation_id: self.causation_id,
            reason: self.reason,
            metadata: self.metadata,
        }
    }
}

/// Runtime toggle for audit persistence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    /// Whether calls append to PostgreSQL.
    pub enabled: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// The explicit result of an awaited append attempt.
#[must_use = "audit append outcomes must be checked, including the explicitly disabled outcome"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditAppendOutcome {
    /// The row was inserted on the caller-owned connection or transaction.
    Appended,
    /// Persistence was explicitly disabled by configuration.
    Disabled,
}

/// Stable, value-free audit persistence failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuditSinkError {
    /// The caller's whole transaction may be replayed for this SQLSTATE.
    #[error("audit transaction encountered a transient conflict")]
    Transient(RetryableSqlState),
    /// PostgreSQL rejected state that passed public validation.
    #[error("audit persistence rejected the requested state")]
    ConstraintViolation,
    /// PostgreSQL was unavailable or returned an unclassified error.
    #[error("audit persistence is unavailable")]
    Unavailable,
}

impl RetryableTransactionError for AuditSinkError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Transient(state) => Some(*state),
            Self::ConstraintViolation | Self::Unavailable => None,
        }
    }
}

/// Synchronous-in-transaction PostgreSQL append sink without an owned pool or transaction.
#[derive(Clone, Copy, Debug)]
pub struct PostgresAuditSink {
    config: AuditConfig,
}

impl PostgresAuditSink {
    /// Creates a sink with an explicit runtime toggle.
    #[must_use]
    pub const fn new(config: AuditConfig) -> Self {
        Self { config }
    }

    /// Returns the sink configuration.
    #[must_use]
    pub const fn config(self) -> AuditConfig {
        self.config
    }

    /// Inserts one complete event using the caller-owned connection or transaction.
    ///
    /// The future completes only after PostgreSQL accepts the `INSERT`. This method never starts,
    /// commits, rolls back, queues, retries, or spawns work. Pass a transaction connection to make
    /// the protected business effect and audit record atomic.
    ///
    /// # Errors
    ///
    /// Returns [`AuditSinkError::Transient`] for a retryable transaction conflict,
    /// [`AuditSinkError::ConstraintViolation`] for schema rejection, or
    /// [`AuditSinkError::Unavailable`] for other database failures. Errors never contain event data.
    pub async fn append_with(
        &self,
        connection: &mut PgConnection,
        event: &AuditEvent,
    ) -> Result<AuditAppendOutcome, AuditSinkError> {
        let started = Instant::now();
        if !self.config.enabled {
            record_append("disabled", started.elapsed());
            return Ok(AuditAppendOutcome::Disabled);
        }

        let result = sqlx::query(INSERT_AUDIT_EVENT)
            .bind(event.id.as_uuid())
            .bind(event.occurred_at)
            .bind(event.event_type.as_str())
            .bind(event.actor.kind().as_str())
            .bind(event.actor.subject_id().map(SubjectId::as_uuid))
            .bind(event.subject_id.map(SubjectId::as_uuid))
            .bind(event.impersonator_subject_id.map(SubjectId::as_uuid))
            .bind(event.effective_tenant_id.map(TenantId::as_uuid))
            .bind(event.action.as_str())
            .bind(event.resource_kind.as_str())
            .bind(event.resource_id.as_ref().map(AuditResourceId::as_str))
            .bind(event.outcome.as_str())
            .bind(event.request_id.map(RequestId::as_uuid))
            .bind(event.correlation_id.map(CorrelationId::as_uuid))
            .bind(event.causation_id.map(CausationId::as_uuid))
            .bind(event.reason.as_ref().map(AuditReasonCode::as_str))
            .bind(sqlx::types::Json(&event.metadata.entries))
            .execute(&mut *connection)
            .await
            .map(|_| AuditAppendOutcome::Appended)
            .map_err(|error| map_sqlx_error(&error));
        record_append(append_result_label(result), started.elapsed());
        result
    }
}

impl Default for PostgresAuditSink {
    fn default() -> Self {
        Self::new(AuditConfig::default())
    }
}

fn map_sqlx_error(error: &sqlx::Error) -> AuditSinkError {
    if let Some(state) = RetryableSqlState::from_sqlx(error) {
        return AuditSinkError::Transient(state);
    }
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
    {
        Some(code)
            if matches!(
                code.as_ref(),
                "22001" | "22003" | "22P02" | "23502" | "23505" | "23514"
            ) =>
        {
            AuditSinkError::ConstraintViolation
        }
        _ => AuditSinkError::Unavailable,
    }
}

fn append_result_label(result: Result<AuditAppendOutcome, AuditSinkError>) -> &'static str {
    match result {
        Ok(AuditAppendOutcome::Appended) => "appended",
        Ok(AuditAppendOutcome::Disabled) => "disabled",
        Err(AuditSinkError::Transient(_)) => "transient",
        Err(AuditSinkError::ConstraintViolation) => "constraint_violation",
        Err(AuditSinkError::Unavailable) => "unavailable",
    }
}

fn record_append(result: &'static str, elapsed: std::time::Duration) {
    metrics::counter!(
        "rsk_audit_appends_total",
        "result" => result,
    )
    .increment(1);
    metrics::histogram!("rsk_audit_append_duration_seconds").record(elapsed.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action() -> Result<Action, Box<dyn std::error::Error>> {
        Ok(Action::new("identity.update")?)
    }

    fn resource_kind() -> Result<ResourceKind, Box<dyn std::error::Error>> {
        Ok(ResourceKind::new("identity")?)
    }

    #[test]
    fn identifiers_enforce_portable_absolute_bounds_without_echoing_values() {
        assert_eq!(AuditEventType::new(""), Err(AuditIdentifierError::Empty));
        assert_eq!(
            AuditResourceId::new("x".repeat(MAX_IDENTIFIER_BYTES + 1)),
            Err(AuditIdentifierError::TooLong)
        );
        let rejected = "secret value with spaces";
        let error = AuditReasonCode::new(rejected).err();
        assert_eq!(error, Some(AuditIdentifierError::InvalidCharacter));
        assert!(!format!("{error:?}").contains(rejected));
        assert!(AuditEventType::new("identity.updated:v2").is_ok());
        assert_eq!(
            SecurityEventName::ImpersonationStarted.as_str(),
            "security.admin.impersonation.started"
        );
        assert_eq!(
            SecurityEventName::ImpersonationEnded.as_str(),
            "security.admin.impersonation.ended"
        );
    }

    #[test]
    fn metadata_is_closed_bounded_and_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let builder = AuditMetadata::builder()
            .insert(AuditMetadataField::Attempt(42))?
            .insert(AuditMetadataField::Cached(false))?
            .insert(AuditMetadataField::Interactive(true))?;
        let rendered = format!("{builder:?}");
        assert!(!rendered.contains("42"));
        assert!(!rendered.contains("attempt"));

        let metadata = builder.build();
        assert_eq!(metadata.len(), 3);
        assert!(!format!("{metadata:?}").contains("42"));
        let duplicate = AuditMetadata::builder()
            .insert(AuditMetadataField::Attempt(1))?
            .insert(AuditMetadataField::Attempt(2))
            .err();
        assert_eq!(duplicate, Some(AuditMetadataError::DuplicateField));
        Ok(())
    }

    #[test]
    fn typed_builder_keeps_actor_subject_impersonator_tenant_and_lineage_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let actor = SubjectId::new();
        let subject = SubjectId::new();
        let impersonator = SubjectId::new();
        let tenant = TenantId::new();
        let request_id = RequestId::from_uuid(Uuid::nil());
        let correlation_id = CorrelationId::from_uuid(Uuid::from_u128(1));
        let causation_id = CausationId::from_uuid(Uuid::from_u128(2));
        let occurred_at = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
        let event = AuditEvent::builder(
            SecurityEventName::AdministrativeIdentityAction,
            occurred_at,
            AuditActor::User(actor),
            AuditScope::Tenant(tenant),
            action()?,
            resource_kind()?,
            AuditOutcome::Denied,
        )
        .subject_id(subject)
        .impersonator_subject_id(impersonator)?
        .request_id(request_id)
        .correlation_id(correlation_id)
        .causation_id(causation_id)
        .resource_id(AuditResourceId::new("user_42")?)
        .reason(AuditReasonCode::new("policy.denied")?)
        .build();

        assert_eq!(
            event.event_type().as_str(),
            "security.admin.identity_action"
        );
        assert_eq!(event.actor(), AuditActor::User(actor));
        assert_eq!(event.subject_id(), Some(subject));
        assert_eq!(event.impersonator_subject_id(), Some(impersonator));
        assert_eq!(event.effective_tenant_id(), Some(tenant));
        assert_eq!(event.request_id(), Some(request_id));
        assert_eq!(event.correlation_id(), Some(correlation_id));
        assert_eq!(event.causation_id(), Some(causation_id));
        assert_eq!(event.occurred_at(), occurred_at);
        Ok(())
    }

    #[test]
    fn builder_rejects_incoherent_impersonators() -> Result<(), Box<dyn std::error::Error>> {
        let subject = SubjectId::new();
        let occurred_at = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
        for actor in [
            AuditActor::System,
            AuditActor::Anonymous,
            AuditActor::ServiceAccount(SubjectId::new()),
            AuditActor::User(subject),
        ] {
            let result = AuditEvent::builder(
                SecurityEventName::AdministrativeIdentityAction,
                occurred_at,
                actor,
                AuditScope::Global,
                action()?,
                resource_kind()?,
                AuditOutcome::Denied,
            )
            .impersonator_subject_id(subject);
            assert_eq!(result.err(), Some(AuditImpersonationError));
        }
        Ok(())
    }

    #[test]
    fn actor_variants_encode_coherent_subject_presence() {
        let user = SubjectId::new();
        let service = SubjectId::new();
        let actors = [
            (AuditActor::System, AuditActorKind::System, None),
            (AuditActor::Anonymous, AuditActorKind::Anonymous, None),
            (AuditActor::User(user), AuditActorKind::User, Some(user)),
            (
                AuditActor::ServiceAccount(service),
                AuditActorKind::ServiceAccount,
                Some(service),
            ),
        ];
        for (actor, kind, subject_id) in actors {
            assert_eq!(actor.kind(), kind);
            assert_eq!(actor.subject_id(), subject_id);
        }
    }

    #[test]
    fn audit_event_id_rejects_non_v7_without_echoing_input() {
        let rejected = Uuid::nil();
        let error = AuditEventId::from_uuid(rejected).err();
        assert_eq!(error, Some(AuditEventIdError));
        assert!(!format!("{error:?}").contains(&rejected.to_string()));
        assert_eq!(
            AuditEventId::new().as_uuid().get_version(),
            Some(Version::SortRand)
        );
    }
}
