use std::{fmt, future::Future, pin::Pin, sync::Arc, time::Duration};

use omnius_auth_core::{SubjectId, TenantId};
use omnius_postgres::PostgresPool;
use sqlx::Row as _;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::{Uuid, Variant, Version};

const MAX_CAPTURE_CIPHERTEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_DISPLAY_BYTES: usize = 1024 * 1024;
const MAX_CAPTURE_AGE: Duration = Duration::from_hours(24);
const PARTS_PER_MILLION: u32 = 1_000_000;
const MAX_POLICY_NAME_BYTES: usize = 128;

type AdminFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A canonical diagnostic capture identifier.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DiagnosticCaptureId(Uuid);

impl DiagnosticCaptureId {
    /// Creates a server-generated time-ordered identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Restores a canonical `UUIDv7` identifier.
    ///
    /// # Errors
    ///
    /// Returns [`LlmAdminError::InvalidRecord`] for another UUID version or variant.
    pub fn from_uuid(value: Uuid) -> Result<Self, LlmAdminError> {
        if value.get_version() == Some(Version::SortRand) && value.get_variant() == Variant::RFC4122
        {
            Ok(Self(value))
        } else {
            Err(LlmAdminError::InvalidRecord)
        }
    }

    /// Returns the database representation.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Debug for DiagnosticCaptureId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiagnosticCaptureId([redacted])")
    }
}

impl Default for DiagnosticCaptureId {
    fn default() -> Self {
        Self::new()
    }
}

/// A bounded configured encryption-key or redaction-profile name.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DiagnosticPolicyName(String);

impl DiagnosticPolicyName {
    /// Validates and owns a portable policy name.
    ///
    /// # Errors
    ///
    /// Returns [`LlmAdminError::InvalidPolicy`] for empty, oversized, or non-portable values.
    pub fn new(value: impl Into<String>) -> Result<Self, LlmAdminError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_POLICY_NAME_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'_' | b'-')
            })
        {
            return Err(LlmAdminError::InvalidPolicy);
        }
        Ok(Self(value))
    }

    /// Borrows the validated value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DiagnosticPolicyName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiagnosticPolicyName([bounded])")
    }
}

/// Protected display policy. Diagnostic content access is disabled unless built explicitly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticCaptureDisplayPolicy {
    enabled: bool,
    maximum_capture_age: Duration,
    maximum_display_bytes: usize,
}

impl DiagnosticCaptureDisplayPolicy {
    /// Builds an explicitly enabled, short-lived, bounded display policy.
    ///
    /// # Errors
    ///
    /// Returns [`LlmAdminError::InvalidPolicy`] for zero or excessive bounds.
    pub fn enabled(
        maximum_capture_age: Duration,
        maximum_display_bytes: usize,
    ) -> Result<Self, LlmAdminError> {
        if maximum_capture_age.is_zero()
            || maximum_capture_age > MAX_CAPTURE_AGE
            || maximum_display_bytes == 0
            || maximum_display_bytes > MAX_DISPLAY_BYTES
        {
            return Err(LlmAdminError::InvalidPolicy);
        }
        Ok(Self {
            enabled: true,
            maximum_capture_age,
            maximum_display_bytes,
        })
    }

    /// Reports whether diagnostic display is explicitly enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the maximum accepted age from capture to expiry.
    #[must_use]
    pub const fn maximum_capture_age(&self) -> Duration {
        self.maximum_capture_age
    }

    /// Returns the maximum post-redaction display size.
    #[must_use]
    pub const fn maximum_display_bytes(&self) -> usize {
        self.maximum_display_bytes
    }
}

impl Default for DiagnosticCaptureDisplayPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            maximum_capture_age: Duration::ZERO,
            maximum_display_bytes: 0,
        }
    }
}

/// Encrypted, sampled capture loaded through a tenant-scoped repository.
pub struct EncryptedDiagnosticCapture {
    id: DiagnosticCaptureId,
    tenant_id: TenantId,
    principal_id: SubjectId,
    encryption_key_id: DiagnosticPolicyName,
    redaction_profile: DiagnosticPolicyName,
    sample_rate_ppm: u32,
    sample_value: u32,
    ciphertext: Box<[u8]>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl EncryptedDiagnosticCapture {
    /// Restores one validated encrypted record.
    ///
    /// # Errors
    ///
    /// Returns [`LlmAdminError::InvalidRecord`] for unencrypted, unsampled, unbounded, or
    /// incoherently timed records.
    #[expect(
        clippy::too_many_arguments,
        reason = "the persistence boundary validates every mandatory capture control"
    )]
    pub fn restore(
        id: DiagnosticCaptureId,
        tenant_id: TenantId,
        principal_id: SubjectId,
        encryption_key_id: DiagnosticPolicyName,
        redaction_profile: DiagnosticPolicyName,
        sample_rate_ppm: u32,
        sample_value: u32,
        ciphertext: Vec<u8>,
        created_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Self, LlmAdminError> {
        if ciphertext.is_empty()
            || ciphertext.len() > MAX_CAPTURE_CIPHERTEXT_BYTES
            || sample_rate_ppm == 0
            || sample_rate_ppm > PARTS_PER_MILLION
            || sample_value >= sample_rate_ppm
            || expires_at <= created_at
        {
            return Err(LlmAdminError::InvalidRecord);
        }
        Ok(Self {
            id,
            tenant_id,
            principal_id,
            encryption_key_id,
            redaction_profile,
            sample_rate_ppm,
            sample_value,
            ciphertext: ciphertext.into_boxed_slice(),
            created_at,
            expires_at,
        })
    }

    /// Returns the capture identity.
    #[must_use]
    pub const fn id(&self) -> DiagnosticCaptureId {
        self.id
    }

    /// Returns the tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the principal whose operation was sampled.
    #[must_use]
    pub const fn principal_id(&self) -> SubjectId {
        self.principal_id
    }

    /// Borrows the configured encryption-key identifier.
    #[must_use]
    pub const fn encryption_key_id(&self) -> &DiagnosticPolicyName {
        &self.encryption_key_id
    }

    /// Borrows the mandatory redaction profile.
    #[must_use]
    pub const fn redaction_profile(&self) -> &DiagnosticPolicyName {
        &self.redaction_profile
    }

    /// Returns the sampling rate used when the capture was admitted.
    #[must_use]
    pub const fn sample_rate_ppm(&self) -> u32 {
        self.sample_rate_ppm
    }

    /// Returns the admitted sampling value.
    #[must_use]
    pub const fn sample_value(&self) -> u32 {
        self.sample_value
    }

    /// Borrows encrypted bytes only for the configured decryptor.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the capture time.
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Returns the mandatory deletion deadline.
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

impl fmt::Debug for EncryptedDiagnosticCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedDiagnosticCapture")
            .field("id", &self.id)
            .field("ciphertext_bytes", &self.ciphertext.len())
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Request to display one capture on the separately protected administration surface.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DiagnosticCaptureDisplayRequest {
    /// Authenticated administrator.
    pub actor_id: SubjectId,
    /// Explicit tenant fence.
    pub tenant_id: TenantId,
    /// Explicit capture target.
    pub capture_id: DiagnosticCaptureId,
    /// Trusted request time.
    pub now: OffsetDateTime,
}

impl fmt::Debug for DiagnosticCaptureDisplayRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticCaptureDisplayRequest")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Final redacted display value. Debug output never formats its content.
pub struct DiagnosticCaptureDisplay {
    /// Capture identity.
    pub capture_id: DiagnosticCaptureId,
    /// Tenant boundary.
    pub tenant_id: TenantId,
    /// Principal whose operation was captured.
    pub principal_id: SubjectId,
    /// Capture time.
    pub created_at: OffsetDateTime,
    /// Mandatory expiry.
    pub expires_at: OffsetDateTime,
    redacted_content: String,
}

impl DiagnosticCaptureDisplay {
    /// Borrows the redacted display content.
    #[must_use]
    pub fn redacted_content(&self) -> &str {
        &self.redacted_content
    }
}

impl fmt::Debug for DiagnosticCaptureDisplay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticCaptureDisplay")
            .field("capture_id", &self.capture_id)
            .field("content_bytes", &self.redacted_content.len())
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Closed audit outcome for one diagnostic display attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticCaptureAuditOutcome {
    /// Display policy was disabled.
    Disabled,
    /// The protected authorization boundary denied access.
    Denied,
    /// No capture existed in the tenant fence.
    NotFound,
    /// The encrypted capture expired or exceeded policy age.
    Expired,
    /// Decryption or mandatory redaction failed.
    Failed,
    /// Redacted content was displayed.
    Displayed,
}

/// Tenant-scoped encrypted capture persistence port.
pub trait DiagnosticCaptureRepository: Send + Sync {
    /// Loads exactly one capture without cross-tenant lookup.
    fn find(
        &self,
        tenant_id: TenantId,
        capture_id: DiagnosticCaptureId,
    ) -> AdminFuture<'_, Result<Option<EncryptedDiagnosticCapture>, LlmAdminError>>;
}

/// Dedicated authorization port for diagnostic content display.
pub trait DiagnosticCaptureAuthorizer: Send + Sync {
    /// Authorizes the exact actor, tenant, and capture target and fails closed.
    fn authorize(
        &self,
        request: DiagnosticCaptureDisplayRequest,
    ) -> AdminFuture<'_, Result<(), LlmAdminError>>;
}

/// Configured decryptor; implementations resolve only approved key identifiers.
pub trait DiagnosticCaptureDecryptor: Send + Sync {
    /// Decrypts one bounded ciphertext without logging key identifiers or bytes.
    fn decrypt(
        &self,
        key_id: &DiagnosticPolicyName,
        ciphertext: &[u8],
    ) -> AdminFuture<'_, Result<Vec<u8>, LlmAdminError>>;
}

/// Mandatory policy-selected redactor applied after decryption and before display.
pub trait DiagnosticCaptureRedactor: Send + Sync {
    /// Produces display-safe text or fails closed.
    fn redact(
        &self,
        profile: &DiagnosticPolicyName,
        plaintext: &[u8],
    ) -> AdminFuture<'_, Result<String, LlmAdminError>>;
}

/// Durable content-free audit port for every diagnostic display decision.
pub trait DiagnosticCaptureAuditor: Send + Sync {
    /// Records the protected attempt. Failure prevents content display.
    fn record(
        &self,
        request: DiagnosticCaptureDisplayRequest,
        outcome: DiagnosticCaptureAuditOutcome,
    ) -> AdminFuture<'_, Result<(), LlmAdminError>>;
}

/// Fail-closed protected diagnostic display service.
#[derive(Clone)]
pub struct DiagnosticCaptureDisplayService {
    policy: DiagnosticCaptureDisplayPolicy,
    repository: Arc<dyn DiagnosticCaptureRepository>,
    authorizer: Arc<dyn DiagnosticCaptureAuthorizer>,
    decryptor: Arc<dyn DiagnosticCaptureDecryptor>,
    redactor: Arc<dyn DiagnosticCaptureRedactor>,
    auditor: Arc<dyn DiagnosticCaptureAuditor>,
}

impl DiagnosticCaptureDisplayService {
    /// Composes the display seam. A default policy keeps it disabled.
    #[must_use]
    pub fn new(
        policy: DiagnosticCaptureDisplayPolicy,
        repository: Arc<dyn DiagnosticCaptureRepository>,
        authorizer: Arc<dyn DiagnosticCaptureAuthorizer>,
        decryptor: Arc<dyn DiagnosticCaptureDecryptor>,
        redactor: Arc<dyn DiagnosticCaptureRedactor>,
        auditor: Arc<dyn DiagnosticCaptureAuditor>,
    ) -> Self {
        Self {
            policy,
            repository,
            authorizer,
            decryptor,
            redactor,
            auditor,
        }
    }

    /// Authorizes, decrypts, redacts, bounds, audits, and returns one exceptional capture display.
    ///
    /// # Errors
    ///
    /// Returns a content-free error. Audit failure always prevents display.
    #[allow(
        clippy::too_many_lines,
        reason = "the exceptional display path keeps every fail-closed authorization and audit gate visible"
    )]
    pub async fn display(
        &self,
        request: DiagnosticCaptureDisplayRequest,
    ) -> Result<DiagnosticCaptureDisplay, LlmAdminError> {
        if !self.policy.is_enabled() {
            return self
                .fail(
                    request,
                    DiagnosticCaptureAuditOutcome::Disabled,
                    LlmAdminError::Disabled,
                )
                .await;
        }
        if self.authorizer.authorize(request).await.is_err() {
            return self
                .fail(
                    request,
                    DiagnosticCaptureAuditOutcome::Denied,
                    LlmAdminError::Denied,
                )
                .await;
        }
        let Some(capture) = self
            .repository
            .find(request.tenant_id, request.capture_id)
            .await?
        else {
            return self
                .fail(
                    request,
                    DiagnosticCaptureAuditOutcome::NotFound,
                    LlmAdminError::NotFound,
                )
                .await;
        };
        if capture.tenant_id() != request.tenant_id || capture.id() != request.capture_id {
            return self
                .fail(
                    request,
                    DiagnosticCaptureAuditOutcome::NotFound,
                    LlmAdminError::NotFound,
                )
                .await;
        }
        let maximum_age = time::Duration::try_from(self.policy.maximum_capture_age())
            .map_err(|_| LlmAdminError::InvalidPolicy)?;
        let latest_expiry = capture
            .created_at()
            .checked_add(maximum_age)
            .ok_or(LlmAdminError::InvalidRecord)?;
        if request.now < capture.created_at()
            || request.now >= capture.expires_at()
            || capture.expires_at() > latest_expiry
        {
            return self
                .fail(
                    request,
                    DiagnosticCaptureAuditOutcome::Expired,
                    LlmAdminError::Expired,
                )
                .await;
        }
        let Ok(plaintext) = self
            .decryptor
            .decrypt(capture.encryption_key_id(), capture.ciphertext())
            .await
        else {
            return self
                .fail(
                    request,
                    DiagnosticCaptureAuditOutcome::Failed,
                    LlmAdminError::Processing,
                )
                .await;
        };
        let redacted = match self
            .redactor
            .redact(capture.redaction_profile(), &plaintext)
            .await
        {
            Ok(value)
                if !value.is_empty() && value.len() <= self.policy.maximum_display_bytes() =>
            {
                value
            }
            Ok(_) | Err(_) => {
                return self
                    .fail(
                        request,
                        DiagnosticCaptureAuditOutcome::Failed,
                        LlmAdminError::Processing,
                    )
                    .await;
            }
        };
        self.auditor
            .record(request, DiagnosticCaptureAuditOutcome::Displayed)
            .await
            .map_err(|_| LlmAdminError::AuditUnavailable)?;
        Ok(DiagnosticCaptureDisplay {
            capture_id: capture.id(),
            tenant_id: capture.tenant_id(),
            principal_id: capture.principal_id(),
            created_at: capture.created_at(),
            expires_at: capture.expires_at(),
            redacted_content: redacted,
        })
    }

    async fn fail<T>(
        &self,
        request: DiagnosticCaptureDisplayRequest,
        outcome: DiagnosticCaptureAuditOutcome,
        error: LlmAdminError,
    ) -> Result<T, LlmAdminError> {
        self.auditor
            .record(request, outcome)
            .await
            .map_err(|_| LlmAdminError::AuditUnavailable)?;
        Err(error)
    }
}

/// PostgreSQL tenant-scoped encrypted diagnostic-capture reader.
#[derive(Clone)]
pub struct PostgresDiagnosticCaptureRepository {
    pool: PostgresPool,
}

impl PostgresDiagnosticCaptureRepository {
    /// Creates a reader over the managed PostgreSQL pool.
    #[must_use]
    pub const fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }

    /// Deletes a bounded batch of expired encrypted captures.
    ///
    /// # Errors
    ///
    /// Returns a content-free query or persistence error.
    pub async fn purge_expired(
        &self,
        now: OffsetDateTime,
        limit: u16,
    ) -> Result<u64, LlmAdminError> {
        if limit == 0 || limit > 1_000 {
            return Err(LlmAdminError::InvalidQuery);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| LlmAdminError::Unavailable)?;
        let result = sqlx::query(
            "WITH expired AS (SELECT capture_id FROM public.llm_diagnostic_captures WHERE expires_at <= $1 ORDER BY expires_at, capture_id LIMIT $2 FOR UPDATE SKIP LOCKED) DELETE FROM public.llm_diagnostic_captures AS capture USING expired WHERE capture.capture_id = expired.capture_id",
        )
        .bind(now)
        .bind(i64::from(limit))
        .execute(&mut *connection)
        .await
        .map_err(|_| LlmAdminError::Unavailable)?;
        Ok(result.rows_affected())
    }
}

impl DiagnosticCaptureRepository for PostgresDiagnosticCaptureRepository {
    fn find(
        &self,
        tenant_id: TenantId,
        capture_id: DiagnosticCaptureId,
    ) -> AdminFuture<'_, Result<Option<EncryptedDiagnosticCapture>, LlmAdminError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .acquire()
                .await
                .map_err(|_| LlmAdminError::Unavailable)?;
            let row = sqlx::query(
                "SELECT capture_id, tenant_id, principal_id, encryption_key_id, redaction_profile, sample_rate_ppm, sample_value, encrypted_payload, created_at, expires_at FROM public.llm_diagnostic_captures WHERE tenant_id = $1 AND capture_id = $2",
            )
            .bind(tenant_id.as_uuid())
            .bind(capture_id.as_uuid())
            .fetch_optional(&mut *connection)
            .await
            .map_err(|_| LlmAdminError::Unavailable)?;
            row.map(|row| {
                let id = DiagnosticCaptureId::from_uuid(
                    row.try_get("capture_id")
                        .map_err(|_| LlmAdminError::InvalidRecord)?,
                )?;
                let row_tenant = TenantId::from_uuid(
                    row.try_get("tenant_id")
                        .map_err(|_| LlmAdminError::InvalidRecord)?,
                )
                .map_err(|_| LlmAdminError::InvalidRecord)?;
                let principal_id = SubjectId::from_uuid(
                    row.try_get("principal_id")
                        .map_err(|_| LlmAdminError::InvalidRecord)?,
                )
                .map_err(|_| LlmAdminError::InvalidRecord)?;
                let sample_rate = row
                    .try_get::<i32, _>("sample_rate_ppm")
                    .map_err(|_| LlmAdminError::InvalidRecord)?;
                let sample_value = row
                    .try_get::<i32, _>("sample_value")
                    .map_err(|_| LlmAdminError::InvalidRecord)?;
                EncryptedDiagnosticCapture::restore(
                    id,
                    row_tenant,
                    principal_id,
                    DiagnosticPolicyName::new(
                        row.try_get::<String, _>("encryption_key_id")
                            .map_err(|_| LlmAdminError::InvalidRecord)?,
                    )?,
                    DiagnosticPolicyName::new(
                        row.try_get::<String, _>("redaction_profile")
                            .map_err(|_| LlmAdminError::InvalidRecord)?,
                    )?,
                    u32::try_from(sample_rate).map_err(|_| LlmAdminError::InvalidRecord)?,
                    u32::try_from(sample_value).map_err(|_| LlmAdminError::InvalidRecord)?,
                    row.try_get("encrypted_payload")
                        .map_err(|_| LlmAdminError::InvalidRecord)?,
                    row.try_get("created_at")
                        .map_err(|_| LlmAdminError::InvalidRecord)?,
                    row.try_get("expires_at")
                        .map_err(|_| LlmAdminError::InvalidRecord)?,
                )
            })
            .transpose()
        })
    }
}

/// Stable keyset position for a content-free usage page.
#[derive(Clone, Eq, PartialEq)]
pub struct LlmUsageCursor {
    /// Last update timestamp from the previous page.
    pub updated_at: OffsetDateTime,
    /// Reservation tie-breaker from the previous page.
    pub reservation_id: String,
}

impl fmt::Debug for LlmUsageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LlmUsageCursor")
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

/// Protected usage-view request scoped to one tenant.
#[derive(Clone, Eq, PartialEq)]
pub struct LlmUsageViewRequest {
    /// Authenticated administrator.
    pub actor_id: SubjectId,
    /// Explicit tenant boundary.
    pub tenant_id: TenantId,
    /// Maximum rows, from 1 through 100.
    pub limit: u16,
    /// Optional stable keyset position.
    pub cursor: Option<LlmUsageCursor>,
}

impl fmt::Debug for LlmUsageViewRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LlmUsageViewRequest")
            .field("limit", &self.limit)
            .field("has_cursor", &self.cursor.is_some())
            .finish_non_exhaustive()
    }
}

/// One content-free usage and audit reconciliation projection.
#[derive(Clone, Eq, PartialEq)]
pub struct LlmUsageProjection {
    /// Tenant identity shared by usage and audit evidence.
    pub tenant_id: TenantId,
    /// Stable usage reservation identity.
    pub reservation_id: String,
    /// Authenticated principal accounting identity.
    pub principal_id: Option<String>,
    /// API-key accounting identity.
    pub api_key_id: Option<String>,
    /// Provider accounting identity.
    pub provider_id: Option<String>,
    /// Model accounting identity.
    pub model_id: Option<String>,
    /// Route accounting identity.
    pub route_id: Option<String>,
    /// Tool accounting identity.
    pub tool_id: Option<String>,
    /// Product-neutral operation identity.
    pub operation_id: Option<String>,
    /// Durable job accounting identity.
    pub job_id: Option<String>,
    /// Reservation lifecycle state.
    pub state: String,
    /// Provider-usage evidence state.
    pub usage_status: String,
    /// Compare-and-set ledger version.
    pub version: u64,
    /// Effective request count.
    pub effective_requests: u64,
    /// Effective concurrent stream count.
    pub effective_concurrent_streams: u64,
    /// Effective token count.
    pub effective_tokens: u64,
    /// Effective provider-specific unit count.
    pub effective_units: u64,
    /// Effective tool-call count.
    pub effective_tool_calls: u64,
    /// Effective media-byte count.
    pub effective_media_bytes: u64,
    /// Effective cost in integer microunits.
    pub effective_cost_microunits: u64,
    /// Reservation creation time.
    pub created_at: OffsetDateTime,
    /// Latest reservation mutation time.
    pub updated_at: OffsetDateTime,
    /// Latest matching content-free audit event.
    pub audit_event_id: Option<Uuid>,
    /// Latest matching audit event time.
    pub audit_occurred_at: Option<OffsetDateTime>,
    /// Audit actor when present.
    pub audit_actor_subject_id: Option<Uuid>,
    /// Audit subject when present.
    pub audit_subject_id: Option<Uuid>,
    /// Audit tenant when present.
    pub audit_effective_tenant_id: Option<Uuid>,
    /// Closed audit outcome when present.
    pub audit_outcome: Option<String>,
    /// Whether audit tenant and principal evidence agrees with the usage reservation.
    pub identities_reconciled: bool,
}

impl fmt::Debug for LlmUsageProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LlmUsageProjection")
            .field("state", &self.state)
            .field("usage_status", &self.usage_status)
            .field("version", &self.version)
            .field("identities_reconciled", &self.identities_reconciled)
            .finish_non_exhaustive()
    }
}

/// One bounded page from the protected usage projection.
#[derive(Clone, Eq, PartialEq)]
pub struct LlmUsagePage {
    /// Content-free projection rows.
    pub items: Vec<LlmUsageProjection>,
    /// Cursor for another page.
    pub next_cursor: Option<LlmUsageCursor>,
}

impl fmt::Debug for LlmUsagePage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LlmUsagePage")
            .field("item_count", &self.items.len())
            .field("has_next", &self.next_cursor.is_some())
            .finish()
    }
}

/// Tenant-scoped content-free usage projection port.
pub trait LlmUsageViewRepository: Send + Sync {
    /// Loads one stable bounded page.
    fn list<'a>(
        &'a self,
        request: &'a LlmUsageViewRequest,
    ) -> AdminFuture<'a, Result<LlmUsagePage, LlmAdminError>>;
}

/// Dedicated protected authorization port for usage evidence.
pub trait LlmUsageViewAuthorizer: Send + Sync {
    /// Authorizes the exact actor and tenant boundary.
    fn authorize(
        &self,
        request: &LlmUsageViewRequest,
    ) -> AdminFuture<'_, Result<(), LlmAdminError>>;
}

/// Access-controlled usage-view service.
#[derive(Clone)]
pub struct LlmUsageViewService {
    repository: Arc<dyn LlmUsageViewRepository>,
    authorizer: Arc<dyn LlmUsageViewAuthorizer>,
}

impl LlmUsageViewService {
    /// Composes protected authorization with content-free persistence.
    #[must_use]
    pub fn new(
        repository: Arc<dyn LlmUsageViewRepository>,
        authorizer: Arc<dyn LlmUsageViewAuthorizer>,
    ) -> Self {
        Self {
            repository,
            authorizer,
        }
    }

    /// Authorizes and loads one tenant-scoped page.
    ///
    /// # Errors
    ///
    /// Returns a content-free denial, query, persistence, or record error.
    pub async fn list(&self, request: &LlmUsageViewRequest) -> Result<LlmUsagePage, LlmAdminError> {
        validate_usage_request(request)?;
        self.authorizer
            .authorize(request)
            .await
            .map_err(|_| LlmAdminError::Denied)?;
        self.repository.list(request).await
    }
}

/// PostgreSQL reader for the security-barrier usage/audit reconciliation view.
#[derive(Clone)]
pub struct PostgresLlmUsageViewRepository {
    pool: PostgresPool,
}

impl PostgresLlmUsageViewRepository {
    /// Creates a reader over the managed PostgreSQL pool.
    #[must_use]
    pub const fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }
}

impl LlmUsageViewRepository for PostgresLlmUsageViewRepository {
    fn list<'a>(
        &'a self,
        request: &'a LlmUsageViewRequest,
    ) -> AdminFuture<'a, Result<LlmUsagePage, LlmAdminError>> {
        Box::pin(async move {
            validate_usage_request(request)?;
            let fetch_limit = i64::from(request.limit) + 1;
            let cursor_time = request.cursor.as_ref().map(|cursor| cursor.updated_at);
            let cursor_id = request
                .cursor
                .as_ref()
                .map(|cursor| cursor.reservation_id.as_str());
            let mut connection = self
                .pool
                .acquire()
                .await
                .map_err(|_| LlmAdminError::Unavailable)?;
            let rows = sqlx::query(
                "SELECT tenant_id, reservation_id, principal_id, api_key_id, provider_id, model_id, route_id, tool_id, operation_id, job_id, state, usage_status, version, effective_requests::text AS effective_requests, effective_concurrent_streams::text AS effective_concurrent_streams, effective_tokens::text AS effective_tokens, effective_units::text AS effective_units, effective_tool_calls::text AS effective_tool_calls, effective_media_bytes::text AS effective_media_bytes, effective_cost_microunits::text AS effective_cost_microunits, created_at, updated_at, audit_event_id, audit_occurred_at, audit_actor_subject_id, audit_subject_id, audit_effective_tenant_id, audit_outcome, identities_reconciled FROM public.llm_usage_audit_reconciliation_v1 WHERE tenant_id = $1 AND ($2::timestamptz IS NULL OR (updated_at, reservation_id) < ($2, $3)) ORDER BY updated_at DESC, reservation_id DESC LIMIT $4",
            )
            .bind(request.tenant_id.as_uuid())
            .bind(cursor_time)
            .bind(cursor_id)
            .bind(fetch_limit)
            .fetch_all(&mut *connection)
            .await
            .map_err(|_| LlmAdminError::Unavailable)?;
            let has_more = rows.len() > usize::from(request.limit);
            let mut items = Vec::with_capacity(rows.len().min(usize::from(request.limit)));
            for row in rows.into_iter().take(usize::from(request.limit)) {
                items.push(decode_usage_projection(&row)?);
            }
            let next_cursor = if has_more {
                items.last().map(|item| LlmUsageCursor {
                    updated_at: item.updated_at,
                    reservation_id: item.reservation_id.clone(),
                })
            } else {
                None
            };
            Ok(LlmUsagePage { items, next_cursor })
        })
    }
}

fn validate_usage_request(request: &LlmUsageViewRequest) -> Result<(), LlmAdminError> {
    if request.limit == 0 || request.limit > 100 {
        return Err(LlmAdminError::InvalidQuery);
    }
    if request.cursor.as_ref().is_some_and(|cursor| {
        cursor.reservation_id.is_empty()
            || cursor.reservation_id.len() > 128
            || !cursor.reservation_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@')
            })
    }) {
        return Err(LlmAdminError::InvalidQuery);
    }
    Ok(())
}

fn decode_usage_projection(
    row: &sqlx::postgres::PgRow,
) -> Result<LlmUsageProjection, LlmAdminError> {
    let tenant_id = TenantId::from_uuid(
        row.try_get("tenant_id")
            .map_err(|_| LlmAdminError::InvalidRecord)?,
    )
    .map_err(|_| LlmAdminError::InvalidRecord)?;
    let version = row
        .try_get::<i64, _>("version")
        .map_err(|_| LlmAdminError::InvalidRecord)?;
    Ok(LlmUsageProjection {
        tenant_id,
        reservation_id: required_safe_usage_id(row, "reservation_id")?,
        principal_id: optional_safe_usage_id(row, "principal_id")?,
        api_key_id: optional_safe_usage_id(row, "api_key_id")?,
        provider_id: optional_safe_usage_id(row, "provider_id")?,
        model_id: optional_safe_usage_id(row, "model_id")?,
        route_id: optional_safe_usage_id(row, "route_id")?,
        tool_id: optional_safe_usage_id(row, "tool_id")?,
        operation_id: optional_safe_usage_id(row, "operation_id")?,
        job_id: optional_safe_usage_id(row, "job_id")?,
        state: closed_usage_value(
            row,
            "state",
            &["reserved", "committed", "reconciled", "released"],
        )?,
        usage_status: closed_usage_value(
            row,
            "usage_status",
            &["estimated", "actual", "missing", "ambiguous"],
        )?,
        version: u64::try_from(version).map_err(|_| LlmAdminError::InvalidRecord)?,
        effective_requests: usage_amount(row, "effective_requests")?,
        effective_concurrent_streams: usage_amount(row, "effective_concurrent_streams")?,
        effective_tokens: usage_amount(row, "effective_tokens")?,
        effective_units: usage_amount(row, "effective_units")?,
        effective_tool_calls: usage_amount(row, "effective_tool_calls")?,
        effective_media_bytes: usage_amount(row, "effective_media_bytes")?,
        effective_cost_microunits: usage_amount(row, "effective_cost_microunits")?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| LlmAdminError::InvalidRecord)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| LlmAdminError::InvalidRecord)?,
        audit_event_id: row
            .try_get("audit_event_id")
            .map_err(|_| LlmAdminError::InvalidRecord)?,
        audit_occurred_at: row
            .try_get("audit_occurred_at")
            .map_err(|_| LlmAdminError::InvalidRecord)?,
        audit_actor_subject_id: row
            .try_get("audit_actor_subject_id")
            .map_err(|_| LlmAdminError::InvalidRecord)?,
        audit_subject_id: row
            .try_get("audit_subject_id")
            .map_err(|_| LlmAdminError::InvalidRecord)?,
        audit_effective_tenant_id: row
            .try_get("audit_effective_tenant_id")
            .map_err(|_| LlmAdminError::InvalidRecord)?,
        audit_outcome: optional_closed_usage_value(
            row,
            "audit_outcome",
            &["succeeded", "denied", "failed"],
        )?,
        identities_reconciled: row
            .try_get("identities_reconciled")
            .map_err(|_| LlmAdminError::InvalidRecord)?,
    })
}

fn usage_amount(row: &sqlx::postgres::PgRow, column: &str) -> Result<u64, LlmAdminError> {
    row.try_get::<String, _>(column)
        .map_err(|_| LlmAdminError::InvalidRecord)?
        .parse()
        .map_err(|_| LlmAdminError::InvalidRecord)
}

fn required_safe_usage_id(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> Result<String, LlmAdminError> {
    let value = row
        .try_get::<String, _>(column)
        .map_err(|_| LlmAdminError::InvalidRecord)?;
    if safe_usage_id(&value) {
        Ok(value)
    } else {
        Err(LlmAdminError::InvalidRecord)
    }
}

fn optional_safe_usage_id(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> Result<Option<String>, LlmAdminError> {
    let value = row
        .try_get::<Option<String>, _>(column)
        .map_err(|_| LlmAdminError::InvalidRecord)?;
    if value.as_ref().is_none_or(|value| safe_usage_id(value)) {
        Ok(value)
    } else {
        Err(LlmAdminError::InvalidRecord)
    }
}

fn safe_usage_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@')
        })
}

fn closed_usage_value(
    row: &sqlx::postgres::PgRow,
    column: &str,
    allowed: &[&str],
) -> Result<String, LlmAdminError> {
    let value = row
        .try_get::<String, _>(column)
        .map_err(|_| LlmAdminError::InvalidRecord)?;
    if allowed.contains(&value.as_str()) {
        Ok(value)
    } else {
        Err(LlmAdminError::InvalidRecord)
    }
}

fn optional_closed_usage_value(
    row: &sqlx::postgres::PgRow,
    column: &str,
    allowed: &[&str],
) -> Result<Option<String>, LlmAdminError> {
    let value = row
        .try_get::<Option<String>, _>(column)
        .map_err(|_| LlmAdminError::InvalidRecord)?;
    if value
        .as_ref()
        .is_none_or(|value| allowed.contains(&value.as_str()))
    {
        Ok(value)
    } else {
        Err(LlmAdminError::InvalidRecord)
    }
}

/// Content-free protected LLM administration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LlmAdminError {
    /// Diagnostic capture display is disabled by default policy.
    #[error("diagnostic capture display is disabled")]
    Disabled,
    /// The protected authorization boundary denied access.
    #[error("diagnostic capture display denied")]
    Denied,
    /// The capture was not found in the tenant boundary.
    #[error("diagnostic capture not found")]
    NotFound,
    /// The capture expired or exceeded the permitted age.
    #[error("diagnostic capture expired")]
    Expired,
    /// Decryption, redaction, or size enforcement failed closed.
    #[error("diagnostic capture processing failed")]
    Processing,
    /// Protected configuration was unsafe.
    #[error("invalid diagnostic capture policy")]
    InvalidPolicy,
    /// A usage-view bound or cursor was invalid.
    #[error("invalid LLM usage view query")]
    InvalidQuery,
    /// Persisted metadata violated a mandatory capture control.
    #[error("invalid diagnostic capture record")]
    InvalidRecord,
    /// PostgreSQL or another protected dependency was unavailable.
    #[error("LLM administration unavailable")]
    Unavailable,
    /// Durable display audit could not be recorded.
    #[error("diagnostic capture audit unavailable")]
    AuditUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_display_policy_defaults_disabled() {
        let policy = DiagnosticCaptureDisplayPolicy::default();

        assert!(!policy.is_enabled());
    }

    #[test]
    fn enabled_policy_rejects_unbounded_display() {
        let result =
            DiagnosticCaptureDisplayPolicy::enabled(Duration::from_secs(60), MAX_DISPLAY_BYTES + 1);

        assert_eq!(result, Err(LlmAdminError::InvalidPolicy));
    }

    #[test]
    fn encrypted_capture_rejects_non_admitted_sample() -> Result<(), LlmAdminError> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let expires_at = created_at + time::Duration::minutes(5);
        let result = EncryptedDiagnosticCapture::restore(
            DiagnosticCaptureId::new(),
            TenantId::new(),
            SubjectId::new(),
            DiagnosticPolicyName::new("kms-key-1")?,
            DiagnosticPolicyName::new("llm-default")?,
            100,
            100,
            vec![1],
            created_at,
            expires_at,
        );

        assert!(matches!(result, Err(LlmAdminError::InvalidRecord)));
        Ok(())
    }
}
