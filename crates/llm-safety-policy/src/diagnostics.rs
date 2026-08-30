use std::{fmt, sync::Arc};

use omnius_llm_core::RawRetentionPolicy;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// Maximum lifetime of one diagnostic-capture admission.
pub const MAX_DIAGNOSTIC_CAPTURE_WINDOW: Duration = Duration::hours(1);
/// Maximum number of provider calls admitted by one diagnostic-capture request.
pub const MAX_DIAGNOSTIC_CAPTURE_SAMPLES: u32 = 1_000;

#[allow(
    dead_code,
    reason = "only crate-owned trusted diagnostic authority adapters may construct this evidence"
)]
/// Authoritative authorization evidence for diagnostic capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DiagnosticAuthorization {
    /// The application authorization boundary explicitly allowed diagnostic capture.
    AllowedByAuthoritativePolicy,
    /// The application authorization boundary denied diagnostic capture.
    Denied,
}

#[allow(
    dead_code,
    reason = "only crate-owned trusted diagnostic authority adapters may construct this evidence"
)]
/// Verified encryption evidence for retained diagnostic payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EncryptionEvidence {
    /// The capture sink verified managed envelope encryption before admission.
    VerifiedEnvelopeEncryption,
}

/// A fixed audit receipt digest proving that diagnostic capture was recorded.
#[derive(Clone, Copy, Eq, PartialEq)]
struct DiagnosticAuditEvidence([u8; 32]);

impl DiagnosticAuditEvidence {
    /// Creates nonempty, content-free audit evidence.
    ///
    /// # Errors
    ///
    /// Returns [`DiagnosticEvidenceError`] when the receipt digest is all zeroes.
    pub(crate) const fn new(receipt_digest: [u8; 32]) -> Result<Self, DiagnosticEvidenceError> {
        let mut index = 0;
        while index < receipt_digest.len() {
            if receipt_digest[index] != 0 {
                return Ok(Self(receipt_digest));
            }
            index += 1;
        }
        Err(DiagnosticEvidenceError)
    }
}

impl fmt::Debug for DiagnosticAuditEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiagnosticAuditEvidence([redacted digest])")
    }
}

/// Diagnostic audit evidence was empty.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("diagnostic audit evidence is invalid")]
struct DiagnosticEvidenceError;

/// Authoritative controls invoked by diagnostic-capture admission.
///
/// Application composition supplies this port from its authorization service, managed encrypted
/// sink, and transactional audit recorder. Request callers cannot attach approval evidence.
pub(crate) trait DiagnosticCaptureControls {
    /// Returns the ordinary authorization decision for this exact capture request.
    fn authorization(&self) -> Option<DiagnosticAuthorization>;

    /// Returns verified managed-encryption evidence for the configured capture sink.
    fn encryption(&self) -> Option<EncryptionEvidence>;

    /// Records the authorization/capture decision and returns its content-free receipt digest.
    fn audit_receipt_digest(&self) -> Option<[u8; 32]>;
}

/// Complete per-request evidence considered for diagnostic payload capture.
pub struct DiagnosticCaptureRequest {
    expires_at: Option<OffsetDateTime>,
    sample_cap: Option<u32>,
    sample_ordinal: u32,
}

impl DiagnosticCaptureRequest {
    /// Creates bounded caller intent without accepting authorization, encryption, or audit claims.
    #[must_use]
    pub const fn new(
        expires_at: Option<OffsetDateTime>,
        sample_cap: Option<u32>,
        sample_ordinal: u32,
    ) -> Self {
        Self {
            expires_at,
            sample_cap,
            sample_ordinal,
        }
    }

    /// Returns the requested expiry after successful admission validation.
    pub(crate) const fn expires_at(&self) -> Option<OffsetDateTime> {
        self.expires_at
    }
}

impl fmt::Debug for DiagnosticCaptureRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticCaptureRequest")
            .field("expiry_present", &self.expires_at.is_some())
            .field("sample_cap", &self.sample_cap)
            .field("sample_ordinal", &self.sample_ordinal)
            .finish()
    }
}

/// Stateful fail-closed diagnostic-capture admission.
///
/// Public request code can construct only [`Self::disabled`]. A future trusted composition adapter
/// must live in this crate to bind verified authorization, encryption, and audit services.
#[derive(Clone)]
pub struct DiagnosticCaptureAdmission {
    controls: Arc<dyn DiagnosticCaptureControls>,
}

impl DiagnosticCaptureAdmission {
    pub(crate) fn new(controls: Arc<dyn DiagnosticCaptureControls>) -> Self {
        Self { controls }
    }

    /// Creates an admission boundary that always rejects capture authorization.
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(Arc::new(DisabledDiagnosticCaptureControls))
    }

    /// A successful decision is the only path in this crate to full provider-payload
    /// retention. Missing, denied, expired, oversized, or out-of-sample evidence fails.
    ///
    /// # Errors
    ///
    /// Returns [`DiagnosticAdmissionError`] for the first unsatisfied closed condition.
    pub fn effective_raw_retention(
        &self,
        request: &DiagnosticCaptureRequest,
        now: OffsetDateTime,
    ) -> Result<RawRetentionPolicy, DiagnosticAdmissionError> {
        match self.controls.authorization() {
            None => return Err(DiagnosticAdmissionError::AuthorizationMissing),
            Some(DiagnosticAuthorization::Denied) => {
                return Err(DiagnosticAdmissionError::AuthorizationDenied);
            }
            Some(DiagnosticAuthorization::AllowedByAuthoritativePolicy) => {}
        }

        let expires_at = request
            .expires_at
            .ok_or(DiagnosticAdmissionError::ExpiryMissing)?;
        if expires_at <= now {
            return Err(DiagnosticAdmissionError::Expired);
        }
        if expires_at - now > MAX_DIAGNOSTIC_CAPTURE_WINDOW {
            return Err(DiagnosticAdmissionError::ExpiryExceedsMaximum);
        }

        let sample_cap = request
            .sample_cap
            .ok_or(DiagnosticAdmissionError::SampleCapMissing)?;
        if sample_cap == 0 || sample_cap > MAX_DIAGNOSTIC_CAPTURE_SAMPLES {
            return Err(DiagnosticAdmissionError::SampleCapOutOfBounds);
        }
        if request.sample_ordinal == 0 || request.sample_ordinal > sample_cap {
            return Err(DiagnosticAdmissionError::SampleNotAdmitted);
        }

        self.controls
            .encryption()
            .ok_or(DiagnosticAdmissionError::EncryptionEvidenceMissing)?;
        let receipt = self
            .controls
            .audit_receipt_digest()
            .ok_or(DiagnosticAdmissionError::AuditEvidenceMissing)?;
        DiagnosticAuditEvidence::new(receipt)
            .map_err(|_| DiagnosticAdmissionError::AuditEvidenceMissing)?;

        Ok(RawRetentionPolicy::Full)
    }
}

impl fmt::Debug for DiagnosticCaptureAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticCaptureAdmission")
            .finish_non_exhaustive()
    }
}

struct DisabledDiagnosticCaptureControls;

impl DiagnosticCaptureControls for DisabledDiagnosticCaptureControls {
    fn authorization(&self) -> Option<DiagnosticAuthorization> {
        None
    }

    fn encryption(&self) -> Option<EncryptionEvidence> {
        None
    }

    fn audit_receipt_digest(&self) -> Option<[u8; 32]> {
        None
    }
}

/// Closed, content-free diagnostic-capture rejection reasons.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DiagnosticAdmissionError {
    /// No authorization result accompanied the request.
    #[error("diagnostic capture authorization evidence is missing")]
    AuthorizationMissing,
    /// Authoritative policy denied capture.
    #[error("diagnostic capture is not authorized")]
    AuthorizationDenied,
    /// No finite expiration accompanied the request.
    #[error("diagnostic capture expiry is missing")]
    ExpiryMissing,
    /// The capture request already expired.
    #[error("diagnostic capture admission expired")]
    Expired,
    /// The requested lifetime exceeded the crate-wide maximum.
    #[error("diagnostic capture expiry exceeds the fixed maximum")]
    ExpiryExceedsMaximum,
    /// No finite sample cap accompanied the request.
    #[error("diagnostic capture sample cap is missing")]
    SampleCapMissing,
    /// The sample cap was zero or exceeded the crate-wide maximum.
    #[error("diagnostic capture sample cap is outside fixed bounds")]
    SampleCapOutOfBounds,
    /// The current one-based sample ordinal was outside the admitted sample set.
    #[error("diagnostic capture sample is not admitted")]
    SampleNotAdmitted,
    /// The capture sink did not supply verified encryption evidence.
    #[error("diagnostic capture encryption evidence is missing")]
    EncryptionEvidenceMissing,
    /// The audit adapter did not supply a receipt digest.
    #[error("diagnostic capture audit evidence is missing")]
    AuditEvidenceMissing,
}

impl DiagnosticAdmissionError {
    /// Returns the closed audit and telemetry reason for this rejection.
    #[must_use]
    pub const fn reason_code(self) -> crate::SafetyReasonCode {
        match self {
            Self::AuthorizationMissing => crate::SafetyReasonCode::DiagnosticAuthorizationMissing,
            Self::AuthorizationDenied => crate::SafetyReasonCode::DiagnosticAuthorizationDenied,
            Self::ExpiryMissing | Self::Expired | Self::ExpiryExceedsMaximum => {
                crate::SafetyReasonCode::DiagnosticExpiryInvalid
            }
            Self::SampleCapMissing | Self::SampleCapOutOfBounds | Self::SampleNotAdmitted => {
                crate::SafetyReasonCode::DiagnosticSamplingInvalid
            }
            Self::EncryptionEvidenceMissing => crate::SafetyReasonCode::DiagnosticEncryptionMissing,
            Self::AuditEvidenceMissing => crate::SafetyReasonCode::DiagnosticAuditMissing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct TestControls {
        authorization: Option<DiagnosticAuthorization>,
        encryption: Option<EncryptionEvidence>,
        audit_receipt: Option<[u8; 32]>,
    }

    impl TestControls {
        const fn allowed() -> Self {
            Self {
                authorization: Some(DiagnosticAuthorization::AllowedByAuthoritativePolicy),
                encryption: Some(EncryptionEvidence::VerifiedEnvelopeEncryption),
                audit_receipt: Some([7; 32]),
            }
        }
    }

    impl DiagnosticCaptureControls for TestControls {
        fn authorization(&self) -> Option<DiagnosticAuthorization> {
            self.authorization
        }

        fn encryption(&self) -> Option<EncryptionEvidence> {
            self.encryption
        }

        fn audit_receipt_digest(&self) -> Option<[u8; 32]> {
            self.audit_receipt
        }
    }

    fn admission(controls: TestControls) -> DiagnosticCaptureAdmission {
        DiagnosticCaptureAdmission::new(Arc::new(controls))
    }

    #[test]
    fn trusted_controls_admit_only_exact_bounded_request() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let request = DiagnosticCaptureRequest::new(
            Some(now + MAX_DIAGNOSTIC_CAPTURE_WINDOW),
            Some(MAX_DIAGNOSTIC_CAPTURE_SAMPLES),
            MAX_DIAGNOSTIC_CAPTURE_SAMPLES,
        );

        assert_eq!(
            admission(TestControls::allowed()).effective_raw_retention(&request, now),
            Ok(RawRetentionPolicy::Full)
        );
    }

    #[test]
    fn denied_controls_and_invalid_audit_receipts_fail_closed() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let request = DiagnosticCaptureRequest::new(Some(now + Duration::minutes(5)), Some(1), 1);
        let mut controls = TestControls::allowed();
        controls.authorization = Some(DiagnosticAuthorization::Denied);
        assert_eq!(
            admission(controls).effective_raw_retention(&request, now),
            Err(DiagnosticAdmissionError::AuthorizationDenied)
        );

        controls = TestControls::allowed();
        controls.audit_receipt = Some([0; 32]);
        assert_eq!(
            admission(controls).effective_raw_retention(&request, now),
            Err(DiagnosticAdmissionError::AuditEvidenceMissing)
        );
    }

    #[test]
    fn request_expiry_and_sampling_bounds_fail_closed() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let excessive_expiry = DiagnosticCaptureRequest::new(
            Some(now + MAX_DIAGNOSTIC_CAPTURE_WINDOW + Duration::seconds(1)),
            Some(1),
            1,
        );
        assert_eq!(
            admission(TestControls::allowed()).effective_raw_retention(&excessive_expiry, now),
            Err(DiagnosticAdmissionError::ExpiryExceedsMaximum)
        );

        let invalid_sample =
            DiagnosticCaptureRequest::new(Some(now + Duration::minutes(5)), Some(1), 2);
        assert_eq!(
            admission(TestControls::allowed()).effective_raw_retention(&invalid_sample, now),
            Err(DiagnosticAdmissionError::SampleNotAdmitted)
        );
    }
}
