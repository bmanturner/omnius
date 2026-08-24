//! Deterministic fixtures for authentication adapter contract tests.

use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    AssuranceLevel, AuthMethod, Principal, PrincipalError, PrincipalKind, Scope, SubjectId,
    TenantId,
};

const SUBJECT_UUID: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0101);
const TENANT_UUID: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0102);

/// A deterministic builder for the real canonical [`Principal`] type.
///
/// Adapter tests should customize only the fields represented by their input,
/// then compare the adapter result with [`ensure_principal_matches`].
#[derive(Clone, Debug)]
pub struct TestPrincipalFactory {
    subject_id: SubjectId,
    kind: PrincipalKind,
    tenant_id: Option<TenantId>,
    auth_method: AuthMethod,
    authenticated_at: OffsetDateTime,
    assurance: AssuranceLevel,
    scopes: Vec<Scope>,
}

impl TestPrincipalFactory {
    /// Creates a factory for an explicit deterministic subject and instant.
    #[must_use]
    pub const fn new(subject_id: SubjectId, authenticated_at: OffsetDateTime) -> Self {
        Self {
            subject_id,
            kind: PrincipalKind::User,
            tenant_id: None,
            auth_method: AuthMethod::Session,
            authenticated_at,
            assurance: AssuranceLevel::Aal1,
            scopes: Vec::new(),
        }
    }

    /// Replaces the subject identifier.
    #[must_use]
    pub const fn with_subject_id(mut self, subject_id: SubjectId) -> Self {
        self.subject_id = subject_id;
        self
    }

    /// Replaces the principal kind.
    #[must_use]
    pub const fn with_kind(mut self, kind: PrincipalKind) -> Self {
        self.kind = kind;
        self
    }

    /// Replaces the optional tenant context.
    #[must_use]
    pub const fn with_tenant_id(mut self, tenant_id: Option<TenantId>) -> Self {
        self.tenant_id = tenant_id;
        self
    }

    /// Replaces the authentication mechanism.
    #[must_use]
    pub const fn with_auth_method(mut self, auth_method: AuthMethod) -> Self {
        self.auth_method = auth_method;
        self
    }

    /// Replaces the authentication instant.
    #[must_use]
    pub const fn with_authenticated_at(mut self, authenticated_at: OffsetDateTime) -> Self {
        self.authenticated_at = authenticated_at;
        self
    }

    /// Replaces the assurance level.
    #[must_use]
    pub const fn with_assurance(mut self, assurance: AssuranceLevel) -> Self {
        self.assurance = assurance;
        self
    }

    /// Replaces the granted scopes.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Vec<Scope>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Builds the canonical principal and applies its production invariants.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalError`] when the configured scope set is too large.
    pub fn build(self) -> Result<Principal, PrincipalError> {
        Principal::new(
            self.subject_id,
            self.kind,
            self.tenant_id,
            self.auth_method,
            self.authenticated_at,
            self.assurance,
            self.scopes,
        )
    }
}

impl Default for TestPrincipalFactory {
    fn default() -> Self {
        Self::new(SubjectId(SUBJECT_UUID), OffsetDateTime::UNIX_EPOCH)
            .with_tenant_id(Some(TenantId(TENANT_UUID)))
    }
}

/// A mechanism adapter returned a principal that differs from its canonical expectation.
///
/// The error is intentionally value-free so failed conformance checks do not
/// copy identity or scope data into generic error channels.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("authentication adapter produced a non-canonical principal")]
pub struct PrincipalMismatch;

/// Compares an adapter result with its canonical expected principal.
///
/// # Errors
///
/// Returns [`PrincipalMismatch`] when any of the seven canonical fields differ.
pub fn ensure_principal_matches(
    actual: &Principal,
    expected: &Principal,
) -> Result<(), PrincipalMismatch> {
    if actual == expected {
        Ok(())
    } else {
        Err(PrincipalMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Scope;

    #[test]
    fn default_factory_is_deterministic_and_uses_real_principal_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = TestPrincipalFactory::default()
            .with_auth_method(AuthMethod::Jwt)
            .with_assurance(AssuranceLevel::Aal2)
            .with_scopes(vec![Scope::new("write")?, Scope::new("read")?])
            .build()?;
        let second = TestPrincipalFactory::default()
            .with_auth_method(AuthMethod::Jwt)
            .with_assurance(AssuranceLevel::Aal2)
            .with_scopes(vec![Scope::new("read")?, Scope::new("write")?])
            .build()?;

        assert!(ensure_principal_matches(&first, &second).is_ok());
        assert_eq!(first.scopes[0].as_str(), "read");
        Ok(())
    }

    #[test]
    fn conformance_failure_is_value_free() -> Result<(), Box<dyn std::error::Error>> {
        let session = TestPrincipalFactory::default()
            .with_auth_method(AuthMethod::Session)
            .build()?;
        let jwt = TestPrincipalFactory::default()
            .with_auth_method(AuthMethod::Jwt)
            .build()?;

        assert_eq!(
            ensure_principal_matches(&session, &jwt),
            Err(PrincipalMismatch)
        );
        assert_eq!(
            PrincipalMismatch.to_string(),
            "authentication adapter produced a non-canonical principal"
        );
        Ok(())
    }
}
