//! Secure password authentication, verification, and recovery capability.
//!
//! The crate uses Argon2id PHC verifiers, a bounded versioned pepper ring,
//! random single-use verification tokens, and caller-owned PostgreSQL
//! transactions. Secret-bearing types redact `Debug` output and errors carry no
//! rejected values.

mod account;
mod config;
mod password;
mod postgres;
mod registration;
mod token;

pub use account::{
    ActivePasswordUser, InvitationConsumption, InvitationIssueRequest, InvitationIssuer,
    InvitationListRequest, InvitationMutation, IssuedRegistrationInvitation,
    RegistrationInvitationMetadata, RegistrationRequest, RegistrationRequestOutcome, UserStatus,
};
pub use config::{PasswordPepper, PasswordPolicy, PasswordPolicyConfig, PasswordPolicyError};
pub use password::{
    PasswordEngine, PasswordError, PasswordInput, PasswordVerification, PasswordWorker,
    PersistedPasswordCredential, StoredPasswordHash,
};
pub use postgres::{
    CompletedVerificationRequest, IdentityTokenRequest, PasswordStoreError, PostgresPasswordStore,
    TokenConsumption, TokenDispatch, VerificationRequestOutcome,
};
pub use registration::{
    InvitationToken, InvitationTokenDigest, InvitationTokenError, InvitationTokenGenerator,
    InvitationTokenPepper, IssuedInvitationToken, OsInvitationTokenGenerator, RegistrationMode,
    RegistrationPolicy, RegistrationPolicyConfig, RegistrationPolicyError, SecretAccountLink,
};
pub use token::{
    IssuedToken, OsTokenGenerator, TokenDigest, TokenError, TokenGenerator, TokenPurpose,
    VerificationToken,
};

#[cfg(any(test, feature = "test-support"))]
pub use token::DeterministicTokenGenerator;
