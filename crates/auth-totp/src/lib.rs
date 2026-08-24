//! Encrypted TOTP multi-factor authentication with durable replay prevention.
//!
//! Enrollment seeds are generated from operating-system entropy, encrypted with
//! AES-256-GCM under a domain-separated key, and bound to their user by versioned
//! additional authenticated data. Confirmation and verification persist the
//! matched RFC 6238 step. Recovery codes use visible lookup identifiers and
//! peppered Argon2id PHC hashes, and are consumed atomically.

mod config;
mod crypto;
mod recovery;
mod store;

pub use config::{TOTP_DIGITS, TOTP_STEP_SECONDS, TotpConfig, TotpConfigError};
pub use recovery::RecoveryCodeSet;
pub use store::{
    ConfirmedTotpEnrollment, PendingTotpEnrollment, TotpCredentialMetadata, TotpStore,
    TotpStoreError,
};
