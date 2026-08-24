//! Durable passkey registration, account-bound authentication, and conditional UI.
//!
//! The crate delegates every `WebAuthn` protocol decision to `webauthn-rs`. Only opaque handles
//! cross the server boundary for ceremony state; the serializable official state remains in
//! PostgreSQL and is atomically consumed exactly once before response validation.

mod config;
mod service;
mod types;

pub use config::{WebAuthnConfig, WebAuthnConfigError};
pub use service::WebAuthnService;
pub use types::{
    AuthenticationStart, CeremonyHandle, CeremonyHandleError, PasskeyMetadata, RegistrationStart,
    WebAuthnServiceError,
};
pub use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};
