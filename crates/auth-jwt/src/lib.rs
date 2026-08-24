//! Bounded resource-server JWT verification with safe JWKS rotation.
//!
//! This crate delegates all token/JWK parsing and cryptographic verification to
//! `jsonwebtoken`. It adds explicit trust configuration, bounded no-redirect
//! JWKS retrieval, refresh coalescing, claim policy, and canonical `Principal`
//! mapping without exposing raw claims or bearer values.

mod bearer;
mod config;
mod verifier;

pub use bearer::{BearerPrincipal, BearerRejection};
pub use config::{JwtAlgorithm, JwtConfig, JwtConfigError, JwtIssuerConfig};
pub use verifier::{JwtBuildError, JwtVerifier, JwtVerifyError};
