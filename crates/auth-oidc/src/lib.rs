//! OIDC authorization-code login and explicit external-identity linking.
//!
//! Protocol-specific credentials and claims remain inside this adapter. Successful
//! flows map only verified issuer/subject pairs to the canonical authentication
//! principal through [`OidcIdentityStore`].
//!
//! Applications persist every [`AuthorizationStart`] through [`OidcPendingStore::issue`]
//! before redirecting the browser, then atomically consume callback state through
//! [`OidcPendingStore::take`] before calling [`OidcFlow::complete`].

mod config;
mod flow;
mod identity_store;
mod pending_store;

pub use config::{OidcConfig, OidcConfigError, OidcProviderConfig};
pub use flow::{
    AuthorizationStart, CompletedAuthorization, FlowPurpose, OidcBuildError, OidcFlow,
    OidcFlowError, TakenAuthorization, VerifiedIdentity,
};
pub use identity_store::{
    AccountOutcome, IdentityLinkOutcome, OidcIdentityStore, OidcStoreError, UnlinkOutcome,
};
pub use pending_store::{
    IssuedAuthorization, OidcPendingStore, OidcPendingStoreError, PendingAuthorizationId,
};
