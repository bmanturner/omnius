//! Application-owned administration, authentication, billing, and feature-flag contracts.

#[cfg(any(feature = "admin", test))]
use crate::ports::AdminAuthorityResolverPort;
#[cfg(any(feature = "admin", test))]
use crate::ports::AdminOperationHandlerPort;
#[cfg(any(feature = "billing", test))]
use crate::ports::BillingProviderPort;
#[cfg(any(feature = "feature-flags", test))]
use crate::ports::FeatureFlagExposureRecorderPort;
#[cfg(any(feature = "feature-flags", test))]
use crate::ports::FeatureFlagProviderPort;
#[cfg(any(feature = "auth-oauth-server", test))]
use crate::ports::OauthRuntimePort;
#[cfg(any(feature = "auth-oidc", test))]
use crate::ports::OidcRuntimePort;
#[cfg(any(feature = "auth-session-redis", test))]
use crate::ports::RedisSessionRuntimePort;
#[cfg(any(feature = "auth-totp", test))]
use crate::ports::TotpRuntimePort;
#[cfg(any(feature = "auth-webauthn", test))]
use crate::ports::WebauthnRuntimePort;

/// Complete application-owned administration contract.
#[derive(Default)]
#[cfg(any(feature = "admin", test))]
pub struct AdminRuntime {
    pub(crate) authority_resolver: Option<std::sync::Arc<dyn AdminAuthorityResolverPort>>,
    pub(crate) operation_handler: Option<std::sync::Arc<dyn AdminOperationHandlerPort>>,
}

#[cfg(any(feature = "admin", test))]
impl AdminRuntime {
    port_setter!(
        with_authority_resolver,
        authority_resolver,
        dyn AdminAuthorityResolverPort
    );
    port_setter!(
        with_operation_handler,
        operation_handler,
        dyn AdminOperationHandlerPort
    );
}

/// Complete application-owned authentication contract.
#[derive(Default)]
#[cfg(any(
    feature = "auth-password",
    feature = "auth-session-postgres",
    feature = "auth-api-key",
    feature = "auth-http",
    feature = "auth-session-redis",
    feature = "auth-oidc",
    feature = "auth-webauthn",
    feature = "auth-totp",
    feature = "auth-oauth-server",
    test
))]
pub struct AuthRuntime {
    #[cfg(any(feature = "auth-http", test))]
    pub(crate) authenticated_http: Option<omnius_auth_http::AuthenticatedHttpRuntime>,
    #[cfg(any(feature = "auth-session-redis", test))]
    pub(crate) redis_session: Option<std::sync::Arc<dyn RedisSessionRuntimePort>>,
    #[cfg(any(feature = "auth-oidc", test))]
    pub(crate) oidc: Option<std::sync::Arc<dyn OidcRuntimePort>>,
    #[cfg(any(feature = "auth-oauth-server", test))]
    pub(crate) oauth: Option<std::sync::Arc<dyn OauthRuntimePort>>,
    #[cfg(any(feature = "auth-webauthn", test))]
    pub(crate) webauthn: Option<std::sync::Arc<dyn WebauthnRuntimePort>>,
    #[cfg(any(feature = "auth-totp", test))]
    pub(crate) totp: Option<std::sync::Arc<dyn TotpRuntimePort>>,
}

#[cfg(any(
    feature = "auth-http",
    feature = "auth-password",
    feature = "auth-session-postgres",
    feature = "auth-api-key",
    feature = "auth-session-redis",
    feature = "auth-oidc",
    feature = "auth-webauthn",
    feature = "auth-totp",
    feature = "auth-oauth-server",
    test
))]
impl AuthRuntime {
    /// Owns the concrete authenticated HTTP composition.
    #[cfg(any(feature = "auth-http", test))]
    #[must_use]
    pub fn new(authenticated_http: omnius_auth_http::AuthenticatedHttpRuntime) -> Self {
        Self {
            authenticated_http: Some(authenticated_http),
            ..Self::default()
        }
    }

    /// Borrows the concrete authenticated HTTP composition.
    #[cfg(any(feature = "auth-http", test))]
    #[must_use]
    pub fn authenticated_http(&self) -> Option<&omnius_auth_http::AuthenticatedHttpRuntime> {
        self.authenticated_http.as_ref()
    }

    #[cfg(any(feature = "auth-session-redis", test))]
    port_setter!(
        with_redis_session_runtime,
        redis_session,
        dyn RedisSessionRuntimePort
    );
    #[cfg(any(feature = "auth-oidc", test))]
    port_setter!(with_oidc_runtime, oidc, dyn OidcRuntimePort);
    #[cfg(any(feature = "auth-oauth-server", test))]
    port_setter!(with_oauth_runtime, oauth, dyn OauthRuntimePort);
    #[cfg(any(feature = "auth-webauthn", test))]
    port_setter!(with_webauthn_runtime, webauthn, dyn WebauthnRuntimePort);
    #[cfg(any(feature = "auth-totp", test))]
    port_setter!(with_totp_runtime, totp, dyn TotpRuntimePort);
}

/// Application-owned billing contract.
#[derive(Default)]
#[cfg(any(feature = "billing", test))]
pub struct BillingRuntime {
    pub(crate) provider: Option<std::sync::Arc<dyn BillingProviderPort>>,
}

#[cfg(any(feature = "billing", test))]
impl BillingRuntime {
    port_setter!(with_provider, provider, dyn BillingProviderPort);
}

/// Application-owned feature-flag contract.
#[derive(Default)]
#[cfg(any(feature = "feature-flags", test))]
pub struct FeatureFlagsRuntime {
    pub(crate) provider: Option<std::sync::Arc<dyn FeatureFlagProviderPort>>,
    pub(crate) exposure_recorder: Option<std::sync::Arc<dyn FeatureFlagExposureRecorderPort>>,
}

#[cfg(any(feature = "feature-flags", test))]
impl FeatureFlagsRuntime {
    port_setter!(with_provider, provider, dyn FeatureFlagProviderPort);
    port_setter!(
        with_exposure_recorder,
        exposure_recorder,
        dyn FeatureFlagExposureRecorderPort
    );
}
