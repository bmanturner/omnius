mod reading_items;

use axum::Router;
use serde::Deserialize;
use serde_json::Value;
use service_kit::auth_http::{
    AccountEmailConfig, AuthenticatedHttpBuildError, AuthenticatedHttpConfig,
    AuthenticatedHttpInput, RegistrationMode, api_key_auth::AuthenticatedIdentityBuildError,
    auth_http_operations_for, auth_openapi_contribution_for, build_authenticated_http,
};
use service_kit::{
    ApplicationConfigError, ApplicationContributions, ApplicationExtension,
    ApplicationExtensionError, ApplicationFactoryError, ApplicationRuntime, AuthRuntime,
    EmailRuntime, JobsRuntime, JobsRuntimeError,
};
use thiserror::Error;
const CONTRACT_SESSION_COOKIE_NAME: &str = "reading_list_session";
const CONTRACT_REGISTRATION_MODE: RegistrationMode = RegistrationMode::SelfService;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationConfig {
    auth: AuthenticatedHttpConfig,
    email: AccountEmailConfig,
    trusted_origins: Vec<String>,
}

#[derive(Debug, Error)]
enum ApplicationBuildError {
    #[error("reading-list application configuration is invalid: {0}")]
    Configuration(#[source] ApplicationConfigError),
    #[error(
        "reading-list authentication contract requires self-service registration and the \
         reading_list_session cookie"
    )]
    ContractPolicy,
    #[error("reading-list selected runtime is incomplete: {0}")]
    Runtime(#[source] ApplicationExtensionError),
    #[error("reading-list authentication runtime could not be built: {0}")]
    Authentication(#[source] AuthenticatedHttpBuildError),
    #[error("reading-list authenticated application router could not be built: {0}")]
    PrincipalProtection(#[source] AuthenticatedIdentityBuildError),
    #[error("reading-list email job registry could not be built: {0}")]
    EmailJobs(#[source] JobsRuntimeError),
}

/// Application-owned contribution boundary.
pub(crate) fn contributions(contributions: ApplicationContributions) -> ApplicationContributions {
    contributions
        .with_contract_document(application_contract)
        .with_application_factory(build_application)
}

async fn build_application(
    mut runtime: ApplicationRuntime,
) -> Result<ApplicationContributions, ApplicationFactoryError> {
    let deployment = runtime.deployment();
    let ApplicationConfig {
        auth,
        email,
        trusted_origins,
    } = runtime
        .deserialize_application()
        .map_err(ApplicationBuildError::Configuration)?;
    validate_contract_policy(&auth)?;
    let pool = runtime
        .postgres_pool()
        .map_err(ApplicationBuildError::Runtime)?;
    let product_pool = pool.clone();
    let outbound_http = runtime
        .outbound_http()
        .map_err(ApplicationBuildError::Runtime)?;

    let authenticated = build_authenticated_http(AuthenticatedHttpInput {
        pool,
        config: auth,
        account_email: email,
        trusted_origins,
        outbound_http,
        deployment,
    })
    .await
    .map_err(ApplicationBuildError::Authentication)?;

    let protected_router = authenticated
        .protect_application_router(reading_items::router(product_pool))
        .map_err(ApplicationBuildError::PrincipalProtection)?;
    let application_extension = ApplicationExtension::new(
        protected_router,
        reading_items::ROUTES,
        reading_items::openapi_fragment(),
        reading_items::OPERATIONS,
    );
    let jobs = JobsRuntime::default()
        .with_authenticated_email(&authenticated)
        .map_err(ApplicationBuildError::EmailJobs)?;
    let email = EmailRuntime::from_authenticated_http(&authenticated);

    Ok(ApplicationContributions::new()
        .with_application_extension_runtime(application_extension)
        .with_jobs_runtime(jobs)
        .with_email_output(email)
        .with_auth_runtime(AuthRuntime::new(authenticated)))
}
fn validate_contract_policy(config: &AuthenticatedHttpConfig) -> Result<(), ApplicationBuildError> {
    if config.session.cookie_name != CONTRACT_SESSION_COOKIE_NAME
        || config.registration.mode != Some(CONTRACT_REGISTRATION_MODE)
    {
        return Err(ApplicationBuildError::ContractPolicy);
    }
    Ok(())
}

fn application_contract() -> Value {
    let mut document =
        auth_openapi_contribution_for(CONTRACT_SESSION_COOKIE_NAME, CONTRACT_REGISTRATION_MODE)
            .unwrap_or_else(|error| {
                panic!("the static authentication contract must be valid: {error}")
            });
    merge_openapi_fragment(&mut document, &reading_items::openapi_fragment()).unwrap_or_else(
        |()| panic!("the static reading-list contract must compose without conflicts"),
    );
    let expected = auth_http_operations_for(CONTRACT_REGISTRATION_MODE)
        .iter()
        .chain(reading_items::OPERATIONS)
        .copied()
        .collect::<Vec<_>>();
    service_kit::openapi::validate_operation_coverage_value(&document, &expected)
        .unwrap_or_else(|error| panic!("the merged reading-list contract must be valid: {error}"));
    document
}

fn merge_openapi_fragment(target: &mut Value, source: &Value) -> Result<(), ()> {
    let target = target.as_object_mut().ok_or(())?;
    let source = source.as_object().ok_or(())?;
    for section in ["paths", "components"] {
        let Some(source_section) = source.get(section).and_then(Value::as_object) else {
            continue;
        };
        let target_section = target
            .entry(section)
            .or_insert_with(|| Value::Object(serde_json::Map::new()))
            .as_object_mut()
            .ok_or(())?;
        merge_openapi_object(target_section, source_section)?;
    }
    Ok(())
}

fn merge_openapi_object(
    target: &mut serde_json::Map<String, Value>,
    source: &serde_json::Map<String, Value>,
) -> Result<(), ()> {
    for (key, value) in source {
        if target.get(key) == Some(value) {
            continue;
        }
        if let Some(existing) = target.get_mut(key) {
            merge_openapi_object(
                existing.as_object_mut().ok_or(())?,
                value.as_object().ok_or(())?,
            )?;
        } else {
            target.insert(key.clone(), value.clone());
        }
    }
    Ok(())
}

pub(crate) fn default_extension() -> ApplicationExtension {
    ApplicationExtension::new(Router::new(), &[], application_contract(), &[])
}

#[cfg(test)]
mod tests;
