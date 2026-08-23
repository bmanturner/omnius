//! Exercises the foundational runtime, HTTP, TLS, and persistence APIs.

use std::{io, str::FromStr};

use axum::{Router, body::Body, http::Request, response::IntoResponse, routing::get};
use sqlx::postgres::PgConnectOptions;
use tower::ServiceExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| io::Error::other("failed to install the ring crypto provider"))?;
    }
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let _database = PgConnectOptions::from_str("postgres://service:secret@localhost/service")?;
    let _http = reqwest::Client::builder()
        .https_only(true)
        .use_preconfigured_tls(tls)
        .build()?;

    let app = Router::new().route("/live", get(|| async { "live" }));
    let response = app
        .oneshot(Request::get("/live").body(Body::empty())?)
        .await?;
    if !response.status().is_success() {
        return Err("compatibility route returned a failure status".into());
    }
    let _ = response.into_response();
    Ok(())
}
