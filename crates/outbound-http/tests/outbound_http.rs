#![expect(
    clippy::expect_used,
    reason = "integration-test setup and assertions use explicit panic diagnostics"
)]

//! Behavioral coverage for reusable outbound HTTP policy clients.

use std::time::Duration;

use tokio::{io::AsyncWriteExt as _, net::TcpListener, time};

use reqwest::{Method, StatusCode};
use rsk_outbound_http::{
    BuildError, ConfigError, OutboundHttpClients, OutboundHttpConfig, OutboundHttpError,
    OutboundRequest, PolicyClass, ProxyPolicy,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn client_config() -> OutboundHttpConfig {
    OutboundHttpConfig {
        connect_timeout: Duration::from_secs(1),
        total_timeout: Duration::from_secs(2),
        response_body_limit_bytes: 32,
        max_redirects: 2,
        proxy: ProxyPolicy::Disabled,
        user_agent: "rsk-outbound-http-test/1".to_owned(),
    }
}

fn get_request(clients: &OutboundHttpClients, policy: PolicyClass, url: &str) -> OutboundRequest {
    clients
        .request(policy, Method::GET, url)
        .build()
        .expect("test URL should build")
}

#[tokio::test]
async fn client_reuse_api_uses_the_same_holder_for_repeated_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/reuse"))
        .respond_with(ResponseTemplate::new(204))
        .expect(2)
        .mount(&server)
        .await;
    let clients = OutboundHttpClients::new(&client_config()).expect("clients should build");

    let first_request = get_request(
        &clients,
        PolicyClass::Standard,
        &format!("{}/reuse", server.uri()),
    );
    let first_response = clients
        .execute_bounded(first_request)
        .await
        .expect("first request should complete");
    let second_request = get_request(
        &clients,
        PolicyClass::Standard,
        &format!("{}/reuse", server.uri()),
    );
    let second_response = clients
        .execute_bounded(second_request)
        .await
        .expect("second request should complete");

    assert_eq!(first_response.status(), StatusCode::NO_CONTENT);
    assert_eq!(second_response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn bounded_body_returns_bytes_within_the_cap() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/body"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"bounded"))
        .mount(&server)
        .await;
    let clients = OutboundHttpClients::new(&client_config()).expect("clients should build");
    let request = get_request(
        &clients,
        PolicyClass::Standard,
        &format!("{}/body", server.uri()),
    );

    let response = clients
        .execute_bounded(request)
        .await
        .expect("bounded response should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"bounded");
}

#[tokio::test]
async fn bounded_body_rejects_a_response_above_the_cap() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/large"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 33]))
        .mount(&server)
        .await;
    let clients = OutboundHttpClients::new(&client_config()).expect("clients should build");
    let request = get_request(
        &clients,
        PolicyClass::Standard,
        &format!("{}/large", server.uri()),
    );

    let error = clients
        .execute_bounded(request)
        .await
        .expect_err("oversized response should fail");

    assert_eq!(error, OutboundHttpError::ResponseTooLarge);
}

#[tokio::test]
async fn total_timeout_applies_at_the_client_level() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(250)))
        .mount(&server)
        .await;
    let mut config = client_config();
    config.connect_timeout = Duration::from_millis(40);
    config.total_timeout = Duration::from_millis(80);
    let clients = OutboundHttpClients::new(&config).expect("clients should build");
    let request = get_request(
        &clients,
        PolicyClass::Standard,
        &format!("{}/slow", server.uri()),
    );

    let error = clients
        .execute(request)
        .await
        .expect_err("slow request should time out");

    assert_eq!(error, OutboundHttpError::Timeout);
}

#[tokio::test]
async fn total_timeout_remains_active_while_streaming_the_body() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener should bind");
    let address = listener.local_addr().expect("test listener address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("test connection");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
            .await
            .expect("response headers");
        time::sleep(Duration::from_millis(200)).await;
        let _ = stream.write_all(b"late").await;
    });
    let mut config = client_config();
    config.connect_timeout = Duration::from_millis(40);
    config.total_timeout = Duration::from_millis(80);
    let clients = OutboundHttpClients::new(&config).expect("clients should build");
    let request = get_request(
        &clients,
        PolicyClass::NoRedirect,
        &format!("http://{address}/body-timeout"),
    );
    let response = clients
        .execute(request)
        .await
        .expect("headers should arrive before the total timeout");

    let error = clients
        .read_body(response)
        .await
        .expect_err("body delay should exhaust the total timeout");

    assert_eq!(error, OutboundHttpError::Timeout);
    server.await.expect("test server should stop");
}

#[tokio::test]
async fn redirect_policy_is_selected_explicitly() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/redirect"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/final"))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/final"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let clients = OutboundHttpClients::new(&client_config()).expect("clients should build");

    let standard_request = get_request(
        &clients,
        PolicyClass::Standard,
        &format!("{}/redirect", server.uri()),
    );
    let standard = clients
        .execute(standard_request)
        .await
        .expect("standard policy should follow redirect");
    let no_redirect_request = get_request(
        &clients,
        PolicyClass::NoRedirect,
        &format!("{}/redirect", server.uri()),
    );
    let no_redirect = clients
        .execute(no_redirect_request)
        .await
        .expect("no-redirect policy should return redirect");

    assert_eq!(standard.status(), StatusCode::NO_CONTENT);
    assert_eq!(no_redirect.status(), StatusCode::FOUND);
}

#[test]
fn strict_configuration_rejects_unknown_and_out_of_range_fields() {
    let unknown = serde_json::from_str::<OutboundHttpConfig>(
        r#"{
            "connect_timeout": "1s",
            "total_timeout": "2s",
            "response_body_limit_bytes": 32,
            "max_redirects": 2,
            "proxy": { "mode": "disabled" },
            "user_agent": "test/1",
            "unexpected": true
        }"#,
    );
    assert!(unknown.is_err());

    let mut invalid = client_config();
    invalid.connect_timeout = Duration::from_secs(3);
    invalid.total_timeout = Duration::from_secs(2);

    assert_eq!(invalid.validate(), Err(ConfigError::ConnectExceedsTotal));
}

#[test]
fn diagnostics_redact_user_agent_and_explicit_proxy_values() {
    const USER_AGENT_SECRET: &str = "Bearer top-secret\n";
    const PROXY_SECRET: &str = "http://user:proxy-secret@[::1";

    let mut user_agent_config = client_config();
    user_agent_config.user_agent = USER_AGENT_SECRET.to_owned();
    let user_agent_error =
        OutboundHttpClients::new(&user_agent_config).expect_err("invalid user agent should fail");
    let user_agent_diagnostic = format!("{user_agent_error:?} {user_agent_error}");
    let user_agent_config_debug = format!("{user_agent_config:?}");

    assert_eq!(
        user_agent_error,
        BuildError::InvalidConfiguration(ConfigError::InvalidUserAgent)
    );
    assert!(!user_agent_diagnostic.contains("top-secret"));
    assert!(!user_agent_config_debug.contains("top-secret"));

    let mut proxy_config = client_config();
    proxy_config.proxy = ProxyPolicy::Explicit {
        url: PROXY_SECRET.to_owned(),
    };
    let proxy_error =
        OutboundHttpClients::new(&proxy_config).expect_err("invalid proxy should fail");
    let proxy_diagnostic = format!("{proxy_error:?} {proxy_error}");
    let proxy_config_debug = format!("{proxy_config:?}");

    assert_eq!(proxy_error, BuildError::Proxy);
    assert!(!proxy_diagnostic.contains("proxy-secret"));
    assert!(!proxy_config_debug.contains("proxy-secret"));
}

#[test]
fn request_build_diagnostics_do_not_expose_rejected_values() {
    const URL_SECRET: &str = "http://user:request-secret@[::1";
    let clients = OutboundHttpClients::new(&client_config()).expect("clients should build");
    let builder = clients.request(PolicyClass::Standard, Method::GET, URL_SECRET);
    let builder_debug = format!("{builder:?}");
    let error = builder.build().expect_err("invalid URL should not build");
    let diagnostic = format!("{error:?} {error}");

    assert_eq!(error, OutboundHttpError::RequestBuild);
    assert!(!builder_debug.contains("request-secret"));
    assert!(!diagnostic.contains("request-secret"));
}
