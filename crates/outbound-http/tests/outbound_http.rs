#![expect(
    clippy::expect_used,
    reason = "integration-test setup and assertions use explicit panic diagnostics"
)]

//! SSRF admission, rebinding, redirect, deadline, and decoded-body security contracts.

use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use omnius_outbound_http::{
    ApprovedUrl, BuildError, ConfigError, OutboundHttpClients, OutboundHttpConfig,
    OutboundHttpError, OutboundUrlPolicy, OutboundUrlPolicyConfig, PolicyClass, ProxyPolicy,
    Resolver, ResolverError, ResolverFuture,
};
use reqwest::{Method, StatusCode, Url};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

type ResolveAnswer = Result<Vec<IpAddr>, ResolverError>;
type ResolveSequences = HashMap<String, VecDeque<ResolveAnswer>>;

#[derive(Clone, Debug)]
struct FakeResolver {
    answers: Arc<Mutex<ResolveSequences>>,
    fallback: ResolveAnswer,
}

impl FakeResolver {
    fn returning(addresses: Vec<IpAddr>) -> Self {
        Self {
            answers: Arc::new(Mutex::new(HashMap::new())),
            fallback: Ok(addresses),
        }
    }

    fn failing() -> Self {
        Self {
            answers: Arc::new(Mutex::new(HashMap::new())),
            fallback: Err(ResolverError),
        }
    }

    fn with_sequence(host: &str, answers: impl IntoIterator<Item = ResolveAnswer>) -> Self {
        Self {
            answers: Arc::new(Mutex::new(HashMap::from([(
                host.to_owned(),
                answers.into_iter().collect(),
            )]))),
            fallback: Err(ResolverError),
        }
    }
}

impl Resolver for FakeResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> ResolverFuture<'a> {
        let answer = self
            .answers
            .lock()
            .ok()
            .and_then(|mut answers| answers.get_mut(host).and_then(VecDeque::pop_front))
            .unwrap_or_else(|| self.fallback.clone());
        Box::pin(async move { answer })
    }
}

#[derive(Clone, Copy, Debug)]
struct StalledResolver;

impl Resolver for StalledResolver {
    fn resolve<'a>(&'a self, _host: &'a str) -> ResolverFuture<'a> {
        Box::pin(std::future::pending())
    }
}

#[derive(Debug, Default)]
struct ApproveThenStallResolver {
    calls: AtomicUsize,
}

impl Resolver for ApproveThenStallResolver {
    fn resolve<'a>(&'a self, _host: &'a str) -> ResolverFuture<'a> {
        if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
            Box::pin(async { Ok(vec![public_address()]) })
        } else {
            Box::pin(std::future::pending())
        }
    }
}

fn public_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
}

fn loopback_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn client_config() -> OutboundHttpConfig {
    OutboundHttpConfig {
        connect_timeout: Duration::from_secs(1),
        total_timeout: Duration::from_secs(2),
        response_body_limit_bytes: 64,
        max_redirects: 3,
        proxy: ProxyPolicy::Disabled,
        user_agent: "omnius-outbound-http-test/1".to_owned(),
        url_policy: OutboundUrlPolicyConfig {
            allowed_https_ports: vec![443, 8443],
            allow_development_loopback_http: true,
            ..OutboundUrlPolicyConfig::default()
        },
    }
}

fn loopback_clients() -> Result<OutboundHttpClients, BuildError> {
    OutboundHttpClients::with_resolver(
        &client_config(),
        Arc::new(FakeResolver::returning(vec![loopback_address()])),
    )
}

async fn approve(
    clients: &OutboundHttpClients,
    value: &str,
) -> Result<ApprovedUrl, Box<dyn Error>> {
    Ok(clients.approve(Url::parse(value)?).await?)
}

async fn start_loopback_stream(
    chunks: Vec<(Duration, &'static [u8])>,
) -> Result<String, Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let _server = tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut request = [0_u8; 1024];
        let Ok(read) = socket.read(&mut request).await else {
            return;
        };
        if read == 0
            || socket
                .write_all(
                    b"HTTP/1.1 429 Too Many Requests\r\n\
                      content-type: application/octet-stream\r\n\
                      x-stream-test: ordered\r\n\
                      connection: close\r\n\r\n",
                )
                .await
                .is_err()
            || socket.flush().await.is_err()
        {
            return;
        }
        for (delay, chunk) in chunks {
            tokio::time::sleep(delay).await;
            if socket.write_all(chunk).await.is_err() || socket.flush().await.is_err() {
                return;
            }
        }
    });
    Ok(format!("http://{address}/stream"))
}

#[tokio::test]
async fn policy_rejects_non_https_authority_features_and_disallowed_ports()
-> Result<(), Box<dyn Error>> {
    let policy = OutboundUrlPolicy::with_resolver(
        OutboundUrlPolicyConfig::default(),
        Arc::new(FakeResolver::returning(vec![public_address()])),
    )?;
    for value in [
        "http://public.test/path",
        "ftp://public.test/path",
        "https://user:secret@public.test/path",
        "https://public.test/path#fragment",
        "https://public.test:444/path",
    ] {
        let error = policy
            .approve(Url::parse(value)?)
            .await
            .expect_err("unsafe URL must be rejected");
        assert_eq!(error, OutboundHttpError::DestinationRejected, "{value}");
    }
    Ok(())
}

#[tokio::test]
async fn policy_accepts_only_configured_https_ports() -> Result<(), Box<dyn Error>> {
    let policy = OutboundUrlPolicy::with_resolver(
        OutboundUrlPolicyConfig {
            allowed_https_ports: vec![443, 8443],
            allow_development_loopback_http: false,
            ..OutboundUrlPolicyConfig::default()
        },
        Arc::new(FakeResolver::returning(vec![public_address()])),
    )?;
    policy
        .approve(Url::parse("https://public.test:8443/path")?)
        .await?;
    let error = policy
        .approve(Url::parse("https://public.test:9443/path")?)
        .await
        .expect_err("port must be rejected");
    assert_eq!(error, OutboundHttpError::DestinationRejected);
    Ok(())
}

#[tokio::test]
async fn policy_rejects_all_special_use_ip_literals() -> Result<(), Box<dyn Error>> {
    let policy = OutboundUrlPolicy::new(OutboundUrlPolicyConfig::default())?;
    for address in [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.168.0.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
        "[::]",
        "[::1]",
        "[::ffff:8.8.8.8]",
        "[64:ff9b::808:808]",
        "[100::1]",
        "[2001:db8::1]",
        "[2002:0808:0808::1]",
        "[3fff::1]",
        "[fc00::1]",
        "[fe80::1]",
        "[ff02::1]",
    ] {
        let url = Url::parse(&format!("https://{address}/"))?;
        let error = policy
            .approve(url)
            .await
            .expect_err("special-use address must be rejected");
        assert_eq!(error, OutboundHttpError::DestinationRejected, "{address}");
    }
    Ok(())
}

#[tokio::test]
async fn mixed_dns_answers_and_dns_errors_fail_closed() -> Result<(), Box<dyn Error>> {
    let mixed = OutboundUrlPolicy::with_resolver(
        OutboundUrlPolicyConfig::default(),
        Arc::new(FakeResolver::returning(vec![
            public_address(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ])),
    )?;
    let error = mixed
        .approve(Url::parse("https://mixed.test/")?)
        .await
        .expect_err("mixed answer must be rejected");
    assert_eq!(error, OutboundHttpError::DestinationRejected);

    let failed = OutboundUrlPolicy::with_resolver(
        OutboundUrlPolicyConfig::default(),
        Arc::new(FakeResolver::failing()),
    )?;
    let error = failed
        .approve(Url::parse("https://failed.test/")?)
        .await
        .expect_err("DNS error must fail closed");
    assert_eq!(error, OutboundHttpError::Resolution);
    Ok(())
}

#[tokio::test]
async fn configured_deny_cidrs_cover_exact_boundaries_and_mixed_answers()
-> Result<(), Box<dyn Error>> {
    let config = OutboundUrlPolicyConfig {
        deny_cidrs: vec!["8.8.8.0/24".to_owned(), "2606:4700:4700::/48".to_owned()],
        ..OutboundUrlPolicyConfig::default()
    };
    let literals = OutboundUrlPolicy::with_resolver(
        config.clone(),
        Arc::new(FakeResolver::returning(vec![public_address()])),
    )?;
    for value in [
        "https://8.8.8.0/",
        "https://8.8.8.255/",
        "https://[2606:4700:4700::]/",
        "https://[2606:4700:4700:ffff:ffff:ffff:ffff:ffff]/",
    ] {
        let error = literals
            .approve(Url::parse(value)?)
            .await
            .expect_err("CIDR boundary must be denied");
        assert_eq!(error, OutboundHttpError::DestinationRejected);
    }
    literals.approve(Url::parse("https://8.8.9.0/")?).await?;
    literals
        .approve(Url::parse("https://[2606:4700:4701::]/")?)
        .await?;

    let mixed = OutboundUrlPolicy::with_resolver(
        config,
        Arc::new(FakeResolver::returning(vec![
            "8.8.9.1".parse()?,
            "8.8.8.1".parse()?,
        ])),
    )?;
    let error = mixed
        .approve(Url::parse("https://mixed-internal.test/")?)
        .await
        .expect_err("one denied DNS answer must reject the complete set");
    assert_eq!(error, OutboundHttpError::DestinationRejected);
    Ok(())
}

#[tokio::test]
async fn configured_deny_cidr_is_rechecked_at_connect_time() -> Result<(), Box<dyn Error>> {
    let mut config = client_config();
    config.url_policy.deny_cidrs = vec!["8.8.8.0/24".to_owned()];
    let resolver = FakeResolver::with_sequence(
        "internal-rebind.test",
        [Ok(vec!["8.8.9.1".parse()?]), Ok(vec!["8.8.8.1".parse()?])],
    );
    let clients = OutboundHttpClients::with_resolver(&config, Arc::new(resolver))?;
    let approved = approve(&clients, "https://internal-rebind.test/").await?;
    let request = clients
        .request(PolicyClass::NoRedirect, Method::GET, &approved)
        .build()?;
    let error = clients
        .execute(request)
        .await
        .expect_err("connect-time configured CIDR must be denied");
    assert_eq!(error, OutboundHttpError::Transport);
    Ok(())
}

#[tokio::test]
async fn dns_lookup_timeout_and_unique_answer_cap_fail_closed() -> Result<(), Box<dyn Error>> {
    let timeout_config = OutboundUrlPolicyConfig {
        dns_timeout: Duration::from_millis(20),
        ..OutboundUrlPolicyConfig::default()
    };
    let stalled = OutboundUrlPolicy::with_resolver(timeout_config, Arc::new(StalledResolver))?;
    let error = stalled
        .approve(Url::parse("https://stalled-approval.test/")?)
        .await
        .expect_err("initial DNS lookup must time out");
    assert_eq!(error, OutboundHttpError::Resolution);

    let answer_config = OutboundUrlPolicyConfig {
        max_dns_answers: 2,
        ..OutboundUrlPolicyConfig::default()
    };
    let excessive = OutboundUrlPolicy::with_resolver(
        answer_config.clone(),
        Arc::new(FakeResolver::returning(vec![
            "8.8.8.8".parse()?,
            "1.1.1.1".parse()?,
            "9.9.9.9".parse()?,
        ])),
    )?;
    let error = excessive
        .approve(Url::parse("https://many-answers.test/")?)
        .await
        .expect_err("too many unique answers must fail");
    assert_eq!(error, OutboundHttpError::Resolution);

    let duplicates = OutboundUrlPolicy::with_resolver(
        answer_config,
        Arc::new(FakeResolver::returning(vec![
            "8.8.8.8".parse()?,
            "8.8.8.8".parse()?,
            "1.1.1.1".parse()?,
        ])),
    )?;
    duplicates
        .approve(Url::parse("https://duplicate-answers.test/")?)
        .await?;
    Ok(())
}

#[tokio::test]
async fn connect_time_dns_timeout_and_answer_cap_fail_closed() -> Result<(), Box<dyn Error>> {
    let mut timeout_config = client_config();
    timeout_config.url_policy.dns_timeout = Duration::from_millis(20);
    let clients = OutboundHttpClients::with_resolver(
        &timeout_config,
        Arc::new(ApproveThenStallResolver::default()),
    )?;
    let approved = approve(&clients, "https://connect-stalled.test/").await?;
    let request = clients
        .request(PolicyClass::NoRedirect, Method::GET, &approved)
        .build()?;
    let error = clients
        .execute(request)
        .await
        .expect_err("connect-time DNS must time out");
    assert_eq!(error, OutboundHttpError::Transport);

    let mut answer_config = client_config();
    answer_config.url_policy.max_dns_answers = 2;
    let resolver = FakeResolver::with_sequence(
        "connect-many.test",
        [
            Ok(vec![public_address()]),
            Ok(vec![
                "8.8.8.8".parse()?,
                "1.1.1.1".parse()?,
                "9.9.9.9".parse()?,
            ]),
        ],
    );
    let clients = OutboundHttpClients::with_resolver(&answer_config, Arc::new(resolver))?;
    let approved = approve(&clients, "https://connect-many.test/").await?;
    let request = clients
        .request(PolicyClass::NoRedirect, Method::GET, &approved)
        .build()?;
    let error = clients
        .execute(request)
        .await
        .expect_err("connect-time unique answer cap must fail");
    assert_eq!(error, OutboundHttpError::Transport);
    Ok(())
}

#[tokio::test]
async fn development_http_requires_an_explicit_loopback_only_policy() -> Result<(), Box<dyn Error>>
{
    let disabled = OutboundUrlPolicy::with_resolver(
        OutboundUrlPolicyConfig::default(),
        Arc::new(FakeResolver::returning(vec![loopback_address()])),
    )?;
    let error = disabled
        .approve(Url::parse("http://dev.test:8080/")?)
        .await
        .expect_err("HTTP must require explicit development policy");
    assert_eq!(error, OutboundHttpError::DestinationRejected);

    let enabled = OutboundUrlPolicy::with_resolver(
        OutboundUrlPolicyConfig {
            allowed_https_ports: vec![443],
            allow_development_loopback_http: true,
            ..OutboundUrlPolicyConfig::default()
        },
        Arc::new(FakeResolver::returning(vec![loopback_address()])),
    )?;
    enabled
        .approve(Url::parse("http://127.0.0.1:8080/")?)
        .await?;
    let error = enabled
        .approve(Url::parse("http://localhost:8080/")?)
        .await
        .expect_err("development HTTP hostnames must not use DNS");
    assert_eq!(error, OutboundHttpError::DestinationRejected);
    Ok(())
}

#[tokio::test]
async fn approved_url_cannot_cross_policy_boundaries() -> Result<(), Box<dyn Error>> {
    let first = loopback_clients()?;
    let second = loopback_clients()?;
    let approved = approve(&first, "http://127.0.0.1:8080/").await?;

    let error = second
        .request(PolicyClass::NoRedirect, Method::GET, &approved)
        .build()
        .expect_err("foreign approval must not authorize another client");
    assert_eq!(error, OutboundHttpError::DestinationRejected);
    Ok(())
}

#[tokio::test]
async fn connect_time_resolution_rejects_dns_rebinding() -> Result<(), Box<dyn Error>> {
    let resolver = FakeResolver::with_sequence(
        "rebind.test",
        [Ok(vec![public_address()]), Ok(vec![loopback_address()])],
    );
    let clients = OutboundHttpClients::with_resolver(&client_config(), Arc::new(resolver))?;
    let approved = approve(&clients, "https://rebind.test/resource").await?;
    let request = clients
        .request(PolicyClass::NoRedirect, Method::GET, &approved)
        .build()?;

    let error = clients
        .execute(request)
        .await
        .expect_err("connect-time loopback answer must fail");
    assert_eq!(error, OutboundHttpError::Transport);
    Ok(())
}

#[tokio::test]
async fn standard_redirects_resolve_relative_locations_and_no_redirect_does_not_follow()
-> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/final"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/final"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let clients = loopback_clients()?;
    let approved = approve(&clients, &format!("{}/start", server.uri())).await?;

    let standard = clients
        .request(PolicyClass::Standard, Method::GET, &approved)
        .build()?;
    let response = clients.execute_bounded(standard).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"ok");

    let no_redirect = clients
        .request(PolicyClass::NoRedirect, Method::GET, &approved)
        .build()?;
    let response = clients.execute_bounded(no_redirect).await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    Ok(())
}

#[tokio::test]
async fn redirect_to_metadata_address_is_rejected_before_connect() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", "http://169.254.169.254/latest/meta-data"),
        )
        .mount(&server)
        .await;
    let clients = loopback_clients()?;
    let approved = approve(&clients, &format!("{}/start", server.uri())).await?;
    let request = clients
        .request(PolicyClass::Standard, Method::GET, &approved)
        .build()?;

    let error = clients
        .execute(request)
        .await
        .expect_err("metadata redirect must fail");
    assert_eq!(error, OutboundHttpError::DestinationRejected);
    Ok(())
}

#[tokio::test]
async fn redirect_loops_and_limits_are_rejected() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/loop"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/loop"))
        .mount(&server)
        .await;
    let clients = loopback_clients()?;
    let approved = approve(&clients, &format!("{}/loop", server.uri())).await?;
    let request = clients
        .request(PolicyClass::Standard, Method::GET, &approved)
        .build()?;
    let error = clients
        .execute(request)
        .await
        .expect_err("redirect loop must fail");
    assert_eq!(error, OutboundHttpError::RedirectLoop);
    Ok(())
}

#[tokio::test]
async fn cross_origin_redirect_strips_sensitive_internal_and_hop_headers()
-> Result<(), Box<dyn Error>> {
    let source = MockServer::start().await;
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/target", target.uri())),
        )
        .mount(&source)
        .await;
    Mock::given(method("GET"))
        .and(path("/target"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&target)
        .await;
    let clients = loopback_clients()?;
    let approved = approve(&clients, &format!("{}/start", source.uri())).await?;
    let request = clients
        .request(PolicyClass::Standard, Method::GET, &approved)
        .bearer_auth("bearer-secret")
        .header("cookie", "session=secret")
        .header("proxy-authorization", "proxy-secret")
        .header("x-api-key", "api-secret")
        .header("x-omnius-internal-auth", "internal-secret")
        .header("connection", "keep-alive, x-hop-secret")
        .header("x-hop-secret", "hop-secret")
        .build()?;
    clients.execute_bounded(request).await?;

    let requests = target
        .received_requests()
        .await
        .expect("target request history");
    let redirected = requests.first().expect("target request");
    for name in [
        "authorization",
        "cookie",
        "proxy-authorization",
        "x-api-key",
        "x-omnius-internal-auth",
        "connection",
        "x-hop-secret",
    ] {
        assert!(!redirected.headers.contains_key(name), "{name}");
    }
    Ok(())
}

#[tokio::test]
async fn post_302_redirect_becomes_get_without_entity_headers() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/start"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/target"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/target"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let clients = loopback_clients()?;
    let approved = approve(&clients, &format!("{}/start", server.uri())).await?;
    let request = clients
        .request(PolicyClass::Standard, Method::POST, &approved)
        .header("content-type", "text/plain")
        .body("secret body")
        .build()?;
    clients.execute_bounded(request).await?;

    let requests = server
        .received_requests()
        .await
        .expect("server request history");
    let redirected = requests
        .iter()
        .find(|request| request.url.path() == "/target")
        .expect("redirected request");
    assert_eq!(redirected.method.as_str(), "GET");
    assert!(redirected.body.is_empty());
    assert!(!redirected.headers.contains_key("content-type"));
    assert!(!redirected.headers.contains_key("content-length"));
    Ok(())
}

#[tokio::test]
async fn redirect_chain_uses_one_total_deadline() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/one"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", "/two")
                .set_delay(Duration::from_millis(70)),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/two"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("late")
                .set_delay(Duration::from_millis(70)),
        )
        .mount(&server)
        .await;
    let mut config = client_config();
    config.total_timeout = Duration::from_millis(100);
    config.connect_timeout = Duration::from_millis(50);
    let clients = OutboundHttpClients::with_resolver(
        &config,
        Arc::new(FakeResolver::returning(vec![loopback_address()])),
    )?;
    let approved = approve(&clients, &format!("{}/one", server.uri())).await?;
    let request = clients
        .request(PolicyClass::Standard, Method::GET, &approved)
        .build()?;

    let error = clients
        .execute_bounded(request)
        .await
        .expect_err("redirect chain must time out");
    assert_eq!(error, OutboundHttpError::Timeout);
    Ok(())
}

#[tokio::test]
async fn stalled_redirect_resolution_obeys_the_chain_deadline() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://stalled.test/target"),
        )
        .mount(&server)
        .await;
    let mut config = client_config();
    config.total_timeout = Duration::from_millis(50);
    config.connect_timeout = Duration::from_millis(25);
    let clients = OutboundHttpClients::with_resolver(&config, Arc::new(StalledResolver))?;
    let approved = approve(&clients, &format!("{}/start", server.uri())).await?;
    let request = clients
        .request(PolicyClass::Standard, Method::GET, &approved)
        .build()?;

    let error = clients
        .execute(request)
        .await
        .expect_err("stalled redirect DNS must time out");
    assert_eq!(error, OutboundHttpError::Timeout);
    Ok(())
}

#[tokio::test]
async fn streaming_response_preserves_metadata_and_ordered_body() -> Result<(), Box<dyn Error>> {
    let uri = start_loopback_stream(vec![
        (Duration::ZERO, &b"alpha"[..]),
        (Duration::from_millis(20), &b"-beta"[..]),
        (Duration::from_millis(20), &b"-gamma"[..]),
    ])
    .await?;
    let clients = loopback_clients()?;
    let approved = approve(&clients, &uri).await?;
    let request = clients
        .request(PolicyClass::NoRedirect, Method::GET, &approved)
        .build()?;

    let response = clients.execute_streaming(request).await?;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response
            .headers()
            .get("x-stream-test")
            .and_then(|value| value.to_str().ok()),
        Some("ordered")
    );

    let (status, headers, mut stream) = response.into_parts();
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        headers
            .get("x-stream-test")
            .and_then(|value| value.to_str().ok()),
        Some("ordered")
    );
    let mut body = Vec::new();
    while let Some(chunk) = stream.next_chunk().await {
        body.extend_from_slice(&chunk?);
    }
    assert_eq!(body, b"alpha-beta-gamma");
    Ok(())
}

#[tokio::test]
async fn streaming_response_rejects_a_chunk_crossing_the_caller_cap() -> Result<(), Box<dyn Error>>
{
    let uri = start_loopback_stream(vec![
        (Duration::ZERO, &b"123"[..]),
        (Duration::from_millis(20), &b"456"[..]),
    ])
    .await?;
    let clients = loopback_clients()?;
    let approved = approve(&clients, &uri).await?;
    let request = clients
        .request(PolicyClass::NoRedirect, Method::GET, &approved)
        .build()?;

    let response = clients.execute_streaming_with_limit(request, 5).await?;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let mut stream = response.into_body();
    assert_eq!(
        stream.next_chunk().await.transpose()?,
        Some(b"123".to_vec())
    );
    assert_eq!(
        stream.next_chunk().await,
        Some(Err(OutboundHttpError::ResponseTooLarge))
    );
    assert_eq!(stream.next_chunk().await, None);
    Ok(())
}

#[tokio::test]
async fn streaming_response_uses_the_configured_cap_when_it_is_lower() -> Result<(), Box<dyn Error>>
{
    let uri = start_loopback_stream(vec![
        (Duration::ZERO, &b"abc"[..]),
        (Duration::from_millis(20), &b"def"[..]),
    ])
    .await?;
    let mut config = client_config();
    config.response_body_limit_bytes = 4;
    let clients = OutboundHttpClients::with_resolver(
        &config,
        Arc::new(FakeResolver::returning(vec![loopback_address()])),
    )?;
    let approved = approve(&clients, &uri).await?;
    let request = clients
        .request(PolicyClass::NoRedirect, Method::GET, &approved)
        .build()?;

    let response = clients.execute_streaming_with_limit(request, 8).await?;
    let mut stream = response.into_body();
    assert_eq!(
        stream.next_chunk().await.transpose()?,
        Some(b"abc".to_vec())
    );
    assert_eq!(
        stream.next_chunk().await,
        Some(Err(OutboundHttpError::ResponseTooLarge))
    );
    Ok(())
}

#[tokio::test]
async fn streaming_body_reads_obey_the_original_total_deadline() -> Result<(), Box<dyn Error>> {
    let uri = start_loopback_stream(vec![
        (Duration::ZERO, &b"first"[..]),
        (Duration::from_secs(1), &b"late"[..]),
    ])
    .await?;
    let mut config = client_config();
    config.total_timeout = Duration::from_millis(300);
    config.connect_timeout = Duration::from_millis(100);
    let clients = OutboundHttpClients::with_resolver(
        &config,
        Arc::new(FakeResolver::returning(vec![loopback_address()])),
    )?;
    let approved = approve(&clients, &uri).await?;
    let request = clients
        .request(PolicyClass::NoRedirect, Method::GET, &approved)
        .build()?;

    let response = clients.execute_streaming(request).await?;
    let mut stream = response.into_body();
    let first = stream
        .next_chunk()
        .await
        .transpose()?
        .expect("first body chunk");
    assert_eq!(first, b"first");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let deadline_result =
        tokio::time::timeout(Duration::from_millis(250), stream.next_chunk()).await?;
    assert_eq!(deadline_result, Some(Err(OutboundHttpError::Timeout)));
    assert_eq!(stream.next_chunk().await, None);
    Ok(())
}

#[tokio::test]
async fn decoded_response_body_cap_is_enforced() -> Result<(), Box<dyn Error>> {
    // gzip-compressed 128 repeated `x` bytes; the wire size is below the decoded cap.
    const GZIP_BODY: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 2, 3, 171, 168, 24, 88, 0, 0, 73, 44, 184, 137, 128, 0, 0, 0,
    ];
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/gzip"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "gzip")
                .set_body_bytes(GZIP_BODY),
        )
        .mount(&server)
        .await;
    let clients = loopback_clients()?;
    let approved = approve(&clients, &format!("{}/gzip", server.uri())).await?;
    let request = clients
        .request(PolicyClass::NoRedirect, Method::GET, &approved)
        .build()?;

    let error = clients
        .execute_bounded(request)
        .await
        .expect_err("decoded body must exceed cap");
    assert_eq!(error, OutboundHttpError::ResponseTooLarge);
    Ok(())
}

#[tokio::test]
async fn policy_and_request_diagnostics_are_redacted() -> Result<(), Box<dyn Error>> {
    const SECRET: &str = "request-secret";
    let policy = OutboundUrlPolicy::with_resolver(
        OutboundUrlPolicyConfig::default(),
        Arc::new(FakeResolver::returning(vec![public_address()])),
    )?;
    let approved = policy
        .approve(Url::parse(&format!("https://public.test/{SECRET}"))?)
        .await?;
    let debug = format!("{policy:?} {approved:?}");
    assert!(!debug.contains(SECRET));
    assert!(debug.contains("[REDACTED]"));
    Ok(())
}

#[test]
fn invalid_bounded_configuration_and_proxy_modes_fail_closed() {
    let mut config = client_config();
    config.url_policy.allowed_https_ports.clear();
    let error = OutboundHttpClients::new(&config).expect_err("ports must fail");
    assert_eq!(
        error,
        BuildError::InvalidConfiguration(ConfigError::HttpsPorts)
    );

    let mut config = client_config();
    config.proxy = ProxyPolicy::Environment;
    let error = OutboundHttpClients::new(&config).expect_err("proxy must fail");
    assert_eq!(
        error,
        BuildError::InvalidConfiguration(ConfigError::ProxyUnsupported)
    );

    let mut config = client_config();
    config.url_policy.deny_cidrs = vec!["8.8.8.1/24".to_owned()];
    let error = OutboundHttpClients::new(&config).expect_err("non-canonical CIDR must fail");
    assert_eq!(
        error,
        BuildError::InvalidConfiguration(ConfigError::DenyCidrs)
    );

    let mut config = client_config();
    config.url_policy.dns_timeout = Duration::ZERO;
    let error = OutboundHttpClients::new(&config).expect_err("zero DNS timeout must fail");
    assert_eq!(
        error,
        BuildError::InvalidConfiguration(ConfigError::DnsTimeout)
    );

    let mut config = client_config();
    config.url_policy.max_dns_answers = 0;
    let error = OutboundHttpClients::new(&config).expect_err("zero DNS answer cap must fail");
    assert_eq!(
        error,
        BuildError::InvalidConfiguration(ConfigError::DnsAnswers)
    );
}
