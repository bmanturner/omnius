//! Real PostgreSQL coverage for the dedicated authenticated MCP composition root.

use std::{error::Error, sync::Arc, time::Duration as StdDuration};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, EncodingKey,
    jwk::{AlgorithmParameters, Jwk},
};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Scope, SubjectId, TenantId};
use omnius_auth_oauth_server::{
    AccessTokenClaims, AccessTokenClaimsInput, AuthorizationServerConfig, ClientId, GrantType,
    JwtId, KeyAlgorithm, KeyState, ResourceConfig, ResourceScopeConfig, ResourceUri, RsaPublicJwk,
    SigningKeyConfig, TokenEndpointAuthMethod, TokenPepper, ValidatedAuthorizationServerConfig,
    store::{
        ClientSource, ClientUpsert, GrantCreate, LiveGrant, OAuthPostgresStore, PublicSubject,
    },
    types::{ApplicationType, RedirectUri, ResponseType},
};
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_mcp_server::{
    MCP_PROTECTED_RESOURCE_METADATA_PATH, REFERENCE_RECORDS_LIST_TOOL,
    ReferenceMcpApplicationInput, build_reference_mcp_application,
};
use omnius_mcp_server_core::MCP_PROTOCOL_REVISION;
use omnius_mcp_transport_http::{MCP_HTTP_PATH, McpHttpConfig};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_pagination::{CursorCodec, CursorSigningKey};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_reference_api::oauth_provider::{MCP_RESOURCE_PATH, REFERENCE_RECORDS_READ_SCOPE};
use omnius_reference_domain::{ReferenceRecord, ReferenceRecordId, ReferenceRecordRepository as _};
use omnius_reference_postgres::PostgresReferenceRecordRepository;
use omnius_test_support::PostgresFixture;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const ISSUER: &str = "http://127.0.0.1:49261";
const MCP_RESOURCE: &str = "http://127.0.0.1:49261/mcp";
const CLIENT: &str = "reference-mcp-integration-client";
const KEY_ID: &str = "reference-mcp-integration-key";
const PRIVATE_KEY: &str = include_str!("../../../crates/auth-jwt/tests/test_rsa_key.pem");
const DISCOVERY_CHALLENGE: &str = concat!(
    "Bearer resource_metadata=\"",
    "http://127.0.0.1:49261/.well-known/oauth-protected-resource/mcp",
    "\", scope=\"reference-records:read\""
);
const INVALID_REQUEST_CHALLENGE: &str = concat!(
    "Bearer error=\"invalid_request\", resource_metadata=\"",
    "http://127.0.0.1:49261/.well-known/oauth-protected-resource/mcp",
    "\", scope=\"reference-records:read\""
);
const INVALID_TOKEN_CHALLENGE: &str = concat!(
    "Bearer error=\"invalid_token\", resource_metadata=\"",
    "http://127.0.0.1:49261/.well-known/oauth-protected-resource/mcp",
    "\", scope=\"reference-records:read\""
);
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct TestDatabase {
    pool: PostgresPool,
    _fixture: PostgresFixture,
}

impl TestDatabase {
    async fn start() -> TestResult<Self> {
        let fixture = PostgresFixture::start().await?;
        let pool =
            PostgresPool::connect(&postgres_config(&fixture), DeploymentEnvironment::Test).await?;
        let runner = MigrationRunner::new(
            pool.clone(),
            &MIGRATOR,
            SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
            MigrationConfig {
                run_on_startup: false,
                operation_timeout: StdDuration::from_secs(10),
            },
            DeploymentEnvironment::Test,
        )?;
        runner.run().await?;
        Ok(Self {
            pool,
            _fixture: fixture,
        })
    }
}

struct TestScenario {
    database: TestDatabase,
    router: Router,
    seeded: ReferenceRecord,
    live_grant: LiveGrant,
    token: String,
    root_token: String,
    expired_token: String,
    tenant_token: String,
    revoked_token: String,
}

impl TestScenario {
    async fn start() -> TestResult<Self> {
        let database = TestDatabase::start().await?;
        let now = OffsetDateTime::now_utc();
        let authorization_server = Arc::new(authorization_server_config(now)?);
        let live_grant = seed_global_grant(&database.pool, now - Duration::minutes(10)).await?;
        let seeded =
            ReferenceRecord::create(ReferenceRecordId::new(), "seeded through PostgreSQL", now)?;
        PostgresReferenceRecordRepository::new(database.pool.clone())
            .create(&seeded)
            .await?;
        let token = mint_token(
            &authorization_server,
            &live_grant,
            ResourceUri::parse(MCP_RESOURCE.to_owned(), false)?,
            vec![Scope::new(REFERENCE_RECORDS_READ_SCOPE)?],
            now,
            now + Duration::minutes(10),
        )?;
        let root_token = mint_token(
            &authorization_server,
            &live_grant,
            ResourceUri::parse(ISSUER.to_owned(), false)?,
            vec![Scope::new(REFERENCE_RECORDS_READ_SCOPE)?],
            now,
            now + Duration::minutes(10),
        )?;
        let expired_token = mint_token(
            &authorization_server,
            &live_grant,
            ResourceUri::parse(MCP_RESOURCE.to_owned(), false)?,
            vec![Scope::new(REFERENCE_RECORDS_READ_SCOPE)?],
            now - Duration::minutes(10),
            now - Duration::seconds(1),
        )?;
        let tenant_grant = seed_tenant_grant(&database.pool, &live_grant, now).await?;
        let tenant_token = mint_token(
            &authorization_server,
            &tenant_grant,
            ResourceUri::parse(MCP_RESOURCE.to_owned(), false)?,
            vec![Scope::new(REFERENCE_RECORDS_READ_SCOPE)?],
            now,
            now + Duration::minutes(10),
        )?;
        let revoked_token = mint_token(
            &authorization_server,
            &live_grant,
            ResourceUri::parse(MCP_RESOURCE.to_owned(), false)?,
            vec![Scope::new(REFERENCE_RECORDS_READ_SCOPE)?],
            now,
            now + Duration::minutes(10),
        )?;
        let app = build_reference_mcp_application(ReferenceMcpApplicationInput {
            authorization_server,
            pool: database.pool.clone(),
            local_identity_provider: "email".to_owned(),
            cursor_codec: CursorCodec::new(CursorSigningKey::from_slice(&[9_u8; 32])?),
            http: McpHttpConfig::default(),
        })?;
        Ok(Self {
            database,
            router: app.router(),
            seeded,
            live_grant,
            token,
            root_token,
            expired_token,
            tenant_token,
            revoked_token,
        })
    }

    async fn assert_metadata_and_request_rejections(&self) -> TestResult {
        let metadata = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(MCP_PROTECTED_RESOURCE_METADATA_PATH)
                    .header(header::HOST, "localhost")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(metadata.status(), StatusCode::OK);
        let metadata = response_json(metadata).await?;
        assert_eq!(metadata["resource"], MCP_RESOURCE);
        assert_eq!(
            metadata["scopes_supported"],
            json!([REFERENCE_RECORDS_READ_SCOPE])
        );

        let missing = self
            .router
            .clone()
            .oneshot(mcp_request("tools/list", 1, request_meta(), None, None)?)
            .await?;
        assert_bearer_rejection(&missing, StatusCode::UNAUTHORIZED, DISCOVERY_CHALLENGE)?;

        let query = self
            .router
            .clone()
            .oneshot(mcp_request(
                "tools/list",
                2,
                request_meta(),
                None,
                Some("access_token=forbidden"),
            )?)
            .await?;
        assert_bearer_rejection(&query, StatusCode::BAD_REQUEST, INVALID_REQUEST_CHALLENGE)?;

        let malformed = self
            .router
            .clone()
            .oneshot(mcp_request(
                "tools/list",
                30,
                request_meta(),
                Some("token with-space"),
                None,
            )?)
            .await?;
        assert_bearer_rejection(
            &malformed,
            StatusCode::BAD_REQUEST,
            INVALID_REQUEST_CHALLENGE,
        )?;

        let malformed_token = self
            .router
            .clone()
            .oneshot(mcp_request(
                "tools/list",
                34,
                request_meta(),
                Some("not-a-jwt"),
                None,
            )?)
            .await?;
        assert_bearer_rejection(
            &malformed_token,
            StatusCode::UNAUTHORIZED,
            INVALID_TOKEN_CHALLENGE,
        )
    }

    async fn assert_token_context_rejections(&self) -> TestResult {
        let wrong_audience = self
            .router
            .clone()
            .oneshot(mcp_request(
                "tools/list",
                3,
                request_meta(),
                Some(&self.root_token),
                None,
            )?)
            .await?;
        assert_bearer_rejection(
            &wrong_audience,
            StatusCode::UNAUTHORIZED,
            INVALID_TOKEN_CHALLENGE,
        )?;

        let expired = self
            .router
            .clone()
            .oneshot(mcp_request(
                "tools/list",
                31,
                request_meta(),
                Some(&self.expired_token),
                None,
            )?)
            .await?;
        assert_bearer_rejection(&expired, StatusCode::UNAUTHORIZED, INVALID_TOKEN_CHALLENGE)?;

        let tenant_bearing = self
            .router
            .clone()
            .oneshot(mcp_request(
                "tools/list",
                32,
                request_meta(),
                Some(&self.tenant_token),
                None,
            )?)
            .await?;
        assert_bearer_rejection(
            &tenant_bearing,
            StatusCode::UNAUTHORIZED,
            INVALID_TOKEN_CHALLENGE,
        )
    }

    async fn assert_successful_tool_flow(&self) -> TestResult {
        let listed = self
            .router
            .clone()
            .oneshot(mcp_request(
                "tools/list",
                4,
                request_meta(),
                Some(&self.token),
                None,
            )?)
            .await?;
        assert_eq!(listed.status(), StatusCode::OK);
        let listed = response_json(listed).await?;
        assert_eq!(listed["result"]["tools"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            listed["result"]["tools"][0]["name"],
            REFERENCE_RECORDS_LIST_TOOL
        );

        let called = self
            .router
            .clone()
            .oneshot(mcp_request(
                "tools/call",
                5,
                json!({
                    "_meta": request_meta(),
                    "name": REFERENCE_RECORDS_LIST_TOOL,
                    "arguments": {"limit": 20}
                }),
                Some(&self.token),
                None,
            )?)
            .await?;
        let called_status = called.status();
        let called = response_json(called).await?;
        assert_eq!(called_status, StatusCode::OK, "{called}");
        assert_eq!(
            called["result"]["structuredContent"]["items"][0]["name"],
            self.seeded.name(),
            "{called}"
        );
        Ok(())
    }

    async fn assert_unsupported_primitive_response(&self) -> TestResult {
        let resources = self
            .router
            .clone()
            .oneshot(mcp_request(
                "resources/list",
                6,
                request_meta(),
                Some(&self.token),
                None,
            )?)
            .await?;
        let resources_status = resources.status();
        let resources = response_json(resources).await?;
        assert_eq!(resources_status, StatusCode::NOT_FOUND, "{resources}");
        assert_eq!(resources["error"]["code"], -32601, "{resources}");
        Ok(())
    }

    async fn revoke_grant_and_assert_rejection(&self) -> TestResult {
        let mut connection = self.database.pool.acquire().await?;
        sqlx::query(
            "UPDATE oauth_grants \
             SET revoked_at = $2, updated_at = $2, version = version + 1 \
             WHERE id = $1",
        )
        .bind(self.live_grant.id.as_uuid())
        .bind(OffsetDateTime::now_utc())
        .execute(&mut *connection)
        .await?;
        drop(connection);
        let revoked = self
            .router
            .clone()
            .oneshot(mcp_request(
                "tools/list",
                33,
                request_meta(),
                Some(&self.revoked_token),
                None,
            )?)
            .await?;
        assert_bearer_rejection(&revoked, StatusCode::UNAUTHORIZED, INVALID_TOKEN_CHALLENGE)
    }

    async fn assert_authorization_server_routes_absent(&self) -> TestResult {
        let auth_server_routes = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/.well-known/oauth-authorization-server")
                    .header(header::HOST, "localhost")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(auth_server_routes.status(), StatusCode::NOT_FOUND);
        Ok(())
    }
}

#[tokio::test]
async fn exact_live_mcp_token_lists_and_calls_only_the_real_reference_tool() -> TestResult {
    let scenario = TestScenario::start().await?;
    scenario.assert_metadata_and_request_rejections().await?;
    scenario.assert_token_context_rejections().await?;
    scenario.assert_successful_tool_flow().await?;
    scenario.assert_unsupported_primitive_response().await?;
    scenario.revoke_grant_and_assert_rejection().await?;
    scenario.assert_authorization_server_routes_absent().await?;
    scenario.database.pool.close().await?;
    Ok(())
}

fn postgres_config(fixture: &PostgresFixture) -> PostgresConfig {
    PostgresConfig {
        url: fixture.database_url().clone(),
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 6,
        connect_timeout: StdDuration::from_secs(5),
        acquire_timeout: StdDuration::from_secs(2),
        idle_timeout: StdDuration::from_secs(30),
        max_lifetime: StdDuration::from_secs(60),
        max_lifetime_jitter: StdDuration::from_secs(10),
        application_name: "reference-mcp-integration-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: StdDuration::from_secs(5),
        lock_timeout: StdDuration::from_secs(2),
        health_timeout: StdDuration::from_secs(2),
        shutdown_timeout: StdDuration::from_secs(3),
        transaction_retry: TransactionRetryConfig {
            max_attempts: 3,
            base_delay: StdDuration::from_millis(5),
            max_delay: StdDuration::from_millis(50),
            max_jitter: StdDuration::from_millis(5),
            isolation: TransactionIsolation::Serializable,
        },
    }
}

fn authorization_server_config(
    now: OffsetDateTime,
) -> TestResult<ValidatedAuthorizationServerConfig> {
    let config = AuthorizationServerConfig {
        enabled: true,
        issuer: ISSUER.to_owned(),
        token_pepper: Some(TokenPepper::parse(&URL_SAFE_NO_PAD.encode([7_u8; 32]))?),
        dynamic_client_registration: false,
        resources: vec![
            ResourceConfig {
                uri: ISSUER.to_owned(),
                name: "Reference API".to_owned(),
                description: "Root API resource".to_owned(),
                minimum_assurance: AssuranceLevel::Aal1,
                scopes: vec![ResourceScopeConfig {
                    name: Scope::new("api:read")?,
                    description: "Read the root API".to_owned(),
                }],
            },
            ResourceConfig {
                uri: format!("{ISSUER}{MCP_RESOURCE_PATH}"),
                name: "Reference MCP".to_owned(),
                description: "Dedicated MCP resource".to_owned(),
                minimum_assurance: AssuranceLevel::Aal1,
                scopes: vec![ResourceScopeConfig {
                    name: Scope::new(REFERENCE_RECORDS_READ_SCOPE)?,
                    description: "Read reference records through MCP".to_owned(),
                }],
            },
        ],
        signing_keys: vec![SigningKeyConfig {
            kid: KEY_ID.to_owned(),
            algorithm: KeyAlgorithm::RS256,
            state: KeyState::Active,
            public_jwk: public_jwk()?,
            private_key_pkcs8_pem: Some(SecretString::from(PRIVATE_KEY.to_owned())),
            verification_until: None,
        }],
        ..AuthorizationServerConfig::default()
    };
    config
        .build_for(DeploymentEnvironment::Test, now)?
        .ok_or_else(|| "enabled authorization server was not built".into())
}

fn public_jwk() -> TestResult<RsaPublicJwk> {
    let encoding = EncodingKey::from_rsa_pem(PRIVATE_KEY.as_bytes())?;
    let derived = Jwk::from_encoding_key(&encoding, Algorithm::RS256)?;
    let AlgorithmParameters::RSA(parameters) = derived.algorithm else {
        return Err("test key did not produce an RSA JWK".into());
    };
    Ok(RsaPublicJwk {
        kty: "RSA".to_owned(),
        public_key_use: "sig".to_owned(),
        key_ops: vec!["verify".to_owned()],
        alg: "RS256".to_owned(),
        kid: KEY_ID.to_owned(),
        n: parameters.n,
        e: parameters.e,
    })
}

async fn seed_global_grant(
    pool: &PostgresPool,
    now: OffsetDateTime,
) -> TestResult<omnius_auth_oauth_server::store::LiveGrant> {
    let subject_id = SubjectId::new();
    let mut connection = pool.acquire().await?;
    sqlx::query("INSERT INTO users (id, status, created_at) VALUES ($1, 'active', $2)")
        .bind(subject_id.as_uuid())
        .bind(now)
        .execute(&mut *connection)
        .await?;
    sqlx::query(
        "INSERT INTO identities \
         (id, user_id, provider, provider_subject, created_at, verified_at) \
         VALUES ($1, $2, 'email', 'mcp-user@example.test', $3, $3)",
    )
    .bind(Uuid::now_v7())
    .bind(subject_id.as_uuid())
    .bind(now)
    .execute(&mut *connection)
    .await?;
    drop(connection);

    let store = OAuthPostgresStore::new(pool.clone());
    store
        .upsert_client(&ClientUpsert {
            client_id: ClientId::parse(CLIENT)?,
            source: ClientSource::PreRegistered,
            display_name: "Reference MCP client".to_owned(),
            client_uri: Some("https://client.example.test".to_owned()),
            logo_uri: None,
            application_type: ApplicationType::Web,
            token_endpoint_auth_method: TokenEndpointAuthMethod::None,
            client_secret_digest: None,
            response_types: vec![ResponseType::Code],
            grant_types: vec![GrantType::AuthorizationCode],
            allowed_scopes: vec![Scope::new(REFERENCE_RECORDS_READ_SCOPE)?],
            public_jwks: None,
            redirect_uris: vec![RedirectUri::parse(
                "https://client.example.test/callback".to_owned(),
            )?],
            post_logout_redirect_uris: Vec::new(),
            metadata_document_uri: None,
            metadata_cache: None,
            now,
        })
        .await?;
    store
        .allocate_subject(
            subject_id,
            PublicSubject::parse(URL_SAFE_NO_PAD.encode([8_u8; 32]))?,
            now,
        )
        .await?;
    Ok(store
        .create_grant(&GrantCreate {
            user_id: subject_id,
            tenant_id: None,
            client_id: ClientId::parse(CLIENT)?,
            resources: vec![ResourceUri::parse(MCP_RESOURCE.to_owned(), false)?],
            granted_scopes: vec![Scope::new(REFERENCE_RECORDS_READ_SCOPE)?],
            authenticated_at: now,
            assurance_level: AssuranceLevel::Aal1,
            authentication_methods: vec![AuthMethod::Password],
            consented_at: now,
        })
        .await?)
}

async fn seed_tenant_grant(
    pool: &PostgresPool,
    global_grant: &omnius_auth_oauth_server::store::LiveGrant,
    now: OffsetDateTime,
) -> TestResult<omnius_auth_oauth_server::store::LiveGrant> {
    let tenant_id = TenantId::new();
    let mut connection = pool.acquire().await?;
    sqlx::query(
        "INSERT INTO organizations \
         (id, name, status, version, owner_guard_version, created_at, updated_at) \
         VALUES ($1, 'MCP tenant', 'suspended', 1, 0, $2, $2)",
    )
    .bind(tenant_id.as_uuid())
    .bind(now)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, 'owner', 'active', 1, $3, $3)",
    )
    .bind(tenant_id.as_uuid())
    .bind(global_grant.user_id.as_uuid())
    .bind(now)
    .execute(&mut *connection)
    .await?;
    sqlx::query("UPDATE organizations SET status = 'active', updated_at = $2 WHERE id = $1")
        .bind(tenant_id.as_uuid())
        .bind(now)
        .execute(&mut *connection)
        .await?;
    drop(connection);

    Ok(OAuthPostgresStore::new(pool.clone())
        .create_grant(&GrantCreate {
            user_id: global_grant.user_id,
            tenant_id: Some(tenant_id),
            client_id: global_grant.client_id.clone(),
            resources: vec![ResourceUri::parse(MCP_RESOURCE.to_owned(), false)?],
            granted_scopes: vec![Scope::new(REFERENCE_RECORDS_READ_SCOPE)?],
            authenticated_at: now,
            assurance_level: AssuranceLevel::Aal1,
            authentication_methods: vec![AuthMethod::Password],
            consented_at: now,
        })
        .await?)
}

fn mint_token(
    config: &ValidatedAuthorizationServerConfig,
    grant: &omnius_auth_oauth_server::store::LiveGrant,
    audience: ResourceUri,
    scopes: Vec<Scope>,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> TestResult<String> {
    let claims = AccessTokenClaims::new(AccessTokenClaimsInput {
        issuer: config.issuer().clone(),
        subject: grant.public_subject.as_str().to_owned(),
        audience,
        expires_at,
        not_before: issued_at,
        issued_at,
        jwt_id: JwtId::new(),
        client_id: grant.client_id.clone(),
        grant_id: grant.id,
        scopes,
        auth_time: grant.authenticated_at,
        acr: "aal1".to_owned(),
        amr: vec!["pwd".to_owned()],
    })?;
    Ok(config
        .signing_keys()
        .sign_access_token(&claims)?
        .expose_once())
}

fn request_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_REVISION,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {
            "name": "reference-mcp-test-client",
            "version": "1.0.0"
        }
    })
}

fn mcp_request(
    method: &str,
    id: i64,
    params: Value,
    token: Option<&str>,
    query: Option<&str>,
) -> TestResult<Request<Body>> {
    let uri = query.map_or_else(
        || MCP_HTTP_PATH.to_owned(),
        |query| format!("{MCP_HTTP_PATH}?{query}"),
    );
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-protocol-version", MCP_PROTOCOL_REVISION)
        .header("mcp-method", method);
    if let Some(name) = params.get("name").and_then(Value::as_str) {
        builder = builder.header("mcp-name", name);
    }
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    Ok(builder.body(Body::from(serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": if params.get("_meta").is_some() {
            params
        } else {
            json!({"_meta": params})
        }
    }))?))?)
}

fn assert_bearer_rejection(
    response: &axum::response::Response,
    status: StatusCode,
    challenge: &str,
) -> TestResult {
    assert_eq!(response.status(), status);
    assert_eq!(
        response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .ok_or("bearer rejection omitted WWW-Authenticate")?
            .to_str()?,
        challenge
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .ok_or("bearer rejection omitted Cache-Control")?
            .to_str()?,
        "no-store"
    );
    Ok(())
}

async fn response_json(response: axum::response::Response) -> TestResult<Value> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 2 * 1024 * 1024).await?,
    )?)
}
