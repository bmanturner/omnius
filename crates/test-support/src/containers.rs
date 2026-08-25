use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use rsk_config::SecretString;
use testcontainers::{
    ContainerAsync, ContainerRequest, GenericImage, Image, ImageExt,
    core::{ContainerPort, IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use thiserror::Error;
use url::Url;

const POSTGRES_IMAGE: &str = "postgres";
const POSTGRES_TAG: &str = "17.6-alpine3.22";
const POSTGRES_PORT: u16 = 5432;
const REDIS_IMAGE: &str = "redis";
const REDIS_TAG: &str = "8.2.1-alpine";
const REDIS_PORT: u16 = 6379;
const NATS_IMAGE: &str = "nats";
const NATS_TAG: &str = "2.11.9-alpine";
const NATS_PORT: u16 = 4222;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

/// An isolated PostgreSQL 17 container with generated non-default credentials.
pub struct PostgresFixture {
    container: ContainerAsync<GenericImage>,
    database_url: SecretString,
    database: String,
    username: String,
}

impl PostgresFixture {
    /// Starts PostgreSQL and returns only after its native ready message.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerFixtureError`] for Docker, port, or URL failures.
    pub async fn start() -> Result<Self, ContainerFixtureError> {
        let suffix = next_suffix();
        let database = format!("rsk_test_{suffix}");
        let username = format!("rsk_test_{suffix}");
        let password = format!("rsk-pg-{suffix}-password");
        let ready = "database system is ready to accept connections";
        let image = GenericImage::new(POSTGRES_IMAGE, POSTGRES_TAG)
            .with_exposed_port(POSTGRES_PORT.tcp())
            .with_wait_for(WaitFor::message_on_stdout(ready))
            .with_wait_for(WaitFor::message_on_stderr(ready))
            .with_env_var("POSTGRES_DB", &database)
            .with_env_var("POSTGRES_USER", &username)
            .with_env_var("POSTGRES_PASSWORD", &password)
            .with_env_var("POSTGRES_INITDB_ARGS", "--auth-host=scram-sha-256");
        let container = loopback_request(image, POSTGRES_PORT.tcp())
            .start()
            .await
            .map_err(ContainerFixtureError::Container)?;
        let database_url = authenticated_url(
            &container,
            POSTGRES_PORT,
            "postgres",
            &username,
            &password,
            &database,
        )
        .await?;
        Ok(Self {
            container,
            database_url,
            database,
            username,
        })
    }

    /// Returns the redacted database URL. Tests explicitly expose it only when
    /// constructing a provider client.
    #[must_use]
    pub const fn database_url(&self) -> &SecretString {
        &self.database_url
    }

    /// Returns the isolated database name.
    #[must_use]
    pub fn database(&self) -> &str {
        &self.database
    }

    /// Returns the generated role name.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Removes the container immediately instead of waiting for `Drop` cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerFixtureError`] when Docker cannot remove it.
    pub async fn cleanup(self) -> Result<(), ContainerFixtureError> {
        self.container
            .rm()
            .await
            .map_err(ContainerFixtureError::Container)
    }
}

impl fmt::Debug for PostgresFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresFixture")
            .field("database", &self.database)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// An isolated authenticated Redis 8 container and key namespace.
pub struct RedisFixture {
    container: ContainerAsync<GenericImage>,
    redis_url: SecretString,
    namespace: String,
}

impl RedisFixture {
    /// Starts Redis and returns only after its native ready message.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerFixtureError`] for Docker, port, or URL failures.
    pub async fn start() -> Result<Self, ContainerFixtureError> {
        let suffix = next_suffix();
        let password = format!("rsk-redis-{suffix}-password");
        let namespace = format!("rsk:{suffix}:");
        let image = GenericImage::new(REDIS_IMAGE, REDIS_TAG)
            .with_exposed_port(REDIS_PORT.tcp())
            .with_wait_for(WaitFor::message_on_either_std(
                "Ready to accept connections",
            ))
            .with_cmd(["redis-server", "--requirepass", &password]);
        let container = loopback_request(image, REDIS_PORT.tcp())
            .start()
            .await
            .map_err(ContainerFixtureError::Container)?;
        let redis_url =
            authenticated_url(&container, REDIS_PORT, "redis", "default", &password, "").await?;
        Ok(Self {
            container,
            redis_url,
            namespace,
        })
    }

    /// Returns the redacted authenticated Redis URL.
    #[must_use]
    pub const fn redis_url(&self) -> &SecretString {
        &self.redis_url
    }

    /// Returns the isolated key prefix for this fixture.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Removes the container immediately instead of waiting for `Drop` cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerFixtureError`] when Docker cannot remove it.
    pub async fn cleanup(self) -> Result<(), ContainerFixtureError> {
        self.container
            .rm()
            .await
            .map_err(ContainerFixtureError::Container)
    }
}

impl fmt::Debug for RedisFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisFixture")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

/// An authenticated NATS container with `JetStream` and an isolated subject prefix.
pub struct NatsFixture {
    container: ContainerAsync<GenericImage>,
    nats_url: SecretString,
    subject_prefix: String,
}

impl NatsFixture {
    /// Starts NATS with `JetStream` and waits for its native ready message.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerFixtureError`] for Docker, port, or URL failures.
    pub async fn start() -> Result<Self, ContainerFixtureError> {
        let suffix = next_suffix();
        let username = format!("rsk_test_{suffix}");
        let password = format!("rsk-nats-{suffix}-password");
        let subject_prefix = format!("rsk.test.{suffix}");
        let image = GenericImage::new(NATS_IMAGE, NATS_TAG)
            .with_exposed_port(NATS_PORT.tcp())
            .with_wait_for(WaitFor::message_on_either_std("Server is ready"))
            .with_cmd(["--user", &username, "--pass", &password, "--jetstream"]);
        let container = loopback_request(image, NATS_PORT.tcp())
            .start()
            .await
            .map_err(ContainerFixtureError::Container)?;
        let nats_url =
            authenticated_url(&container, NATS_PORT, "nats", &username, &password, "").await?;
        Ok(Self {
            container,
            nats_url,
            subject_prefix,
        })
    }

    /// Returns the redacted authenticated NATS URL.
    #[must_use]
    pub const fn nats_url(&self) -> &SecretString {
        &self.nats_url
    }

    /// Returns the isolated subject/stream prefix for this fixture.
    #[must_use]
    pub fn subject_prefix(&self) -> &str {
        &self.subject_prefix
    }

    /// Removes the container immediately instead of waiting for `Drop` cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerFixtureError`] when Docker cannot remove it.
    pub async fn cleanup(self) -> Result<(), ContainerFixtureError> {
        self.container
            .rm()
            .await
            .map_err(ContainerFixtureError::Container)
    }
}

impl fmt::Debug for NatsFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsFixture")
            .field("subject_prefix", &self.subject_prefix)
            .finish_non_exhaustive()
    }
}

/// Core-NATS fixture with exact-subject allowed and denied-subscription identities.
pub struct NatsCoreFanoutRoleFixture {
    container: ContainerAsync<GenericImage>,
    runtime_url: SecretString,
    denied_sub_url: SecretString,
    subject: String,
}

impl NatsCoreFanoutRoleFixture {
    /// Starts a Core-NATS-only server with exact publish and subscribe permissions.
    ///
    /// Neither identity has `JetStream`, inbox, or wildcard permissions, and the server does not
    /// enable `JetStream`, proving ephemeral fan-out does not depend on a durable stream.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerFixtureError`] for Docker, port, or URL failures.
    pub async fn start() -> Result<Self, ContainerFixtureError> {
        let suffix = next_suffix();
        let subject = format!("rsk.test.{suffix}.realtime");
        let denied_sub_control_subject = format!("rsk.test.{suffix}.denied-control");
        let runtime_user = format!("fanout_{suffix}");
        let runtime_password = format!("rsk-fanout-{suffix}-password");
        let denied_sub_user = format!("fanout_publish_only_{suffix}");
        let denied_sub_password = format!("rsk-fanout-publish-only-{suffix}-password");
        let config = format!(
            r#"port: 4222
authorization {{
  users: [
    {{
      user: "{runtime_user}"
      password: "{runtime_password}"
      permissions: {{
        publish: {{ allow: ["{subject}"] }}
        subscribe: {{ allow: ["{subject}"] }}
      }}
    }}
    {{
      user: "{denied_sub_user}"
      password: "{denied_sub_password}"
      permissions: {{
        publish: {{ allow: ["{subject}"] }}
        subscribe: {{ allow: ["{denied_sub_control_subject}"] }}
      }}
    }}
  ]
}}
"#,
        );
        let container = start_role_nats(config).await?;
        let runtime_url = authenticated_url(
            &container,
            NATS_PORT,
            "nats",
            &runtime_user,
            &runtime_password,
            "",
        )
        .await?;
        let denied_sub_url = authenticated_url(
            &container,
            NATS_PORT,
            "nats",
            &denied_sub_user,
            &denied_sub_password,
            "",
        )
        .await?;
        Ok(Self {
            container,
            runtime_url,
            denied_sub_url,
            subject,
        })
    }

    /// Authenticated endpoint restricted to this fixture's exact fan-out subject.
    #[must_use]
    pub const fn runtime_url(&self) -> &SecretString {
        &self.runtime_url
    }

    /// Authenticated endpoint that may publish but cannot subscribe to the fan-out subject.
    #[must_use]
    pub const fn denied_sub_url(&self) -> &SecretString {
        &self.denied_sub_url
    }

    /// Exact subject authorized for ephemeral fan-out.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Removes the container immediately instead of waiting for `Drop` cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerFixtureError`] when Docker cannot remove it.
    pub async fn cleanup(self) -> Result<(), ContainerFixtureError> {
        self.container
            .rm()
            .await
            .map_err(ContainerFixtureError::Container)
    }
}

impl fmt::Debug for NatsCoreFanoutRoleFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsCoreFanoutRoleFixture")
            .field("subject", &self.subject)
            .field("credentials", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// NATS `JetStream` fixture with distinct administrator, publisher, and consumer identities.
pub struct NatsRoleFixture {
    container: ContainerAsync<GenericImage>,
    admin_url: SecretString,
    publisher_url: SecretString,
    consumer_url: SecretString,
    subject_prefix: String,
    stream_name: String,
    dlq_stream_name: String,
    durable_name: String,
}

impl NatsRoleFixture {
    /// Starts a role-isolated NATS server with exact runtime subject permissions.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerFixtureError`] for Docker, port, or URL failures.
    pub async fn start() -> Result<Self, ContainerFixtureError> {
        let suffix = next_suffix();
        let subject_prefix = format!("rsk.test.{suffix}");
        let stream_name = format!("RSK_TEST_{suffix}_EVENTS");
        let dlq_stream_name = format!("RSK_TEST_{suffix}_DLQ");
        let durable_name = format!("RSK_TEST_{suffix}_WORKER");
        let admin_user = format!("admin_{suffix}");
        let publisher_user = format!("publisher_{suffix}");
        let consumer_user = format!("consumer_{suffix}");
        let admin_password = format!("rsk-admin-{suffix}-password");
        let publisher_password = format!("rsk-publisher-{suffix}-password");
        let consumer_password = format!("rsk-consumer-{suffix}-password");
        let event_filter = format!("{subject_prefix}.events.>");
        let dlq_subject = format!("{subject_prefix}.dlq");
        let config = format!(
            r#"port: 4222
jetstream {{
  store_dir: "/data/jetstream"
}}
authorization {{
  users: [
    {{
      user: "{admin_user}"
      password: "{admin_password}"
      permissions: {{
        publish: {{ allow: ["$JS.API.STREAM.>", "$JS.API.CONSUMER.>"] }}
        subscribe: {{ allow: ["_INBOX.>"] }}
      }}
    }}
    {{
      user: "{publisher_user}"
      password: "{publisher_password}"
      permissions: {{
        publish: {{ allow: ["{event_filter}", "$JS.API.STREAM.INFO.{stream_name}"] }}
        subscribe: {{ allow: ["_INBOX.>"] }}
      }}
    }}
    {{
      user: "{consumer_user}"
      password: "{consumer_password}"
      permissions: {{
        publish: {{ allow: [
          "$JS.API.STREAM.INFO.{stream_name}",
          "$JS.API.STREAM.INFO.{dlq_stream_name}",
          "$JS.API.CONSUMER.INFO.{stream_name}.{durable_name}",
          "$JS.API.CONSUMER.MSG.NEXT.{stream_name}.{durable_name}",
          "$JS.ACK.{stream_name}.{durable_name}.>",
          "{dlq_subject}"
        ] }}
        subscribe: {{ allow: ["_INBOX.>"] }}
      }}
    }}
  ]
}}
"#,
        );
        let container = start_role_nats(config).await?;
        let admin_url = authenticated_url(
            &container,
            NATS_PORT,
            "nats",
            &admin_user,
            &admin_password,
            "",
        )
        .await?;
        let publisher_url = authenticated_url(
            &container,
            NATS_PORT,
            "nats",
            &publisher_user,
            &publisher_password,
            "",
        )
        .await?;
        let consumer_url = authenticated_url(
            &container,
            NATS_PORT,
            "nats",
            &consumer_user,
            &consumer_password,
            "",
        )
        .await?;
        Ok(Self {
            container,
            admin_url,
            publisher_url,
            consumer_url,
            subject_prefix,
            stream_name,
            dlq_stream_name,
            durable_name,
        })
    }

    /// Authenticated administrative endpoint.
    #[must_use]
    pub const fn admin_url(&self) -> &SecretString {
        &self.admin_url
    }

    /// Authenticated publication-only endpoint.
    #[must_use]
    pub const fn publisher_url(&self) -> &SecretString {
        &self.publisher_url
    }

    /// Authenticated durable-consumer endpoint.
    #[must_use]
    pub const fn consumer_url(&self) -> &SecretString {
        &self.consumer_url
    }

    /// Isolated NATS subject prefix.
    #[must_use]
    pub fn subject_prefix(&self) -> &str {
        &self.subject_prefix
    }

    /// Main stream name pre-authorized for this fixture.
    #[must_use]
    pub fn stream_name(&self) -> &str {
        &self.stream_name
    }

    /// DLQ stream name pre-authorized for this fixture.
    #[must_use]
    pub fn dlq_stream_name(&self) -> &str {
        &self.dlq_stream_name
    }

    /// Durable consumer name pre-authorized for this fixture.
    #[must_use]
    pub fn durable_name(&self) -> &str {
        &self.durable_name
    }

    /// Removes the container immediately instead of waiting for `Drop` cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerFixtureError`] when Docker cannot remove it.
    pub async fn cleanup(self) -> Result<(), ContainerFixtureError> {
        self.container
            .rm()
            .await
            .map_err(ContainerFixtureError::Container)
    }
}
async fn start_role_nats(
    config: String,
) -> Result<ContainerAsync<GenericImage>, ContainerFixtureError> {
    let image = GenericImage::new(NATS_IMAGE, NATS_TAG)
        .with_exposed_port(NATS_PORT.tcp())
        .with_wait_for(WaitFor::message_on_either_std("Server is ready"))
        .with_copy_to("/etc/nats/nats.conf", config.into_bytes())
        .with_cmd(["-c", "/etc/nats/nats.conf"]);
    loopback_request(image, NATS_PORT.tcp())
        .start()
        .await
        .map_err(ContainerFixtureError::Container)
}

impl fmt::Debug for NatsRoleFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsRoleFixture")
            .field("subject_prefix", &self.subject_prefix)
            .field("credentials", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Container fixture construction or cleanup failed.
#[derive(Debug, Error)]
pub enum ContainerFixtureError {
    /// Docker or Testcontainers could not complete the requested lifecycle step.
    #[error("test container lifecycle failed")]
    Container(#[source] testcontainers::TestcontainersError),
    /// The private endpoint could not be represented as a URL.
    #[error("test container endpoint URL is invalid")]
    Url(#[source] url::ParseError),
    /// Generated credentials could not be applied to the URL.
    #[error("test container endpoint credentials are invalid")]
    Credentials,
}

fn loopback_request<I: Image>(
    image: ContainerRequest<I>,
    port: ContainerPort,
) -> ContainerRequest<I> {
    image
        .with_mapped_port(0, port)
        .with_startup_timeout(STARTUP_TIMEOUT)
        .with_host_config_modifier(|host_config| {
            if let Some(port_bindings) = host_config.port_bindings.as_mut() {
                for bindings in port_bindings.values_mut().flatten() {
                    for binding in bindings {
                        binding.host_ip = Some("127.0.0.1".to_owned());
                    }
                }
            }
        })
}

async fn authenticated_url(
    container: &ContainerAsync<GenericImage>,
    internal_port: u16,
    scheme: &str,
    username: &str,
    password: &str,
    path: &str,
) -> Result<SecretString, ContainerFixtureError> {
    let host = container
        .get_host()
        .await
        .map_err(ContainerFixtureError::Container)?;
    let port = container
        .get_host_port_ipv4(internal_port.tcp())
        .await
        .map_err(ContainerFixtureError::Container)?;
    let mut url =
        Url::parse(&format!("{scheme}://localhost")).map_err(ContainerFixtureError::Url)?;
    url.set_host(Some(&host.to_string()))
        .map_err(ContainerFixtureError::Url)?;
    url.set_port(Some(port))
        .map_err(|()| ContainerFixtureError::Credentials)?;
    url.set_username(username)
        .map_err(|()| ContainerFixtureError::Credentials)?;
    url.set_password(Some(password))
        .map_err(|()| ContainerFixtureError::Credentials)?;
    url.set_path(path);
    Ok(SecretString::from(url.to_string()))
}

fn next_suffix() -> u64 {
    NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rsk_config::ExposeSecret as _;
    use sqlx::postgres::PgPoolOptions;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
        time,
    };

    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    #[tokio::test]
    async fn postgres_container_uses_random_loopback_port_and_unique_identity() -> TestResult {
        let fixture = PostgresFixture::start().await?;
        let url = Url::parse(fixture.database_url().expose_secret())?;
        assert_eq!(url.scheme(), "postgres");
        assert_ne!(url.port(), Some(POSTGRES_PORT));
        assert!(url.host_str().is_some_and(is_loopback));
        assert_eq!(url.path().trim_start_matches('/'), fixture.database());
        let pool = time::timeout(
            Duration::from_secs(5),
            PgPoolOptions::new()
                .max_connections(1)
                .connect(fixture.database_url().expose_secret()),
        )
        .await??;
        let value = sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&pool)
            .await?;
        assert_eq!(value, 1);
        pool.close().await;
        fixture.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    async fn redis_container_requires_authentication_and_is_namespaced() -> TestResult {
        let fixture = RedisFixture::start().await?;
        let url = Url::parse(fixture.redis_url().expose_secret())?;
        assert!(url.host_str().is_some_and(is_loopback));
        assert!(fixture.namespace().starts_with("rsk:"));
        let host = url.host_str().ok_or("missing host")?;
        let port = url.port().ok_or("missing port")?;
        let password = url.password().ok_or("missing password")?;
        let mut stream =
            time::timeout(Duration::from_secs(2), TcpStream::connect((host, port))).await??;
        let auth = format!(
            "*2\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n",
            password.len(),
            password
        );
        stream.write_all(auth.as_bytes()).await?;
        stream.write_all(b"*1\r\n$4\r\nPING\r\n").await?;
        let mut response = [0_u8; 64];
        let read = time::timeout(Duration::from_secs(2), stream.read(&mut response)).await??;
        let response = std::str::from_utf8(&response[..read])?;
        assert!(response.contains("+OK\r\n"));
        assert!(response.contains("+PONG\r\n"));
        fixture.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    async fn nats_container_requires_authentication_and_enables_jetstream() -> TestResult {
        let fixture = NatsFixture::start().await?;
        let url = Url::parse(fixture.nats_url().expose_secret())?;
        assert!(url.host_str().is_some_and(is_loopback));
        assert!(fixture.subject_prefix().starts_with("rsk.test."));
        let host = url.host_str().ok_or("missing host")?;
        let port = url.port().ok_or("missing port")?;
        let username = url.username();
        let password = url.password().ok_or("missing password")?;
        let mut stream =
            time::timeout(Duration::from_secs(2), TcpStream::connect((host, port))).await??;
        let mut info = [0_u8; 2048];
        let read = time::timeout(Duration::from_secs(2), stream.read(&mut info)).await??;
        let info = std::str::from_utf8(&info[..read])?;
        assert!(info.starts_with("INFO "));
        assert!(info.contains("\"jetstream\":true"));
        let connect =
            format!("CONNECT {{\"user\":\"{username}\",\"pass\":\"{password}\"}}\r\nPING\r\n");
        stream.write_all(connect.as_bytes()).await?;
        let mut response = [0_u8; 256];
        let read = time::timeout(Duration::from_secs(2), stream.read(&mut response)).await??;
        let response = std::str::from_utf8(&response[..read])?;
        assert!(response.contains("PONG\r\n"));
        fixture.cleanup().await?;
        Ok(())
    }

    fn is_loopback(host: &str) -> bool {
        host.parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
            || host == "localhost"
    }
}
