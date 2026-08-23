//! Deterministic, hermetic fixtures for service and module tests.
//!
//! This crate is tooling only. Production compositions use the corresponding
//! `rsk-core` and `rsk-config` contracts directly.

mod clock;
mod config;
mod containers;
mod ids;
mod provider_fake;
mod random;
mod server;

pub use clock::{TestClock, TestClockError};
pub use config::TestConfigBuilder;
pub use containers::{ContainerFixtureError, NatsFixture, PostgresFixture, RedisFixture};
pub use ids::{TestIdError, TestIds};
pub use provider_fake::{
    ProviderFake, ProviderFakeError, ProviderMock, ProviderMockGuard, ProviderRequest,
    ProviderResponse, provider_matchers,
};
pub use random::DeterministicRandom;
pub use server::{TestClient, TestServer, TestServerError};
