//! Deterministic, hermetic fixtures for service and module tests.
//!
//! This crate is tooling only. Production compositions use the corresponding
//! `omnius-core` and `omnius-config` contracts directly.

mod clock;
mod config;
mod containers;
mod ids;
mod profile;
mod provider_fake;
mod random;
mod server;

pub use clock::{TestClock, TestClockError};
pub use config::TestConfigBuilder;
pub use containers::{
    ContainerFixtureError, MinioFixture, NatsCoreFanoutRoleFixture, NatsFixture, NatsRoleFixture,
    PostgresFixture, RedisFixture,
};
pub use ids::{TestIdError, TestIds};
pub use profile::{
    CleanDirectory, ProfileCommand, ProfileGenerationHarness, ProfileHarnessError, TEST_PROFILE_ENV,
};
pub use provider_fake::{
    ProviderFake, ProviderFakeError, ProviderMock, ProviderMockGuard, ProviderRequest,
    ProviderResponse, provider_matchers,
};
pub use random::DeterministicRandom;
pub use omnius_auth_core::testing::{
    PrincipalMismatch, TestPrincipalFactory, ensure_principal_matches,
};
pub use server::{TestClient, TestServer, TestServerError};
