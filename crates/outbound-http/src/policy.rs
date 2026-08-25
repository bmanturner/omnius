use hickory_resolver::{TokioResolver, config::LookupIpStrategy};
use std::{
    collections::HashSet,
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use reqwest::{
    Url,
    dns::{Addrs, Name, Resolve, Resolving},
};
use serde::Deserialize;
use thiserror::Error;

use crate::{ConfigError, OutboundHttpError, REDACTED};

const MAX_URL_BYTES: usize = 8 * 1024;
const MAX_ALLOWED_HTTPS_PORTS: usize = 16;
const MAX_CONFIGURED_DENY_CIDRS: usize = 64;
const MAX_CIDR_BYTES: usize = 64;
const MAX_DNS_ANSWERS: usize = 64;
const MAX_DNS_TIMEOUT: Duration = Duration::from_secs(10);

/// Strict, bounded URL-admission configuration.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct OutboundUrlPolicyConfig {
    /// HTTPS destination ports accepted by the policy.
    pub allowed_https_ports: Vec<u16>,
    /// Allows HTTP only for literal loopback IP URLs.
    ///
    /// This is intended exclusively for explicitly configured development and test fixtures.
    pub allow_development_loopback_http: bool,
    /// Deployment-internal CIDRs denied in addition to fixed special-use ranges.
    pub deny_cidrs: Vec<String>,
    /// Hard deadline for each DNS lookup.
    #[serde(with = "humantime_serde")]
    pub dns_timeout: Duration,
    /// Maximum unique addresses accepted from one DNS lookup.
    pub max_dns_answers: usize,
}

impl Default for OutboundUrlPolicyConfig {
    fn default() -> Self {
        Self {
            allowed_https_ports: vec![443],
            allow_development_loopback_http: false,
            deny_cidrs: Vec::new(),
            dns_timeout: Duration::from_secs(2),
            max_dns_answers: 32,
        }
    }
}

impl fmt::Debug for OutboundUrlPolicyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundUrlPolicyConfig")
            .field("allowed_https_ports", &self.allowed_https_ports)
            .field(
                "allow_development_loopback_http",
                &self.allow_development_loopback_http,
            )
            .field("deny_cidr_count", &self.deny_cidrs.len())
            .field("dns_timeout", &self.dns_timeout)
            .field("max_dns_answers", &self.max_dns_answers)
            .finish()
    }
}

impl OutboundUrlPolicyConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.allowed_https_ports.is_empty()
            || self.allowed_https_ports.len() > MAX_ALLOWED_HTTPS_PORTS
            || self.allowed_https_ports.contains(&0)
        {
            return Err(ConfigError::HttpsPorts);
        }
        let mut ports = self.allowed_https_ports.clone();
        ports.sort_unstable();
        ports.dedup();
        if ports.len() != self.allowed_https_ports.len() {
            return Err(ConfigError::HttpsPorts);
        }
        if self.dns_timeout.is_zero() || self.dns_timeout > MAX_DNS_TIMEOUT {
            return Err(ConfigError::DnsTimeout);
        }
        if !(1..=MAX_DNS_ANSWERS).contains(&self.max_dns_answers) {
            return Err(ConfigError::DnsAnswers);
        }
        parse_deny_cidrs(&self.deny_cidrs).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DenyCidr {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl DenyCidr {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        if value.is_empty() || value.len() > MAX_CIDR_BYTES {
            return Err(ConfigError::DenyCidrs);
        }
        let (address, prefix) = value.split_once('/').ok_or(ConfigError::DenyCidrs)?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| ConfigError::DenyCidrs)?;
        let prefix = prefix.parse::<u32>().map_err(|_| ConfigError::DenyCidrs)?;
        match address {
            IpAddr::V4(address) if prefix <= 32 => {
                let mask = prefix_mask_v4(prefix);
                let network = u32::from(address);
                if network & mask != network {
                    return Err(ConfigError::DenyCidrs);
                }
                Ok(Self::V4 { network, mask })
            }
            IpAddr::V6(address) if prefix <= 128 => {
                let mask = prefix_mask_v6(prefix);
                let network = u128::from(address);
                if network & mask != network {
                    return Err(ConfigError::DenyCidrs);
                }
                Ok(Self::V6 { network, mask })
            }
            _ => Err(ConfigError::DenyCidrs),
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, mask }, IpAddr::V4(address)) => {
                u32::from(address) & mask == network
            }
            (Self::V6 { network, mask }, IpAddr::V6(address)) => {
                u128::from(address) & mask == network
            }
            _ => false,
        }
    }
}

fn prefix_mask_v4(prefix: u32) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_mask_v6(prefix: u32) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn parse_deny_cidrs(values: &[String]) -> Result<Vec<DenyCidr>, ConfigError> {
    if values.len() > MAX_CONFIGURED_DENY_CIDRS {
        return Err(ConfigError::DenyCidrs);
    }
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let cidr = DenyCidr::parse(value)?;
        if parsed.contains(&cidr) {
            return Err(ConfigError::DenyCidrs);
        }
        parsed.push(cidr);
    }
    Ok(parsed)
}

/// Value-free DNS resolution failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("outbound DNS resolution failed")]
pub struct ResolverError;

/// Boxed future returned by [`Resolver`].
pub type ResolverFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, ResolverError>> + Send + 'a>>;

/// Deterministic seam for complete DNS answer sets.
///
/// Implementations must return every address for `host`; callers reject the whole set when any
/// address is forbidden. Errors and empty sets fail closed.
pub trait Resolver: Send + Sync {
    /// Resolves one normalized host name.
    fn resolve<'a>(&'a self, host: &'a str) -> ResolverFuture<'a>;
}

/// Cancellable async system DNS resolver.
#[derive(Clone)]
pub struct SystemResolver {
    inner: TokioResolver,
}

impl SystemResolver {
    /// Builds a resolver from the operating system DNS configuration snapshot.
    ///
    /// # Errors
    ///
    /// Returns a value-free error when system DNS configuration or resolver construction fails.
    pub fn new() -> Result<Self, ResolverError> {
        let mut builder = TokioResolver::builder_tokio().map_err(|_| ResolverError)?;
        let options = builder.options_mut();
        options.timeout = MAX_DNS_TIMEOUT;
        options.attempts = 0;
        options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        let inner = builder.build().map_err(|_| ResolverError)?;
        Ok(Self { inner })
    }
}

impl fmt::Debug for SystemResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemResolver")
            .field("inner", &REDACTED)
            .finish()
    }
}

impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> ResolverFuture<'a> {
        let resolver = self.inner.clone();
        let fqdn = format!("{host}.");
        Box::pin(async move {
            let lookup = resolver.lookup_ip(fqdn).await.map_err(|_| ResolverError)?;
            let mut seen = HashSet::with_capacity(MAX_DNS_ANSWERS);
            let mut addresses = Vec::new();
            for address in lookup.iter() {
                if seen.insert(address) {
                    if addresses.len() == MAX_DNS_ANSWERS {
                        return Err(ResolverError);
                    }
                    addresses.push(address);
                }
            }
            if addresses.is_empty() {
                Err(ResolverError)
            } else {
                Ok(addresses)
            }
        })
    }
}

/// Opaque URL that passed complete admission under an [`OutboundUrlPolicy`].
pub struct ApprovedUrl {
    url: Url,
    policy_identity: Arc<()>,
}

impl ApprovedUrl {
    /// Borrows the normalized approved URL for provider SDK boundaries.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.url
    }

    pub(crate) fn belongs_to(&self, policy: &OutboundUrlPolicy) -> bool {
        Arc::ptr_eq(&self.policy_identity, &policy.identity)
    }
}

impl fmt::Debug for ApprovedUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ApprovedUrl")
            .field(&REDACTED)
            .finish()
    }
}

#[derive(Debug)]
struct AddressPolicy {
    deny_cidrs: Vec<DenyCidr>,
}

impl AddressPolicy {
    fn is_configured_denied(&self, address: IpAddr) -> bool {
        self.deny_cidrs.iter().any(|cidr| cidr.contains(address))
    }

    fn allows_public(&self, address: IpAddr) -> bool {
        is_public_ip(address) && !self.is_configured_denied(address)
    }

    fn allows_development_loopback(&self, address: IpAddr) -> bool {
        address.is_loopback() && !self.is_configured_denied(address)
    }
}

/// Central URL admission policy with a complete-answer resolver.
#[derive(Clone)]
pub struct OutboundUrlPolicy {
    config: OutboundUrlPolicyConfig,
    resolver: Arc<dyn Resolver>,
    address_policy: Arc<AddressPolicy>,
    identity: Arc<()>,
}

impl OutboundUrlPolicy {
    /// Creates a policy using the bounded system resolver.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the policy configuration or system resolver is unavailable.
    pub fn new(config: OutboundUrlPolicyConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        let resolver = SystemResolver::new().map_err(|_| ConfigError::SystemResolver)?;
        Self::with_resolver(config, Arc::new(resolver))
    }

    /// Creates a policy with an injected deterministic resolver.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the policy configuration is invalid.
    pub fn with_resolver(
        config: OutboundUrlPolicyConfig,
        resolver: Arc<dyn Resolver>,
    ) -> Result<Self, ConfigError> {
        config.validate()?;
        let address_policy = Arc::new(AddressPolicy {
            deny_cidrs: parse_deny_cidrs(&config.deny_cidrs)?,
        });
        Ok(Self {
            config,
            resolver,
            identity: Arc::new(()),
            address_policy,
        })
    }

    async fn resolve_hostname(&self, host: &str) -> Result<Vec<IpAddr>, OutboundHttpError> {
        let addresses = tokio::time::timeout(self.config.dns_timeout, self.resolver.resolve(host))
            .await
            .map_err(|_| OutboundHttpError::Resolution)?
            .map_err(|_| OutboundHttpError::Resolution)?;
        bounded_unique_answers(addresses, self.config.max_dns_answers)
            .map_err(|_| OutboundHttpError::Resolution)
    }

    pub(crate) fn validating_resolver(&self, resolver: Arc<dyn Resolver>) -> ValidatingResolver {
        ValidatingResolver {
            resolver,
            address_policy: Arc::clone(&self.address_policy),
            dns_timeout: self.config.dns_timeout,
            max_dns_answers: self.config.max_dns_answers,
        }
    }

    /// Normalizes and approves one URL after checking its complete resolved address set.
    ///
    /// # Errors
    ///
    /// Fails closed for invalid syntax or authority, credentials, fragments, schemes, ports,
    /// DNS errors, empty answers, mixed public/private answers, and every special-use address.
    pub async fn approve(&self, mut url: Url) -> Result<ApprovedUrl, OutboundHttpError> {
        if url.as_str().len() > MAX_URL_BYTES
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(OutboundHttpError::DestinationRejected);
        }
        let original_host = url
            .host_str()
            .ok_or(OutboundHttpError::DestinationRejected)?;
        if original_host.contains('%') {
            return Err(OutboundHttpError::DestinationRejected);
        }
        let normalized_host = original_host.trim_end_matches('.').to_owned();
        if normalized_host.is_empty() || normalized_host.len() > 253 {
            return Err(OutboundHttpError::DestinationRejected);
        }
        if normalized_host.len() != original_host.len() {
            url.set_host(Some(&normalized_host))
                .map_err(|_| OutboundHttpError::DestinationRejected)?;
        }
        let port = url
            .port_or_known_default()
            .ok_or(OutboundHttpError::DestinationRejected)?;
        let is_development_http = match url.scheme() {
            "https" if self.config.allowed_https_ports.contains(&port) => false,
            "http" if self.config.allow_development_loopback_http => true,
            _ => return Err(OutboundHttpError::DestinationRejected),
        };
        let host = url
            .host_str()
            .ok_or(OutboundHttpError::DestinationRejected)?;
        let address_host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        let literal = address_host.parse::<IpAddr>().ok();
        let addresses = match (is_development_http, literal) {
            (_, Some(address)) => vec![address],
            (true, None) => return Err(OutboundHttpError::DestinationRejected),
            (false, None) => self.resolve_hostname(host).await?,
        };
        let allowed = if is_development_http {
            addresses
                .iter()
                .copied()
                .all(|address| self.address_policy.allows_development_loopback(address))
        } else {
            addresses
                .iter()
                .copied()
                .all(|address| self.address_policy.allows_public(address))
        };
        if addresses.is_empty() || !allowed {
            return Err(OutboundHttpError::DestinationRejected);
        }
        Ok(ApprovedUrl {
            url,
            policy_identity: Arc::clone(&self.identity),
        })
    }
}

impl fmt::Debug for OutboundUrlPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundUrlPolicy")
            .field("config", &self.config)
            .field("resolver", &REDACTED)
            .field(
                "address_policy_deny_count",
                &self.address_policy.deny_cidrs.len(),
            )
            .field("identity", &REDACTED)
            .finish()
    }
}

fn ipv4_in(address: Ipv4Addr, network: [u8; 4], prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(address) & mask == u32::from(Ipv4Addr::from(network)) & mask
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    const SPECIAL: [([u8; 4], u32); 17] = [
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 31, 196, 0], 24),
        ([192, 52, 193, 0], 24),
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([192, 175, 48, 0], 24),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 3),
    ];
    !SPECIAL
        .iter()
        .any(|(network, prefix)| ipv4_in(address, *network, *prefix))
}

fn ipv6_in(address: Ipv6Addr, network: [u8; 16], prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    u128::from(address) & mask == u128::from(Ipv6Addr::from(network)) & mask
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    const SPECIAL: [([u8; 16], u32); 13] = [
        ([0; 16], 96),
        (
            [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            96,
        ),
        (
            [0, 0x64, 0xff, 0x9b, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            48,
        ),
        ([0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 64),
        ([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 23),
        (
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
        ),
        ([0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 16),
        ([0x3f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 20),
        ([0x5f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 16),
        ([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7),
        ([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
        ([0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
        ([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8),
    ];
    let global_unicast = ipv6_in(
        address,
        [0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        3,
    );
    global_unicast
        && !SPECIAL
            .iter()
            .any(|(network, prefix)| ipv6_in(address, *network, *prefix))
}

pub(crate) fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn bounded_unique_answers(
    mut addresses: Vec<IpAddr>,
    max_unique: usize,
) -> Result<Vec<IpAddr>, ResolverError> {
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() || addresses.len() > max_unique {
        Err(ResolverError)
    } else {
        Ok(addresses)
    }
}

#[derive(Clone)]
pub(crate) struct ValidatingResolver {
    resolver: Arc<dyn Resolver>,
    address_policy: Arc<AddressPolicy>,
    dns_timeout: Duration,
    max_dns_answers: usize,
}

impl Resolve for ValidatingResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = Arc::clone(&self.resolver);
        let address_policy = Arc::clone(&self.address_policy);
        let dns_timeout = self.dns_timeout;
        let max_dns_answers = self.max_dns_answers;
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addresses = tokio::time::timeout(dns_timeout, resolver.resolve(&host))
                .await
                .map_err(|_| Box::new(ResolverError) as Box<dyn std::error::Error + Send + Sync>)?
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            let addresses = bounded_unique_answers(addresses, max_dns_answers)
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            if !addresses
                .iter()
                .copied()
                .all(|address| address_policy.allows_public(address))
            {
                return Err(Box::new(ResolverError) as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(
                addresses
                    .into_iter()
                    .map(|address| SocketAddr::new(address, 0)),
            ) as Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_use_ipv4_is_rejected() {
        for address in [
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(198, 51, 100, 1),
            Ipv4Addr::new(203, 0, 113, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
        ] {
            assert!(!is_public_ipv4(address), "{address}");
        }
        assert!(is_public_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn special_use_ipv6_is_rejected() -> Result<(), std::net::AddrParseError> {
        for address in [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::LOCALHOST,
            "::ffff:8.8.8.8".parse()?,
            "64:ff9b::808:808".parse()?,
            "100::1".parse()?,
            "2001:db8::1".parse()?,
            "2002:0808:0808::1".parse()?,
            "3fff::1".parse()?,
            "fc00::1".parse()?,
            "fe80::1".parse()?,
            "ff02::1".parse()?,
        ] {
            assert!(!is_public_ipv6(address), "{address}");
        }
        let public = "2606:4700:4700::1111".parse()?;
        assert!(is_public_ipv6(public));
        Ok(())
    }
}
