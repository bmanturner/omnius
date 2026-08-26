use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use rsk_auth_core::TenantId;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::{Uuid, Variant, Version};

const MAX_PROVIDER_ID_BYTES: usize = 64;
const MAX_PROVIDER_OBJECT_ID_BYTES: usize = 255;
const MAX_APPLICATION_KEY_BYTES: usize = 128;
const MAX_FACT_KEY_BYTES: usize = 128;
const MAX_FACT_TEXT_BYTES: usize = 255;
const MAX_STATE_FACTS: usize = 64;
const MAX_STATE_FACT_JSON_BYTES: usize = 32 * 1024;
const MAX_SUBSCRIPTIONS: usize = 64;
const MAX_INVOICES: usize = 128;
const MAX_PLAN_ENTITLEMENTS: usize = 128;

/// A bounded billing value failed validation. The rejected value is never retained.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BillingValueError {
    /// A string value was empty, oversized, or outside its portable grammar.
    #[error("billing identifier is invalid")]
    InvalidIdentifier,
    /// A provider revision or event sequence exceeded PostgreSQL's signed range.
    #[error("billing provider fence is invalid")]
    InvalidFence,
    /// A collection exceeded its fixed cardinality or contained duplicate identities.
    #[error("billing collection is invalid")]
    InvalidCollection,
    /// A timestamp relationship or numeric fact was incoherent.
    #[error("billing state is incoherent")]
    IncoherentState,
}

fn portable_identifier(value: &str, max: usize, lowercase: bool) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if value.len() > max
        || if lowercase {
            !first.is_ascii_lowercase()
        } else {
            !first.is_ascii_alphanumeric()
        }
    {
        return false;
    }
    bytes.all(|byte| {
        (if lowercase {
            byte.is_ascii_lowercase()
        } else {
            byte.is_ascii_alphanumeric()
        }) || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
    })
}

macro_rules! bounded_string {
    ($name:ident, $max:expr, $lowercase:expr, $doc:literal, safe_debug) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Validates and owns a value.
            ///
            /// # Errors
            ///
            /// Returns [`BillingValueError::InvalidIdentifier`] for invalid input.
            pub fn parse(value: impl Into<String>) -> Result<Self, BillingValueError> {
                let value = value.into();
                if portable_identifier(&value, $max, $lowercase) {
                    Ok(Self(value))
                } else {
                    Err(BillingValueError::InvalidIdentifier)
                }
            }

            /// Borrows the persistence representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = BillingValueError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }
    };
    ($name:ident, $max:expr, $lowercase:expr, $doc:literal, redacted_debug) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Validates and owns a value.
            ///
            /// # Errors
            ///
            /// Returns [`BillingValueError::InvalidIdentifier`] for invalid input.
            pub fn parse(value: impl Into<String>) -> Result<Self, BillingValueError> {
                let value = value.into();
                if portable_identifier(&value, $max, $lowercase) {
                    Ok(Self(value))
                } else {
                    Err(BillingValueError::InvalidIdentifier)
                }
            }

            /// Borrows the persistence representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("value", &"[REDACTED]")
                    .field("byte_len", &self.0.len())
                    .finish_non_exhaustive()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = BillingValueError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }
    };
}

bounded_string!(
    ProviderId,
    MAX_PROVIDER_ID_BYTES,
    true,
    "A low-cardinality provider adapter identity.",
    safe_debug
);
bounded_string!(
    ProviderObjectId,
    MAX_PROVIDER_OBJECT_ID_BYTES,
    false,
    "A provider-owned customer, subscription, price, invoice, or usage identity.",
    redacted_debug
);
bounded_string!(
    ProviderEventId,
    MAX_PROVIDER_OBJECT_ID_BYTES,
    false,
    "A provider-owned event identity already authenticated by the inbound webhook adapter.",
    redacted_debug
);
bounded_string!(
    PlanKey,
    MAX_APPLICATION_KEY_BYTES,
    true,
    "An application-owned product plan key.",
    safe_debug
);
bounded_string!(
    EntitlementKey,
    MAX_APPLICATION_KEY_BYTES,
    true,
    "An application-owned entitlement key.",
    safe_debug
);
bounded_string!(
    MeterKey,
    MAX_APPLICATION_KEY_BYTES,
    true,
    "An application-owned usage meter key.",
    safe_debug
);
bounded_string!(
    UsageIdempotencyKey,
    MAX_PROVIDER_OBJECT_ID_BYTES,
    false,
    "A tenant-and-meter-scoped usage idempotency key.",
    redacted_debug
);
bounded_string!(
    RepairIdempotencyKey,
    MAX_PROVIDER_OBJECT_ID_BYTES,
    false,
    "A tenant-and-provider-scoped repair request idempotency key.",
    redacted_debug
);
bounded_string!(
    ProviderStateKey,
    MAX_FACT_KEY_BYTES,
    true,
    "A provider-specific, namespaced state-fact key.",
    safe_debug
);
bounded_string!(
    ProviderStateText,
    MAX_FACT_TEXT_BYTES,
    false,
    "A bounded provider-specific state value whose diagnostics are redacted.",
    redacted_debug
);

macro_rules! uuid_v7_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a fresh time-ordered identity.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Restores a `UUIDv7` identity.
            ///
            /// # Errors
            ///
            /// Returns [`BillingValueError::InvalidIdentifier`] for any other UUID kind.
            pub fn from_uuid(value: Uuid) -> Result<Self, BillingValueError> {
                if value.get_version() == Some(Version::SortRand)
                    && value.get_variant() == Variant::RFC4122
                {
                    Ok(Self(value))
                } else {
                    Err(BillingValueError::InvalidIdentifier)
                }
            }

            /// Returns the database representation.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::from_uuid(Uuid::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }
    };
}

uuid_v7_id!(
    ReconciliationTaskId,
    "The durable identity of one reconciliation or repair task."
);
uuid_v7_id!(UsageRecordId, "The durable identity of one usage record.");

/// A provider-defined event ordering fence normalized by an exact adapter.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProviderEventSequence(i64);

impl ProviderEventSequence {
    /// Creates a sequence within PostgreSQL's non-negative signed range.
    ///
    /// # Errors
    ///
    /// Returns [`BillingValueError::InvalidFence`] when the value is too large.
    pub fn new(value: u64) -> Result<Self, BillingValueError> {
        i64::try_from(value)
            .map(Self)
            .map_err(|_| BillingValueError::InvalidFence)
    }

    /// Returns the database representation.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// A provider API snapshot revision whose ordering semantics belong to its adapter.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProviderRevision(i64);

impl ProviderRevision {
    /// Creates a revision within PostgreSQL's non-negative signed range.
    ///
    /// # Errors
    ///
    /// Returns [`BillingValueError::InvalidFence`] when the value is too large.
    pub fn new(value: u64) -> Result<Self, BillingValueError> {
        i64::try_from(value)
            .map(Self)
            .map_err(|_| BillingValueError::InvalidFence)
    }

    /// Returns the database representation.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// A typed provider-specific state fact. Values are never included in diagnostics.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ProviderStateValue {
    /// Boolean provider fact.
    Boolean(bool),
    /// Signed provider fact.
    Integer(i64),
    /// Provider identifier or status token.
    Text(ProviderStateText),
    /// UTC provider timestamp.
    Timestamp(OffsetDateTime),
}

impl fmt::Debug for ProviderStateValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderStateValue([REDACTED])")
    }
}

/// A bounded, duplicate-free map of provider-specific facts.
#[derive(Clone, Default, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProviderStateFacts(BTreeMap<ProviderStateKey, ProviderStateValue>);

impl ProviderStateFacts {
    /// Creates at most 64 uniquely named facts.
    ///
    /// # Errors
    ///
    /// Returns [`BillingValueError::InvalidCollection`] for overflow, duplicate keys, or encoded
    /// JSON beyond 32 KiB.
    pub fn new(
        facts: impl IntoIterator<Item = (ProviderStateKey, ProviderStateValue)>,
    ) -> Result<Self, BillingValueError> {
        let mut values = BTreeMap::new();
        for (index, (key, value)) in facts.into_iter().enumerate() {
            if index >= MAX_STATE_FACTS || values.insert(key, value).is_some() {
                return Err(BillingValueError::InvalidCollection);
            }
        }
        if serde_json::to_vec(&values)
            .map_or(true, |encoded| encoded.len() > MAX_STATE_FACT_JSON_BYTES)
        {
            return Err(BillingValueError::InvalidCollection);
        }
        Ok(Self(values))
    }

    /// Returns the number of provider facts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether there are no provider facts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for ProviderStateFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderStateFacts")
            .field("fact_count", &self.len())
            .finish_non_exhaustive()
    }
}

/// Provider-normalized billing standing used only by application grace policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingStanding {
    /// Provider state is current and paid according to the adapter's exact semantics.
    InGoodStanding,
    /// Provider state is delinquent and may receive application grace.
    Delinquent,
    /// Provider state is not yet entitled.
    Pending,
    /// Provider state has ended.
    Ended,
}

/// Mirrored dunning facts retained independently from entitlement evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DunningFacts {
    started_at: OffsetDateTime,
    attempt_count: u16,
    next_attempt_at: Option<OffsetDateTime>,
}

impl DunningFacts {
    /// Builds coherent, bounded dunning facts.
    ///
    /// # Errors
    ///
    /// Returns [`BillingValueError::IncoherentState`] for more than 100 attempts or a next attempt
    /// before dunning began.
    pub fn new(
        started_at: OffsetDateTime,
        attempt_count: u16,
        next_attempt_at: Option<OffsetDateTime>,
    ) -> Result<Self, BillingValueError> {
        if attempt_count > 100 || next_attempt_at.is_some_and(|next| next < started_at) {
            return Err(BillingValueError::IncoherentState);
        }
        Ok(Self {
            started_at,
            attempt_count,
            next_attempt_at,
        })
    }

    /// Returns when provider dunning began.
    #[must_use]
    pub const fn started_at(self) -> OffsetDateTime {
        self.started_at
    }

    /// Returns the bounded attempt count.
    #[must_use]
    pub const fn attempt_count(self) -> u16 {
        self.attempt_count
    }

    /// Returns the provider's next attempt time when supplied.
    #[must_use]
    pub const fn next_attempt_at(self) -> Option<OffsetDateTime> {
        self.next_attempt_at
    }
}

/// One authoritative provider customer snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderCustomer {
    id: ProviderObjectId,
    state: ProviderStateFacts,
}

impl ProviderCustomer {
    /// Creates a customer mirror without interpreting provider facts.
    #[must_use]
    pub const fn new(id: ProviderObjectId, state: ProviderStateFacts) -> Self {
        Self { id, state }
    }

    /// Returns the provider customer identity.
    #[must_use]
    pub const fn id(&self) -> &ProviderObjectId {
        &self.id
    }

    /// Returns the exact bounded provider facts.
    #[must_use]
    pub const fn state(&self) -> &ProviderStateFacts {
        &self.state
    }
}

/// One authoritative provider subscription snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderSubscription {
    id: ProviderObjectId,
    customer_id: ProviderObjectId,
    price_id: ProviderObjectId,
    standing: BillingStanding,
    current_period_end: Option<OffsetDateTime>,
    dunning: Option<DunningFacts>,
    state: ProviderStateFacts,
}

impl ProviderSubscription {
    /// Creates a provider-preserving subscription mirror.
    ///
    /// # Errors
    ///
    /// Returns [`BillingValueError::IncoherentState`] unless exact delinquency state and dunning
    /// facts are present together.
    pub fn new(
        id: ProviderObjectId,
        customer_id: ProviderObjectId,
        price_id: ProviderObjectId,
        standing: BillingStanding,
        current_period_end: Option<OffsetDateTime>,
        dunning: Option<DunningFacts>,
        state: ProviderStateFacts,
    ) -> Result<Self, BillingValueError> {
        if matches!(standing, BillingStanding::Delinquent) != dunning.is_some() {
            return Err(BillingValueError::IncoherentState);
        }
        Ok(Self {
            id,
            customer_id,
            price_id,
            standing,
            current_period_end,
            dunning,
            state,
        })
    }

    /// Returns the provider subscription identity.
    #[must_use]
    pub const fn id(&self) -> &ProviderObjectId {
        &self.id
    }

    /// Returns the provider customer identity.
    #[must_use]
    pub const fn customer_id(&self) -> &ProviderObjectId {
        &self.customer_id
    }

    /// Returns the provider price identity, interpreted only through explicit application mapping.
    #[must_use]
    pub const fn price_id(&self) -> &ProviderObjectId {
        &self.price_id
    }

    /// Returns the exact-adapter billing standing.
    #[must_use]
    pub const fn standing(&self) -> BillingStanding {
        self.standing
    }

    /// Returns the current period boundary when the provider supplies one.
    #[must_use]
    pub const fn current_period_end(&self) -> Option<OffsetDateTime> {
        self.current_period_end
    }

    /// Returns provider dunning facts without applying grace policy.
    #[must_use]
    pub const fn dunning(&self) -> Option<DunningFacts> {
        self.dunning
    }

    /// Returns exact bounded provider state.
    #[must_use]
    pub const fn state(&self) -> &ProviderStateFacts {
        &self.state
    }
}

/// Three-letter uppercase ISO-style currency code retained as a provider fact.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct CurrencyCode([u8; 3]);

impl CurrencyCode {
    /// Parses three uppercase ASCII letters.
    ///
    /// # Errors
    ///
    /// Returns [`BillingValueError::InvalidIdentifier`] for any other value.
    pub fn parse(value: &str) -> Result<Self, BillingValueError> {
        let bytes = value.as_bytes();
        if bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_uppercase) {
            return Err(BillingValueError::InvalidIdentifier);
        }
        Ok(Self([bytes[0], bytes[1], bytes[2]]))
    }

    /// Returns the database representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

/// One authoritative provider invoice snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderInvoice {
    id: ProviderObjectId,
    customer_id: ProviderObjectId,
    amount_due_minor: u64,
    currency: CurrencyCode,
    due_at: Option<OffsetDateTime>,
    paid_at: Option<OffsetDateTime>,
    state: ProviderStateFacts,
}

impl ProviderInvoice {
    /// Creates a bounded invoice mirror.
    ///
    /// # Errors
    ///
    /// Returns [`BillingValueError::IncoherentState`] when the amount exceeds PostgreSQL `bigint`.
    pub fn new(
        id: ProviderObjectId,
        customer_id: ProviderObjectId,
        amount_due_minor: u64,
        currency: CurrencyCode,
        due_at: Option<OffsetDateTime>,
        paid_at: Option<OffsetDateTime>,
        state: ProviderStateFacts,
    ) -> Result<Self, BillingValueError> {
        if i64::try_from(amount_due_minor).is_err() {
            return Err(BillingValueError::IncoherentState);
        }
        Ok(Self {
            id,
            customer_id,
            amount_due_minor,
            currency,
            due_at,
            paid_at,
            state,
        })
    }

    /// Returns the provider invoice identity.
    #[must_use]
    pub const fn id(&self) -> &ProviderObjectId {
        &self.id
    }

    /// Returns the provider customer identity.
    #[must_use]
    pub const fn customer_id(&self) -> &ProviderObjectId {
        &self.customer_id
    }

    /// Returns minor currency units within PostgreSQL's signed range.
    #[must_use]
    pub const fn amount_due_minor(&self) -> u64 {
        self.amount_due_minor
    }

    /// Returns the invoice currency.
    #[must_use]
    pub const fn currency(&self) -> CurrencyCode {
        self.currency
    }

    /// Returns the due timestamp when supplied.
    #[must_use]
    pub const fn due_at(&self) -> Option<OffsetDateTime> {
        self.due_at
    }

    /// Returns the payment timestamp when supplied.
    #[must_use]
    pub const fn paid_at(&self) -> Option<OffsetDateTime> {
        self.paid_at
    }

    /// Returns exact bounded provider state.
    #[must_use]
    pub const fn state(&self) -> &ProviderStateFacts {
        &self.state
    }
}

/// A complete provider API snapshot authorized to replace local billing mirrors.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderSnapshot {
    tenant_id: TenantId,
    provider: ProviderId,
    revision: ProviderRevision,
    observed_at: OffsetDateTime,
    customer: ProviderCustomer,
    subscriptions: Vec<ProviderSubscription>,
    invoices: Vec<ProviderInvoice>,
}

impl ProviderSnapshot {
    /// Creates a bounded, internally coherent full snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`BillingValueError`] for oversized collections, duplicate provider identities, or
    /// child records belonging to another customer.
    pub fn new(
        tenant_id: TenantId,
        provider: ProviderId,
        revision: ProviderRevision,
        observed_at: OffsetDateTime,
        customer: ProviderCustomer,
        subscriptions: Vec<ProviderSubscription>,
        invoices: Vec<ProviderInvoice>,
    ) -> Result<Self, BillingValueError> {
        if subscriptions.len() > MAX_SUBSCRIPTIONS || invoices.len() > MAX_INVOICES {
            return Err(BillingValueError::InvalidCollection);
        }
        let mut subscriptions_seen = BTreeSet::new();
        for subscription in &subscriptions {
            if subscription.customer_id() != customer.id()
                || !subscriptions_seen.insert(subscription.id().as_str())
            {
                return Err(BillingValueError::InvalidCollection);
            }
        }
        let mut invoices_seen = BTreeSet::new();
        for invoice in &invoices {
            if invoice.customer_id() != customer.id()
                || !invoices_seen.insert(invoice.id().as_str())
            {
                return Err(BillingValueError::InvalidCollection);
            }
        }
        Ok(Self {
            tenant_id,
            provider,
            revision,
            observed_at,
            customer,
            subscriptions,
            invoices,
        })
    }

    /// Returns the canonical tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the exact provider adapter identity.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns the provider API revision fence.
    #[must_use]
    pub const fn revision(&self) -> ProviderRevision {
        self.revision
    }

    /// Returns when the authoritative API read completed.
    #[must_use]
    pub const fn observed_at(&self) -> OffsetDateTime {
        self.observed_at
    }

    /// Returns the customer mirror.
    #[must_use]
    pub const fn customer(&self) -> &ProviderCustomer {
        &self.customer
    }

    /// Returns the bounded subscription mirror set.
    #[must_use]
    pub fn subscriptions(&self) -> &[ProviderSubscription] {
        &self.subscriptions
    }

    /// Returns the bounded invoice mirror set.
    #[must_use]
    pub fn invoices(&self) -> &[ProviderInvoice] {
        &self.invoices
    }
}

/// A verified provider event reduced by an exact provider adapter to ordering facts only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderEvent {
    tenant_id: TenantId,
    event_id: ProviderEventId,
    sequence: ProviderEventSequence,
}

impl ProviderEvent {
    /// Creates a provider event fence.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        event_id: ProviderEventId,
        sequence: ProviderEventSequence,
    ) -> Self {
        Self {
            tenant_id,
            event_id,
            sequence,
        }
    }

    /// Returns the canonical tenant decoded from authenticated provider scope and payload.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the provider event identity.
    #[must_use]
    pub const fn event_id(&self) -> &ProviderEventId {
        &self.event_id
    }

    /// Returns the provider-defined monotonic event sequence.
    #[must_use]
    pub const fn sequence(&self) -> ProviderEventSequence {
        self.sequence
    }
}

/// Application-owned entitlement value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum EntitlementValue {
    /// Boolean capability grant.
    Boolean(bool),
    /// Non-zero quota or capacity ceiling.
    Limit(u64),
}

impl EntitlementValue {
    pub(crate) fn kind(self) -> &'static str {
        match self {
            Self::Boolean(_) => "boolean",
            Self::Limit(_) => "limit",
        }
    }

    pub(crate) fn boolean(self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(value),
            Self::Limit(_) => None,
        }
    }

    pub(crate) fn limit(self) -> Option<i64> {
        match self {
            Self::Boolean(_) => None,
            Self::Limit(value) => i64::try_from(value).ok(),
        }
    }
}

/// One application-owned entitlement grant within a plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EntitlementGrant {
    key: EntitlementKey,
    value: EntitlementValue,
}

impl EntitlementGrant {
    /// Creates a grant and rejects zero or oversized limits.
    ///
    /// # Errors
    ///
    /// Returns [`BillingValueError::IncoherentState`] for a limit outside `1..=i64::MAX`.
    pub fn new(key: EntitlementKey, value: EntitlementValue) -> Result<Self, BillingValueError> {
        if matches!(value, EntitlementValue::Limit(0))
            || value.limit().is_none() && matches!(value, EntitlementValue::Limit(_))
        {
            return Err(BillingValueError::IncoherentState);
        }
        Ok(Self { key, value })
    }

    /// Returns the entitlement key.
    #[must_use]
    pub const fn key(&self) -> &EntitlementKey {
        &self.key
    }

    /// Returns the application grant value.
    #[must_use]
    pub const fn value(&self) -> EntitlementValue {
        self.value
    }
}

/// An application-owned product plan definition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlanDefinition {
    key: PlanKey,
    enabled: bool,
    entitlements: Vec<EntitlementGrant>,
}

impl PlanDefinition {
    /// Creates a bounded plan with unique entitlement keys.
    ///
    /// # Errors
    ///
    /// Returns [`BillingValueError::InvalidCollection`] for duplicate or more than 128 grants.
    pub fn new(
        key: PlanKey,
        enabled: bool,
        entitlements: Vec<EntitlementGrant>,
    ) -> Result<Self, BillingValueError> {
        if entitlements.len() > MAX_PLAN_ENTITLEMENTS {
            return Err(BillingValueError::InvalidCollection);
        }
        let mut keys = BTreeSet::new();
        for entitlement in &entitlements {
            if !keys.insert(entitlement.key().as_str()) {
                return Err(BillingValueError::InvalidCollection);
            }
        }
        Ok(Self {
            key,
            enabled,
            entitlements,
        })
    }

    /// Returns the plan key.
    #[must_use]
    pub const fn key(&self) -> &PlanKey {
        &self.key
    }

    /// Returns whether the application currently offers this plan.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the plan's grants.
    #[must_use]
    pub fn entitlements(&self) -> &[EntitlementGrant] {
        &self.entitlements
    }
}

/// Explicit mapping from an exact provider price identity to an application plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPriceMapping {
    provider: ProviderId,
    price_id: ProviderObjectId,
    plan_key: PlanKey,
}

impl ProviderPriceMapping {
    /// Creates a provider-specific mapping without interpreting the provider price.
    #[must_use]
    pub const fn new(provider: ProviderId, price_id: ProviderObjectId, plan_key: PlanKey) -> Self {
        Self {
            provider,
            price_id,
            plan_key,
        }
    }

    /// Returns the provider adapter identity.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns the provider price identity.
    #[must_use]
    pub const fn price_id(&self) -> &ProviderObjectId {
        &self.price_id
    }

    /// Returns the mapped application plan.
    #[must_use]
    pub const fn plan_key(&self) -> &PlanKey {
        &self.plan_key
    }
}

/// One idempotent usage fact proposed for durable local recording.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewUsageRecord {
    meter: MeterKey,
    idempotency_key: UsageIdempotencyKey,
    quantity: u64,
    occurred_at: OffsetDateTime,
}

impl NewUsageRecord {
    /// Creates a positive usage fact bounded by PostgreSQL `bigint`.
    ///
    /// # Errors
    ///
    /// Returns [`BillingValueError::IncoherentState`] for zero or oversized quantities.
    pub fn new(
        meter: MeterKey,
        idempotency_key: UsageIdempotencyKey,
        quantity: u64,
        occurred_at: OffsetDateTime,
    ) -> Result<Self, BillingValueError> {
        if quantity == 0 || i64::try_from(quantity).is_err() {
            return Err(BillingValueError::IncoherentState);
        }
        Ok(Self {
            meter,
            idempotency_key,
            quantity,
            occurred_at,
        })
    }

    /// Returns the meter key.
    #[must_use]
    pub const fn meter(&self) -> &MeterKey {
        &self.meter
    }

    /// Returns the usage idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> &UsageIdempotencyKey {
        &self.idempotency_key
    }

    /// Returns the positive quantity.
    #[must_use]
    pub const fn quantity(&self) -> u64 {
        self.quantity
    }

    /// Returns when usage occurred.
    #[must_use]
    pub const fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }
}

/// Effective local entitlement produced only by reconciled provider state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveEntitlement {
    key: EntitlementKey,
    value: EntitlementValue,
    provider: ProviderId,
    revision: ProviderRevision,
    valid_until: Option<OffsetDateTime>,
    in_grace: bool,
}

impl EffectiveEntitlement {
    pub(crate) fn restored(
        key: EntitlementKey,
        value: EntitlementValue,
        provider: ProviderId,
        revision: ProviderRevision,
        valid_until: Option<OffsetDateTime>,
        in_grace: bool,
    ) -> Self {
        Self {
            key,
            value,
            provider,
            revision,
            valid_until,
            in_grace,
        }
    }

    /// Returns the application entitlement key.
    #[must_use]
    pub const fn key(&self) -> &EntitlementKey {
        &self.key
    }

    /// Returns the effective grant.
    #[must_use]
    pub const fn value(&self) -> EntitlementValue {
        self.value
    }

    /// Returns the reconciled provider that established the grant.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns the authoritative snapshot revision.
    #[must_use]
    pub const fn revision(&self) -> ProviderRevision {
        self.revision
    }

    /// Returns the local access boundary when one exists.
    #[must_use]
    pub const fn valid_until(&self) -> Option<OffsetDateTime> {
        self.valid_until
    }

    /// Returns whether the grant currently relies on application grace policy.
    #[must_use]
    pub const fn in_grace(&self) -> bool {
        self.in_grace
    }
}
