use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt::{self, Write as _};
use std::str::FromStr;

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use thiserror::Error;

const MAX_MESSAGE_ID_BYTES: usize = 128;
const MAX_ARGUMENT_NAME_BYTES: usize = 64;
const MAX_TIME_ZONE_BYTES: usize = 64;

// Active ISO 4217 entries with numeric minor-unit definitions. Test/no-currency codes and entries
// whose ISO minor unit is `N.A.` are deliberately excluded.
const ISO_4217_CODES: &str = "AED AFN ALL AMD AOA ARS AUD AWG AZN BAM BBD BDT BGN BHD BIF BMD BND BOB BOV BRL BSD BTN BWP BYN BZD CAD CDF CHE CHF CHW CLF CLP CNY COP COU CRC CUP CVE CZK DJF DKK DOP DZD EGP ERN ETB EUR FJD FKP GBP GEL GHS GIP GMD GNF GTQ GYD HKD HNL HTG HUF IDR ILS INR IQD IRR ISK JMD JOD JPY KES KGS KHR KMF KPW KRW KWD KYD KZT LAK LBP LKR LRD LSL LYD MAD MDL MGA MKD MMK MNT MOP MRU MUR MVR MWK MXN MXV MYR MZN NAD NGN NIO NOK NPR NZD OMR PAB PEN PGK PHP PKR PLN PYG QAR RON RSD RUB RWF SAR SBD SCR SDG SEK SGD SHP SLE SOS SRD SSP STN SVC SYP SZL THB TJS TMT TND TOP TRY TTD TWD TZS UAH UGX USD USN UYI UYU UYW UZS VED VES VND VUV WST XAF XCD XCG XOF XPF YER ZAR ZMW ZWG";

/// A validated Fluent message identifier.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct MessageId(Box<str>);

impl MessageId {
    /// Validates a Fluent message identifier.
    ///
    /// # Errors
    ///
    /// Returns [`MessageIdError`] for an empty, oversized, or malformed identifier.
    pub fn parse(value: &str) -> Result<Self, MessageIdError> {
        if !valid_identifier(value, MAX_MESSAGE_ID_BYTES) {
            return Err(MessageIdError);
        }
        Ok(Self(value.into()))
    }

    /// Returns the identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for MessageId {
    type Err = MessageIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MessageId([redacted])")
    }
}

/// A redacted message identifier error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid message identifier")]
pub struct MessageIdError;

/// A validated Fluent argument name.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct ArgumentName(Box<str>);

impl ArgumentName {
    /// Validates a Fluent argument name.
    ///
    /// # Errors
    ///
    /// Returns [`ArgumentError::InvalidName`] for an empty, oversized, or malformed name.
    pub fn parse(value: &str) -> Result<Self, ArgumentError> {
        if !valid_identifier(value, MAX_ARGUMENT_NAME_BYTES) {
            return Err(ArgumentError::InvalidName);
        }
        Ok(Self(value.into()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ArgumentName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArgumentName([redacted])")
    }
}

fn valid_identifier(value: &str, maximum_bytes: usize) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= maximum_bytes
        && first.is_ascii_alphabetic()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// An ISO 4217 currency code.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CurrencyCode([u8; 3]);

impl CurrencyCode {
    /// Parses a registered uppercase ISO 4217 code.
    ///
    /// # Errors
    ///
    /// Returns [`CurrencyError`] unless the value is a registered uppercase ISO 4217 code.
    pub fn parse(value: &str) -> Result<Self, CurrencyError> {
        let bytes: [u8; 3] = value.as_bytes().try_into().map_err(|_| CurrencyError)?;
        if !bytes.iter().all(u8::is_ascii_uppercase)
            || !ISO_4217_CODES
                .split_ascii_whitespace()
                .any(|code| code == value)
        {
            return Err(CurrencyError);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn minor_digits(self) -> u32 {
        if self.is_one_of(&[
            *b"BIF", *b"CLP", *b"DJF", *b"GNF", *b"ISK", *b"JPY", *b"KMF", *b"KRW", *b"PYG",
            *b"RWF", *b"UGX", *b"UYI", *b"VND", *b"VUV", *b"XAF", *b"XOF", *b"XPF",
        ]) {
            0
        } else if self.is_one_of(&[
            *b"BHD", *b"IQD", *b"JOD", *b"KWD", *b"LYD", *b"OMR", *b"TND",
        ]) {
            3
        } else if self.is_one_of(&[*b"CLF", *b"UYW"]) {
            4
        } else {
            2
        }
    }

    fn is_one_of(self, values: &[[u8; 3]]) -> bool {
        values.contains(&self.0)
    }
}

impl FromStr for CurrencyCode {
    type Err = CurrencyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Display for CurrencyCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            formatter.write_char(char::from(byte))?;
        }
        Ok(())
    }
}

impl fmt::Debug for CurrencyCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CurrencyCode([redacted])")
    }
}

/// A redacted ISO 4217 currency error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid currency code")]
pub struct CurrencyError;

/// A currency amount represented exactly in the currency's minor unit.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CurrencyAmount {
    code: CurrencyCode,
    minor_units: i64,
}

impl CurrencyAmount {
    /// Creates an exact currency amount.
    #[must_use]
    pub const fn new(code: CurrencyCode, minor_units: i64) -> Self {
        Self { code, minor_units }
    }

    /// Returns the ISO 4217 code.
    #[must_use]
    pub const fn code(self) -> CurrencyCode {
        self.code
    }

    /// Returns the signed amount in the currency's minor unit.
    #[must_use]
    pub const fn minor_units(self) -> i64 {
        self.minor_units
    }
}

impl fmt::Debug for CurrencyAmount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CurrencyAmount([redacted])")
    }
}

/// A validated IANA time zone used for rendering UTC instants.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TimeZone {
    name: &'static str,
    value: Tz,
}

impl TimeZone {
    /// Parses `UTC` or a database-backed geographic IANA time-zone identifier.
    ///
    /// Fixed offsets, `Etc/GMT` sign-inverted zones, legacy top-level aliases, path-like values, and
    /// case-insensitive guesses are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`TimeZoneError`] unless the value is `UTC` or an exact database-backed geographic
    /// IANA identifier accepted by the strict policy.
    pub fn parse(value: &str) -> Result<Self, TimeZoneError> {
        if value.is_empty() || value.len() > MAX_TIME_ZONE_BYTES {
            return Err(TimeZoneError);
        }

        let geographic = value.split_once('/').is_some_and(|(area, location)| {
            matches!(
                area,
                "Africa"
                    | "America"
                    | "Antarctica"
                    | "Arctic"
                    | "Asia"
                    | "Atlantic"
                    | "Australia"
                    | "Europe"
                    | "Indian"
                    | "Pacific"
            ) && !location.is_empty()
                && location.split('/').all(|part| {
                    !part.is_empty()
                        && part.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'+')
                        })
                })
        });
        if value != "UTC" && !geographic {
            return Err(TimeZoneError);
        }

        let parsed = value.parse::<Tz>().map_err(|_| TimeZoneError)?;
        if parsed.name() != value {
            return Err(TimeZoneError);
        }
        Ok(Self {
            name: parsed.name(),
            value: parsed,
        })
    }

    /// Returns the validated IANA identifier.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    pub(crate) const fn value(self) -> Tz {
        self.value
    }
}

impl FromStr for TimeZone {
    type Err = TimeZoneError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Debug for TimeZone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TimeZone([redacted])")
    }
}

/// A redacted time-zone parsing error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid time zone")]
pub struct TimeZoneError;

/// A UTC instant suitable for storage and later localized rendering.
#[derive(Clone, Eq, PartialEq)]
pub struct UtcInstant(DateTime<Utc>);

impl UtcInstant {
    /// Wraps an existing UTC instant.
    #[must_use]
    pub const fn new(value: DateTime<Utc>) -> Self {
        Self(value)
    }

    /// Constructs an instant from Unix timestamp parts.
    ///
    /// # Errors
    ///
    /// Returns [`InstantError`] when the timestamp parts are outside Chrono's representable range.
    pub fn from_timestamp(seconds: i64, nanoseconds: u32) -> Result<Self, InstantError> {
        DateTime::from_timestamp(seconds, nanoseconds)
            .map(Self)
            .ok_or(InstantError)
    }

    pub(crate) fn value(&self) -> &DateTime<Utc> {
        &self.0
    }
}

impl fmt::Debug for UtcInstant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UtcInstant([redacted])")
    }
}

/// A redacted invalid-instant error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid UTC instant")]
pub struct InstantError;

/// One of the bounded, application-owned date-time presentation styles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DateTimeStyle {
    /// A compact locale-ordered numeric representation with minutes and zone abbreviation.
    Short,
    /// An unambiguous ISO-ordered representation with seconds, numeric offset, and zone abbreviation.
    Long,
}

/// A UTC instant paired with a validated rendering time zone and fixed presentation style.
#[derive(Clone, Eq, PartialEq)]
pub struct ZonedDateTime {
    instant: UtcInstant,
    time_zone: TimeZone,
    style: DateTimeStyle,
}

impl ZonedDateTime {
    /// Creates a safe date-time rendering parameter.
    #[must_use]
    pub const fn new(instant: UtcInstant, time_zone: TimeZone, style: DateTimeStyle) -> Self {
        Self {
            instant,
            time_zone,
            style,
        }
    }

    pub(crate) const fn instant(&self) -> &UtcInstant {
        &self.instant
    }

    pub(crate) const fn time_zone(&self) -> TimeZone {
        self.time_zone
    }

    pub(crate) const fn style(&self) -> DateTimeStyle {
        self.style
    }
}

impl fmt::Debug for ZonedDateTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ZonedDateTime([redacted])")
    }
}

/// A typed Fluent message parameter.
#[derive(Clone)]
pub enum MessageArg {
    /// Bounded-at-render user or application text.
    Text(String),
    /// A signed integer retaining Fluent plural-selection semantics.
    Count(i64),
    /// An exact, locale-formatted ISO 4217 currency amount.
    Currency(CurrencyAmount),
    /// A UTC instant rendered in a validated IANA time zone.
    DateTime(ZonedDateTime),
}

impl fmt::Debug for MessageArg {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Text(_) => "Text([redacted])",
            Self::Count(_) => "Count([redacted])",
            Self::Currency(_) => "Currency([redacted])",
            Self::DateTime(_) => "DateTime([redacted])",
        };
        formatter.write_str(kind)
    }
}

/// A collection of named typed Fluent arguments.
#[derive(Clone, Default)]
pub struct MessageArgs {
    values: BTreeMap<ArgumentName, MessageArg>,
}

impl MessageArgs {
    /// Creates an empty argument collection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }

    /// Parses the argument name and inserts a value, rejecting duplicate names.
    ///
    /// # Errors
    ///
    /// Returns [`ArgumentError`] when the name is invalid or already present.
    pub fn try_insert(&mut self, name: &str, value: MessageArg) -> Result<(), ArgumentError> {
        let name = ArgumentName::parse(name)?;
        match self.values.entry(name) {
            Entry::Vacant(entry) => {
                entry.insert(value);
                Ok(())
            }
            Entry::Occupied(_) => Err(ArgumentError::DuplicateName),
        }
    }

    /// Returns the number of arguments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns whether the collection is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&ArgumentName, &MessageArg)> {
        self.values.iter()
    }
}

impl fmt::Debug for MessageArgs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageArgs")
            .field("argument_count", &self.values.len())
            .finish()
    }
}

/// A redacted argument construction error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ArgumentError {
    /// The name is not a bounded Fluent identifier.
    #[error("invalid argument name")]
    InvalidName,
    /// The same name was inserted more than once.
    #[error("duplicate argument name")]
    DuplicateName,
}
