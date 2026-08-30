use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Serialize, Serializer};

use crate::{ResourceError, TemplateVariableName};

const MAX_URI_BYTES: usize = 2_048;
const MAX_AUTHORITY_BYTES: usize = 128;
const MAX_PATH_SEGMENT_BYTES: usize = 256;
const MAX_PATH_SEGMENTS: usize = 64;

/// A centrally parsed non-fetching canonical resource URI.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceUri {
    raw: String,
    scheme: String,
    authority: String,
    segments: Vec<String>,
}

impl ResourceUri {
    /// Parses a canonical non-network `omnius://` resource URI.
    ///
    /// Every other scheme, userinfo, ports, IP-style authorities, fragments, queries,
    /// malformed or ambiguous escapes, traversal, controls, backslashes, and decoded
    /// delimiters are rejected. These URIs are logical identifiers and never fetch targets.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the URI violates the fixed safe grammar.
    pub fn parse(value: String) -> Result<Self, ResourceError> {
        let (scheme, authority, raw_segments) = parse_uri_parts(&value)?;
        let segments = raw_segments
            .into_iter()
            .map(decode_segment)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            raw: value,
            scheme,
            authority,
            segments,
        })
    }

    /// Borrows the exact validated URI spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Borrows the validated non-fetching scheme.
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Borrows the validated authority.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Borrows the decoded, traversal-safe path segments.
    #[must_use]
    pub fn path_segments(&self) -> &[String] {
        &self.segments
    }

    pub(crate) fn has_same_origin(&self, other: &Self) -> bool {
        self.scheme == other.scheme && self.authority == other.authority
    }
}

impl Serialize for ResourceUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl fmt::Display for ResourceUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw.fmt(formatter)
    }
}

impl fmt::Debug for ResourceUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResourceUri([redacted])")
    }
}

#[derive(Clone, Eq, PartialEq)]
enum TemplateSegment {
    Literal(String),
    Variable(TemplateVariableName),
}

/// A non-ambiguous resource URI template whose variables occupy complete path segments.
#[derive(Clone, Eq, PartialEq)]
pub struct ResourceUriTemplate {
    raw: String,
    scheme: String,
    authority: String,
    segments: Vec<TemplateSegment>,
}

impl ResourceUriTemplate {
    /// Parses a strict segment-variable resource URI template.
    ///
    /// Variables use `{lower_snake_name}` and must occupy a whole path segment.
    /// Authority variables, duplicate variables, and all unsafe URI forms are rejected.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the template violates the fixed grammar.
    pub fn parse(value: String) -> Result<Self, ResourceError> {
        let (scheme, authority, raw_segments) = parse_uri_parts(&value)?;
        let mut variables = BTreeSet::new();
        let mut segments = Vec::with_capacity(raw_segments.len());
        for raw_segment in raw_segments {
            if raw_segment.starts_with('{') || raw_segment.ends_with('}') {
                if !(raw_segment.starts_with('{')
                    && raw_segment.ends_with('}')
                    && raw_segment.len() > 2)
                {
                    return Err(ResourceError::invalid_value());
                }
                let name =
                    TemplateVariableName::new(raw_segment[1..raw_segment.len() - 1].to_owned())?;
                if !variables.insert(name.clone()) {
                    return Err(ResourceError::invalid_value());
                }
                segments.push(TemplateSegment::Variable(name));
            } else {
                segments.push(TemplateSegment::Literal(decode_segment(raw_segment)?));
            }
        }
        if variables.is_empty() {
            return Err(ResourceError::invalid_value());
        }
        Ok(Self {
            raw: value,
            scheme,
            authority,
            segments,
        })
    }

    /// Borrows the exact validated URI-template spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Borrows the fixed template authority.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Reports whether the template declares a variable with the supplied name.
    #[must_use]
    pub fn has_variable(&self, name: &TemplateVariableName) -> bool {
        self.segments.iter().any(
            |segment| matches!(segment, TemplateSegment::Variable(variable) if variable == name),
        )
    }

    /// Resolves a safe URI to decoded variable values when the whole template matches.
    #[must_use]
    pub fn resolve(&self, uri: &ResourceUri) -> Option<BTreeMap<String, String>> {
        if self.scheme != uri.scheme
            || self.authority != uri.authority
            || self.segments.len() != uri.segments.len()
        {
            return None;
        }
        let mut variables = BTreeMap::new();
        for (template_segment, uri_segment) in self.segments.iter().zip(&uri.segments) {
            match template_segment {
                TemplateSegment::Literal(literal) if literal != uri_segment => return None,
                TemplateSegment::Literal(_) => {}
                TemplateSegment::Variable(name) => {
                    variables.insert(name.as_str().to_owned(), uri_segment.clone());
                }
            }
        }
        Some(variables)
    }
    pub(crate) fn matches_uri(&self, uri: &ResourceUri) -> bool {
        self.scheme == uri.scheme
            && self.authority == uri.authority
            && self.segments.len() == uri.segments.len()
            && self
                .segments
                .iter()
                .zip(&uri.segments)
                .all(|(template, resolved)| match template {
                    TemplateSegment::Literal(literal) => literal == resolved,
                    TemplateSegment::Variable(_) => true,
                })
    }

    pub(crate) fn overlaps(&self, other: &Self) -> bool {
        self.scheme == other.scheme
            && self.authority == other.authority
            && self.segments.len() == other.segments.len()
            && self
                .segments
                .iter()
                .zip(&other.segments)
                .all(|(left, right)| match (left, right) {
                    (TemplateSegment::Literal(left), TemplateSegment::Literal(right)) => {
                        left == right
                    }
                    _ => true,
                })
    }
}

impl Serialize for ResourceUriTemplate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl fmt::Display for ResourceUriTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw.fmt(formatter)
    }
}

impl fmt::Debug for ResourceUriTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResourceUriTemplate([redacted])")
    }
}

fn parse_uri_parts(value: &str) -> Result<(String, String, Vec<&str>), ResourceError> {
    if value.is_empty()
        || value.len() > MAX_URI_BYTES
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
        || value.contains('?')
        || value.contains('#')
    {
        return Err(ResourceError::invalid_value());
    }
    let (scheme, remainder) = value
        .split_once("://")
        .ok_or_else(ResourceError::invalid_value)?;
    if scheme != "omnius" {
        return Err(ResourceError::invalid_value());
    }
    let (authority, path) = remainder
        .split_once('/')
        .ok_or_else(ResourceError::invalid_value)?;
    if !valid_authority(authority) || path.is_empty() {
        return Err(ResourceError::invalid_value());
    }
    let segments = path.split('/').collect::<Vec<_>>();
    if segments.len() > MAX_PATH_SEGMENTS || segments.iter().any(|segment| segment.is_empty()) {
        return Err(ResourceError::invalid_value());
    }
    Ok((scheme.to_owned(), authority.to_owned(), segments))
}

fn valid_authority(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AUTHORITY_BYTES
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn decode_segment(raw: &str) -> Result<String, ResourceError> {
    if raw.is_empty() || raw.len() > MAX_PATH_SEGMENT_BYTES {
        return Err(ResourceError::invalid_value());
    }
    let raw_bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw_bytes.len() {
        let byte = raw_bytes[index];
        if byte == b'%' {
            if index + 2 >= raw_bytes.len() {
                return Err(ResourceError::invalid_value());
            }
            let high =
                canonical_hex(raw_bytes[index + 1]).ok_or_else(ResourceError::invalid_value)?;
            let low =
                canonical_hex(raw_bytes[index + 2]).ok_or_else(ResourceError::invalid_value)?;
            let decoded_byte = (high << 4) | low;
            if decoded_byte.is_ascii() && is_raw_path_byte(decoded_byte) {
                return Err(ResourceError::invalid_value());
            }
            decoded.push(decoded_byte);
            index += 3;
        } else {
            if !byte.is_ascii() || !is_raw_path_byte(byte) {
                return Err(ResourceError::invalid_value());
            }
            decoded.push(byte);
            index += 1;
        }
    }
    let decoded = String::from_utf8(decoded).map_err(|_| ResourceError::invalid_value())?;
    if decoded.is_empty()
        || decoded.len() > MAX_PATH_SEGMENT_BYTES
        || matches!(decoded.as_str(), "." | "..")
        || decoded.chars().any(|character| {
            character.is_control()
                || matches!(character, '\\' | '/' | ':' | '?' | '#' | '%' | '{' | '}')
        })
    {
        return Err(ResourceError::invalid_value());
    }
    Ok(decoded)
}

fn canonical_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_raw_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b'@'
        )
}
