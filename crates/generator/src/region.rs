use std::{collections::BTreeSet, error::Error, fmt};

use crate::state::{MANAGED_MARKER_VERSION, ManagedRegionRecord, sha256_hex};

const BEGIN_TOKEN: &str = "omnius:managed-begin";
const END_TOKEN: &str = "omnius:managed-end";

/// One validated managed region borrowed from its source file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedRegion<'a> {
    /// Stable region identifier.
    pub id: &'a str,
    /// Marker grammar version.
    pub marker_version: u32,
    /// Hash recorded in the opening marker.
    pub content_hash: &'a str,
    /// Exact managed bytes between marker lines.
    pub content: &'a str,
    begin_line_start: usize,
    begin_line_end: usize,
    content_start: usize,
    content_end: usize,
    prefix: &'a str,
    suffix: &'a str,
}

/// Corrupt, ambiguous, or unexpectedly edited managed markers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionError {
    message: String,
}

impl RegionError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RegionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for RegionError {}

/// Parses every managed region while rejecting malformed, nested, duplicate,
/// orphaned, or hash-invalid markers.
///
/// Marker payloads are language-neutral and may follow `#`, `//`, or `<!--`
/// comment prefixes:
/// `omnius:managed-begin id=<id> version=1 hash=<sha256>` and
/// `omnius:managed-end id=<id>`.
///
/// # Errors
///
/// Returns [`RegionError`] for any marker corruption. A file with no markers is
/// valid and returns an empty vector.
pub fn parse_managed_regions(source: &str) -> Result<Vec<ManagedRegion<'_>>, RegionError> {
    let mut parser = RegionParser::new();
    let mut offset = 0;
    for segment in source.split_inclusive('\n') {
        let line_end = offset + segment.trim_end_matches(['\r', '\n']).len();
        let next_offset = offset + segment.len();
        if let Some(marker) = parse_marker(&source[offset..line_end])? {
            parser.apply(source, marker, offset, line_end, next_offset)?;
        }
        offset = next_offset;
    }
    parser.finish()
}

struct RegionParser<'a> {
    regions: Vec<ManagedRegion<'a>>,
    open: Option<OpenMarker<'a>>,
    ids: BTreeSet<&'a str>,
}

impl<'a> RegionParser<'a> {
    fn new() -> Self {
        Self {
            regions: Vec::new(),
            open: None,
            ids: BTreeSet::new(),
        }
    }

    fn apply(
        &mut self,
        source: &'a str,
        marker: Marker<'a>,
        line_start: usize,
        line_end: usize,
        next_offset: usize,
    ) -> Result<(), RegionError> {
        match marker {
            Marker::Begin {
                id,
                version,
                hash,
                prefix,
                suffix,
            } => {
                if let Some(existing) = &self.open {
                    return Err(RegionError::new(format!(
                        "managed region `{id}` is nested inside `{}`",
                        existing.id
                    )));
                }
                if !self.ids.insert(id) {
                    return Err(RegionError::new(format!(
                        "duplicate managed region id `{id}`"
                    )));
                }
                self.open = Some(OpenMarker {
                    id,
                    version,
                    hash,
                    begin_line_start: line_start,
                    begin_line_end: line_end,
                    content_start: next_offset,
                    prefix,
                    suffix,
                });
                Ok(())
            }
            Marker::End { id } => self.close(source, id, line_start),
        }
    }

    fn close(&mut self, source: &'a str, id: &str, content_end: usize) -> Result<(), RegionError> {
        let Some(begin) = self.open.take() else {
            return Err(RegionError::new(format!(
                "managed region end `{id}` has no opening marker"
            )));
        };
        if begin.id != id {
            return Err(RegionError::new(format!(
                "managed region `{}` ends with mismatched id `{id}`",
                begin.id
            )));
        }
        let content = &source[begin.content_start..content_end];
        let actual_hash = sha256_hex(content.as_bytes());
        if begin.version != MANAGED_MARKER_VERSION {
            return Err(RegionError::new(format!(
                "managed region `{id}` uses unsupported marker version {}",
                begin.version
            )));
        }
        if begin.hash != actual_hash {
            return Err(RegionError::new(format!(
                "managed region `{id}` content was edited outside the generator: marker hash {}, actual hash {actual_hash}",
                begin.hash
            )));
        }
        self.regions.push(ManagedRegion {
            id: begin.id,
            marker_version: begin.version,
            content_hash: begin.hash,
            content,
            begin_line_start: begin.begin_line_start,
            begin_line_end: begin.begin_line_end,
            content_start: begin.content_start,
            content_end,
            prefix: begin.prefix,
            suffix: begin.suffix,
        });
        Ok(())
    }

    fn finish(self) -> Result<Vec<ManagedRegion<'a>>, RegionError> {
        if let Some(begin) = self.open {
            return Err(RegionError::new(format!(
                "managed region `{}` is missing its end marker",
                begin.id
            )));
        }
        Ok(self.regions)
    }
}

/// Replaces one approved region and updates only its opening marker and content.
/// Every byte before the opening marker and from the closing marker onward is
/// retained exactly.
///
/// # Errors
///
/// Returns [`RegionError`] when markers are corrupt, the region is missing, the
/// state record does not match the file, or content was edited without approval.
pub fn reconcile_managed_region(
    source: &str,
    expected: &ManagedRegionRecord,
    new_content: &str,
) -> Result<String, RegionError> {
    if (!new_content.is_empty() && !new_content.ends_with('\n'))
        || new_content.contains("omnius:managed-")
    {
        return Err(RegionError::new(
            "managed replacement content must end with a newline and may not contain markers",
        ));
    }
    let regions = parse_managed_regions(source)?;
    let region = regions
        .iter()
        .find(|region| region.id == expected.id)
        .ok_or_else(|| {
            RegionError::new(format!(
                "managed region `{}` is missing from `{}`",
                expected.id, expected.path
            ))
        })?;
    if region.marker_version != expected.marker_version {
        return Err(RegionError::new(format!(
            "managed region `{}` marker version changed from {} to {}",
            expected.id, expected.marker_version, region.marker_version
        )));
    }
    if region.content_hash != expected.content_hash {
        return Err(RegionError::new(format!(
            "managed region `{}` hash differs from project state: state {}, marker {}",
            expected.id, expected.content_hash, region.content_hash
        )));
    }

    let new_hash = sha256_hex(new_content.as_bytes());
    if new_hash == region.content_hash && new_content == region.content {
        return Ok(source.to_owned());
    }

    let mut reconciled = String::with_capacity(
        source.len() - (region.content_end - region.content_start) + new_content.len(),
    );
    reconciled.push_str(&source[..region.begin_line_start]);
    reconciled.push_str(region.prefix);
    reconciled.push_str(BEGIN_TOKEN);
    reconciled.push_str(" id=");
    reconciled.push_str(region.id);
    reconciled.push_str(" version=");
    reconciled.push_str(&region.marker_version.to_string());
    reconciled.push_str(" hash=");
    reconciled.push_str(&new_hash);
    reconciled.push_str(region.suffix);
    reconciled.push_str(&source[region.begin_line_end..region.content_start]);
    reconciled.push_str(new_content);
    reconciled.push_str(&source[region.content_end..]);
    Ok(reconciled)
}

struct OpenMarker<'a> {
    id: &'a str,
    version: u32,
    hash: &'a str,
    begin_line_start: usize,
    begin_line_end: usize,
    content_start: usize,
    prefix: &'a str,
    suffix: &'a str,
}

#[derive(Clone, Copy)]
enum Marker<'a> {
    Begin {
        id: &'a str,
        version: u32,
        hash: &'a str,
        prefix: &'a str,
        suffix: &'a str,
    },
    End {
        id: &'a str,
    },
}

fn parse_marker(line: &str) -> Result<Option<Marker<'_>>, RegionError> {
    let trimmed_start = line.trim_start_matches([' ', '\t']);
    if trimmed_start.starts_with("///") || trimmed_start.starts_with("//!") {
        return Ok(None);
    }
    let Some(token_offset) = trimmed_start
        .find(BEGIN_TOKEN)
        .or_else(|| trimmed_start.find(END_TOKEN))
    else {
        return Ok(None);
    };
    let prefix_len = line.len() - trimmed_start.len() + token_offset;
    let prefix = &line[..prefix_len];
    if !valid_prefix(prefix) {
        let is_comment_line = trimmed_start.starts_with('#')
            || trimmed_start.starts_with("//")
            || trimmed_start.starts_with("<!--");
        return if is_comment_line {
            Err(RegionError::new(
                "managed marker must be the only payload in a comment line",
            ))
        } else {
            Ok(None)
        };
    }
    let payload_with_suffix = &line[prefix_len..];
    let (payload, suffix) = split_comment_suffix(payload_with_suffix);
    let mut fields = payload.split_ascii_whitespace();
    let token = fields
        .next()
        .ok_or_else(|| RegionError::new("empty managed marker"))?;
    let mut id = None;
    let mut version = None;
    let mut hash = None;
    for field in fields {
        let Some((key, value)) = field.split_once('=') else {
            return Err(RegionError::new(format!(
                "invalid managed marker field `{field}`"
            )));
        };
        if value.is_empty() {
            return Err(RegionError::new(format!(
                "empty managed marker field `{key}`"
            )));
        }
        match key {
            "id" if id.replace(value).is_none() => {}
            "version" if version.replace(value).is_none() => {}
            "hash" if hash.replace(value).is_none() => {}
            _ => {
                return Err(RegionError::new(format!(
                    "unknown or duplicate managed marker field `{key}`"
                )));
            }
        }
    }
    let id = id.ok_or_else(|| RegionError::new("managed marker is missing id"))?;
    if !valid_id(id) {
        return Err(RegionError::new(format!(
            "managed marker has invalid id `{id}`"
        )));
    }
    match token {
        BEGIN_TOKEN => {
            let version = version
                .ok_or_else(|| RegionError::new("managed begin marker is missing version"))?
                .parse::<u32>()
                .map_err(|_| RegionError::new("managed marker version is not an integer"))?;
            let hash =
                hash.ok_or_else(|| RegionError::new("managed begin marker is missing hash"))?;
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(RegionError::new(
                    "managed marker hash is not lowercase SHA-256",
                ));
            }
            Ok(Some(Marker::Begin {
                id,
                version,
                hash,
                prefix,
                suffix,
            }))
        }
        END_TOKEN => {
            if version.is_some() || hash.is_some() {
                return Err(RegionError::new(
                    "managed end marker may contain only its id",
                ));
            }
            Ok(Some(Marker::End { id }))
        }
        _ => Ok(None),
    }
}

fn split_comment_suffix(value: &str) -> (&str, &str) {
    let trimmed = value.trim_end_matches([' ', '\t']);
    if let Some(payload) = trimmed.strip_suffix("-->") {
        let payload = payload.trim_end_matches([' ', '\t']);
        (&value[..payload.len()], &value[payload.len()..])
    } else {
        (trimmed, &value[trimmed.len()..])
    }
}

fn valid_prefix(prefix: &str) -> bool {
    let trimmed = prefix.trim();
    matches!(trimmed, "#" | "//" | "<!--")
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
