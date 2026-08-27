use std::{collections::HashSet, fmt, io, marker::PhantomData, str::FromStr as _};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use lettre::{Address, message::header::ContentType};
use omnius_jobs_core::IdempotencyKey;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, IgnoredAny, SeqAccess, Visitor},
    ser::SerializeStruct as _,
};
use serde_json::{Value, value::RawValue};
use uuid::Uuid;

use crate::EmailError;

const ABSOLUTE_RECIPIENTS: usize = 100;
const ABSOLUTE_HEADERS: usize = 64;
const ABSOLUTE_ATTACHMENTS: usize = 16;
const ABSOLUTE_ATTACHMENT_BYTES: usize = 512 * 1024;
const ABSOLUTE_ATTACHMENT_TOTAL_BYTES: usize = 512 * 1024;
const ABSOLUTE_CONTEXT_BYTES: usize = 128 * 1024;
const ABSOLUTE_CONTEXT_DEPTH: usize = 16;
const ABSOLUTE_CONTEXT_NODES: usize = 4_096;
pub(crate) struct BoundedVec<T, const MAXIMUM: usize>(Vec<T>);

impl<T, const MAXIMUM: usize> BoundedVec<T, MAXIMUM> {
    pub(crate) fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T, const MAXIMUM: usize> Default for BoundedVec<T, MAXIMUM> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<'de, T, const MAXIMUM: usize> Deserialize<'de> for BoundedVec<T, MAXIMUM>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedVecVisitor<T, const MAXIMUM: usize>(PhantomData<T>);

        impl<'de, T, const MAXIMUM: usize> Visitor<'de> for BoundedVecVisitor<T, MAXIMUM>
        where
            T: Deserialize<'de>,
        {
            type Value = BoundedVec<T, MAXIMUM>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded sequence")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let capacity = sequence.size_hint().unwrap_or(0).min(MAXIMUM);
                let mut values = Vec::with_capacity(capacity);
                while values.len() < MAXIMUM {
                    let Some(value) = sequence.next_element()? else {
                        return Ok(BoundedVec(values));
                    };
                    values.push(value);
                }
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom("bounded sequence exceeds its limit"));
                }
                Ok(BoundedVec(values))
            }
        }

        deserializer.deserialize_seq(BoundedVecVisitor::<T, MAXIMUM>(PhantomData))
    }
}

macro_rules! redacted_string {
    ($name:ident, $validator:ident, $error:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Borrows the validated value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = EmailError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                $validator(value)?;
                Ok(Self(value.to_owned()))
            }
        }

        impl TryFrom<String> for $name {
            type Error = EmailError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                $validator(&value)?;
                Ok(Self(value))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::try_from(String::deserialize(deserializer)?)
                    .map_err(|_| D::Error::custom($error))
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
    };
}

fn validate_email_address(value: &str) -> Result<(), EmailError> {
    if value.is_empty()
        || value.len() > 320
        || value != value.trim()
        || value.chars().any(char::is_control)
        || Address::from_str(value).is_err()
    {
        return Err(EmailError::InvalidAddress);
    }
    Ok(())
}

fn validate_display_name(value: &str) -> Result<(), EmailError> {
    validate_header_text(value, 256)
}

fn validate_subject(value: &str) -> Result<(), EmailError> {
    validate_header_text(value, 998)
}

fn validate_custom_header_name(value: &str) -> Result<(), EmailError> {
    if value.len() < 3
        || value.len() > 76
        || !value.is_ascii()
        || !value
            .get(..2)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("x-"))
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(EmailError::InvalidHeader);
    }
    Ok(())
}

fn validate_custom_header_value(value: &str) -> Result<(), EmailError> {
    validate_header_text(value, 998)
}

fn validate_header_text(value: &str, maximum: usize) -> Result<(), EmailError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(EmailError::InvalidHeader);
    }
    Ok(())
}

fn validate_template_name(value: &str) -> Result<(), EmailError> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(EmailError::InvalidTemplateName);
    }
    Ok(())
}

fn validate_attachment_name(value: &str) -> Result<(), EmailError> {
    if value.is_empty()
        || value.len() > 255
        || matches!(value, "." | "..")
        || value.contains(['/', '\\'])
        || value.chars().any(char::is_control)
    {
        return Err(EmailError::InvalidAttachment);
    }
    Ok(())
}

fn validate_media_type(value: &str) -> Result<(), EmailError> {
    let Some((top, sub)) = value.split_once('/') else {
        return Err(EmailError::InvalidAttachment);
    };
    let allowed = |byte: u8| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
            )
    };
    if value.len() > 127
        || top.is_empty()
        || sub.is_empty()
        || sub.contains('/')
        || !top.bytes().all(allowed)
        || !sub.bytes().all(allowed)
        || ContentType::parse(value).is_err()
    {
        return Err(EmailError::InvalidAttachment);
    }
    Ok(())
}

fn validate_client_message_id(value: &str) -> Result<(), EmailError> {
    let Some(uuid) = value
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix("@omnius.invalid>"))
    else {
        return Err(EmailError::InvalidMessageId);
    };
    let bytes = uuid.as_bytes();
    if bytes.len() != 36
        || bytes.get(14) != Some(&b'7')
        || !matches!(bytes.get(19), Some(b'8' | b'9' | b'a' | b'b'))
        || bytes.iter().enumerate().any(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte != b'-'
            } else {
                !matches!(byte, b'0'..=b'9' | b'a'..=b'f')
            }
        })
    {
        return Err(EmailError::InvalidMessageId);
    }
    Ok(())
}

fn validate_provider_message_id(value: &str) -> Result<(), EmailError> {
    if value.is_empty()
        || value.len() > 255
        || !value.is_ascii()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-' | b'@' | b'<' | b'>' | b':' | b'+')
        })
    {
        return Err(EmailError::InvalidMessageId);
    }
    Ok(())
}

redacted_string!(
    EmailAddress,
    validate_email_address,
    "email address is invalid",
    "A syntactically validated, bounded mailbox address with redacted diagnostics."
);
redacted_string!(
    DisplayName,
    validate_display_name,
    "email display name is invalid",
    "A bounded internationalized display name encoded by lettre when emitted."
);
redacted_string!(
    EmailSubject,
    validate_subject,
    "email subject is invalid",
    "A bounded internationalized subject with no control characters."
);
redacted_string!(
    CustomHeaderName,
    validate_custom_header_name,
    "custom email header name is invalid",
    "A bounded extension header name restricted to the `X-` namespace."
);
redacted_string!(
    CustomHeaderValue,
    validate_custom_header_value,
    "custom email header value is invalid",
    "A bounded internationalized extension-header value with no control characters."
);
redacted_string!(
    TemplateName,
    validate_template_name,
    "email template identifier is invalid",
    "A portable registry key that can never represent a filesystem path."
);
redacted_string!(
    AttachmentName,
    validate_attachment_name,
    "email attachment name is invalid",
    "A bounded attachment filename with no path or control characters."
);
redacted_string!(
    AttachmentMediaType,
    validate_media_type,
    "email attachment media type is invalid",
    "A validated attachment media type without parameters."
);
redacted_string!(
    ClientMessageId,
    validate_client_message_id,
    "client message identifier is invalid",
    "An exact canonical `<UUIDv7@omnius.invalid>` durable client submission identifier."
);
redacted_string!(
    ProviderMessageId,
    validate_provider_message_id,
    "provider message identifier is invalid",
    "A bounded provider-issued identifier with redacted diagnostics."
);

impl ClientMessageId {
    /// Creates an opaque `UUIDv7` client submission identifier for a new durable email effect.
    #[must_use]
    pub fn new_random() -> Self {
        Self(format!("<{}@omnius.invalid>", Uuid::now_v7()))
    }
}

/// One safely encoded mailbox header value.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxAddress {
    address: EmailAddress,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<DisplayName>,
}

impl MailboxAddress {
    /// Creates a mailbox address and optional internationalized display name.
    #[must_use]
    pub const fn new(address: EmailAddress, display_name: Option<DisplayName>) -> Self {
        Self {
            address,
            display_name,
        }
    }

    /// Validated address.
    #[must_use]
    pub const fn address(&self) -> &EmailAddress {
        &self.address
    }

    /// Optional internationalized display name.
    #[must_use]
    pub const fn display_name(&self) -> Option<&DisplayName> {
        self.display_name.as_ref()
    }

    pub(crate) fn into_parts(self) -> (EmailAddress, Option<DisplayName>) {
        (self.address, self.display_name)
    }
}

impl fmt::Debug for MailboxAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MailboxAddress")
            .field("address", &"[REDACTED]")
            .field("has_display_name", &self.display_name.is_some())
            .finish_non_exhaustive()
    }
}

/// A non-empty, absolutely bounded recipient set.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct RecipientSet {
    to: Vec<MailboxAddress>,
    cc: Vec<MailboxAddress>,
    bcc: Vec<MailboxAddress>,
}

impl RecipientSet {
    /// Creates a recipient set with a fixed absolute ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`EmailError::RecipientLimit`] when no recipient is supplied, the absolute count
    /// ceiling is exceeded, or an exact address is repeated across recipient headers.
    pub fn new(
        to: Vec<MailboxAddress>,
        cc: Vec<MailboxAddress>,
        bcc: Vec<MailboxAddress>,
    ) -> Result<Self, EmailError> {
        let count = to
            .len()
            .checked_add(cc.len())
            .and_then(|count| count.checked_add(bcc.len()))
            .ok_or(EmailError::RecipientLimit)?;
        if count == 0 || count > ABSOLUTE_RECIPIENTS {
            return Err(EmailError::RecipientLimit);
        }
        let mut unique = HashSet::with_capacity(count);
        if to
            .iter()
            .chain(&cc)
            .chain(&bcc)
            .any(|mailbox| !unique.insert(mailbox.address.as_str()))
        {
            return Err(EmailError::RecipientLimit);
        }
        Ok(Self { to, cc, bcc })
    }

    /// Aggregate recipient count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.to.len() + self.cc.len() + self.bcc.len()
    }

    /// Whether the set has no recipient. Valid instances are never empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Primary recipients.
    #[must_use]
    pub fn to(&self) -> &[MailboxAddress] {
        &self.to
    }

    /// Carbon-copy recipients.
    #[must_use]
    pub fn cc(&self) -> &[MailboxAddress] {
        &self.cc
    }

    /// Blind-carbon-copy recipients.
    #[must_use]
    pub fn bcc(&self) -> &[MailboxAddress] {
        &self.bcc
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Vec<MailboxAddress>,
        Vec<MailboxAddress>,
        Vec<MailboxAddress>,
    ) {
        (self.to, self.cc, self.bcc)
    }
}

impl<'de> Deserialize<'de> for RecipientSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            to: BoundedVec<MailboxAddress, ABSOLUTE_RECIPIENTS>,
            #[serde(default)]
            cc: BoundedVec<MailboxAddress, ABSOLUTE_RECIPIENTS>,
            #[serde(default)]
            bcc: BoundedVec<MailboxAddress, ABSOLUTE_RECIPIENTS>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.to.into_inner(),
            wire.cc.into_inner(),
            wire.bcc.into_inner(),
        )
        .map_err(|_| D::Error::custom("email recipient set is invalid"))
    }
}

impl fmt::Debug for RecipientSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecipientSet")
            .field("to_count", &self.to.len())
            .field("cc_count", &self.cc.len())
            .field("bcc_count", &self.bcc.len())
            .finish_non_exhaustive()
    }
}

/// One validated custom extension header.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomHeader {
    name: CustomHeaderName,
    value: CustomHeaderValue,
}

impl CustomHeader {
    /// Creates one custom header from already validated components.
    #[must_use]
    pub const fn new(name: CustomHeaderName, value: CustomHeaderValue) -> Self {
        Self { name, value }
    }

    /// Header name.
    #[must_use]
    pub const fn name(&self) -> &CustomHeaderName {
        &self.name
    }

    /// Header value.
    #[must_use]
    pub const fn value(&self) -> &CustomHeaderValue {
        &self.value
    }

    pub(crate) fn into_parts(self) -> (CustomHeaderName, CustomHeaderValue) {
        (self.name, self.value)
    }
}

impl fmt::Debug for CustomHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CustomHeader")
            .field("name", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Bounded in-memory attachment data. Serialized job payloads use base64 rather than integer arrays.
#[derive(Clone, Eq, PartialEq)]
pub struct EmailAttachment {
    name: AttachmentName,
    media_type: AttachmentMediaType,
    data: Vec<u8>,
}

impl EmailAttachment {
    /// Creates a fixed-size attachment.
    ///
    /// # Errors
    ///
    /// Returns [`EmailError::AttachmentLimit`] when `data` is empty or exceeds the absolute
    /// per-attachment ceiling.
    pub fn new(
        name: AttachmentName,
        media_type: AttachmentMediaType,
        data: Vec<u8>,
    ) -> Result<Self, EmailError> {
        if data.is_empty() || data.len() > ABSOLUTE_ATTACHMENT_BYTES {
            return Err(EmailError::AttachmentLimit);
        }
        Ok(Self {
            name,
            media_type,
            data,
        })
    }

    /// Attachment byte count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether attachment data is empty. Valid attachments are never empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Validated filename.
    #[must_use]
    pub const fn name(&self) -> &AttachmentName {
        &self.name
    }

    /// Validated media type.
    #[must_use]
    pub const fn media_type(&self) -> &AttachmentMediaType {
        &self.media_type
    }

    pub(crate) fn into_parts(self) -> (AttachmentName, AttachmentMediaType, Vec<u8>) {
        (self.name, self.media_type, self.data)
    }
}

impl Serialize for EmailAttachment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("EmailAttachment", 3)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("media_type", &self.media_type)?;
        state.serialize_field("data_base64", &BASE64.encode(&self.data))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for EmailAttachment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            name: AttachmentName,
            media_type: AttachmentMediaType,
            data_base64: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        let maximum_encoded = ABSOLUTE_ATTACHMENT_BYTES
            .saturating_add(2)
            .saturating_div(3)
            .saturating_mul(4);
        if wire.data_base64.len() > maximum_encoded {
            return Err(D::Error::custom("email attachment exceeds its limit"));
        }
        let data = BASE64
            .decode(wire.data_base64)
            .map_err(|_| D::Error::custom("email attachment encoding is invalid"))?;
        Self::new(wire.name, wire.media_type, data)
            .map_err(|_| D::Error::custom("email attachment exceeds its limit"))
    }
}

impl fmt::Debug for EmailAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailAttachment")
            .field("name", &"[REDACTED]")
            .field("media_type", &"[REDACTED]")
            .field("byte_len", &self.data.len())
            .finish_non_exhaustive()
    }
}

/// JSON object constrained by serialized bytes, nesting depth, and total node count.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TemplateContext {
    value: Value,
    #[serde(skip)]
    serialized_bytes: usize,
}

impl TemplateContext {
    /// Validates an owned JSON object against fixed structural ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`EmailError::ContextLimit`] for non-object roots or any exceeded ceiling.
    pub fn new(value: Value) -> Result<Self, EmailError> {
        if !value.is_object() {
            return Err(EmailError::ContextLimit);
        }
        let mut nodes = 0_usize;
        validate_json_shape(&value, 0, &mut nodes)?;
        let serialized_bytes = bounded_serialized_len(&value, ABSOLUTE_CONTEXT_BYTES)?;
        Ok(Self {
            value,
            serialized_bytes,
        })
    }

    /// An empty context object.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            value: Value::Object(serde_json::Map::new()),
            serialized_bytes: 2,
        }
    }

    /// Serialized JSON byte count used for configured-limit checks.
    #[must_use]
    pub const fn serialized_bytes(&self) -> usize {
        self.serialized_bytes
    }

    pub(crate) const fn value(&self) -> &Value {
        &self.value
    }
}

impl<'de> Deserialize<'de> for TemplateContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        if raw.get().len() > ABSOLUTE_CONTEXT_BYTES {
            return Err(D::Error::custom("email template context exceeds its limit"));
        }
        let value = serde_json::from_str(raw.get())
            .map_err(|_| D::Error::custom("email template context is invalid"))?;
        Self::new(value).map_err(|_| D::Error::custom("email template context exceeds its limit"))
    }
}

impl fmt::Debug for TemplateContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TemplateContext")
            .field("value", &"[REDACTED]")
            .field("serialized_bytes", &self.serialized_bytes)
            .finish_non_exhaustive()
    }
}

fn validate_json_shape(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), EmailError> {
    if depth > ABSOLUTE_CONTEXT_DEPTH {
        return Err(EmailError::ContextLimit);
    }
    *nodes = nodes.checked_add(1).ok_or(EmailError::ContextLimit)?;
    if *nodes > ABSOLUTE_CONTEXT_NODES {
        return Err(EmailError::ContextLimit);
    }
    match value {
        Value::Array(values) => {
            for value in values {
                validate_json_shape(value, depth + 1, nodes)?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                if key.len() > 256 || key.chars().any(char::is_control) {
                    return Err(EmailError::ContextLimit);
                }
                validate_json_shape(value, depth + 1, nodes)?;
            }
        }
        Value::String(value) if value.len() > ABSOLUTE_CONTEXT_BYTES => {
            return Err(EmailError::ContextLimit);
        }
        _ => {}
    }
    Ok(())
}

struct CountingWriter {
    written: usize,
    maximum: usize,
}

impl io::Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .written
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("limit"))?;
        if next > self.maximum {
            return Err(io::Error::other("limit"));
        }
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_serialized_len(value: &Value, maximum: usize) -> Result<usize, EmailError> {
    let mut writer = CountingWriter {
        written: 0,
        maximum,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| EmailError::ContextLimit)?;
    Ok(writer.written)
}

/// A caller-identified template delivery request. Rendering happens only inside the service.
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub struct SendEmailRequest {
    idempotency_key: IdempotencyKey,
    client_message_id: ClientMessageId,
    from: MailboxAddress,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reply_to: Option<MailboxAddress>,
    recipients: RecipientSet,
    subject: EmailSubject,
    template: TemplateName,
    context: TemplateContext,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    headers: Vec<CustomHeader>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attachments: Vec<EmailAttachment>,
}

impl SendEmailRequest {
    /// Creates a delivery request without optional headers or attachments.
    ///
    /// `client_message_id` must be created once for the durable effect and reused by every retry.
    #[must_use]
    pub const fn new(
        idempotency_key: IdempotencyKey,
        client_message_id: ClientMessageId,
        from: MailboxAddress,
        recipients: RecipientSet,
        subject: EmailSubject,
        template: TemplateName,
        context: TemplateContext,
    ) -> Self {
        Self {
            idempotency_key,
            client_message_id,
            from,
            reply_to: None,
            recipients,
            subject,
            template,
            context,
            headers: Vec::new(),
            attachments: Vec::new(),
        }
    }

    /// Sets an optional reply-to mailbox.
    #[must_use]
    pub fn with_reply_to(mut self, reply_to: MailboxAddress) -> Self {
        self.reply_to = Some(reply_to);
        self
    }

    /// Sets absolutely bounded extension headers.
    ///
    /// # Errors
    ///
    /// Returns [`EmailError::HeaderLimit`] for excessive count or aggregate bytes.
    pub fn with_headers(mut self, headers: Vec<CustomHeader>) -> Result<Self, EmailError> {
        validate_absolute_headers(&headers)?;
        self.headers = headers;
        Ok(self)
    }

    /// Sets absolutely bounded attachments.
    ///
    /// # Errors
    ///
    /// Returns [`EmailError::AttachmentLimit`] for excessive count or aggregate bytes.
    pub fn with_attachments(
        mut self,
        attachments: Vec<EmailAttachment>,
    ) -> Result<Self, EmailError> {
        validate_absolute_attachments(&attachments)?;
        self.attachments = attachments;
        Ok(self)
    }

    /// Caller idempotency key. SMTP remains at-least-once and may duplicate after ambiguous failure.
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
    /// Persisted client submission identifier. Retries must reuse this value unchanged.
    #[must_use]
    pub const fn client_message_id(&self) -> &ClientMessageId {
        &self.client_message_id
    }

    /// Selected registered template key.
    #[must_use]
    pub const fn template(&self) -> &TemplateName {
        &self.template
    }

    /// Recipient count without exposing mailbox values.
    #[must_use]
    pub fn recipient_count(&self) -> usize {
        self.recipients.len()
    }

    /// Attachment count without exposing filenames or content.
    #[must_use]
    pub fn attachment_count(&self) -> usize {
        self.attachments.len()
    }

    pub(crate) fn validate_limits(&self, limits: &crate::EmailLimits) -> Result<(), EmailError> {
        if self.recipients.len() > usize::from(limits.max_recipients) {
            return Err(EmailError::RecipientLimit);
        }
        if self.subject.as_str().len() > usize::from(limits.max_subject_bytes) {
            return Err(EmailError::InvalidHeader);
        }
        let max_context_bytes =
            usize::try_from(limits.max_context_bytes).map_err(|_| EmailError::Config)?;
        if self.context.serialized_bytes() > max_context_bytes {
            return Err(EmailError::ContextLimit);
        }
        validate_configured_headers(&self.headers, limits)?;
        validate_configured_attachments(&self.attachments, limits)
    }
    pub(crate) fn validate_custom_headers(
        &self,
        policy: &crate::CustomHeaderPolicy,
    ) -> Result<(), EmailError> {
        for (index, header) in self.headers.iter().enumerate() {
            if !policy.allows(&header.name)
                || self.headers[..index].iter().any(|prior| {
                    prior
                        .name
                        .as_str()
                        .eq_ignore_ascii_case(header.name.as_str())
                })
            {
                return Err(EmailError::InvalidHeader);
            }
        }
        Ok(())
    }

    pub(crate) fn into_parts(self) -> SendEmailParts {
        SendEmailParts {
            from: self.from,
            reply_to: self.reply_to,
            recipients: self.recipients,
            subject: self.subject,
            template: self.template,
            context: self.context,
            headers: self.headers,
            attachments: self.attachments,
        }
    }
}

impl<'de> Deserialize<'de> for SendEmailRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            idempotency_key: IdempotencyKey,
            client_message_id: ClientMessageId,
            from: MailboxAddress,
            #[serde(default)]
            reply_to: Option<MailboxAddress>,
            recipients: RecipientSet,
            subject: EmailSubject,
            template: TemplateName,
            context: TemplateContext,
            #[serde(default)]
            headers: BoundedVec<CustomHeader, ABSOLUTE_HEADERS>,
            #[serde(default)]
            attachments: BoundedVec<EmailAttachment, ABSOLUTE_ATTACHMENTS>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let mut request = Self::new(
            wire.idempotency_key,
            wire.client_message_id,
            wire.from,
            wire.recipients,
            wire.subject,
            wire.template,
            wire.context,
        );
        request.reply_to = wire.reply_to;
        request = request
            .with_headers(wire.headers.into_inner())
            .map_err(|_| D::Error::custom("email header set exceeds its limit"))?;
        request
            .with_attachments(wire.attachments.into_inner())
            .map_err(|_| D::Error::custom("email attachments exceed their limit"))
    }
}

impl fmt::Debug for SendEmailRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SendEmailRequest")
            .field("idempotency_key", &"[REDACTED]")
            .field("client_message_id", &"[REDACTED]")
            .field("mailboxes", &"[REDACTED]")
            .field("subject", &"[REDACTED]")
            .field("template", &self.template)
            .field("context", &"[REDACTED]")
            .field("recipient_count", &self.recipients.len())
            .field("header_count", &self.headers.len())
            .field("attachment_count", &self.attachments.len())
            .finish_non_exhaustive()
    }
}

pub(crate) struct SendEmailParts {
    pub from: MailboxAddress,
    pub reply_to: Option<MailboxAddress>,
    pub recipients: RecipientSet,
    pub subject: EmailSubject,
    pub template: TemplateName,
    pub context: TemplateContext,
    pub headers: Vec<CustomHeader>,
    pub attachments: Vec<EmailAttachment>,
}

fn validate_absolute_headers(headers: &[CustomHeader]) -> Result<(), EmailError> {
    if headers.len() > ABSOLUTE_HEADERS {
        return Err(EmailError::HeaderLimit);
    }
    let bytes = headers.iter().try_fold(0_usize, |total, header| {
        total
            .checked_add(header.name.as_str().len())
            .and_then(|total| total.checked_add(header.value.as_str().len()))
            .ok_or(EmailError::HeaderLimit)
    })?;
    if bytes > 32 * 1024 {
        return Err(EmailError::HeaderLimit);
    }
    Ok(())
}

fn validate_configured_headers(
    headers: &[CustomHeader],
    limits: &crate::EmailLimits,
) -> Result<(), EmailError> {
    if headers.len() > usize::from(limits.max_headers) {
        return Err(EmailError::HeaderLimit);
    }
    let bytes = headers.iter().try_fold(0_usize, |total, header| {
        total
            .checked_add(header.name.as_str().len())
            .and_then(|total| total.checked_add(header.value.as_str().len()))
            .ok_or(EmailError::HeaderLimit)
    })?;
    let max_header_bytes =
        usize::try_from(limits.max_header_bytes).map_err(|_| EmailError::Config)?;
    if bytes > max_header_bytes {
        return Err(EmailError::HeaderLimit);
    }
    Ok(())
}

fn validate_absolute_attachments(attachments: &[EmailAttachment]) -> Result<(), EmailError> {
    if attachments.len() > ABSOLUTE_ATTACHMENTS {
        return Err(EmailError::AttachmentLimit);
    }
    let bytes = attachments.iter().try_fold(0_usize, |total, attachment| {
        total
            .checked_add(attachment.len())
            .ok_or(EmailError::AttachmentLimit)
    })?;
    if bytes > ABSOLUTE_ATTACHMENT_TOTAL_BYTES {
        return Err(EmailError::AttachmentLimit);
    }
    Ok(())
}

fn validate_configured_attachments(
    attachments: &[EmailAttachment],
    limits: &crate::EmailLimits,
) -> Result<(), EmailError> {
    let max_attachment_bytes =
        usize::try_from(limits.max_attachment_bytes).map_err(|_| EmailError::Config)?;
    if attachments.len() > usize::from(limits.max_attachments)
        || attachments
            .iter()
            .any(|attachment| attachment.len() > max_attachment_bytes)
    {
        return Err(EmailError::AttachmentLimit);
    }
    let bytes = attachments.iter().try_fold(0_usize, |total, attachment| {
        total
            .checked_add(attachment.len())
            .ok_or(EmailError::AttachmentLimit)
    })?;
    let max_total_bytes =
        usize::try_from(limits.max_attachment_total_bytes).map_err(|_| EmailError::Config)?;
    if bytes > max_total_bytes {
        return Err(EmailError::AttachmentLimit);
    }
    Ok(())
}
