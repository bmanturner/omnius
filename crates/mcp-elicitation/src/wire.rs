use std::collections::BTreeMap;
use std::fmt;

use rmcp::model::{
    ClientCapabilities, ElicitRequest, ElicitRequestParams, ElicitationSchema, InputRequest,
    InputRequiredResult,
};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::model::{
    ClientElicitationCapabilities, ElicitationChallenge, InputResponseMap, PlannedElicitation,
};

const MAX_INPUT_RESPONSES_BYTES: usize = 1024 * 1024;

/// Failure at the adapter-private RMCP wire boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WireError {
    /// A previously validated plan could not be represented by current RMCP types.
    #[error("elicitation plan is not representable by the current MCP protocol")]
    InvalidPlan,
    /// A validated JSON Schema changed when adapted through the RMCP form schema type.
    #[error("elicitation schema is not losslessly representable by the current MCP protocol")]
    LossySchema,
    /// `inputResponses` was malformed, duplicated a key, or exceeded its byte bound.
    #[error("MCP input responses are invalid")]
    InvalidResponses,
}

/// Converts one transport-neutral challenge into pinned current RMCP wire types.
///
/// # Errors
///
/// Returns a redacted error if a validated plan is not exactly representable by current RMCP
/// types or if the form schema changes during an RMCP JSON round trip.
pub fn to_rmcp_input_required(
    challenge: &ElicitationChallenge,
) -> Result<InputRequiredResult, WireError> {
    let mut requests = BTreeMap::new();
    for (key, request) in challenge.plan.requests() {
        let params = match request {
            PlannedElicitation::Form(form) => {
                let schema_object = form
                    .schema()
                    .as_object()
                    .cloned()
                    .ok_or(WireError::InvalidPlan)?;
                let requested_schema = ElicitationSchema::from_json_schema(schema_object)
                    .map_err(|_| WireError::InvalidPlan)?;
                let converted_schema =
                    serde_json::to_value(&requested_schema).map_err(|_| WireError::LossySchema)?;
                if &converted_schema != form.schema() {
                    return Err(WireError::LossySchema);
                }
                ElicitRequestParams::FormElicitationParams {
                    meta: None,
                    message: form.message().to_owned(),
                    requested_schema,
                }
            }
            PlannedElicitation::Url(url) => ElicitRequestParams::UrlElicitationParams {
                meta: None,
                message: url.message().to_owned(),
                url: url.url().as_str().to_owned(),
                elicitation_id: url.elicitation_id().to_owned(),
            },
        };
        requests.insert(
            key.as_str().to_owned(),
            InputRequest::Elicitation(ElicitRequest::new(params)),
        );
    }
    Ok(InputRequiredResult::new(
        Some(requests),
        Some(challenge.request_state.expose_for_wire().to_owned()),
    ))
}

/// Extracts only client-advertised elicitation modes from pinned RMCP capabilities.
#[must_use]
pub fn client_elicitation_capabilities_from_rmcp(
    capabilities: &ClientCapabilities,
) -> ClientElicitationCapabilities {
    let elicitation = capabilities.elicitation.as_ref();
    let form = elicitation.and_then(|capability| capability.form.as_ref());
    let url = elicitation.is_some_and(|capability| capability.url.is_some());
    match (form, url) {
        (Some(form), true) => {
            ClientElicitationCapabilities::form_and_url(form.schema_validation.unwrap_or(false))
        }
        (Some(form), false) => {
            ClientElicitationCapabilities::form(form.schema_validation.unwrap_or(false))
        }
        (None, true) => ClientElicitationCapabilities::url(),
        (None, false) => ClientElicitationCapabilities::default(),
    }
}

/// Parses raw `inputResponses` while rejecting duplicate outer keys before a map can erase them.
///
/// # Errors
///
/// Returns [`WireError::InvalidResponses`] for malformed, duplicate, or oversized input.
pub fn parse_input_responses(bytes: &[u8]) -> Result<InputResponseMap, WireError> {
    if bytes.len() > MAX_INPUT_RESPONSES_BYTES {
        return Err(WireError::InvalidResponses);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let parsed = DuplicateAwareResponses::deserialize(&mut deserializer)
        .map_err(|_| WireError::InvalidResponses)?;
    deserializer
        .end()
        .map_err(|_| WireError::InvalidResponses)?;
    Ok(parsed.0)
}

struct DuplicateAwareResponses(InputResponseMap);

impl<'de> Deserialize<'de> for DuplicateAwareResponses {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ResponseVisitor)
    }
}

struct ResponseVisitor;

impl<'de> Visitor<'de> for ResponseVisitor {
    type Value = DuplicateAwareResponses;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object of uniquely keyed MCP input responses")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut responses = BTreeMap::new();
        while let Some((key, value)) = map.next_entry::<String, Value>()? {
            if responses.insert(key, value).is_some() {
                return Err(serde::de::Error::custom("duplicate input response key"));
            }
        }
        Ok(DuplicateAwareResponses(responses))
    }
}
