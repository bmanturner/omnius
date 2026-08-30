use std::fmt;

use omnius_jobs_core::JobId;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use time::OffsetDateTime;

use crate::{
    ConversationContractError, ConversationId, ConversationRevision, DefinitionRevision,
    value::validate_utc,
};

const MAX_DEFINITION_ID_BYTES: usize = 128;
const MAX_TOOL_REFERENCES: usize = 64;

fn definition_id_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DEFINITION_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'/' | b'.' | b'_' | b'-')
        })
}

macro_rules! definition_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validates and owns a bounded portable definition identity.
            ///
            /// # Errors
            ///
            /// Returns [`ConversationContractError::InvalidJobSnapshot`] for empty,
            /// oversized, or non-portable input.
            pub fn new(value: impl Into<String>) -> Result<Self, ConversationContractError> {
                let value = value.into();
                if definition_id_is_valid(&value) {
                    Ok(Self(value))
                } else {
                    Err(ConversationContractError::InvalidJobSnapshot)
                }
            }

            /// Borrows the stable definition identity.
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

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }
    };
}

definition_id!(
    PromptDefinitionId,
    "A stable versioned prompt-definition identity."
);
definition_id!(
    RouteDefinitionId,
    "A stable versioned model-route definition identity."
);
definition_id!(
    SchemaDefinitionId,
    "A stable versioned structured-output schema identity."
);
definition_id!(
    ToolDefinitionId,
    "A stable versioned tool definition identity."
);

macro_rules! revision_reference {
    ($name:ident, $id:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        pub struct $name {
            id: $id,
            revision: DefinitionRevision,
        }

        impl $name {
            /// Creates one immutable definition revision reference.
            #[must_use]
            pub const fn new(id: $id, revision: DefinitionRevision) -> Self {
                Self { id, revision }
            }

            /// Borrows the stable definition identity.
            #[must_use]
            pub const fn id(&self) -> &$id {
                &self.id
            }

            /// Returns the exact snapshotted definition revision.
            #[must_use]
            pub const fn revision(&self) -> DefinitionRevision {
                self.revision
            }
        }
    };
}

revision_reference!(
    PromptRevisionReference,
    PromptDefinitionId,
    "An immutable prompt identity and revision used by a durable job."
);
revision_reference!(
    RouteRevisionReference,
    RouteDefinitionId,
    "An immutable route identity and revision used by a durable job."
);
revision_reference!(
    SchemaRevisionReference,
    SchemaDefinitionId,
    "An immutable output-schema identity and revision used by a durable job."
);
revision_reference!(
    ToolRevisionReference,
    ToolDefinitionId,
    "An immutable tool identity and revision used by a durable job."
);

/// A complete immutable reference snapshot captured before durable LLM job enqueue.
///
/// The snapshot intentionally owns only definition identities and revisions. Prompt content,
/// provider models, schemas, tool payloads, and provider wire types cannot enter this value.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct DurableJobReferenceSnapshot {
    conversation_id: ConversationId,
    job_id: JobId,
    prompt: PromptRevisionReference,
    route: RouteRevisionReference,
    #[serde(skip_serializing_if = "Option::is_none")]
    schema: Option<SchemaRevisionReference>,
    tools: Vec<ToolRevisionReference>,
    captured_at: OffsetDateTime,
}

impl DurableJobReferenceSnapshot {
    /// Creates a bounded durable job reference snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidJobSnapshot`] for more than 64 tool
    /// references or duplicate tool identities, and a content-free timeline error for a
    /// non-UTC capture instant.
    pub fn new(
        conversation_id: ConversationId,
        job_id: JobId,
        prompt: PromptRevisionReference,
        route: RouteRevisionReference,
        schema: Option<SchemaRevisionReference>,
        tools: Vec<ToolRevisionReference>,
        captured_at: OffsetDateTime,
    ) -> Result<Self, ConversationContractError> {
        validate_utc(captured_at)?;
        if tools.len() > MAX_TOOL_REFERENCES {
            return Err(ConversationContractError::InvalidJobSnapshot);
        }
        let mut tool_ids = tools
            .iter()
            .map(ToolRevisionReference::id)
            .collect::<Vec<_>>();
        tool_ids.sort_unstable();
        if tool_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ConversationContractError::InvalidJobSnapshot);
        }
        Ok(Self {
            conversation_id,
            job_id,
            prompt,
            route,
            schema,
            tools,
            captured_at,
        })
    }

    /// Returns the conversation identity captured for the job.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the canonical durable job identity.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Borrows the exact prompt revision reference.
    #[must_use]
    pub const fn prompt(&self) -> &PromptRevisionReference {
        &self.prompt
    }

    /// Borrows the exact route revision reference.
    #[must_use]
    pub const fn route(&self) -> &RouteRevisionReference {
        &self.route
    }

    /// Borrows the optional exact output-schema revision reference.
    #[must_use]
    pub const fn schema(&self) -> Option<&SchemaRevisionReference> {
        self.schema.as_ref()
    }

    /// Borrows the ordered exact tool revision references.
    #[must_use]
    pub fn tools(&self) -> &[ToolRevisionReference] {
        &self.tools
    }

    /// Returns the UTC capture instant.
    #[must_use]
    pub const fn captured_at(&self) -> OffsetDateTime {
        self.captured_at
    }
}

impl fmt::Debug for DurableJobReferenceSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableJobReferenceSnapshot")
            .field("conversation_id", &self.conversation_id)
            .field("job_id", &self.job_id)
            .field("prompt", &self.prompt)
            .field("route", &self.route)
            .field("schema", &self.schema)
            .field("tool_count", &self.tools.len())
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableJobReferenceSnapshotWire {
    conversation_id: ConversationId,
    job_id: JobId,
    prompt: PromptRevisionReference,
    route: RouteRevisionReference,
    schema: Option<SchemaRevisionReference>,
    tools: Vec<ToolRevisionReference>,
    captured_at: OffsetDateTime,
}

impl<'de> Deserialize<'de> for DurableJobReferenceSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = DurableJobReferenceSnapshotWire::deserialize(deserializer)?;
        Self::new(
            wire.conversation_id,
            wire.job_id,
            wire.prompt,
            wire.route,
            wire.schema,
            wire.tools,
            wire.captured_at,
        )
        .map_err(D::Error::custom)
    }
}

/// A version-checked command to record an immutable durable job reference snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SaveJobReferenceSnapshot {
    expected_conversation_revision: ConversationRevision,
    snapshot: DurableJobReferenceSnapshot,
}

impl SaveJobReferenceSnapshot {
    /// Creates an immutable snapshot persistence command.
    #[must_use]
    pub const fn new(
        expected_conversation_revision: ConversationRevision,
        snapshot: DurableJobReferenceSnapshot,
    ) -> Self {
        Self {
            expected_conversation_revision,
            snapshot,
        }
    }

    /// Returns the expected conversation revision.
    #[must_use]
    pub const fn expected_conversation_revision(&self) -> ConversationRevision {
        self.expected_conversation_revision
    }

    /// Borrows the immutable owned snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &DurableJobReferenceSnapshot {
        &self.snapshot
    }
}
