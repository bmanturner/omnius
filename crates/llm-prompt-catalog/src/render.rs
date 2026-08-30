use std::{fmt, io};

use minijinja::{AutoEscape, Environment, UndefinedBehavior};
use omnius_llm_core::{ContractError, LlmInputPart, LlmMessage, MessageRole, TextInputPart};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    ContentDigest, PromptId, PromptRevision, PromptRevisionNumber, PromptStatus, UntrustedText,
};

const FIXED_MAX_VARIABLE_BYTES: usize = 262_144;
const FIXED_MAX_VARIABLE_NODES: usize = 16_384;
const FIXED_MAX_VARIABLE_DEPTH: usize = 32;
const FIXED_MAX_STRING_BYTES: usize = 65_536;
const FIXED_MAX_OUTPUT_BYTES: usize = 262_144;
const FIXED_MAX_FUEL: u64 = 5_000_000;
const FIXED_RECURSION_LIMIT: usize = 32;

/// Explicit rendering resource boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenderLimits {
    max_variable_bytes: usize,
    max_variable_nodes: usize,
    max_variable_depth: usize,
    max_string_bytes: usize,
    max_output_bytes_per_channel: usize,
    fuel: u64,
}

impl RenderLimits {
    /// Creates rendering limits within hard process ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError::InvalidLimits`] for zero or above-ceiling values.
    pub fn new(
        max_variable_bytes: usize,
        max_variable_nodes: usize,
        max_variable_depth: usize,
        max_string_bytes: usize,
        max_output_bytes_per_channel: usize,
        fuel: u64,
    ) -> Result<Self, RenderError> {
        if max_variable_bytes == 0
            || max_variable_bytes > FIXED_MAX_VARIABLE_BYTES
            || max_variable_nodes == 0
            || max_variable_nodes > FIXED_MAX_VARIABLE_NODES
            || max_variable_depth == 0
            || max_variable_depth > FIXED_MAX_VARIABLE_DEPTH
            || max_string_bytes == 0
            || max_string_bytes > FIXED_MAX_STRING_BYTES
            || max_output_bytes_per_channel == 0
            || max_output_bytes_per_channel > FIXED_MAX_OUTPUT_BYTES
            || fuel == 0
            || fuel > FIXED_MAX_FUEL
        {
            return Err(RenderError::InvalidLimits);
        }
        Ok(Self {
            max_variable_bytes,
            max_variable_nodes,
            max_variable_depth,
            max_string_bytes,
            max_output_bytes_per_channel,
            fuel,
        })
    }
}

impl Default for RenderLimits {
    fn default() -> Self {
        Self {
            max_variable_bytes: 65_536,
            max_variable_nodes: 4_096,
            max_variable_depth: 16,
            max_string_bytes: 16_384,
            max_output_bytes_per_channel: 65_536,
            fuel: 100_000,
        }
    }
}

/// Trusted rendered instruction text that never receives the untrusted variable context.
#[derive(Clone, Eq, PartialEq)]
pub struct PrivilegedInstruction(String);

impl PrivilegedInstruction {
    /// Borrows trusted instruction text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PrivilegedInstruction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivilegedInstruction([REDACTED])")
    }
}

/// A rendered prompt whose privileged instructions and untrusted data remain separate.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderedPrompt {
    prompt_id: PromptId,
    revision: PromptRevisionNumber,
    content_digest: ContentDigest,
    system: Option<PrivilegedInstruction>,
    developer: Option<PrivilegedInstruction>,
    user: UntrustedText,
}

impl RenderedPrompt {
    /// Borrows the stable prompt identifier.
    #[must_use]
    pub const fn prompt_id(&self) -> &PromptId {
        &self.prompt_id
    }

    /// Returns the immutable prompt revision.
    #[must_use]
    pub const fn revision(&self) -> PromptRevisionNumber {
        self.revision
    }

    /// Returns the bound prompt content digest.
    #[must_use]
    pub const fn content_digest(&self) -> ContentDigest {
        self.content_digest
    }

    /// Borrows optional system instructions.
    #[must_use]
    pub const fn system(&self) -> Option<&PrivilegedInstruction> {
        self.system.as_ref()
    }

    /// Borrows optional developer instructions.
    #[must_use]
    pub const fn developer(&self) -> Option<&PrivilegedInstruction> {
        self.developer.as_ref()
    }

    /// Borrows rendered untrusted user data.
    #[must_use]
    pub const fn user(&self) -> &UntrustedText {
        &self.user
    }

    /// Converts channels to canonical messages without concatenating trust domains.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] if canonical LLM message validation rejects a part.
    pub fn into_messages(self) -> Result<Vec<LlmMessage>, ContractError> {
        let mut messages = Vec::with_capacity(
            1 + usize::from(self.system.is_some()) + usize::from(self.developer.is_some()),
        );
        if let Some(system) = self.system {
            messages.push(text_message(MessageRole::System, system.0)?);
        }
        if let Some(developer) = self.developer {
            messages.push(text_message(MessageRole::Developer, developer.0)?);
        }
        messages.push(text_message(MessageRole::User, self.user.into())?);
        Ok(messages)
    }
}

impl fmt::Debug for RenderedPrompt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedPrompt")
            .field("prompt_id", &self.prompt_id)
            .field("revision", &self.revision)
            .field("content_digest", &self.content_digest)
            .field("system", &self.system)
            .field("developer", &self.developer)
            .field("user", &self.user)
            .finish()
    }
}

fn text_message(role: MessageRole, text: String) -> Result<LlmMessage, ContractError> {
    LlmMessage::new(role, vec![LlmInputPart::Text(TextInputPart::new(text))])
}

/// A compiled, strict renderer for one exact published prompt revision.
pub struct PromptRenderer {
    environment: Environment<'static>,
    input_schema: Value,
    prompt_id: PromptId,
    revision: PromptRevisionNumber,
    content_digest: ContentDigest,
    has_system: bool,
    has_developer: bool,
    limits: RenderLimits,
}

impl PromptRenderer {
    /// Compiles one published revision with strict variables, bounded recursion, and fuel.
    ///
    /// Privileged templates are rejected if they reference variables. This ensures retrieved,
    /// tool, model, and caller values can only enter the user-data channel.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`RenderError`] for a non-published revision, invalid syntax,
    /// variables referenced by privileged templates, or user variables absent from the schema.
    pub fn compile(revision: &PromptRevision, limits: RenderLimits) -> Result<Self, RenderError> {
        if revision.status() != PromptStatus::Published {
            return Err(RenderError::NotPublished);
        }
        let templates = revision.body().templates();
        let mut environment = Environment::new();
        environment.set_undefined_behavior(UndefinedBehavior::Strict);
        environment.set_auto_escape_callback(|_| AutoEscape::None);
        environment.set_fuel(Some(limits.fuel));
        environment.set_recursion_limit(FIXED_RECURSION_LIMIT);
        environment.set_keep_trailing_newline(true);

        if let Some(source) = templates.system() {
            environment
                .add_template_owned("system", source.to_owned())
                .map_err(|_| RenderError::InvalidTemplate)?;
        }
        if let Some(source) = templates.developer() {
            environment
                .add_template_owned("developer", source.to_owned())
                .map_err(|_| RenderError::InvalidTemplate)?;
        }
        environment
            .add_template_owned("user", templates.user().to_owned())
            .map_err(|_| RenderError::InvalidTemplate)?;

        for name in ["system", "developer"] {
            if environment
                .get_template(name)
                .is_ok_and(|template| !template.undeclared_variables(true).is_empty())
            {
                return Err(RenderError::PrivilegedVariable);
            }
        }
        let user = environment
            .get_template("user")
            .map_err(|_| RenderError::InvalidTemplate)?;
        let user_variables = user.undeclared_variables(true);
        if !user_variables.is_empty() {
            let declared = revision
                .body()
                .input_schema()
                .get("properties")
                .and_then(Value::as_object)
                .ok_or(RenderError::UndeclaredVariable)?;
            if user_variables.iter().any(|variable| {
                !declared.contains_key(variable.as_str())
                    && !environment
                        .globals()
                        .any(|(global, _)| global == variable.as_str())
            }) {
                return Err(RenderError::UndeclaredVariable);
            }
        }

        Ok(Self {
            environment,
            input_schema: revision.body().input_schema().clone(),
            prompt_id: revision.id().clone(),
            revision: revision.revision(),
            content_digest: revision.content_digest(),
            has_system: templates.system().is_some(),
            has_developer: templates.developer().is_some(),
            limits,
        })
    }

    /// Validates bounded typed variables and renders all channels independently.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`RenderError`] for size, schema, fuel, strict-variable, or output
    /// failures. No prompt, schema, variable, or rendered value is retained in the error.
    pub fn render(&self, variables: &Value) -> Result<RenderedPrompt, RenderError> {
        if !variables.is_object() {
            return Err(RenderError::VariablesStructure);
        }
        let encoded = serde_json::to_vec(variables).map_err(|_| RenderError::VariablesStructure)?;
        if encoded.len() > self.limits.max_variable_bytes {
            return Err(RenderError::VariablesLimit);
        }
        let mut nodes = 0_usize;
        validate_variables(variables, 0, &mut nodes, self.limits)?;
        let validator = jsonschema::draft202012::options()
            .build(&self.input_schema)
            .map_err(|_| RenderError::InvalidSchema)?;
        if !validator.is_valid(variables) {
            return Err(RenderError::SchemaMismatch);
        }

        let empty = Value::Object(Map::default());
        let system = self
            .has_system
            .then(|| self.render_channel("system", &empty))
            .transpose()?
            .map(PrivilegedInstruction);
        let developer = self
            .has_developer
            .then(|| self.render_channel("developer", &empty))
            .transpose()?
            .map(PrivilegedInstruction);
        let user = UntrustedText::new(self.render_channel("user", variables)?)
            .map_err(|_| RenderError::OutputLimit)?;
        Ok(RenderedPrompt {
            prompt_id: self.prompt_id.clone(),
            revision: self.revision,
            content_digest: self.content_digest,
            system,
            developer,
            user,
        })
    }

    fn render_channel(&self, name: &str, variables: &Value) -> Result<String, RenderError> {
        let template = self
            .environment
            .get_template(name)
            .map_err(|_| RenderError::InvalidTemplate)?;
        let mut output = BoundedOutput::new(self.limits.max_output_bytes_per_channel);
        let result = template.render_captured_to(variables, &mut output);
        if output.exceeded {
            return Err(RenderError::OutputLimit);
        }
        result.map_err(|_| RenderError::TemplateEvaluation)?;
        String::from_utf8(output.bytes).map_err(|_| RenderError::TemplateEvaluation)
    }
}

impl fmt::Debug for PromptRenderer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptRenderer")
            .field("prompt_id", &self.prompt_id)
            .field("revision", &self.revision)
            .field("content_digest", &self.content_digest)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// A value-free prompt compilation or rendering failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RenderError {
    /// A production renderer was requested for a draft or deprecated revision.
    #[error("prompt revision is not published")]
    NotPublished,
    /// A rendering limit was zero or above a hard ceiling.
    #[error("prompt rendering limits are invalid")]
    InvalidLimits,
    /// A catalog schema could not be compiled at the rendering boundary.
    #[error("prompt input schema is invalid")]
    InvalidSchema,
    /// A template could not be compiled or retrieved.
    #[error("prompt template is invalid")]
    InvalidTemplate,
    /// A privileged instruction template referenced caller-controlled variables.
    #[error("privileged prompt templates cannot reference variables")]
    PrivilegedVariable,
    /// A user-data template referenced a variable absent from the input schema.
    #[error("prompt template references an undeclared variable")]
    UndeclaredVariable,
    /// Variables were not represented by a JSON object.
    #[error("prompt variables have an invalid structure")]
    VariablesStructure,
    /// Variables exceeded fixed byte, node, depth, or string boundaries.
    #[error("prompt variables exceed their limits")]
    VariablesLimit,
    /// Variables did not satisfy the revision's JSON Schema.
    #[error("prompt variables do not match the input schema")]
    SchemaMismatch,
    /// `MiniJinja` strict evaluation or fuel accounting stopped the render.
    #[error("prompt template evaluation failed")]
    TemplateEvaluation,
    /// A rendered channel exceeded its byte boundary.
    #[error("rendered prompt exceeds its output limit")]
    OutputLimit,
}

fn validate_variables(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
    limits: RenderLimits,
) -> Result<(), RenderError> {
    *nodes = nodes.checked_add(1).ok_or(RenderError::VariablesLimit)?;
    if depth > limits.max_variable_depth || *nodes > limits.max_variable_nodes {
        return Err(RenderError::VariablesLimit);
    }
    match value {
        Value::String(string) if string.len() > limits.max_string_bytes => {
            Err(RenderError::VariablesLimit)
        }
        Value::Array(array) => {
            for child in array {
                validate_variables(child, depth + 1, nodes, limits)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            for (key, child) in object {
                if key.len() > limits.max_string_bytes {
                    return Err(RenderError::VariablesLimit);
                }
                validate_variables(child, depth + 1, nodes, limits)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
    }
}

struct BoundedOutput {
    bytes: Vec<u8>,
    maximum: usize,
    exceeded: bool,
}

impl BoundedOutput {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum.min(8 * 1024)),
            maximum,
            exceeded: false,
        }
    }
}

impl io::Write for BoundedOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("render output limit"))?;
        if next > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other("render output limit"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
