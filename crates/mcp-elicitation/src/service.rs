use omnius_agent_capability_registry::ConfirmationEvidence;
use omnius_mcp_server_core::McpRequestContext;
use rmcp::model::{ElicitResult, ElicitationAction, RequestStateCodec, SealOptions};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::{
    ArgumentObjectShape, ClaimResult, ClientElicitationCapabilities, ElicitationChallenge,
    ElicitationPlan, InputResponseMap, InvocationContinuation, InvocationDisposition,
    MRTR_EXTENSION_ID, MRTR_EXTENSION_REVISION, MrtrAuditEvent, MrtrAuditKind, MrtrConfig,
    MrtrCorrelation, NormalInvocationRequest, OriginalInvocation, PendingMrtrState, PlanError,
    PlannedElicitation, ReplacementReason, RequestStateToken, ResumeOutcome, StateBinding,
    StateClaim, TerminalStatus, argument_object_shape, set_object_pointer,
    validate_mapping_parents, validate_mapping_shape,
};
use crate::ports::{InvocationError, MrtrStateRepository, NormalInvocationPort, RepositoryError};
use crate::state::{canonical_arguments_digest, state_binding};

const TOKEN_FORMAT_VERSION: u8 = 1;
const MAX_REQUEST_STATE_BYTES: usize = 512;

/// Initial lifecycle request from MCP server core.
pub struct BeginRequest {
    /// Fresh canonical request context with exact extension negotiation.
    pub context: McpRequestContext,
    /// Client-advertised elicitation modes for this request.
    pub client_capabilities: ClientElicitationCapabilities,
    /// Server-authenticated confirmation evidence for this invocation.
    pub confirmation_evidence: ConfirmationEvidence,
    /// Original current capability invocation.
    pub invocation: OriginalInvocation,
    /// Explicit bounded input plan.
    pub plan: ElicitationPlan,
}

impl std::fmt::Debug for BeginRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BeginRequest")
            .field("context", &self.context)
            .field("client_capabilities", &self.client_capabilities)
            .field("confirmation_evidence", &self.confirmation_evidence)
            .field("invocation", &self.invocation)
            .field("plan", &self.plan)
            .finish()
    }
}

/// Retry request from MCP server core.
pub struct ResumeRequest {
    /// Fresh canonical request context with exact extension negotiation.
    pub context: McpRequestContext,
    /// Client-advertised elicitation modes for this request.
    pub client_capabilities: ClientElicitationCapabilities,
    /// Fresh server-authenticated confirmation evidence for this retry.
    pub confirmation_evidence: ConfirmationEvidence,
    /// Original operation reconstructed from the current retry request.
    pub invocation: OriginalInvocation,
    /// Echoed untrusted request state.
    pub request_state: String,
    /// Raw keyed client results after duplicate-aware parsing.
    pub input_responses: InputResponseMap,
}

impl std::fmt::Debug for ResumeRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResumeRequest")
            .field("context", &self.context)
            .field("client_capabilities", &self.client_capabilities)
            .field("confirmation_evidence", &self.confirmation_evidence)
            .field("invocation", &self.invocation)
            .field("request_state", &"[REDACTED]")
            .field("input_responses", &"[REDACTED]")
            .finish()
    }
}

/// Safe lifecycle failure. State existence and binding details are intentionally collapsed.
#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    /// Composition left the extension disabled.
    #[error("MRTR elicitation is disabled")]
    Disabled,
    /// The current request did not negotiate the exact MRTR extension identifier and revision.
    #[error("the exact MRTR extension was not negotiated for this request")]
    ExtensionNotNegotiated,
    /// A planned elicitation mode was not advertised by the client.
    #[error("the client did not advertise the required elicitation mode")]
    UnsupportedMode,
    /// Sensitive form elicitation requires authoritative explicit confirmation.
    #[error("sensitive form elicitation requires explicit confirmation")]
    ConfirmationRequired,
    /// An invocation identifier, argument document, or plan binding is invalid.
    #[error("MRTR invocation binding is invalid")]
    InvalidInvocation,
    /// Plan validation failed before state issuance.
    #[error(transparent)]
    InvalidPlan(#[from] PlanError),
    /// Forgery, expiry, replay, mismatch, and concurrent loss share one safe result.
    #[error("MRTR request state was rejected")]
    StateRejected,
    /// The authoritative state repository failed closed.
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    /// Normal capability invocation failed after claim.
    #[error(transparent)]
    Invocation(#[from] InvocationError),
}

/// Stateless MRTR lifecycle service backed by one atomic replay/audit port and normal invocation.
pub struct MrtrService<R, I> {
    repository: R,
    invoker: I,
    codec: RequestStateCodec,
    config: MrtrConfig,
}

impl<R, I> std::fmt::Debug for MrtrService<R, I> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MrtrService")
            .field("repository", &std::any::type_name::<R>())
            .field("invoker", &std::any::type_name::<I>())
            .field("codec", &self.codec)
            .field("config", &self.config)
            .finish()
    }
}

impl<R, I> MrtrService<R, I>
where
    R: MrtrStateRepository,
    I: NormalInvocationPort,
{
    /// Constructs a service with a high-entropy stable signing key.
    ///
    /// # Errors
    ///
    /// Returns [`crate::model::ConfigError`] for invalid bounds or a key shorter than 32 bytes.
    pub fn try_new(
        repository: R,
        invoker: I,
        signing_key: impl Into<Vec<u8>>,
        config: MrtrConfig,
    ) -> Result<Self, crate::model::ConfigError> {
        let config = config.validate()?;
        let codec = RequestStateCodec::try_new(signing_key)
            .map_err(|_| crate::model::ConfigError::InvalidSigningKey)?;
        Ok(Self {
            repository,
            invoker,
            codec,
            config,
        })
    }

    /// Validates and durably issues one current-protocol challenge.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] before a usable token is returned when policy or atomic durable
    /// state/audit persistence fails.
    pub async fn begin(
        &self,
        request: BeginRequest,
    ) -> Result<ElicitationChallenge, LifecycleError> {
        let BeginRequest {
            context,
            client_capabilities,
            confirmation_evidence,
            invocation,
            plan,
        } = request;
        self.check_begin_request(&context, client_capabilities, confirmation_evidence, &plan)?;
        if !invocation.binding().validate() {
            return Err(LifecycleError::InvalidInvocation);
        }
        validate_mapping_parents(invocation.arguments(), &plan)?;
        let arguments_digest =
            canonical_arguments_digest(invocation.arguments(), self.config.max_argument_bytes)
                .map_err(|_| LifecycleError::InvalidInvocation)?;
        let binding = state_binding(
            &context,
            invocation.binding(),
            arguments_digest,
            invocation.idempotency_key(),
        );
        let record = self.new_record(binding, plan, None, 1, None)?;
        let event = audit_for_record(&record, MrtrAuditKind::Issued);
        let record = self.repository.create_pending(&record, event).await?;
        let token = self.seal(&record)?;
        Ok(challenge_from(record, token))
    }

    /// Claims, verifies, validates, and resumes one retry exactly once.
    ///
    /// Accepted responses are locally schema-validated and discarded after the normal invocation
    /// call. Decline and cancellation are normal outcomes. Correctable response failures consume
    /// the old state and receive a fresh bounded state unless the round ceiling is reached.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::StateRejected`] without revealing whether state existed for any
    /// forgery, expiry, replay, concurrent claim loss, or binding mismatch.
    #[expect(
        clippy::too_many_lines,
        reason = "the retry state machine keeps claim, validation, reinvocation, and atomic transition ordering visible"
    )]
    pub async fn resume(
        &self,
        request: ResumeRequest,
    ) -> Result<ResumeOutcome<I::Output>, LifecycleError> {
        let ResumeRequest {
            context,
            client_capabilities,
            confirmation_evidence,
            invocation,
            request_state,
            input_responses,
        } = request;
        self.check_request_gate(&context)?;
        if !invocation.binding().validate() {
            return Err(LifecycleError::InvalidInvocation);
        }
        let arguments_digest =
            canonical_arguments_digest(invocation.arguments(), self.config.max_argument_bytes)
                .map_err(|_| LifecycleError::InvalidInvocation)?;
        let expected_binding = state_binding(
            &context,
            invocation.binding(),
            arguments_digest,
            invocation.idempotency_key(),
        );
        if request_state.is_empty() || request_state.len() > MAX_REQUEST_STATE_BYTES {
            self.repository
                .record_untrusted_rejection(untrusted_rejection())
                .await?;
            return Err(LifecycleError::StateRejected);
        }
        let payload = match self.open(&request_state, &expected_binding) {
            Ok(payload) if payload.v == TOKEN_FORMAT_VERSION => payload,
            Ok(_) | Err(()) => {
                self.repository
                    .record_untrusted_rejection(untrusted_rejection())
                    .await?;
                return Err(LifecycleError::StateRejected);
            }
        };

        let now = OffsetDateTime::now_utc();
        let claimed_event = audit_for_binding(
            Some(payload.state_id),
            &expected_binding,
            MrtrAuditKind::Claimed,
            None,
            None,
        );
        let rejected_event = audit_for_binding(
            Some(payload.state_id),
            &expected_binding,
            MrtrAuditKind::StateRejected,
            None,
            None,
        );
        let claimed = match self
            .repository
            .claim_pending(
                StateClaim {
                    state_id: payload.state_id,
                    expected_binding: expected_binding.clone(),
                    now,
                },
                claimed_event,
                rejected_event,
            )
            .await?
        {
            ClaimResult::Claimed(state) => *state,
            ClaimResult::Rejected => return Err(LifecycleError::StateRejected),
        };

        if !valid_claimed_record(&claimed, payload.state_id, &expected_binding, now) {
            self.finish(
                &claimed,
                TerminalStatus::Rejected,
                MrtrAuditKind::StateRejected,
            )
            .await?;
            return Err(LifecycleError::StateRejected);
        }
        if let Err(error) =
            Self::check_modes(client_capabilities, confirmation_evidence, &claimed.plan)
        {
            self.finish(
                &claimed,
                TerminalStatus::Rejected,
                MrtrAuditKind::StateRejected,
            )
            .await?;
            return Err(error);
        }
        if validate_mapping_parents(invocation.arguments(), &claimed.plan).is_err() {
            self.finish(
                &claimed,
                TerminalStatus::Rejected,
                MrtrAuditKind::StateRejected,
            )
            .await?;
            return Err(LifecycleError::StateRejected);
        }

        let (binding, mut arguments, idempotency_key) = invocation.into_parts();
        let original_argument_shape = argument_object_shape(&arguments);
        let Ok(response) = validate_responses(&claimed.plan, input_responses, &mut arguments)
        else {
            return self.retry_after_rejection(claimed).await;
        };

        match response {
            ValidatedResponse::Cancelled => {
                self.finish(
                    &claimed,
                    TerminalStatus::Cancelled,
                    MrtrAuditKind::Cancelled,
                )
                .await?;
                Ok(ResumeOutcome::Cancelled)
            }
            ValidatedResponse::Declined => {
                self.finish(&claimed, TerminalStatus::Declined, MrtrAuditKind::Declined)
                    .await?;
                Ok(ResumeOutcome::Declined)
            }
            ValidatedResponse::Invoke { accepted, declined } => {
                let action = match (accepted, declined) {
                    (true, true) => MrtrAuditKind::PartiallyAccepted,
                    (true, false) => MrtrAuditKind::Accepted,
                    (false, true) => MrtrAuditKind::Declined,
                    (false, false) => {
                        self.finish(
                            &claimed,
                            TerminalStatus::Rejected,
                            MrtrAuditKind::StateRejected,
                        )
                        .await?;
                        return Err(LifecycleError::StateRejected);
                    }
                };
                self.repository
                    .record_claimed(claimed.state_id, audit_for_record(&claimed, action))
                    .await?;
                let normal_request = NormalInvocationRequest {
                    context,
                    binding,
                    arguments,
                    idempotency_key,
                    confirmation_evidence,
                    continuation: claimed.continuation,
                    mrtr: MrtrCorrelation {
                        state_id: claimed.state_id,
                        round: claimed.round,
                    },
                };
                match self.invoker.invoke(normal_request).await {
                    Ok(InvocationDisposition::Complete(output)) => {
                        self.finish(
                            &claimed,
                            TerminalStatus::Completed,
                            MrtrAuditKind::Completed,
                        )
                        .await?;
                        Ok(ResumeOutcome::Complete(output))
                    }
                    Ok(InvocationDisposition::InputRequired { plan, continuation }) => {
                        self.advance(
                            claimed,
                            plan,
                            continuation,
                            &original_argument_shape,
                            client_capabilities,
                            confirmation_evidence,
                        )
                        .await
                    }
                    Err(error) => {
                        self.finish(
                            &claimed,
                            TerminalStatus::InvocationFailed,
                            MrtrAuditKind::InvocationFailed,
                        )
                        .await?;
                        Err(LifecycleError::Invocation(error))
                    }
                }
            }
        }
    }

    fn check_request_gate(&self, context: &McpRequestContext) -> Result<(), LifecycleError> {
        if !self.config.enabled {
            return Err(LifecycleError::Disabled);
        }
        let negotiated = context
            .negotiated_extensions()
            .extensions()
            .iter()
            .any(|extension| {
                extension.id().as_str() == MRTR_EXTENSION_ID
                    && extension.revision().as_str() == MRTR_EXTENSION_REVISION
            });
        if !negotiated {
            return Err(LifecycleError::ExtensionNotNegotiated);
        }
        Ok(())
    }

    fn check_begin_request(
        &self,
        context: &McpRequestContext,
        capabilities: ClientElicitationCapabilities,
        confirmation_evidence: ConfirmationEvidence,
        plan: &ElicitationPlan,
    ) -> Result<(), LifecycleError> {
        self.check_request_gate(context)?;
        Self::check_modes(capabilities, confirmation_evidence, plan)
    }

    fn check_modes(
        capabilities: ClientElicitationCapabilities,
        confirmation_evidence: ConfirmationEvidence,
        plan: &ElicitationPlan,
    ) -> Result<(), LifecycleError> {
        let supported = plan.requests().values().all(|request| match request {
            PlannedElicitation::Form(_) => capabilities.supports_form(),
            PlannedElicitation::Url(_) => capabilities.supports_url(),
        });
        if !supported {
            return Err(LifecycleError::UnsupportedMode);
        }
        let has_sensitive_form = plan.requests().values().any(|request| {
            let PlannedElicitation::Form(form) = request else {
                return false;
            };
            form.fields()
                .values()
                .any(|field| field.sensitivity() != crate::model::Sensitivity::Public)
        });
        if has_sensitive_form && confirmation_evidence != ConfirmationEvidence::Confirmed {
            return Err(LifecycleError::ConfirmationRequired);
        }
        Ok(())
    }

    async fn finish(
        &self,
        claimed: &PendingMrtrState,
        status: TerminalStatus,
        kind: MrtrAuditKind,
    ) -> Result<(), RepositoryError> {
        self.repository
            .finish_claimed(claimed.state_id, status, audit_for_record(claimed, kind))
            .await
    }

    fn new_record(
        &self,
        binding: StateBinding,
        plan: ElicitationPlan,
        continuation: Option<InvocationContinuation>,
        round: u16,
        inherited_max_rounds: Option<u16>,
    ) -> Result<PendingMrtrState, LifecycleError> {
        let now = OffsetDateTime::now_utc();
        let ttl = time::Duration::try_from(self.config.request_state_ttl)
            .map_err(|_| LifecycleError::InvalidInvocation)?;
        let expires_at = now
            .checked_add(ttl)
            .ok_or(LifecycleError::InvalidInvocation)?;
        let max_rounds = inherited_max_rounds
            .map_or(plan.max_rounds(), |current| current.min(plan.max_rounds()));
        Ok(PendingMrtrState {
            state_id: Uuid::now_v7(),
            binding,
            plan,
            continuation,
            round,
            max_rounds,
            issued_at: now,
            expires_at,
        })
    }

    fn seal(&self, record: &PendingMrtrState) -> Result<RequestStateToken, LifecycleError> {
        let payload = TokenPayload {
            v: TOKEN_FORMAT_VERSION,
            state_id: record.state_id,
        };
        let options = SealOptions::new()
            .associated_data(record.binding.associated_digest.as_bytes())
            .ttl(self.config.request_state_ttl);
        self.codec
            .seal_json_with(&payload, &options)
            .map(RequestStateToken::new)
            .map_err(|_| LifecycleError::StateRejected)
    }

    fn open(&self, token: &str, binding: &StateBinding) -> Result<TokenPayload, ()> {
        self.codec
            .open_json_with(token, binding.associated_digest.as_bytes())
            .map_err(|_| ())
    }

    async fn retry_after_rejection(
        &self,
        claimed: PendingMrtrState,
    ) -> Result<ResumeOutcome<I::Output>, LifecycleError> {
        if claimed.round >= claimed.max_rounds {
            self.finish(
                &claimed,
                TerminalStatus::Exhausted,
                MrtrAuditKind::Exhausted,
            )
            .await?;
            return Ok(ResumeOutcome::Exhausted);
        }
        let event = audit_for_record(&claimed, MrtrAuditKind::ResponseRejected);
        let old_state_id = claimed.state_id;
        let fresh = self.new_record(
            claimed.binding,
            claimed.plan,
            claimed.continuation,
            claimed.round + 1,
            Some(claimed.max_rounds),
        )?;
        let fresh = self
            .repository
            .replace_claimed(
                old_state_id,
                &fresh,
                ReplacementReason::InvalidResponse,
                event,
            )
            .await?;
        let token = self.seal(&fresh)?;
        Ok(ResumeOutcome::InputRequired(challenge_from(fresh, token)))
    }

    async fn advance(
        &self,
        claimed: PendingMrtrState,
        next_plan: ElicitationPlan,
        continuation: InvocationContinuation,
        original_argument_shape: &ArgumentObjectShape,
        capabilities: ClientElicitationCapabilities,
        confirmation_evidence: ConfirmationEvidence,
    ) -> Result<ResumeOutcome<I::Output>, LifecycleError> {
        if let Err(error) = Self::check_modes(capabilities, confirmation_evidence, &next_plan) {
            self.finish(
                &claimed,
                TerminalStatus::Rejected,
                MrtrAuditKind::StateRejected,
            )
            .await?;
            return Err(error);
        }
        if let Err(error) = validate_mapping_shape(original_argument_shape, &next_plan) {
            self.finish(
                &claimed,
                TerminalStatus::Rejected,
                MrtrAuditKind::StateRejected,
            )
            .await?;
            return Err(error.into());
        }
        if claimed.round >= claimed.max_rounds || claimed.round >= next_plan.max_rounds() {
            self.finish(
                &claimed,
                TerminalStatus::Exhausted,
                MrtrAuditKind::Exhausted,
            )
            .await?;
            return Ok(ResumeOutcome::Exhausted);
        }
        let event = audit_for_record(&claimed, MrtrAuditKind::Advanced);
        let old_state_id = claimed.state_id;
        let fresh = self.new_record(
            claimed.binding,
            next_plan,
            Some(continuation),
            claimed.round + 1,
            Some(claimed.max_rounds),
        )?;
        let fresh = self
            .repository
            .replace_claimed(old_state_id, &fresh, ReplacementReason::MoreInput, event)
            .await?;
        let token = self.seal(&fresh)?;
        Ok(ResumeOutcome::InputRequired(challenge_from(fresh, token)))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TokenPayload {
    v: u8,
    state_id: Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValidatedResponse {
    Cancelled,
    Declined,
    Invoke { accepted: bool, declined: bool },
}

fn validate_responses(
    plan: &ElicitationPlan,
    mut responses: InputResponseMap,
    arguments: &mut Value,
) -> Result<ValidatedResponse, ()> {
    if responses.len() != plan.requests().len()
        || !plan
            .requests()
            .keys()
            .all(|key| responses.contains_key(key.as_str()))
    {
        return Err(());
    }

    let mut cancelled = false;
    let mut declined = false;
    let mut accepted = false;
    for (key, request) in plan.requests() {
        let raw = responses.remove(key.as_str()).ok_or(())?;
        let object = raw.as_object().ok_or(())?;
        if object
            .keys()
            .any(|name| !matches!(name.as_str(), "action" | "content" | "_meta"))
        {
            return Err(());
        }
        let content_present = object.contains_key("content");
        let result: ElicitResult = serde_json::from_value(raw).map_err(|_| ())?;
        match result.action {
            ElicitationAction::Accept => {
                accepted = true;
                match request {
                    PlannedElicitation::Form(form) => {
                        if !content_present {
                            return Err(());
                        }
                        let mut content = result.content.ok_or(())?;
                        let content_object = content.as_object().ok_or(())?;
                        if content_object
                            .keys()
                            .any(|name| !form.fields().contains_key(name))
                        {
                            return Err(());
                        }
                        if !form.validate_content(&content) {
                            return Err(());
                        }
                        let content_object = content.as_object_mut().ok_or(())?;
                        for field in form.fields().values() {
                            if let Some(value) = content_object.remove(field.name()) {
                                set_object_pointer(arguments, field.argument_pointer(), value)
                                    .map_err(|_| ())?;
                            }
                        }
                    }
                    PlannedElicitation::Url(_) => {
                        if content_present || result.content.is_some() {
                            return Err(());
                        }
                    }
                }
            }
            ElicitationAction::Decline => {
                if content_present || result.content.is_some() {
                    return Err(());
                }
                declined = true;
            }
            ElicitationAction::Cancel => {
                if content_present || result.content.is_some() {
                    return Err(());
                }
                cancelled = true;
            }
            _ => return Err(()),
        }
    }

    if cancelled {
        Ok(ValidatedResponse::Cancelled)
    } else if declined && plan.decline_behavior() == crate::model::DeclineBehavior::CompleteDeclined
    {
        Ok(ValidatedResponse::Declined)
    } else {
        Ok(ValidatedResponse::Invoke { accepted, declined })
    }
}

fn valid_claimed_record(
    record: &PendingMrtrState,
    expected_state_id: Uuid,
    expected: &StateBinding,
    now: OffsetDateTime,
) -> bool {
    record.state_id == expected_state_id
        && record.binding == *expected
        && record.plan.version() == ElicitationPlan::VERSION
        && record.round >= 1
        && record.round <= record.max_rounds
        && record.max_rounds <= crate::model::MAX_MRTR_ROUNDS
        && record.issued_at < record.expires_at
        && now < record.expires_at
}

fn challenge_from(
    record: PendingMrtrState,
    request_state: RequestStateToken,
) -> ElicitationChallenge {
    ElicitationChallenge {
        plan: record.plan,
        request_state,
        round: record.round,
        expires_at: record.expires_at,
    }
}

fn untrusted_rejection() -> MrtrAuditEvent {
    MrtrAuditEvent {
        state_id: None,
        kind: MrtrAuditKind::StateRejected,
        method: None,
        capability_key: None,
        capability_revision: None,
        arguments_digest: None,
        round: None,
        sensitivity: None,
    }
}

fn audit_for_record(record: &PendingMrtrState, kind: MrtrAuditKind) -> MrtrAuditEvent {
    audit_for_binding(
        Some(record.state_id),
        &record.binding,
        kind,
        Some(record.round),
        Some(record.plan.sensitivity()),
    )
}

fn audit_for_binding(
    state_id: Option<Uuid>,
    binding: &StateBinding,
    kind: MrtrAuditKind,
    round: Option<u16>,
    sensitivity: Option<crate::model::Sensitivity>,
) -> MrtrAuditEvent {
    MrtrAuditEvent {
        state_id,
        kind,
        method: Some(binding.method),
        capability_key: Some(binding.capability_key.clone()),
        capability_revision: Some(binding.capability_revision.clone()),
        arguments_digest: Some(binding.arguments_digest),
        round,
        sensitivity,
    }
}
