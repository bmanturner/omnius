use std::collections::BTreeMap;

use omnius_core::Clock;
use omnius_mcp_server_core::McpRequestContext;
use rmcp::model::{
    CancelTaskParams, CreateTaskResult, DetailedTask, GetTaskParams, GetTaskResult, InputRequest,
    Task, TaskAckResult, TaskPayload, UpdateTaskParams,
};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;

use crate::{
    CancellationRuntime, CreateTaskCommand, InputResponses, TaskRepository, TaskService,
    TaskServiceError, TaskSnapshot, TaskState,
};

/// Fixed safe RMCP adapter failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RmcpTaskError {
    /// The transport-neutral service rejected the request.
    #[error(transparent)]
    Service(#[from] TaskServiceError),
    /// Authoritative persisted state could not form a valid official wire object.
    #[error("authoritative task state is invalid")]
    InvalidState,
}

/// RMCP wire adapter; protocol-specific types terminate at this boundary.
pub struct RmcpTasksAdapter<R, C, K> {
    service: TaskService<R, C, K>,
}

impl<R, C, K> RmcpTasksAdapter<R, C, K>
where
    R: TaskRepository,
    C: CancellationRuntime,
    K: Clock,
{
    /// Wraps the transport-neutral service.
    #[must_use]
    pub const fn new(service: TaskService<R, C, K>) -> Self {
        Self { service }
    }

    /// Materializes a negotiated task result in lieu of the original synchronous tool result.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpTaskError`] for negotiation, persistence, or wire invariant failure.
    pub async fn create_for_tool_call(
        &self,
        request_context: &McpRequestContext,
        command: CreateTaskCommand,
    ) -> Result<CreateTaskResult, RmcpTaskError> {
        let snapshot = self.service.create(request_context, command).await?;
        Ok(CreateTaskResult::new(base_task(&snapshot)?))
    }

    /// Handles exact official `tasks/get` parameters.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpTaskError`] for negotiation, owner isolation, persistence, or wire failure.
    pub async fn get(
        &self,
        request_context: &McpRequestContext,
        params: GetTaskParams,
    ) -> Result<GetTaskResult, RmcpTaskError> {
        let task_id = params
            .task_id
            .parse()
            .map_err(|_| TaskServiceError::NotFound)?;
        let snapshot = self.service.get(request_context, task_id).await?;
        Ok(GetTaskResult::new(detailed_task(&snapshot)?))
    }

    /// Handles exact official `tasks/update` parameters and returns the required empty ack.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpTaskError`] for negotiation, owner isolation, invalid bounded input, or
    /// persistence failure.
    pub async fn update(
        &self,
        request_context: &McpRequestContext,
        params: UpdateTaskParams,
    ) -> Result<TaskAckResult, RmcpTaskError> {
        let task_id = params
            .task_id
            .parse()
            .map_err(|_| TaskServiceError::NotFound)?;
        let responses =
            InputResponses::new(params.input_responses).map_err(TaskServiceError::from)?;
        self.service
            .update(request_context, task_id, responses)
            .await?;
        Ok(TaskAckResult::default())
    }

    /// Handles exact official `tasks/cancel` parameters and returns the required empty ack.
    ///
    /// # Errors
    ///
    /// Returns [`RmcpTaskError`] for negotiation, owner isolation, or persistence failure.
    pub async fn cancel(
        &self,
        request_context: &McpRequestContext,
        params: CancelTaskParams,
    ) -> Result<TaskAckResult, RmcpTaskError> {
        let task_id = params
            .task_id
            .parse()
            .map_err(|_| TaskServiceError::NotFound)?;
        self.service.cancel(request_context, task_id).await?;
        Ok(TaskAckResult::default())
    }

    /// Returns the transport-neutral service.
    #[must_use]
    pub fn into_inner(self) -> TaskService<R, C, K> {
        self.service
    }
}

fn detailed_task(snapshot: &TaskSnapshot) -> Result<DetailedTask, RmcpTaskError> {
    let payload = match snapshot.state() {
        TaskState::Working => TaskPayload::Working,
        TaskState::InputRequired { round } => {
            let mut requests = BTreeMap::new();
            for (key, exchange) in round.pending() {
                let request: InputRequest = serde_json::from_value(exchange.request().clone())
                    .map_err(|_| RmcpTaskError::InvalidState)?;
                requests.insert(key.as_str().to_owned(), request);
            }
            if requests.is_empty() {
                return Err(RmcpTaskError::InvalidState);
            }
            TaskPayload::InputRequired {
                input_requests: requests,
            }
        }
        TaskState::Completed { result } => TaskPayload::Completed {
            result: result.as_map().clone(),
        },
        TaskState::Failed { failure } => TaskPayload::Failed {
            error: failure.json_rpc_error(),
        },
        TaskState::Cancelled => TaskPayload::Cancelled,
    };
    Ok(DetailedTask::new(base_task(snapshot)?, payload))
}

fn base_task(snapshot: &TaskSnapshot) -> Result<Task, RmcpTaskError> {
    let created_at = snapshot
        .created_at()
        .format(&Rfc3339)
        .map_err(|_| RmcpTaskError::InvalidState)?;
    let updated_at = snapshot
        .updated_at()
        .format(&Rfc3339)
        .map_err(|_| RmcpTaskError::InvalidState)?;
    Ok(Task::new(
        snapshot.task_id().to_string(),
        rmcp_status(snapshot.state()),
        created_at,
        updated_at,
    )
    .with_ttl_ms(snapshot.ttl_ms())
    .with_poll_interval_ms(snapshot.poll_interval_ms()))
}

const fn rmcp_status(state: &TaskState) -> rmcp::model::TaskStatus {
    match state {
        TaskState::Working => rmcp::model::TaskStatus::Working,
        TaskState::InputRequired { .. } => rmcp::model::TaskStatus::InputRequired,
        TaskState::Completed { .. } => rmcp::model::TaskStatus::Completed,
        TaskState::Failed { .. } => rmcp::model::TaskStatus::Failed,
        TaskState::Cancelled => rmcp::model::TaskStatus::Cancelled,
    }
}
