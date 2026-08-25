CREATE TABLE scheduler_schedules (
    id uuid PRIMARY KEY,
    name varchar(128) NOT NULL UNIQUE,
    cron_expression varchar(512) NOT NULL,
    timezone varchar(128) NOT NULL,
    misfire_policy varchar(16) NOT NULL,
    catch_up_max_runs integer,
    max_concurrent_runs integer NOT NULL,
    scheduler_lease_micros bigint NOT NULL,
    execution_lease_micros bigint NOT NULL,
    idempotency_window_micros bigint NOT NULL,
    paused boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1,
    next_run_at timestamptz NOT NULL,
    lease_owner varchar(128),
    lease_token uuid,
    lease_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT scheduler_schedules_id_uuid_v7 CHECK ((get_byte(uuid_send(id), 6) >> 4) = 7 AND (get_byte(uuid_send(id), 8) & 192) = 128),
    CONSTRAINT scheduler_schedules_name_portable CHECK (name ~ '^[a-z0-9][a-z0-9_.-]*$'),
    CONSTRAINT scheduler_schedules_expression_bounded CHECK (octet_length(cron_expression) BETWEEN 1 AND 512 AND cron_expression !~ '[[:cntrl:]]'),
    CONSTRAINT scheduler_schedules_timezone_portable CHECK (timezone ~ '^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$'),
    CONSTRAINT scheduler_schedules_misfire_valid CHECK ((misfire_policy IN ('skip', 'fire_once') AND catch_up_max_runs IS NULL) OR (misfire_policy = 'catch_up' AND catch_up_max_runs BETWEEN 1 AND 1000)),
    CONSTRAINT scheduler_schedules_max_concurrency_bounded CHECK (max_concurrent_runs BETWEEN 1 AND 1000),
    CONSTRAINT scheduler_schedules_scheduler_lease_bounded CHECK (scheduler_lease_micros BETWEEN 1000000 AND 86400000000),
    CONSTRAINT scheduler_schedules_execution_lease_bounded CHECK (execution_lease_micros BETWEEN 2000000 AND 604800000000),
    CONSTRAINT scheduler_schedules_idempotency_window_bounded CHECK (idempotency_window_micros BETWEEN 1000000 AND 2678400000000),
    CONSTRAINT scheduler_schedules_revision_positive CHECK (revision > 0),
    CONSTRAINT scheduler_schedules_lease_complete CHECK ((lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) OR (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL AND (get_byte(uuid_send(lease_token), 6) >> 4) = 7 AND (get_byte(uuid_send(lease_token), 8) & 192) = 128)),
    CONSTRAINT scheduler_schedules_paused_not_leased CHECK (NOT paused OR (lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)),
    CONSTRAINT scheduler_schedules_updated_after_created CHECK (updated_at >= created_at)
);

CREATE INDEX scheduler_schedules_ready_idx ON scheduler_schedules (next_run_at, id) WHERE paused = false;
CREATE INDEX scheduler_schedules_lease_expiry_idx ON scheduler_schedules (lease_expires_at) WHERE lease_expires_at IS NOT NULL;

CREATE TABLE scheduler_job_runs (
    id uuid PRIMARY KEY,
    schedule_id uuid NOT NULL REFERENCES scheduler_schedules(id),
    scheduled_for timestamptz NOT NULL,
    replay_sequence integer NOT NULL DEFAULT 0,
    replay_of uuid REFERENCES scheduler_job_runs(id),
    job_id uuid NOT NULL UNIQUE,
    queue varchar(64) NOT NULL,
    envelope_json text NOT NULL,
    status varchar(24) NOT NULL,
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    dispatch_attempt_count integer NOT NULL DEFAULT 0,
    dispatch_lease_owner varchar(128),
    dispatch_lease_token uuid,
    dispatch_lease_expires_at timestamptz,
    dispatched_at timestamptz,
    last_dispatch_error varchar(64),
    execution_attempt_count integer NOT NULL DEFAULT 0,
    execution_lease_token uuid,
    execution_lease_expires_at timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    failed_at timestamptz,
    failure_code varchar(64),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT scheduler_job_runs_id_uuid_v7 CHECK ((get_byte(uuid_send(id), 6) >> 4) = 7 AND (get_byte(uuid_send(id), 8) & 192) = 128),
    CONSTRAINT scheduler_job_runs_job_id_uuid_v7 CHECK ((get_byte(uuid_send(job_id), 6) >> 4) = 7 AND (get_byte(uuid_send(job_id), 8) & 192) = 128),
    CONSTRAINT scheduler_job_runs_queue_portable CHECK (queue ~ '^[A-Za-z0-9][A-Za-z0-9_.-]*$'),
    CONSTRAINT scheduler_job_runs_envelope_bounded_json CHECK (octet_length(envelope_json) BETWEEN 2 AND 2097152 AND jsonb_typeof(envelope_json::jsonb) = 'object'),
    CONSTRAINT scheduler_job_runs_replay_valid CHECK ((replay_sequence = 0 AND replay_of IS NULL) OR (replay_sequence BETWEEN 1 AND 1000000 AND replay_of IS NOT NULL)),
    CONSTRAINT scheduler_job_runs_attempts_nonnegative CHECK (dispatch_attempt_count >= 0 AND execution_attempt_count >= 0),
    CONSTRAINT scheduler_job_runs_dispatch_error_portable CHECK (last_dispatch_error IS NULL OR last_dispatch_error ~ '^[a-z0-9][a-z0-9_.-]*$'),
    CONSTRAINT scheduler_job_runs_failure_code_portable CHECK (failure_code IS NULL OR failure_code ~ '^[a-z0-9][a-z0-9_.-]*$'),
    CONSTRAINT scheduler_job_runs_dispatch_lease_complete CHECK ((dispatch_lease_owner IS NULL AND dispatch_lease_token IS NULL AND dispatch_lease_expires_at IS NULL) OR (dispatch_lease_owner IS NOT NULL AND dispatch_lease_token IS NOT NULL AND dispatch_lease_expires_at IS NOT NULL AND (get_byte(uuid_send(dispatch_lease_token), 6) >> 4) = 7 AND (get_byte(uuid_send(dispatch_lease_token), 8) & 192) = 128)),
    CONSTRAINT scheduler_job_runs_execution_lease_complete CHECK ((execution_lease_token IS NULL AND execution_lease_expires_at IS NULL) OR (execution_lease_token IS NOT NULL AND execution_lease_expires_at IS NOT NULL AND (get_byte(uuid_send(execution_lease_token), 6) >> 4) = 7 AND (get_byte(uuid_send(execution_lease_token), 8) & 192) = 128)),
    CONSTRAINT scheduler_job_runs_state_complete CHECK (
        (status = 'pending_dispatch' AND dispatch_lease_owner IS NULL AND dispatch_lease_token IS NULL AND dispatch_lease_expires_at IS NULL AND execution_lease_token IS NULL AND execution_lease_expires_at IS NULL AND dispatched_at IS NULL AND started_at IS NULL AND completed_at IS NULL AND failed_at IS NULL AND failure_code IS NULL)
        OR (status = 'dispatching' AND dispatch_lease_owner IS NOT NULL AND dispatch_lease_token IS NOT NULL AND dispatch_lease_expires_at IS NOT NULL AND execution_lease_token IS NULL AND execution_lease_expires_at IS NULL AND completed_at IS NULL AND failed_at IS NULL AND failure_code IS NULL)
        OR (status = 'dispatched' AND dispatch_lease_owner IS NULL AND dispatch_lease_token IS NULL AND dispatch_lease_expires_at IS NULL AND execution_lease_token IS NULL AND execution_lease_expires_at IS NULL AND dispatched_at IS NOT NULL AND completed_at IS NULL AND failed_at IS NULL AND failure_code IS NULL)
        OR (status = 'running' AND dispatch_lease_owner IS NULL AND dispatch_lease_token IS NULL AND dispatch_lease_expires_at IS NULL AND execution_lease_token IS NOT NULL AND execution_lease_expires_at IS NOT NULL AND dispatched_at IS NOT NULL AND started_at IS NOT NULL AND completed_at IS NULL AND failed_at IS NULL AND failure_code IS NULL)
        OR (status = 'completed' AND dispatch_lease_owner IS NULL AND dispatch_lease_token IS NULL AND dispatch_lease_expires_at IS NULL AND execution_lease_token IS NULL AND execution_lease_expires_at IS NULL AND dispatched_at IS NOT NULL AND started_at IS NOT NULL AND completed_at IS NOT NULL AND failed_at IS NULL AND failure_code IS NULL)
        OR (status = 'failed' AND dispatch_lease_owner IS NULL AND dispatch_lease_token IS NULL AND dispatch_lease_expires_at IS NULL AND execution_lease_token IS NULL AND execution_lease_expires_at IS NULL AND dispatched_at IS NOT NULL AND started_at IS NOT NULL AND completed_at IS NULL AND failed_at IS NOT NULL AND failure_code IS NOT NULL)
    )
);

CREATE UNIQUE INDEX scheduler_job_runs_occurrence_identity_idx ON scheduler_job_runs (schedule_id, scheduled_for, replay_sequence);
CREATE UNIQUE INDEX scheduler_job_runs_replay_identity_idx ON scheduler_job_runs (replay_of, replay_sequence) WHERE replay_of IS NOT NULL;
CREATE INDEX scheduler_job_runs_dispatch_ready_idx ON scheduler_job_runs (available_at, scheduled_for, id) WHERE status IN ('pending_dispatch', 'dispatching');
CREATE INDEX scheduler_job_runs_dispatch_lease_expiry_idx ON scheduler_job_runs (dispatch_lease_expires_at) WHERE dispatch_lease_expires_at IS NOT NULL;
CREATE INDEX scheduler_job_runs_execution_lease_expiry_idx ON scheduler_job_runs (execution_lease_expires_at) WHERE execution_lease_expires_at IS NOT NULL;
CREATE INDEX scheduler_job_runs_schedule_status_idx ON scheduler_job_runs (schedule_id, status, scheduled_for, id);

CREATE FUNCTION reject_scheduler_job_run_identity_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id <> OLD.id OR NEW.schedule_id <> OLD.schedule_id OR NEW.scheduled_for <> OLD.scheduled_for OR NEW.replay_sequence <> OLD.replay_sequence OR NEW.replay_of IS DISTINCT FROM OLD.replay_of OR NEW.job_id <> OLD.job_id OR NEW.queue <> OLD.queue OR NEW.envelope_json <> OLD.envelope_json OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION USING ERRCODE = '55000', TABLE = 'scheduler_job_runs', MESSAGE = 'scheduled job identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER scheduler_job_runs_reject_identity_mutation BEFORE UPDATE ON scheduler_job_runs FOR EACH ROW EXECUTE FUNCTION reject_scheduler_job_run_identity_mutation();

CREATE TABLE scheduler_audit_events (
    id uuid PRIMARY KEY,
    schedule_id uuid NOT NULL REFERENCES scheduler_schedules(id),
    action varchar(32) NOT NULL,
    actor varchar(128) NOT NULL,
    reason varchar(256) NOT NULL,
    previous_revision bigint,
    new_revision bigint NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT scheduler_audit_events_id_uuid_v7 CHECK ((get_byte(uuid_send(id), 6) >> 4) = 7 AND (get_byte(uuid_send(id), 8) & 192) = 128),
    CONSTRAINT scheduler_audit_events_action_valid CHECK (action IN ('create', 'update', 'pause', 'resume', 'replay')),
    CONSTRAINT scheduler_audit_events_actor_portable CHECK (actor ~ '^[A-Za-z0-9][A-Za-z0-9_.:@/-]*$'),
    CONSTRAINT scheduler_audit_events_reason_bounded CHECK (octet_length(reason) BETWEEN 1 AND 256 AND reason !~ '[[:cntrl:]]'),
    CONSTRAINT scheduler_audit_events_revision_valid CHECK (new_revision > 0 AND (previous_revision IS NULL OR previous_revision > 0) AND ((action = 'create' AND previous_revision IS NULL) OR (action <> 'create' AND previous_revision IS NOT NULL)))
);
CREATE INDEX scheduler_audit_events_schedule_time_idx ON scheduler_audit_events (schedule_id, occurred_at DESC, id DESC);
CREATE FUNCTION reject_scheduler_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '55000', TABLE = 'scheduler_audit_events', MESSAGE = 'scheduler audit events are append-only';
END;
$$;
CREATE TRIGGER scheduler_audit_events_reject_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON scheduler_audit_events FOR EACH STATEMENT EXECUTE FUNCTION reject_scheduler_audit_mutation();
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE scheduler_audit_events FROM PUBLIC;
