CREATE TABLE public.mcp_tasks (
    task_id uuid PRIMARY KEY,
    subject_id uuid NOT NULL,
    tenant_id uuid,
    capability_id text NOT NULL,
    capability_version text NOT NULL,
    idempotency_key_sha256 bytea NOT NULL,
    request_fingerprint bytea NOT NULL,
    current_job_id uuid NOT NULL,
    generation bigint NOT NULL,
    version bigint NOT NULL,
    status text NOT NULL,
    cancellation_requested boolean NOT NULL DEFAULT false,
    task_key_id text NOT NULL,
    task_key_revision bigint NOT NULL,
    task_algorithm text NOT NULL,
    task_nonce bytea NOT NULL,
    task_ciphertext bytea NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    lease_job_id uuid,
    lease_generation bigint,
    lease_version bigint,
    lease_claimed_at timestamptz,
    lease_expires_at timestamptz,
    CONSTRAINT mcp_tasks_ids_uuid_v7 CHECK (
        get_byte(uuid_send(task_id), 6) >> 4 = 7
        AND get_byte(uuid_send(subject_id), 6) >> 4 = 7
        AND (tenant_id IS NULL OR get_byte(uuid_send(tenant_id), 6) >> 4 = 7)
        AND get_byte(uuid_send(current_job_id), 6) >> 4 = 7
        AND (lease_job_id IS NULL OR get_byte(uuid_send(lease_job_id), 6) >> 4 = 7)
    ),
    CONSTRAINT mcp_tasks_capability_id_bounded CHECK (
        octet_length(capability_id) BETWEEN 1 AND 128
    ),
    CONSTRAINT mcp_tasks_capability_version_bounded CHECK (
        octet_length(capability_version) BETWEEN 1 AND 64
    ),
    CONSTRAINT mcp_tasks_idempotency_key_sha256 CHECK (
        octet_length(idempotency_key_sha256) = 32
    ),
    CONSTRAINT mcp_tasks_fingerprint_sha256 CHECK (octet_length(request_fingerprint) = 32),
    CONSTRAINT mcp_tasks_counters_positive CHECK (
        generation > 0 AND version > 0 AND generation <= version
    ),
    CONSTRAINT mcp_tasks_status_known CHECK (
        status IN ('working', 'input_required', 'completed', 'failed', 'cancelled')
    ),
    CONSTRAINT mcp_tasks_cancelled_is_requested CHECK (
        status <> 'cancelled' OR cancellation_requested
    ),
    CONSTRAINT mcp_tasks_protected_payload_bounded CHECK (
        octet_length(task_key_id) BETWEEN 1 AND 128
        AND task_key_revision > 0
        AND octet_length(task_algorithm) BETWEEN 1 AND 32
        AND task_algorithm ~ '^[a-z][a-z0-9-]*$'
        AND octet_length(task_nonce) = 12
        AND octet_length(task_ciphertext) BETWEEN 16 AND 18875392
    ),
    CONSTRAINT mcp_tasks_timestamps_valid CHECK (
        created_at <= updated_at AND expires_at > created_at
    ),
    CONSTRAINT mcp_tasks_lease_complete CHECK (
        (lease_job_id IS NULL
         AND lease_generation IS NULL
         AND lease_version IS NULL
         AND lease_claimed_at IS NULL
         AND lease_expires_at IS NULL)
        OR
        (lease_job_id IS NOT NULL
         AND lease_job_id = current_job_id
         AND lease_generation = generation
         AND lease_generation > 0
         AND lease_version > 0
         AND lease_claimed_at IS NOT NULL
         AND lease_expires_at > lease_claimed_at
         AND status = 'working')
    ),
    CONSTRAINT mcp_tasks_lease_version_fenced CHECK (
        lease_job_id IS NULL
        OR (
            (NOT cancellation_requested AND lease_version = version)
            OR (cancellation_requested AND lease_version + 1 = version)
        )
    ),
    CONSTRAINT mcp_tasks_initial_state_valid CHECK (
        version <> 1
        OR (
            generation = 1
            AND status = 'working'
            AND NOT cancellation_requested
            AND created_at = updated_at
        )
    ),
    CONSTRAINT mcp_tasks_input_state_versioned CHECK (
        status <> 'input_required' OR version > generation
    )
);

CREATE TABLE public.mcp_task_idempotency (
    subject_id uuid NOT NULL,
    tenant_id uuid,
    operation text NOT NULL,
    capability_id text NOT NULL,
    capability_version text NOT NULL,
    idempotency_key_sha256 bytea NOT NULL,
    request_fingerprint bytea NOT NULL,
    task_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT mcp_task_idempotency_ids_uuid_v7 CHECK (
        get_byte(uuid_send(subject_id), 6) >> 4 = 7
        AND (tenant_id IS NULL OR get_byte(uuid_send(tenant_id), 6) >> 4 = 7)
        AND get_byte(uuid_send(task_id), 6) >> 4 = 7
    ),
    CONSTRAINT mcp_task_idempotency_operation_known CHECK (operation = 'tasks/create'),
    CONSTRAINT mcp_task_idempotency_capability_id_bounded CHECK (
        octet_length(capability_id) BETWEEN 1 AND 128
    ),
    CONSTRAINT mcp_task_idempotency_capability_version_bounded CHECK (
        octet_length(capability_version) BETWEEN 1 AND 64
    ),
    CONSTRAINT mcp_task_idempotency_key_sha256 CHECK (
        octet_length(idempotency_key_sha256) = 32
    ),
    CONSTRAINT mcp_task_idempotency_fingerprint_sha256 CHECK (
        octet_length(request_fingerprint) = 32
    ),
    CONSTRAINT mcp_task_idempotency_task_unique UNIQUE (task_id),
    CONSTRAINT mcp_task_idempotency_scope_unique UNIQUE NULLS NOT DISTINCT (
        subject_id, tenant_id, operation, capability_id, capability_version,
        idempotency_key_sha256
    ),
    CONSTRAINT mcp_task_idempotency_task_fk FOREIGN KEY (task_id)
        REFERENCES public.mcp_tasks (task_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE public.mcp_task_input_keys (
    task_id uuid NOT NULL REFERENCES public.mcp_tasks (task_id),
    input_key_sha256 bytea NOT NULL,
    first_round bigint NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (task_id, input_key_sha256),
    CONSTRAINT mcp_task_input_keys_digest_sha256 CHECK (
        octet_length(input_key_sha256) = 32
    ),
    CONSTRAINT mcp_task_input_keys_round_positive CHECK (first_round > 0)
);

CREATE TABLE public.mcp_task_input_rounds (
    task_id uuid NOT NULL REFERENCES public.mcp_tasks (task_id),
    round_number bigint NOT NULL,
    completed_generation bigint NOT NULL,
    task_version bigint NOT NULL,
    round_key_id text NOT NULL,
    round_key_revision bigint NOT NULL,
    round_algorithm text NOT NULL,
    round_nonce bytea NOT NULL,
    round_ciphertext bytea NOT NULL,
    completed_at timestamptz NOT NULL,
    PRIMARY KEY (task_id, round_number),
    CONSTRAINT mcp_task_input_rounds_sequence_valid CHECK (
        round_number > 0
        AND completed_generation = round_number
        AND task_version > completed_generation
    ),
    CONSTRAINT mcp_task_input_rounds_protected_payload_bounded CHECK (
        octet_length(round_key_id) BETWEEN 1 AND 128
        AND round_key_revision > 0
        AND octet_length(round_algorithm) BETWEEN 1 AND 32
        AND round_algorithm ~ '^[a-z][a-z0-9-]*$'
        AND octet_length(round_nonce) = 12
        AND octet_length(round_ciphertext) BETWEEN 16 AND 1201024
    )
);

CREATE TABLE public.mcp_task_payload_nonces (
    key_id text NOT NULL,
    key_revision bigint NOT NULL,
    nonce bytea NOT NULL,
    task_id uuid NOT NULL,
    payload_kind text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (key_id, key_revision, nonce),
    CONSTRAINT mcp_task_payload_nonces_key_bounded CHECK (
        octet_length(key_id) BETWEEN 1 AND 128 AND key_revision > 0
    ),
    CONSTRAINT mcp_task_payload_nonces_nonce_size CHECK (octet_length(nonce) = 12),
    CONSTRAINT mcp_task_payload_nonces_task_uuid_v7 CHECK (
        get_byte(uuid_send(task_id), 6) >> 4 = 7
    ),
    CONSTRAINT mcp_task_payload_nonces_kind_known CHECK (
        payload_kind IN ('task', 'input_round')
    ),
    CONSTRAINT mcp_task_payload_nonces_task_fk FOREIGN KEY (task_id)
        REFERENCES public.mcp_tasks (task_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE public.mcp_task_events (
    event_sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    task_id uuid NOT NULL REFERENCES public.mcp_tasks (task_id),
    task_version bigint NOT NULL,
    generation bigint NOT NULL,
    event_kind text NOT NULL,
    status text NOT NULL,
    occurred_at timestamptz NOT NULL,
    CONSTRAINT mcp_task_events_counters_positive CHECK (
        task_version > 0 AND generation > 0
    ),
    CONSTRAINT mcp_task_events_kind_known CHECK (
        event_kind IN (
            'created', 'input_recorded', 'resumed', 'cancellation_requested', 'cancelled',
            'execution_claimed', 'execution_released', 'input_required', 'completed', 'failed',
            'expired', 'settled'
        )
    ),
    CONSTRAINT mcp_task_events_status_known CHECK (
        status IN ('working', 'input_required', 'completed', 'failed', 'cancelled')
    )
);

CREATE INDEX mcp_tasks_active_expiry_idx
    ON public.mcp_tasks (expires_at, task_id)
    WHERE status IN ('working', 'input_required');
CREATE INDEX mcp_tasks_active_job_idx
    ON public.mcp_tasks (current_job_id, generation)
    WHERE status = 'working';
CREATE INDEX mcp_tasks_owner_lookup_idx
    ON public.mcp_tasks (subject_id, tenant_id, task_id);
CREATE INDEX mcp_task_events_replay_idx
    ON public.mcp_task_events (task_id, event_sequence);
CREATE INDEX mcp_task_outbox_pending_idx
    ON public.outbox_events (available_at, occurred_at, id)
    WHERE aggregate_type = 'mcp_task' AND published_at IS NULL;

CREATE FUNCTION public.protect_mcp_task_transition() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    business_changed boolean;
    lease_changed boolean;
BEGIN
    IF ROW(
        NEW.task_id, NEW.subject_id, NEW.tenant_id, NEW.capability_id,
        NEW.capability_version, NEW.idempotency_key_sha256, NEW.request_fingerprint,
        NEW.created_at, NEW.expires_at
    ) IS DISTINCT FROM ROW(
        OLD.task_id, OLD.subject_id, OLD.tenant_id, OLD.capability_id,
        OLD.capability_version, OLD.idempotency_key_sha256, OLD.request_fingerprint,
        OLD.created_at, OLD.expires_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            TABLE = 'mcp_tasks',
            MESSAGE = 'MCP task durable identity is immutable';
    END IF;

    IF OLD.status IN ('completed', 'failed', 'cancelled') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            TABLE = 'mcp_tasks',
            MESSAGE = 'terminal MCP tasks are immutable';
    END IF;

    business_changed := ROW(
        NEW.current_job_id, NEW.generation, NEW.version, NEW.status,
        NEW.cancellation_requested, NEW.task_key_id, NEW.task_key_revision,
        NEW.task_algorithm, NEW.task_nonce, NEW.task_ciphertext, NEW.updated_at
    ) IS DISTINCT FROM ROW(
        OLD.current_job_id, OLD.generation, OLD.version, OLD.status,
        OLD.cancellation_requested, OLD.task_key_id, OLD.task_key_revision,
        OLD.task_algorithm, OLD.task_nonce, OLD.task_ciphertext, OLD.updated_at
    );
    lease_changed := ROW(
        NEW.lease_job_id, NEW.lease_generation, NEW.lease_version,
        NEW.lease_claimed_at, NEW.lease_expires_at
    ) IS DISTINCT FROM ROW(
        OLD.lease_job_id, OLD.lease_generation, OLD.lease_version,
        OLD.lease_claimed_at, OLD.lease_expires_at
    );

    IF business_changed THEN
        IF NEW.version <> OLD.version + 1 OR NEW.updated_at <= OLD.updated_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'mcp_tasks_version_cas',
                TABLE = 'mcp_tasks',
                MESSAGE = 'MCP task state changes require one monotonic version';
        END IF;
    ELSIF lease_changed THEN
        IF NEW.version <> OLD.version OR NEW.updated_at IS DISTINCT FROM OLD.updated_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'mcp_tasks_lease_preserves_version',
                TABLE = 'mcp_tasks',
                MESSAGE = 'MCP task lease changes cannot mutate state version';
        END IF;
    ELSE
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'mcp_tasks_noop_update',
            TABLE = 'mcp_tasks',
            MESSAGE = 'MCP task no-op updates are forbidden';
    END IF;

    IF NOT (
        (OLD.status = 'working' AND NEW.status IN ('working', 'input_required', 'completed', 'failed', 'cancelled'))
        OR (OLD.status = 'input_required' AND NEW.status IN ('input_required', 'working', 'failed', 'cancelled'))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'mcp_tasks_state_transition',
            TABLE = 'mcp_tasks',
            MESSAGE = 'MCP task lifecycle transition is invalid';
    END IF;

    IF NEW.generation = OLD.generation + 1 THEN
        IF OLD.status <> 'input_required' OR NEW.status <> 'working'
           OR NEW.current_job_id = OLD.current_job_id THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'mcp_tasks_generation_resume',
                TABLE = 'mcp_tasks',
                MESSAGE = 'MCP task generation may advance only on resume';
        END IF;
    ELSIF NEW.generation <> OLD.generation
          OR NEW.current_job_id IS DISTINCT FROM OLD.current_job_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'mcp_tasks_generation_fence',
            TABLE = 'mcp_tasks',
            MESSAGE = 'MCP task job identity must follow generation';
    END IF;

    IF OLD.cancellation_requested AND NOT NEW.cancellation_requested
       AND NEW.generation <> OLD.generation + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'mcp_tasks_cancellation_monotonic',
            TABLE = 'mcp_tasks',
            MESSAGE = 'MCP task cancellation intent is monotonic within a generation';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER mcp_tasks_protect_transition
BEFORE UPDATE OR DELETE ON public.mcp_tasks
FOR EACH ROW EXECUTE FUNCTION public.protect_mcp_task_transition();

CREATE FUNCTION public.reject_mcp_task_append_only_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'MCP task history and deduplication records are append-only';
END;
$$;

CREATE TRIGGER mcp_task_idempotency_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON public.mcp_task_idempotency
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_mcp_task_append_only_mutation();
CREATE TRIGGER mcp_task_input_keys_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON public.mcp_task_input_keys
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_mcp_task_append_only_mutation();
CREATE TRIGGER mcp_task_input_rounds_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON public.mcp_task_input_rounds
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_mcp_task_append_only_mutation();
CREATE TRIGGER mcp_task_payload_nonces_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON public.mcp_task_payload_nonces
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_mcp_task_append_only_mutation();
CREATE TRIGGER mcp_task_events_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON public.mcp_task_events
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_mcp_task_append_only_mutation();

REVOKE ALL ON TABLE public.mcp_tasks FROM PUBLIC;
REVOKE ALL ON TABLE public.mcp_task_idempotency FROM PUBLIC;
REVOKE ALL ON TABLE public.mcp_task_input_keys FROM PUBLIC;
REVOKE ALL ON TABLE public.mcp_task_input_rounds FROM PUBLIC;
REVOKE ALL ON TABLE public.mcp_task_events FROM PUBLIC;
REVOKE ALL ON TABLE public.mcp_task_payload_nonces FROM PUBLIC;
REVOKE ALL ON SEQUENCE public.mcp_task_events_event_sequence_seq FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.protect_mcp_task_transition() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.reject_mcp_task_append_only_mutation() FROM PUBLIC;

COMMENT ON TABLE public.mcp_tasks IS
    'Authoritative tenant-scoped MCP task state. Protected task material is retained only as versioned authenticated ciphertext.';
COMMENT ON TABLE public.mcp_task_idempotency IS
    'Append-only create deduplication identities containing only SHA-256 key and request fingerprints.';
COMMENT ON TABLE public.mcp_task_input_keys IS
    'Append-only lifetime uniqueness digests for protected input keys; raw keys remain only in protected task state.';
COMMENT ON TABLE public.mcp_task_input_rounds IS
    'Append-only completed input history retained only as versioned authenticated ciphertext for exact worker resumption.';
COMMENT ON TABLE public.mcp_task_payload_nonces IS
    'Append-only nonce ledger preventing authenticated-encryption nonce reuse for each key revision.';
COMMENT ON TABLE public.mcp_task_events IS
    'Append-only payload-free MCP task lifecycle and lease facts; never stores prompts, arguments, responses, or results.';
