CREATE TABLE public.mcp_mrtr_states (
    state_id uuid PRIMARY KEY,
    status varchar(32) NOT NULL,
    principal_digest bytea NOT NULL,
    tenant_digest bytea NOT NULL,
    method varchar(32) NOT NULL,
    capability_key varchar(256) NOT NULL,
    capability_revision varchar(128) NOT NULL,
    arguments_digest bytea NOT NULL,
    idempotency_digest bytea NOT NULL,
    associated_digest bytea NOT NULL,
    plan_version smallint NOT NULL,
    plan jsonb NOT NULL,
    continuation_id uuid,
    round smallint NOT NULL,
    max_rounds smallint NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT mcp_mrtr_status_allowed CHECK (
        status IN (
            'pending', 'claimed', 'replaced_invalid_response', 'replaced_more_input',
            'completed', 'declined', 'cancelled', 'exhausted', 'invocation_failed', 'rejected'
        )
    ),
    CONSTRAINT mcp_mrtr_digest_lengths CHECK (
        octet_length(principal_digest) = 32
        AND octet_length(tenant_digest) = 32
        AND octet_length(arguments_digest) = 32
        AND octet_length(idempotency_digest) = 32
        AND octet_length(associated_digest) = 32
    ),
    CONSTRAINT mcp_mrtr_method_allowed CHECK (
        method IN ('tools/call', 'prompts/get', 'resources/read')
    ),
    CONSTRAINT mcp_mrtr_capability_bounds CHECK (
        octet_length(capability_key) BETWEEN 1 AND 256
        AND capability_key !~ '[[:cntrl:]]'
        AND octet_length(capability_revision) BETWEEN 1 AND 128
        AND capability_revision !~ '[[:cntrl:]]'
    ),
    CONSTRAINT mcp_mrtr_plan_version_supported CHECK (
        plan_version = 1
        AND jsonb_typeof(plan) = 'object'
        AND plan ->> 'version' = '1'
    ),
    CONSTRAINT mcp_mrtr_plan_bounded CHECK (
        octet_length(plan::text) BETWEEN 2 AND 262144
    ),
    CONSTRAINT mcp_mrtr_rounds_bounded CHECK (
        round BETWEEN 1 AND 10
        AND max_rounds BETWEEN 1 AND 10
        AND round <= max_rounds
    ),
    CONSTRAINT mcp_mrtr_lifetime_bounded CHECK (
        expires_at > issued_at
        AND expires_at <= issued_at + INTERVAL '15 minutes'
        AND updated_at >= issued_at
    )
);

CREATE INDEX mcp_mrtr_expiry_idx
    ON public.mcp_mrtr_states (expires_at, state_id);
CREATE INDEX mcp_mrtr_pending_expiry_idx
    ON public.mcp_mrtr_states (expires_at, state_id)
    WHERE status = 'pending';
CREATE INDEX mcp_mrtr_status_updated_idx
    ON public.mcp_mrtr_states (status, updated_at, state_id);
CREATE INDEX mcp_mrtr_arguments_digest_idx
    ON public.mcp_mrtr_states (arguments_digest, state_id);

CREATE TABLE public.mcp_mrtr_audit_events (
    audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    state_id uuid,
    kind varchar(32) NOT NULL,
    method varchar(32),
    capability_key varchar(256),
    capability_revision varchar(128),
    arguments_digest bytea,
    round smallint,
    sensitivity varchar(16),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT mcp_mrtr_audit_kind_allowed CHECK (
        kind IN (
            'issued', 'claimed', 'state_rejected', 'response_rejected', 'accepted',
            'partially_accepted', 'declined', 'cancelled', 'advanced', 'completed',
            'invocation_failed', 'exhausted'
        )
    ),
    CONSTRAINT mcp_mrtr_audit_method_allowed CHECK (
        method IS NULL OR method IN ('tools/call', 'prompts/get', 'resources/read')
    ),
    CONSTRAINT mcp_mrtr_audit_capability_bounds CHECK (
        (capability_key IS NULL OR (
            octet_length(capability_key) BETWEEN 1 AND 256
            AND capability_key !~ '[[:cntrl:]]'
        ))
        AND (capability_revision IS NULL OR (
            octet_length(capability_revision) BETWEEN 1 AND 128
            AND capability_revision !~ '[[:cntrl:]]'
        ))
    ),
    CONSTRAINT mcp_mrtr_audit_digest_length CHECK (
        arguments_digest IS NULL OR octet_length(arguments_digest) = 32
    ),
    CONSTRAINT mcp_mrtr_audit_round_bounded CHECK (
        round IS NULL OR round BETWEEN 1 AND 10
    ),
    CONSTRAINT mcp_mrtr_audit_sensitivity_allowed CHECK (
        sensitivity IS NULL OR sensitivity IN (
            'public', 'personal', 'confidential', 'credential', 'password'
        )
    ),
    CONSTRAINT mcp_mrtr_audit_binding_coherent CHECK (
        (state_id IS NULL
            AND method IS NULL
            AND capability_key IS NULL
            AND capability_revision IS NULL
            AND arguments_digest IS NULL
            AND round IS NULL
            AND sensitivity IS NULL)
        OR
        (state_id IS NOT NULL
            AND method IS NOT NULL
            AND capability_key IS NOT NULL
            AND capability_revision IS NOT NULL
            AND arguments_digest IS NOT NULL)
    )
);

CREATE INDEX mcp_mrtr_audit_state_idx
    ON public.mcp_mrtr_audit_events (state_id, audit_id)
    WHERE state_id IS NOT NULL;
CREATE INDEX mcp_mrtr_audit_kind_time_idx
    ON public.mcp_mrtr_audit_events (kind, occurred_at, audit_id);

CREATE FUNCTION public.enforce_mcp_mrtr_state_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.expires_at > clock_timestamp() THEN
            RAISE EXCEPTION 'live MRTR replay state cannot be deleted' USING ERRCODE = '23514';
        END IF;
        RETURN OLD;
    END IF;

    IF NEW.state_id IS DISTINCT FROM OLD.state_id
       OR NEW.principal_digest IS DISTINCT FROM OLD.principal_digest
       OR NEW.tenant_digest IS DISTINCT FROM OLD.tenant_digest
       OR NEW.method IS DISTINCT FROM OLD.method
       OR NEW.idempotency_digest IS DISTINCT FROM OLD.idempotency_digest
       OR NEW.capability_key IS DISTINCT FROM OLD.capability_key
       OR NEW.capability_revision IS DISTINCT FROM OLD.capability_revision
       OR NEW.arguments_digest IS DISTINCT FROM OLD.arguments_digest
       OR NEW.associated_digest IS DISTINCT FROM OLD.associated_digest
       OR NEW.plan_version IS DISTINCT FROM OLD.plan_version
       OR NEW.plan IS DISTINCT FROM OLD.plan
       OR NEW.continuation_id IS DISTINCT FROM OLD.continuation_id
       OR NEW.round IS DISTINCT FROM OLD.round
       OR NEW.max_rounds IS DISTINCT FROM OLD.max_rounds
       OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'MRTR replay state binding is immutable' USING ERRCODE = '23514';
    END IF;

    IF NOT (
        (OLD.status = 'pending' AND NEW.status = 'claimed')
        OR (
            OLD.status = 'claimed'
            AND NEW.status IN (
                'replaced_invalid_response', 'replaced_more_input', 'completed', 'declined',
                'cancelled', 'exhausted', 'invocation_failed', 'rejected'
            )
        )
    ) THEN
        RAISE EXCEPTION 'MRTR replay state transition is invalid' USING ERRCODE = '23514';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'MRTR replay state timestamp moved backward' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER mcp_mrtr_state_lifecycle
    BEFORE UPDATE OR DELETE ON public.mcp_mrtr_states
    FOR EACH ROW EXECUTE FUNCTION public.enforce_mcp_mrtr_state_lifecycle();

CREATE FUNCTION public.prevent_mcp_mrtr_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'MRTR audit events are append-only' USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER mcp_mrtr_audit_append_only
    BEFORE UPDATE OR DELETE ON public.mcp_mrtr_audit_events
    FOR EACH ROW EXECUTE FUNCTION public.prevent_mcp_mrtr_audit_mutation();
