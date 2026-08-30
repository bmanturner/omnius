CREATE TABLE public.llm_budget_reservations (
    tenant_id uuid NOT NULL,
    reservation_id varchar(128) NOT NULL,
    idempotency_key varchar(128) NOT NULL,
    request_fingerprint bytea NOT NULL,
    principal_id varchar(128),
    api_key_id varchar(128),
    provider_id varchar(128),
    model_id varchar(128),
    route_id varchar(128),
    tool_id varchar(128),
    operation_id varchar(128),
    job_id varchar(128),
    scope_snapshot jsonb NOT NULL,
    estimate_snapshot jsonb NOT NULL,
    policy_snapshot jsonb NOT NULL,
    state_snapshot jsonb NOT NULL,
    state varchar(16) NOT NULL,
    usage_status varchar(16) NOT NULL,
    version bigint NOT NULL,
    effective_requests numeric(20, 0) NOT NULL,
    effective_concurrent_streams numeric(20, 0) NOT NULL,
    effective_tokens numeric(20, 0) NOT NULL,
    effective_units numeric(20, 0) NOT NULL,
    effective_tool_calls numeric(20, 0) NOT NULL,
    effective_media_bytes numeric(20, 0) NOT NULL,
    effective_cost_microunits numeric(20, 0) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT llm_budget_reservations_pkey PRIMARY KEY (tenant_id, reservation_id),
    CONSTRAINT llm_budget_reservations_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES public.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT llm_budget_reservations_tenant_idempotency_key
        UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT llm_budget_reservations_reservation_id_safe CHECK (
        octet_length(reservation_id) BETWEEN 1 AND 128
        AND reservation_id ~ '^[A-Za-z0-9._/:@-]+$'
    ),
    CONSTRAINT llm_budget_reservations_idempotency_key_safe CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9._/:@-]+$'
    ),
    CONSTRAINT llm_budget_reservations_fingerprint_length CHECK (
        octet_length(request_fingerprint) = 32
    ),
    CONSTRAINT llm_budget_reservations_dimension_ids_safe CHECK (
        (principal_id IS NULL OR (
            octet_length(principal_id) BETWEEN 1 AND 128
            AND principal_id ~ '^[A-Za-z0-9._/:@-]+$'
        ))
        AND (api_key_id IS NULL OR (
            octet_length(api_key_id) BETWEEN 1 AND 128
            AND api_key_id ~ '^[A-Za-z0-9._/:@-]+$'
        ))
        AND (provider_id IS NULL OR (
            octet_length(provider_id) BETWEEN 1 AND 128
            AND provider_id ~ '^[A-Za-z0-9._/:@-]+$'
        ))
        AND (model_id IS NULL OR (
            octet_length(model_id) BETWEEN 1 AND 128
            AND model_id ~ '^[A-Za-z0-9._/:@-]+$'
        ))
        AND (route_id IS NULL OR (
            octet_length(route_id) BETWEEN 1 AND 128
            AND route_id ~ '^[A-Za-z0-9._/:@-]+$'
        ))
        AND (tool_id IS NULL OR (
            octet_length(tool_id) BETWEEN 1 AND 128
            AND tool_id ~ '^[A-Za-z0-9._/:@-]+$'
        ))
        AND (operation_id IS NULL OR (
            octet_length(operation_id) BETWEEN 1 AND 128
            AND operation_id ~ '^[A-Za-z0-9._/:@-]+$'
        ))
        AND (job_id IS NULL OR (
            octet_length(job_id) BETWEEN 1 AND 128
            AND job_id ~ '^[A-Za-z0-9._/:@-]+$'
        ))
    ),
    CONSTRAINT llm_budget_reservations_scope_snapshot_shape CHECK (
        jsonb_typeof(scope_snapshot) = 'object'
        AND scope_snapshot ->> 'tenant' = tenant_id::text
        AND scope_snapshot ? 'principal'
        AND scope_snapshot ->> 'principal' IS NOT DISTINCT FROM principal_id
        AND scope_snapshot ? 'api_key'
        AND scope_snapshot ->> 'api_key' IS NOT DISTINCT FROM api_key_id
        AND scope_snapshot ? 'provider'
        AND scope_snapshot ->> 'provider' IS NOT DISTINCT FROM provider_id
        AND scope_snapshot ? 'model'
        AND scope_snapshot ->> 'model' IS NOT DISTINCT FROM model_id
        AND scope_snapshot ? 'route'
        AND scope_snapshot ->> 'route' IS NOT DISTINCT FROM route_id
        AND scope_snapshot ? 'tool'
        AND scope_snapshot ->> 'tool' IS NOT DISTINCT FROM tool_id
        AND scope_snapshot ? 'operation'
        AND scope_snapshot ->> 'operation' IS NOT DISTINCT FROM operation_id
        AND scope_snapshot ? 'job'
        AND scope_snapshot ->> 'job' IS NOT DISTINCT FROM job_id
    ),
    CONSTRAINT llm_budget_reservations_snapshots_shaped CHECK (
        jsonb_typeof(estimate_snapshot) = 'object'
        AND jsonb_typeof(policy_snapshot) = 'array'
        AND jsonb_array_length(policy_snapshot) BETWEEN 0 AND 9
        AND jsonb_typeof(state_snapshot) IN ('string', 'object')
    ),
    CONSTRAINT llm_budget_reservations_state_known CHECK (
        state IN ('reserved', 'committed', 'reconciled', 'released')
    ),
    CONSTRAINT llm_budget_reservations_usage_status_known CHECK (
        usage_status IN ('estimated', 'actual', 'missing', 'ambiguous')
    ),
    CONSTRAINT llm_budget_reservations_lifecycle_valid CHECK (
        (state = 'reserved'
            AND usage_status = 'estimated'
            AND version = 0
            AND state_snapshot = '"reserved"'::jsonb)
        OR (state = 'committed'
            AND usage_status IN ('missing', 'ambiguous')
            AND version = 1
            AND jsonb_typeof(state_snapshot) = 'object'
            AND state_snapshot ? 'committed')
        OR (state = 'reconciled'
            AND usage_status = 'actual'
            AND version IN (1, 2)
            AND jsonb_typeof(state_snapshot) = 'object'
            AND state_snapshot ? 'reconciled')
        OR (state = 'released'
            AND usage_status = 'estimated'
            AND version = 1
            AND state_snapshot = '"released"'::jsonb)
    ),
    CONSTRAINT llm_budget_reservations_effective_values_valid CHECK (
        effective_requests BETWEEN 0 AND 18446744073709551615
        AND effective_concurrent_streams BETWEEN 0 AND 18446744073709551615
        AND effective_tokens BETWEEN 0 AND 18446744073709551615
        AND effective_units BETWEEN 0 AND 18446744073709551615
        AND effective_tool_calls BETWEEN 0 AND 18446744073709551615
        AND effective_media_bytes BETWEEN 0 AND 18446744073709551615
        AND effective_cost_microunits BETWEEN 0 AND 18446744073709551615
    ),
    CONSTRAINT llm_budget_reservations_timestamp_order CHECK (updated_at >= created_at),
    CONSTRAINT llm_budget_reservations_released_zero CHECK (
        state <> 'released'
        OR (
            effective_requests = 0
            AND effective_concurrent_streams = 0
            AND effective_tokens = 0
            AND effective_units = 0
            AND effective_tool_calls = 0
            AND effective_media_bytes = 0
            AND effective_cost_microunits = 0
        )
    )
);

CREATE FUNCTION public.protect_llm_budget_reservation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            TABLE = 'llm_budget_reservations',
            MESSAGE = 'LLM budget reservations cannot be removed';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.reservation_id IS DISTINCT FROM OLD.reservation_id
        OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
        OR NEW.request_fingerprint IS DISTINCT FROM OLD.request_fingerprint
        OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
        OR NEW.api_key_id IS DISTINCT FROM OLD.api_key_id
        OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
        OR NEW.model_id IS DISTINCT FROM OLD.model_id
        OR NEW.route_id IS DISTINCT FROM OLD.route_id
        OR NEW.tool_id IS DISTINCT FROM OLD.tool_id
        OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
        OR NEW.job_id IS DISTINCT FROM OLD.job_id
        OR NEW.scope_snapshot IS DISTINCT FROM OLD.scope_snapshot
        OR NEW.estimate_snapshot IS DISTINCT FROM OLD.estimate_snapshot
        OR NEW.policy_snapshot IS DISTINCT FROM OLD.policy_snapshot
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            TABLE = 'llm_budget_reservations',
            MESSAGE = 'LLM budget reservation identity is immutable';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'llm_budget_reservations_version_cas',
            TABLE = 'llm_budget_reservations',
            MESSAGE = 'LLM budget reservation version must advance exactly once';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER llm_budget_reservations_protect_update
BEFORE UPDATE ON public.llm_budget_reservations
FOR EACH ROW EXECUTE FUNCTION public.protect_llm_budget_reservation();

CREATE TRIGGER llm_budget_reservations_reject_removal
BEFORE DELETE OR TRUNCATE ON public.llm_budget_reservations
FOR EACH STATEMENT EXECUTE FUNCTION public.protect_llm_budget_reservation();

CREATE TABLE public.llm_usage_ledger (
    tenant_id uuid NOT NULL,
    reservation_id varchar(128) NOT NULL,
    version bigint NOT NULL,
    attribution varchar(16) NOT NULL,
    event_kind varchar(16) NOT NULL,
    state varchar(16) NOT NULL,
    usage_status varchar(16) NOT NULL,
    event_snapshot jsonb NOT NULL,
    effective_requests numeric(20, 0) NOT NULL,
    effective_concurrent_streams numeric(20, 0) NOT NULL,
    effective_tokens numeric(20, 0) NOT NULL,
    effective_units numeric(20, 0) NOT NULL,
    effective_tool_calls numeric(20, 0) NOT NULL,
    effective_media_bytes numeric(20, 0) NOT NULL,
    effective_cost_microunits numeric(20, 0) NOT NULL,
    delta_requests numeric(21, 0) NOT NULL,
    delta_concurrent_streams numeric(21, 0) NOT NULL,
    delta_tokens numeric(21, 0) NOT NULL,
    delta_units numeric(21, 0) NOT NULL,
    delta_tool_calls numeric(21, 0) NOT NULL,
    delta_media_bytes numeric(21, 0) NOT NULL,
    delta_cost_microunits numeric(21, 0) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT llm_usage_ledger_pkey
        PRIMARY KEY (tenant_id, reservation_id, version, attribution),
    CONSTRAINT llm_usage_ledger_reservation_fkey
        FOREIGN KEY (tenant_id, reservation_id)
        REFERENCES public.llm_budget_reservations (tenant_id, reservation_id)
        ON DELETE RESTRICT,
    CONSTRAINT llm_usage_ledger_version_valid CHECK (version BETWEEN 0 AND 2),
    CONSTRAINT llm_usage_ledger_attribution_known CHECK (
        attribution IN ('primary', 'retry', 'repair', 'tool')
    ),
    CONSTRAINT llm_usage_ledger_event_kind_known CHECK (
        event_kind IN ('reserved', 'committed', 'reconciled', 'released')
    ),
    CONSTRAINT llm_usage_ledger_state_known CHECK (
        state IN ('reserved', 'committed', 'reconciled', 'released')
    ),
    CONSTRAINT llm_usage_ledger_usage_status_known CHECK (
        usage_status IN ('estimated', 'actual', 'missing', 'ambiguous')
    ),
    CONSTRAINT llm_usage_ledger_event_lifecycle_valid CHECK (
        (event_kind = 'reserved'
            AND state = 'reserved'
            AND usage_status = 'estimated'
            AND version = 0)
        OR (event_kind = 'committed'
            AND version = 1
            AND (
                (state = 'committed' AND usage_status IN ('missing', 'ambiguous'))
                OR (state = 'reconciled' AND usage_status = 'actual')
            ))
        OR (event_kind = 'reconciled'
            AND state = 'reconciled'
            AND usage_status = 'actual'
            AND version = 2)
        OR (event_kind = 'released'
            AND state = 'released'
            AND usage_status = 'estimated'
            AND version = 1)
    ),
    CONSTRAINT llm_usage_ledger_event_snapshot_shape CHECK (
        jsonb_typeof(event_snapshot) = 'object'
    ),
    CONSTRAINT llm_usage_ledger_effective_values_valid CHECK (
        effective_requests BETWEEN 0 AND 18446744073709551615
        AND effective_concurrent_streams BETWEEN 0 AND 18446744073709551615
        AND effective_tokens BETWEEN 0 AND 18446744073709551615
        AND effective_units BETWEEN 0 AND 18446744073709551615
        AND effective_tool_calls BETWEEN 0 AND 18446744073709551615
        AND effective_media_bytes BETWEEN 0 AND 18446744073709551615
        AND effective_cost_microunits BETWEEN 0 AND 18446744073709551615
    ),
    CONSTRAINT llm_usage_ledger_delta_values_valid CHECK (
        delta_requests BETWEEN -18446744073709551615 AND 18446744073709551615
        AND delta_concurrent_streams BETWEEN -18446744073709551615 AND 18446744073709551615
        AND delta_tokens BETWEEN -18446744073709551615 AND 18446744073709551615
        AND delta_units BETWEEN -18446744073709551615 AND 18446744073709551615
        AND delta_tool_calls BETWEEN -18446744073709551615 AND 18446744073709551615
        AND delta_media_bytes BETWEEN -18446744073709551615 AND 18446744073709551615
        AND delta_cost_microunits BETWEEN -18446744073709551615 AND 18446744073709551615
    )
);

CREATE TABLE public.llm_cost_adjustments (
    tenant_id uuid NOT NULL,
    reservation_id varchar(128) NOT NULL,
    version bigint NOT NULL,
    attribution varchar(16) NOT NULL,
    basis varchar(24) NOT NULL,
    previous_cost_microunits numeric(20, 0) NOT NULL,
    new_cost_microunits numeric(20, 0) NOT NULL,
    delta_cost_microunits numeric(21, 0) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT llm_cost_adjustments_pkey
        PRIMARY KEY (tenant_id, reservation_id, version, attribution),
    CONSTRAINT llm_cost_adjustments_ledger_fkey
        FOREIGN KEY (tenant_id, reservation_id, version, attribution)
        REFERENCES public.llm_usage_ledger (tenant_id, reservation_id, version, attribution)
        ON DELETE RESTRICT,
    CONSTRAINT llm_cost_adjustments_basis_known CHECK (
        basis IN ('reservation', 'provider_commit', 'provider_reconcile', 'release')
    ),
    CONSTRAINT llm_cost_adjustments_values_valid CHECK (
        previous_cost_microunits BETWEEN 0 AND 18446744073709551615
        AND new_cost_microunits BETWEEN 0 AND 18446744073709551615
        AND delta_cost_microunits BETWEEN -18446744073709551615 AND 18446744073709551615
        AND delta_cost_microunits = new_cost_microunits - previous_cost_microunits
    )
);

CREATE FUNCTION public.reject_llm_usage_fact_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'LLM usage and cost facts are append-only';
END;
$$;

CREATE TRIGGER llm_usage_ledger_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON public.llm_usage_ledger
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_llm_usage_fact_mutation();

CREATE TRIGGER llm_cost_adjustments_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON public.llm_cost_adjustments
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_llm_usage_fact_mutation();

CREATE INDEX llm_budget_reservations_tenant_active_totals_idx
    ON public.llm_budget_reservations (tenant_id)
    INCLUDE (
        effective_requests, effective_concurrent_streams, effective_tokens, effective_units,
        effective_tool_calls, effective_media_bytes, effective_cost_microunits
    )
    WHERE state <> 'released';

CREATE INDEX llm_budget_reservations_principal_active_totals_idx
    ON public.llm_budget_reservations (tenant_id, principal_id)
    INCLUDE (
        effective_requests, effective_concurrent_streams, effective_tokens, effective_units,
        effective_tool_calls, effective_media_bytes, effective_cost_microunits
    )
    WHERE state <> 'released' AND principal_id IS NOT NULL;

CREATE INDEX llm_budget_reservations_api_key_active_totals_idx
    ON public.llm_budget_reservations (tenant_id, api_key_id)
    INCLUDE (
        effective_requests, effective_concurrent_streams, effective_tokens, effective_units,
        effective_tool_calls, effective_media_bytes, effective_cost_microunits
    )
    WHERE state <> 'released' AND api_key_id IS NOT NULL;

CREATE INDEX llm_budget_reservations_provider_active_totals_idx
    ON public.llm_budget_reservations (tenant_id, provider_id)
    INCLUDE (
        effective_requests, effective_concurrent_streams, effective_tokens, effective_units,
        effective_tool_calls, effective_media_bytes, effective_cost_microunits
    )
    WHERE state <> 'released' AND provider_id IS NOT NULL;

CREATE INDEX llm_budget_reservations_model_active_totals_idx
    ON public.llm_budget_reservations (tenant_id, model_id)
    INCLUDE (
        effective_requests, effective_concurrent_streams, effective_tokens, effective_units,
        effective_tool_calls, effective_media_bytes, effective_cost_microunits
    )
    WHERE state <> 'released' AND model_id IS NOT NULL;

CREATE INDEX llm_budget_reservations_route_active_totals_idx
    ON public.llm_budget_reservations (tenant_id, route_id)
    INCLUDE (
        effective_requests, effective_concurrent_streams, effective_tokens, effective_units,
        effective_tool_calls, effective_media_bytes, effective_cost_microunits
    )
    WHERE state <> 'released' AND route_id IS NOT NULL;

CREATE INDEX llm_budget_reservations_tool_active_totals_idx
    ON public.llm_budget_reservations (tenant_id, tool_id)
    INCLUDE (
        effective_requests, effective_concurrent_streams, effective_tokens, effective_units,
        effective_tool_calls, effective_media_bytes, effective_cost_microunits
    )
    WHERE state <> 'released' AND tool_id IS NOT NULL;

CREATE INDEX llm_budget_reservations_operation_active_totals_idx
    ON public.llm_budget_reservations (tenant_id, operation_id)
    INCLUDE (
        effective_requests, effective_concurrent_streams, effective_tokens, effective_units,
        effective_tool_calls, effective_media_bytes, effective_cost_microunits
    )
    WHERE state <> 'released' AND operation_id IS NOT NULL;

CREATE INDEX llm_budget_reservations_job_active_totals_idx
    ON public.llm_budget_reservations (tenant_id, job_id)
    INCLUDE (
        effective_requests, effective_concurrent_streams, effective_tokens, effective_units,
        effective_tool_calls, effective_media_bytes, effective_cost_microunits
    )
    WHERE state <> 'released' AND job_id IS NOT NULL;

CREATE INDEX llm_usage_ledger_reservation_version_idx
    ON public.llm_usage_ledger (tenant_id, reservation_id, version DESC);

CREATE INDEX llm_usage_ledger_tenant_created_idx
    ON public.llm_usage_ledger (tenant_id, created_at DESC, reservation_id, version DESC);

CREATE INDEX llm_cost_adjustments_tenant_created_nonzero_idx
    ON public.llm_cost_adjustments (tenant_id, created_at DESC, reservation_id, version DESC)
    WHERE delta_cost_microunits <> 0;

COMMENT ON TABLE public.llm_budget_reservations IS
    'Tenant-owned mutable CAS headers for authoritative LLM quota reservations.';
COMMENT ON TABLE public.llm_usage_ledger IS
    'Append-only attributed LLM usage facts; contains no prompts or provider bodies.';
COMMENT ON TABLE public.llm_cost_adjustments IS
    'Append-only exact monetary reconciliation facts in integer microunits.';
COMMENT ON COLUMN public.llm_budget_reservations.request_fingerprint IS
    'Opaque digest of dispatch-affecting input; never raw request content.';
COMMENT ON COLUMN public.llm_usage_ledger.event_snapshot IS
    'Identifier-free canonical ledger event projection.';

REVOKE ALL ON TABLE public.llm_budget_reservations FROM PUBLIC;
REVOKE ALL ON TABLE public.llm_usage_ledger FROM PUBLIC;
REVOKE ALL ON TABLE public.llm_cost_adjustments FROM PUBLIC;
REVOKE ALL ON FUNCTION public.protect_llm_budget_reservation() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.reject_llm_usage_fact_mutation() FROM PUBLIC;
