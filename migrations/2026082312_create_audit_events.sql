CREATE FUNCTION public.audit_metadata_is_safe(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
DECLARE
    item_key text;
    item_value jsonb;
    item_count integer := 0;
BEGIN
    IF jsonb_typeof(candidate) IS DISTINCT FROM 'object' THEN
        RETURN false;
    END IF;

    IF octet_length(candidate::text) > 4096 THEN
        RETURN false;
    END IF;

    FOR item_key, item_value IN SELECT key, value FROM jsonb_each(candidate)
    LOOP
        item_count := item_count + 1;
        IF item_count > 3 THEN
            RETURN false;
        END IF;

        IF item_key = 'attempt' THEN
            IF jsonb_typeof(item_value) <> 'number'
                OR (item_value #>> '{}') !~ '^[0-9]+$'
                OR (item_value #>> '{}')::numeric NOT BETWEEN 0 AND 255
            THEN
                RETURN false;
            END IF;
        ELSIF item_key IN ('cached', 'interactive') THEN
            IF jsonb_typeof(item_value) <> 'boolean' THEN
                RETURN false;
            END IF;
        ELSE
            RETURN false;
        END IF;
    END LOOP;

    RETURN true;
END;
$$;

CREATE TABLE public.audit_events (
    id uuid PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    event_type text NOT NULL,
    actor_kind text NOT NULL,
    actor_subject_id uuid,
    subject_id uuid,
    impersonator_subject_id uuid,
    effective_tenant_id uuid,
    action text NOT NULL,
    resource_kind text NOT NULL,
    resource_id text,
    outcome text NOT NULL,
    request_id uuid,
    correlation_id uuid,
    causation_id uuid,
    reason text,
    metadata jsonb NOT NULL,
    CONSTRAINT audit_events_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT audit_events_event_type_identifier CHECK (
        octet_length(event_type) BETWEEN 1 AND 128
        AND event_type ~ '^[A-Za-z0-9:._-]+$'
    ),
    CONSTRAINT audit_events_actor_kind_check CHECK (
        actor_kind IN ('anonymous', 'user', 'service_account', 'system')
    ),
    CONSTRAINT audit_events_actor_subject_coherent CHECK (
        (actor_kind IN ('user', 'service_account')) = (actor_subject_id IS NOT NULL)
    ),
    CONSTRAINT audit_events_impersonator_coherent CHECK (
        impersonator_subject_id IS NULL
        OR (
            actor_kind = 'user'
            AND impersonator_subject_id <> actor_subject_id
        )
    ),
    CONSTRAINT audit_events_actor_subject_id_uuid_v7 CHECK (
        actor_subject_id IS NULL
        OR (
            (get_byte(uuid_send(actor_subject_id), 6) >> 4) = 7
            AND (get_byte(uuid_send(actor_subject_id), 8) & 192) = 128
        )
    ),
    CONSTRAINT audit_events_subject_id_uuid_v7 CHECK (
        subject_id IS NULL
        OR (
            (get_byte(uuid_send(subject_id), 6) >> 4) = 7
            AND (get_byte(uuid_send(subject_id), 8) & 192) = 128
        )
    ),
    CONSTRAINT audit_events_impersonator_subject_id_uuid_v7 CHECK (
        impersonator_subject_id IS NULL
        OR (
            (get_byte(uuid_send(impersonator_subject_id), 6) >> 4) = 7
            AND (get_byte(uuid_send(impersonator_subject_id), 8) & 192) = 128
        )
    ),
    CONSTRAINT audit_events_effective_tenant_id_uuid_v7 CHECK (
        effective_tenant_id IS NULL
        OR (
            (get_byte(uuid_send(effective_tenant_id), 6) >> 4) = 7
            AND (get_byte(uuid_send(effective_tenant_id), 8) & 192) = 128
        )
    ),
    CONSTRAINT audit_events_action_identifier CHECK (
        octet_length(action) BETWEEN 1 AND 128
        AND action ~ '^[A-Za-z0-9:._-]+$'
    ),
    CONSTRAINT audit_events_resource_kind_identifier CHECK (
        octet_length(resource_kind) BETWEEN 1 AND 128
        AND resource_kind ~ '^[A-Za-z0-9:._-]+$'
    ),
    CONSTRAINT audit_events_resource_id_identifier CHECK (
        resource_id IS NULL
        OR (
            octet_length(resource_id) BETWEEN 1 AND 128
            AND resource_id ~ '^[A-Za-z0-9:._-]+$'
        )
    ),
    CONSTRAINT audit_events_outcome_check CHECK (
        outcome IN ('succeeded', 'denied', 'failed')
    ),
    CONSTRAINT audit_events_reason_identifier CHECK (
        reason IS NULL
        OR (
            octet_length(reason) BETWEEN 1 AND 128
            AND reason ~ '^[A-Za-z0-9:._-]+$'
        )
    ),
    CONSTRAINT audit_events_metadata_safe CHECK (public.audit_metadata_is_safe(metadata))
);

CREATE INDEX audit_events_tenant_time_idx
    ON public.audit_events (effective_tenant_id, occurred_at DESC, id DESC);

CREATE INDEX audit_events_actor_time_idx
    ON public.audit_events (actor_subject_id, occurred_at DESC, id DESC);

CREATE INDEX audit_events_correlation_time_idx
    ON public.audit_events (correlation_id, occurred_at DESC, id DESC);

CREATE FUNCTION public.reject_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        TABLE = 'audit_events',
        MESSAGE = 'audit events are append-only';
END;
$$;

CREATE TRIGGER audit_events_reject_mutation
BEFORE UPDATE OR DELETE OR TRUNCATE ON public.audit_events
FOR EACH STATEMENT
EXECUTE FUNCTION public.reject_audit_event_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON TABLE public.audit_events FROM PUBLIC;
