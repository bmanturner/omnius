CREATE TABLE public.webhook_receipts (
    id uuid PRIMARY KEY,
    provider varchar(64) NOT NULL,
    provider_scope varchar(255) NOT NULL,
    event_id varchar(255) NOT NULL,
    content_digest bytea NOT NULL,
    event_type varchar(128) NOT NULL,
    event_version integer NOT NULL,
    parsed_payload jsonb NOT NULL,
    verified_at timestamptz NOT NULL,
    provider_timestamp timestamptz NOT NULL,
    occurred_at timestamptz,
    status varchar(24) NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL,
    lease_token uuid,
    lease_expires_at timestamptz,
    processed_at timestamptz,
    dead_lettered_at timestamptz,
    last_error_class varchar(64),
    retain_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT webhook_receipts_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT webhook_receipts_provider_identifier CHECK (
        octet_length(provider) BETWEEN 1 AND 64
        AND provider ~ '^[a-z][a-z0-9._-]*$'
    ),
    CONSTRAINT webhook_receipts_scope_identifier CHECK (
        octet_length(provider_scope) BETWEEN 1 AND 255
        AND provider_scope ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    CONSTRAINT webhook_receipts_event_id_identifier CHECK (
        octet_length(event_id) BETWEEN 1 AND 255
        AND event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    CONSTRAINT webhook_receipts_digest_size CHECK (octet_length(content_digest) = 32),
    CONSTRAINT webhook_receipts_event_type_identifier CHECK (
        octet_length(event_type) BETWEEN 1 AND 128
        AND event_type ~ '^[a-z][a-z0-9._-]*$'
    ),
    CONSTRAINT webhook_receipts_event_version_bounded CHECK (
        event_version BETWEEN 1 AND 65535
    ),
    CONSTRAINT webhook_receipts_payload_bounded CHECK (
        octet_length(parsed_payload::text) BETWEEN 1 AND 262144
    ),
    CONSTRAINT webhook_receipts_status_known CHECK (
        status IN ('pending', 'processing', 'processed', 'dead_letter')
    ),
    CONSTRAINT webhook_receipts_attempts_bounded CHECK (attempt_count BETWEEN 0 AND 20),
    CONSTRAINT webhook_receipts_lease_token_uuid_v7 CHECK (
        lease_token IS NULL
        OR (
            (get_byte(uuid_send(lease_token), 6) >> 4) = 7
            AND (get_byte(uuid_send(lease_token), 8) & 192) = 128
        )
    ),
    CONSTRAINT webhook_receipts_lease_pair CHECK (
        (lease_token IS NULL) = (lease_expires_at IS NULL)
    ),
    CONSTRAINT webhook_receipts_state_coherent CHECK (
        (
            status = 'pending'
            AND lease_token IS NULL
            AND processed_at IS NULL
            AND dead_lettered_at IS NULL
        )
        OR (
            status = 'processing'
            AND lease_token IS NOT NULL
            AND processed_at IS NULL
            AND dead_lettered_at IS NULL
            AND attempt_count > 0
        )
        OR (
            status = 'processed'
            AND lease_token IS NULL
            AND processed_at IS NOT NULL
            AND dead_lettered_at IS NULL
        )
        OR (
            status = 'dead_letter'
            AND lease_token IS NULL
            AND processed_at IS NULL
            AND dead_lettered_at IS NOT NULL
            AND attempt_count > 0
        )
    ),
    CONSTRAINT webhook_receipts_failure_class_identifier CHECK (
        last_error_class IS NULL
        OR (
            octet_length(last_error_class) BETWEEN 1 AND 64
            AND last_error_class ~ '^[a-z][a-z0-9._-]*$'
        )
    ),
    CONSTRAINT webhook_receipts_timestamp_order CHECK (
        updated_at >= created_at
        AND available_at >= verified_at
        AND retain_until > verified_at
        AND (lease_expires_at IS NULL OR lease_expires_at > updated_at)
        AND (processed_at IS NULL OR processed_at >= verified_at)
        AND (dead_lettered_at IS NULL OR dead_lettered_at >= verified_at)
    ),
    CONSTRAINT webhook_receipts_identity_key UNIQUE (provider, provider_scope, event_id)
);

CREATE FUNCTION public.webhook_receipts_preserve_fence()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.provider IS DISTINCT FROM OLD.provider
        OR NEW.provider_scope IS DISTINCT FROM OLD.provider_scope
        OR NEW.event_id IS DISTINCT FROM OLD.event_id
        OR NEW.content_digest IS DISTINCT FROM OLD.content_digest
        OR NEW.event_type IS DISTINCT FROM OLD.event_type
        OR NEW.event_version IS DISTINCT FROM OLD.event_version
        OR NEW.provider_timestamp IS DISTINCT FROM OLD.provider_timestamp
        OR NEW.verified_at IS DISTINCT FROM OLD.verified_at
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION 'webhook receipt immutable fence cannot be changed'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER webhook_receipts_preserve_fence
BEFORE UPDATE ON public.webhook_receipts
FOR EACH ROW
EXECUTE FUNCTION public.webhook_receipts_preserve_fence();

CREATE INDEX webhook_receipts_ready_idx
    ON public.webhook_receipts (available_at, id)
    WHERE status = 'pending';

CREATE INDEX webhook_receipts_lease_recovery_idx
    ON public.webhook_receipts (lease_expires_at, id)
    WHERE status = 'processing';

CREATE INDEX webhook_receipts_retention_idx
    ON public.webhook_receipts (retain_until, id)
    WHERE status IN ('processed', 'dead_letter');
