CREATE TABLE public.llm_media_objects (
    media_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE RESTRICT,
    owner_subject_id uuid NOT NULL,
    object_key uuid NOT NULL,
    origin varchar(24) NOT NULL,
    kind varchar(16) NOT NULL,
    expected_size bigint NOT NULL,
    expected_sha256 bytea NOT NULL,
    expected_mime varchar(127) NOT NULL,
    state varchar(24) NOT NULL,
    rejection_reason varchar(32),
    expires_at timestamptz NOT NULL,
    revision bigint NOT NULL DEFAULT 1,
    deletion_revision bigint,
    claim_token uuid,
    claim_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT llm_media_id_uuid_v7 CHECK (
        (get_byte(uuid_send(media_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(media_id), 8) & 192) = 128
    ),
    CONSTRAINT llm_media_owner_uuid_v7 CHECK (
        (get_byte(uuid_send(owner_subject_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(owner_subject_id), 8) & 192) = 128
    ),
    CONSTRAINT llm_media_object_key_uuid_v7 CHECK (
        (get_byte(uuid_send(object_key), 6) >> 4) = 7
        AND (get_byte(uuid_send(object_key), 8) & 192) = 128
    ),
    CONSTRAINT llm_media_tenant_object_unique UNIQUE (tenant_id, object_key),
    CONSTRAINT llm_media_origin_allowed CHECK (origin IN ('user_upload', 'provider_output')),
    CONSTRAINT llm_media_kind_allowed CHECK (kind IN ('image', 'audio', 'video', 'file')),
    CONSTRAINT llm_media_expected_size_bounds CHECK (expected_size BETWEEN 1 AND 536870912),
    CONSTRAINT llm_media_expected_sha256_length CHECK (octet_length(expected_sha256) = 32),
    CONSTRAINT llm_media_expected_mime_canonical CHECK (
        expected_mime = lower(expected_mime)
        AND expected_mime ~ '^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$'
    ),
    CONSTRAINT llm_media_state_allowed CHECK (
        state IN ('quarantined', 'clean', 'rejected', 'deletion_pending', 'deleted')
    ),
    CONSTRAINT llm_media_rejection_allowed CHECK (
        rejection_reason IS NULL OR rejection_reason IN (
            'missing_object', 'size_mismatch', 'checksum_mismatch', 'mime_mismatch',
            'scan_rejected', 'scanner_failure', 'storage_failure'
        )
    ),
    CONSTRAINT llm_media_revision_positive CHECK (revision >= 1),
    CONSTRAINT llm_media_deletion_revision_valid CHECK (
        deletion_revision IS NULL OR deletion_revision BETWEEN 1 AND revision
    ),
    CONSTRAINT llm_media_claim_coherent CHECK (
        (claim_token IS NULL AND claim_expires_at IS NULL)
        OR (
            claim_token IS NOT NULL
            AND claim_expires_at IS NOT NULL
            AND state IN ('quarantined', 'rejected', 'deletion_pending')
            AND (get_byte(uuid_send(claim_token), 6) >> 4) = 7
            AND (get_byte(uuid_send(claim_token), 8) & 192) = 128
        )
    ),
    CONSTRAINT llm_media_state_coherent CHECK (
        (state IN ('quarantined', 'clean') AND rejection_reason IS NULL AND deletion_revision IS NULL)
        OR (state = 'rejected' AND rejection_reason IS NOT NULL AND deletion_revision IS NOT NULL)
        OR (state = 'deletion_pending' AND rejection_reason IS NULL AND deletion_revision IS NOT NULL)
        OR (state = 'deleted' AND deletion_revision IS NOT NULL)
    ),
    CONSTRAINT llm_media_timestamps_ordered CHECK (
        updated_at >= created_at
        AND expires_at > created_at
        AND expires_at <= created_at + INTERVAL '30 days'
        AND (claim_expires_at IS NULL OR claim_expires_at > created_at)
    )
);

CREATE INDEX llm_media_tenant_lookup_idx
    ON public.llm_media_objects (tenant_id, media_id);
CREATE INDEX llm_media_reconciliation_idx
    ON public.llm_media_objects (updated_at, media_id)
    WHERE state IN ('quarantined', 'rejected', 'deletion_pending');
CREATE INDEX llm_media_expiry_idx
    ON public.llm_media_objects (expires_at, media_id)
    WHERE state IN ('quarantined', 'clean');
CREATE INDEX llm_media_expired_claim_idx
    ON public.llm_media_objects (claim_expires_at, media_id)
    WHERE claim_token IS NOT NULL;

CREATE TABLE public.llm_diagnostic_captures (
    capture_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    principal_id uuid NOT NULL,
    operation_id varchar(128),
    job_id varchar(128),
    provider_id varchar(128),
    tool_id varchar(128),
    encryption_key_id varchar(128) NOT NULL,
    redaction_profile varchar(128) NOT NULL,
    sample_rate_ppm integer NOT NULL,
    sample_value integer NOT NULL,
    encrypted_payload bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT llm_diagnostic_capture_id_uuid_v7 CHECK (
        (get_byte(uuid_send(capture_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(capture_id), 8) & 192) = 128
    ),
    CONSTRAINT llm_diagnostic_principal_uuid_v7 CHECK (
        (get_byte(uuid_send(principal_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(principal_id), 8) & 192) = 128
    ),
    CONSTRAINT llm_diagnostic_identity_bounds CHECK (
        (operation_id IS NULL OR (
            octet_length(operation_id) BETWEEN 1 AND 128
            AND operation_id ~ '^[A-Za-z0-9:._/-]+$'
        ))
        AND (job_id IS NULL OR (
            octet_length(job_id) BETWEEN 1 AND 128
            AND job_id ~ '^[A-Za-z0-9:._/-]+$'
        ))
        AND (provider_id IS NULL OR (
            octet_length(provider_id) BETWEEN 1 AND 128
            AND provider_id ~ '^[A-Za-z0-9:._/-]+$'
        ))
        AND (tool_id IS NULL OR (
            octet_length(tool_id) BETWEEN 1 AND 128
            AND tool_id ~ '^[A-Za-z0-9:._/-]+$'
        ))
    ),
    CONSTRAINT llm_diagnostic_policy_names_safe CHECK (
        octet_length(encryption_key_id) BETWEEN 1 AND 128
        AND encryption_key_id ~ '^[A-Za-z0-9:._-]+$'
        AND octet_length(redaction_profile) BETWEEN 1 AND 128
        AND redaction_profile ~ '^[A-Za-z0-9:._-]+$'
    ),
    CONSTRAINT llm_diagnostic_sampling_admitted CHECK (
        sample_rate_ppm BETWEEN 1 AND 1000000
        AND sample_value BETWEEN 0 AND sample_rate_ppm - 1
    ),
    CONSTRAINT llm_diagnostic_ciphertext_bounded CHECK (
        octet_length(encrypted_payload) BETWEEN 1 AND 16777216
    ),
    CONSTRAINT llm_diagnostic_expiry_bounded CHECK (
        expires_at > created_at
        AND expires_at <= created_at + INTERVAL '24 hours'
    )
);

CREATE INDEX llm_diagnostic_capture_tenant_idx
    ON public.llm_diagnostic_captures (tenant_id, capture_id);
CREATE INDEX llm_diagnostic_capture_expiry_idx
    ON public.llm_diagnostic_captures (expires_at, capture_id);

CREATE FUNCTION public.prevent_llm_media_illegal_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.media_id IS DISTINCT FROM OLD.media_id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.owner_subject_id IS DISTINCT FROM OLD.owner_subject_id
       OR NEW.object_key IS DISTINCT FROM OLD.object_key
       OR NEW.origin IS DISTINCT FROM OLD.origin
       OR NEW.kind IS DISTINCT FROM OLD.kind
       OR NEW.expected_size IS DISTINCT FROM OLD.expected_size
       OR NEW.expected_sha256 IS DISTINCT FROM OLD.expected_sha256
       OR NEW.expected_mime IS DISTINCT FROM OLD.expected_mime
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'LLM media immutable metadata cannot be changed' USING ERRCODE = '23514';
    END IF;

    IF OLD.deletion_revision IS NOT NULL
       AND NEW.deletion_revision IS DISTINCT FROM OLD.deletion_revision THEN
        RAISE EXCEPTION 'LLM media deletion revision is immutable' USING ERRCODE = '23514';
    END IF;

    IF NEW.state IS DISTINCT FROM OLD.state THEN
        IF NOT (
            (OLD.state = 'quarantined' AND NEW.state IN ('clean', 'rejected', 'deletion_pending'))
            OR (OLD.state = 'clean' AND NEW.state = 'deletion_pending')
            OR (OLD.state IN ('rejected', 'deletion_pending') AND NEW.state = 'deleted')
        ) THEN
            RAISE EXCEPTION 'LLM media lifecycle cannot move backward' USING ERRCODE = '23514';
        END IF;
        IF NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at THEN
            RAISE EXCEPTION 'LLM media lifecycle transition requires one revision' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.revision IS DISTINCT FROM OLD.revision
          OR NEW.rejection_reason IS DISTINCT FROM OLD.rejection_reason
          OR NEW.deletion_revision IS DISTINCT FROM OLD.deletion_revision
          OR NEW.updated_at IS DISTINCT FROM OLD.updated_at THEN
        RAISE EXCEPTION 'LLM media metadata changed without a lifecycle transition' USING ERRCODE = '23514';
    END IF;

    IF OLD.deletion_revision IS NULL AND NEW.deletion_revision IS NOT NULL
       AND NEW.deletion_revision <> NEW.revision THEN
        RAISE EXCEPTION 'LLM media deletion revision must fence its scheduling transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER llm_media_immutable_lifecycle
    BEFORE UPDATE ON public.llm_media_objects
    FOR EACH ROW EXECUTE FUNCTION public.prevent_llm_media_illegal_mutation();

CREATE VIEW public.llm_usage_admin_v1
WITH (security_barrier = true)
AS
SELECT
    reservation.tenant_id,
    reservation.reservation_id,
    reservation.principal_id,
    reservation.api_key_id,
    reservation.provider_id,
    reservation.model_id,
    reservation.route_id,
    reservation.tool_id,
    reservation.operation_id,
    reservation.job_id,
    reservation.state,
    reservation.usage_status,
    reservation.version,
    reservation.effective_requests,
    reservation.effective_concurrent_streams,
    reservation.effective_tokens,
    reservation.effective_units,
    reservation.effective_tool_calls,
    reservation.effective_media_bytes,
    reservation.effective_cost_microunits,
    reservation.created_at,
    reservation.updated_at
FROM public.llm_budget_reservations AS reservation;

CREATE VIEW public.llm_usage_audit_reconciliation_v1
WITH (security_barrier = true)
AS
SELECT
    usage.tenant_id,
    usage.reservation_id,
    usage.principal_id,
    usage.api_key_id,
    usage.provider_id,
    usage.model_id,
    usage.route_id,
    usage.tool_id,
    usage.operation_id,
    usage.job_id,
    usage.state,
    usage.usage_status,
    usage.version,
    usage.effective_requests,
    usage.effective_concurrent_streams,
    usage.effective_tokens,
    usage.effective_units,
    usage.effective_tool_calls,
    usage.effective_media_bytes,
    usage.effective_cost_microunits,
    usage.created_at,
    usage.updated_at,
    audit.id AS audit_event_id,
    audit.occurred_at AS audit_occurred_at,
    audit.actor_subject_id AS audit_actor_subject_id,
    audit.subject_id AS audit_subject_id,
    audit.effective_tenant_id AS audit_effective_tenant_id,
    audit.outcome AS audit_outcome,
    (
        audit.id IS NOT NULL
        AND audit.effective_tenant_id = usage.tenant_id
        AND (
            usage.principal_id IS NULL
            OR audit.actor_subject_id::text = usage.principal_id
            OR audit.subject_id::text = usage.principal_id
        )
    ) AS identities_reconciled
FROM public.llm_usage_admin_v1 AS usage
LEFT JOIN LATERAL (
    SELECT
        event.id,
        event.occurred_at,
        event.actor_subject_id,
        event.subject_id,
        event.effective_tenant_id,
        event.outcome
    FROM public.audit_events AS event
    WHERE event.event_type = 'security.llm.usage.mutated'
      AND event.resource_kind = 'llm_usage_reservation'
      AND event.resource_id = usage.reservation_id
      AND event.effective_tenant_id = usage.tenant_id
    ORDER BY event.occurred_at DESC, event.id DESC
    LIMIT 1
) AS audit ON true;
