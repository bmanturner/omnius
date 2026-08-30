CREATE TABLE public.llm_conversations (
    tenant_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    revision bigint NOT NULL,
    last_message_sequence bigint,
    deletion_request_id uuid,
    fenced_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT llm_conversations_pkey
        PRIMARY KEY (tenant_id, principal_id, conversation_id),
    CONSTRAINT llm_conversations_conversation_id_uuid_v7 CHECK (
        (get_byte(uuid_send(conversation_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(conversation_id), 8) & 192) = 128
    ),
    CONSTRAINT llm_conversations_revision_positive CHECK (revision > 0),
    CONSTRAINT llm_conversations_sequence_positive CHECK (
        last_message_sequence IS NULL OR last_message_sequence > 0
    ),
    CONSTRAINT llm_conversations_revision_after_sequence CHECK (
        last_message_sequence IS NULL OR revision > last_message_sequence
    ),
    CONSTRAINT llm_conversations_timeline CHECK (updated_at >= created_at),
    CONSTRAINT llm_conversations_fence_complete CHECK (
        (deletion_request_id IS NULL AND fenced_at IS NULL)
        OR (
            deletion_request_id IS NOT NULL
            AND fenced_at IS NOT NULL
            AND fenced_at >= created_at
            AND updated_at = fenced_at
            AND (get_byte(uuid_send(deletion_request_id), 6) >> 4) = 7
            AND (get_byte(uuid_send(deletion_request_id), 8) & 192) = 128
        )
    )
);

CREATE TABLE public.llm_messages (
    tenant_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    message_id uuid NOT NULL,
    sequence bigint NOT NULL,
    revision bigint NOT NULL,
    canonical_message jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT llm_messages_pkey
        PRIMARY KEY (tenant_id, principal_id, conversation_id, message_id),
    CONSTRAINT llm_messages_conversation_fkey
        FOREIGN KEY (tenant_id, principal_id, conversation_id)
        REFERENCES public.llm_conversations (tenant_id, principal_id, conversation_id)
        ON DELETE CASCADE,
    CONSTRAINT llm_messages_sequence_key
        UNIQUE (tenant_id, principal_id, conversation_id, sequence),
    CONSTRAINT llm_messages_message_id_uuid_v7 CHECK (
        (get_byte(uuid_send(message_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(message_id), 8) & 192) = 128
    ),
    CONSTRAINT llm_messages_sequence_positive CHECK (sequence > 0),
    CONSTRAINT llm_messages_revision_positive CHECK (revision > 0),
    CONSTRAINT llm_messages_canonical_object CHECK (jsonb_typeof(canonical_message) = 'object'),
    CONSTRAINT llm_messages_timeline CHECK (updated_at >= created_at)
);

CREATE TABLE public.llm_provider_state (
    tenant_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    state_id uuid NOT NULL,
    revision bigint NOT NULL,
    state_kind text NOT NULL,
    reasoning_summary text,
    reasoning_signature text,
    encrypted_reference text,
    encryption_key_id text,
    encryption_key_revision bigint,
    encryption_algorithm text,
    ciphertext_digest bytea,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT llm_provider_state_pkey
        PRIMARY KEY (tenant_id, principal_id, conversation_id, state_id),
    CONSTRAINT llm_provider_state_conversation_fkey
        FOREIGN KEY (tenant_id, principal_id, conversation_id)
        REFERENCES public.llm_conversations (tenant_id, principal_id, conversation_id)
        ON DELETE CASCADE,
    CONSTRAINT llm_provider_state_state_id_uuid_v7 CHECK (
        (get_byte(uuid_send(state_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(state_id), 8) & 192) = 128
    ),
    CONSTRAINT llm_provider_state_revision_positive CHECK (revision > 0),
    CONSTRAINT llm_provider_state_timeline CHECK (updated_at >= created_at),
    CONSTRAINT llm_provider_state_closed_kind CHECK (
        (state_kind = 'reasoning_summary'
            AND reasoning_summary IS NOT NULL
            AND octet_length(reasoning_summary) BETWEEN 1 AND 16384
            AND (reasoning_signature IS NULL OR octet_length(reasoning_signature) BETWEEN 1 AND 4096)
            AND encrypted_reference IS NULL
            AND encryption_key_id IS NULL
            AND encryption_key_revision IS NULL
            AND encryption_algorithm IS NULL
            AND ciphertext_digest IS NULL)
        OR
        (state_kind = 'encrypted_continuation'
            AND reasoning_summary IS NULL
            AND reasoning_signature IS NULL
            AND encrypted_reference LIKE 'encrypted://%'
            AND octet_length(encrypted_reference) BETWEEN 13 AND 512
            AND encryption_key_id IS NOT NULL
            AND octet_length(encryption_key_id) BETWEEN 1 AND 128
            AND encryption_key_revision > 0
            AND encryption_algorithm IN ('aes_256_gcm', 'xchacha20_poly1305')
            AND octet_length(ciphertext_digest) = 32)
    )
);

CREATE TABLE public.llm_job_reference_snapshots (
    tenant_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    job_id uuid NOT NULL,
    prompt_definition_id text NOT NULL,
    prompt_revision bigint NOT NULL,
    route_definition_id text NOT NULL,
    route_revision bigint NOT NULL,
    schema_definition_id text,
    schema_revision bigint,
    tool_references jsonb NOT NULL,
    captured_at timestamptz NOT NULL,
    CONSTRAINT llm_job_reference_snapshots_pkey
        PRIMARY KEY (tenant_id, principal_id, conversation_id, job_id),
    CONSTRAINT llm_job_reference_snapshots_conversation_fkey
        FOREIGN KEY (tenant_id, principal_id, conversation_id)
        REFERENCES public.llm_conversations (tenant_id, principal_id, conversation_id)
        ON DELETE CASCADE,
    CONSTRAINT llm_job_reference_snapshots_job_id_uuid_v7 CHECK (
        (get_byte(uuid_send(job_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(job_id), 8) & 192) = 128
    ),
    CONSTRAINT llm_job_reference_snapshots_prompt_revision_positive CHECK (prompt_revision > 0),
    CONSTRAINT llm_job_reference_snapshots_route_revision_positive CHECK (route_revision > 0),
    CONSTRAINT llm_job_reference_snapshots_schema_complete CHECK (
        (schema_definition_id IS NULL AND schema_revision IS NULL)
        OR (schema_definition_id IS NOT NULL AND schema_revision > 0)
    ),
    CONSTRAINT llm_job_reference_snapshots_tools_array CHECK (
        jsonb_typeof(tool_references) = 'array'
        AND jsonb_array_length(tool_references) <= 64
    )
);

CREATE TABLE public.llm_deletion_fence_events (
    tenant_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    event_id uuid NOT NULL,
    request_id uuid NOT NULL,
    prior_revision bigint NOT NULL,
    fenced_revision bigint NOT NULL,
    fenced_at timestamptz NOT NULL,
    CONSTRAINT llm_deletion_fence_events_pkey
        PRIMARY KEY (tenant_id, principal_id, conversation_id, event_id),
    CONSTRAINT llm_deletion_fence_events_conversation_fkey
        FOREIGN KEY (tenant_id, principal_id, conversation_id)
        REFERENCES public.llm_conversations (tenant_id, principal_id, conversation_id)
        ON DELETE RESTRICT,
    CONSTRAINT llm_deletion_fence_events_one_per_conversation
        UNIQUE (tenant_id, principal_id, conversation_id),
    CONSTRAINT llm_deletion_fence_events_request_key
        UNIQUE (tenant_id, principal_id, request_id),
    CONSTRAINT llm_deletion_fence_events_inventory_fkey_key
        UNIQUE (tenant_id, principal_id, conversation_id, event_id, request_id),
    CONSTRAINT llm_deletion_fence_events_ids_uuid_v7 CHECK (
        (get_byte(uuid_send(event_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(event_id), 8) & 192) = 128
        AND (get_byte(uuid_send(request_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(request_id), 8) & 192) = 128
    ),
    CONSTRAINT llm_deletion_fence_events_revisions CHECK (
        prior_revision > 0 AND fenced_revision = prior_revision + 1
    )
);

CREATE TABLE public.llm_retention_inventory_events (
    tenant_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    event_id uuid NOT NULL,
    fence_event_id uuid NOT NULL,
    request_id uuid NOT NULL,
    fenced_at timestamptz NOT NULL,
    entries jsonb NOT NULL,
    inventoried_at timestamptz NOT NULL,
    CONSTRAINT llm_retention_inventory_events_pkey
        PRIMARY KEY (tenant_id, principal_id, conversation_id, event_id),
    CONSTRAINT llm_retention_inventory_events_fence_fkey
        FOREIGN KEY (tenant_id, principal_id, conversation_id, fence_event_id, request_id)
        REFERENCES public.llm_deletion_fence_events
            (tenant_id, principal_id, conversation_id, event_id, request_id)
        ON DELETE RESTRICT,
    CONSTRAINT llm_retention_inventory_events_event_id_uuid_v7 CHECK (
        (get_byte(uuid_send(event_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(event_id), 8) & 192) = 128
    ),
    CONSTRAINT llm_retention_inventory_events_entries CHECK (
        jsonb_typeof(entries) = 'array' AND jsonb_array_length(entries) = 4
    ),
    CONSTRAINT llm_retention_inventory_events_timeline CHECK (inventoried_at >= fenced_at)
);

CREATE TABLE public.llm_conversation_inventory_reconciliations (
    tenant_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    request_id uuid NOT NULL,
    adapter_name text NOT NULL,
    adapter_revision integer NOT NULL,
    attempt integer NOT NULL,
    operation text NOT NULL,
    retention_before timestamptz,
    legal_hold_id uuid,
    greatest_fence bigint NOT NULL,
    effect text NOT NULL,
    artifact_id uuid,
    affected_records bigint NOT NULL,
    evidence_digest bytea NOT NULL,
    reconciled_at timestamptz NOT NULL,
    CONSTRAINT llm_conversation_inventory_reconciliations_pkey
        PRIMARY KEY (tenant_id, principal_id, request_id, adapter_name, attempt),
    CONSTRAINT llm_conversation_inventory_adapter_revision_positive CHECK (adapter_revision > 0),
    CONSTRAINT llm_conversation_inventory_attempt_positive CHECK (attempt > 0),
    CONSTRAINT llm_conversation_inventory_fence_positive CHECK (greatest_fence > 0),
    CONSTRAINT llm_conversation_inventory_operation_check CHECK (
        operation IN ('export', 'delete', 'anonymize', 'retention', 'legal_hold_apply', 'legal_hold_release')
    ),
    CONSTRAINT llm_conversation_inventory_operation_fields CHECK (
        (operation = 'retention') = (retention_before IS NOT NULL)
        AND (operation IN ('legal_hold_apply', 'legal_hold_release')) = (legal_hold_id IS NOT NULL)
    ),
    CONSTRAINT llm_conversation_inventory_effect_check CHECK (
        (effect = 'no_data' AND artifact_id IS NULL AND affected_records = 0)
        OR (effect = 'exported' AND artifact_id IS NOT NULL AND affected_records > 0)
        OR (effect = 'mutated' AND artifact_id IS NULL AND affected_records > 0)
    ),
    CONSTRAINT llm_conversation_inventory_affected_nonnegative CHECK (affected_records >= 0),
    CONSTRAINT llm_conversation_inventory_digest_length CHECK (octet_length(evidence_digest) = 32)
);

CREATE INDEX llm_messages_scope_page_idx
    ON public.llm_messages (tenant_id, principal_id, conversation_id, sequence);
CREATE INDEX llm_provider_state_scope_idx
    ON public.llm_provider_state (tenant_id, principal_id, conversation_id);
CREATE INDEX llm_job_reference_snapshots_scope_idx
    ON public.llm_job_reference_snapshots (tenant_id, principal_id, conversation_id, captured_at);
CREATE INDEX llm_retention_inventory_fence_latest_idx
    ON public.llm_retention_inventory_events
        (tenant_id, principal_id, conversation_id, fence_event_id, inventoried_at DESC);
CREATE INDEX llm_conversation_inventory_request_idx
    ON public.llm_conversation_inventory_reconciliations
        (tenant_id, principal_id, request_id, adapter_name, greatest_fence DESC);

CREATE FUNCTION public.protect_llm_conversation_identity() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
        OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR OLD.deletion_request_id IS NOT NULL
            AND (
                NEW.deletion_request_id IS DISTINCT FROM OLD.deletion_request_id
                OR NEW.fenced_at IS DISTINCT FROM OLD.fenced_at
            )
    THEN
        RAISE EXCEPTION 'llm conversation immutable fields cannot change';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER llm_conversations_identity_immutable
BEFORE UPDATE ON public.llm_conversations
FOR EACH ROW EXECUTE FUNCTION public.protect_llm_conversation_identity();

CREATE FUNCTION public.protect_llm_message_identity() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
        OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id
        OR NEW.message_id IS DISTINCT FROM OLD.message_id
        OR NEW.sequence IS DISTINCT FROM OLD.sequence
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION 'llm message immutable fields cannot change';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER llm_messages_identity_immutable
BEFORE UPDATE ON public.llm_messages
FOR EACH ROW EXECUTE FUNCTION public.protect_llm_message_identity();

CREATE FUNCTION public.protect_llm_provider_state_identity() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
        OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id
        OR NEW.state_id IS DISTINCT FROM OLD.state_id
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION 'llm provider state immutable fields cannot change';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER llm_provider_state_identity_immutable
BEFORE UPDATE ON public.llm_provider_state
FOR EACH ROW EXECUTE FUNCTION public.protect_llm_provider_state_identity();

CREATE FUNCTION public.reject_llm_immutable_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'immutable llm record cannot change';
END;
$$;
CREATE TRIGGER llm_job_reference_snapshots_immutable
BEFORE UPDATE ON public.llm_job_reference_snapshots
FOR EACH ROW EXECUTE FUNCTION public.reject_llm_immutable_change();
CREATE TRIGGER llm_deletion_fence_events_immutable
BEFORE UPDATE OR DELETE ON public.llm_deletion_fence_events
FOR EACH ROW EXECUTE FUNCTION public.reject_llm_immutable_change();
CREATE TRIGGER llm_retention_inventory_events_immutable
BEFORE UPDATE OR DELETE ON public.llm_retention_inventory_events
FOR EACH ROW EXECUTE FUNCTION public.reject_llm_immutable_change();

CREATE FUNCTION public.protect_llm_inventory_identity() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
        OR NEW.request_id IS DISTINCT FROM OLD.request_id
        OR NEW.adapter_name IS DISTINCT FROM OLD.adapter_name
        OR NEW.adapter_revision IS DISTINCT FROM OLD.adapter_revision
        OR NEW.attempt IS DISTINCT FROM OLD.attempt
        OR NEW.operation IS DISTINCT FROM OLD.operation
        OR NEW.retention_before IS DISTINCT FROM OLD.retention_before
        OR NEW.legal_hold_id IS DISTINCT FROM OLD.legal_hold_id
        OR NEW.effect IS DISTINCT FROM OLD.effect
        OR NEW.artifact_id IS DISTINCT FROM OLD.artifact_id
        OR NEW.affected_records IS DISTINCT FROM OLD.affected_records
        OR NEW.evidence_digest IS DISTINCT FROM OLD.evidence_digest
        OR NEW.reconciled_at IS DISTINCT FROM OLD.reconciled_at
        OR NEW.greatest_fence < OLD.greatest_fence
    THEN
        RAISE EXCEPTION 'llm inventory immutable facts cannot change';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER llm_conversation_inventory_identity_immutable
BEFORE UPDATE OR DELETE ON public.llm_conversation_inventory_reconciliations
FOR EACH ROW EXECUTE FUNCTION public.protect_llm_inventory_identity();

ALTER TABLE public.llm_conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.llm_conversations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.llm_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.llm_messages FORCE ROW LEVEL SECURITY;
ALTER TABLE public.llm_provider_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.llm_provider_state FORCE ROW LEVEL SECURITY;
ALTER TABLE public.llm_job_reference_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.llm_job_reference_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE public.llm_deletion_fence_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.llm_deletion_fence_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.llm_retention_inventory_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.llm_retention_inventory_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.llm_conversation_inventory_reconciliations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.llm_conversation_inventory_reconciliations FORCE ROW LEVEL SECURITY;

CREATE POLICY llm_conversations_owner_scope ON public.llm_conversations
USING (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.principal_id', true), '')::uuid
)
WITH CHECK (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.principal_id', true), '')::uuid
);
CREATE POLICY llm_messages_owner_scope ON public.llm_messages
USING (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.principal_id', true), '')::uuid
)
WITH CHECK (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.principal_id', true), '')::uuid
);
CREATE POLICY llm_provider_state_owner_scope ON public.llm_provider_state
USING (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.principal_id', true), '')::uuid
)
WITH CHECK (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.principal_id', true), '')::uuid
);
CREATE POLICY llm_job_reference_snapshots_owner_scope ON public.llm_job_reference_snapshots
USING (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.principal_id', true), '')::uuid
)
WITH CHECK (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.principal_id', true), '')::uuid
);
CREATE POLICY llm_deletion_fence_events_owner_scope ON public.llm_deletion_fence_events
USING (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.principal_id', true), '')::uuid
)
WITH CHECK (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.principal_id', true), '')::uuid
);
CREATE POLICY llm_retention_inventory_events_owner_scope ON public.llm_retention_inventory_events
USING (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.principal_id', true), '')::uuid
)
WITH CHECK (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.principal_id', true), '')::uuid
);
CREATE POLICY llm_conversation_inventory_owner_scope
ON public.llm_conversation_inventory_reconciliations
USING (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.principal_id', true), '')::uuid
)
WITH CHECK (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND principal_id = NULLIF(current_setting('app.principal_id', true), '')::uuid
);
