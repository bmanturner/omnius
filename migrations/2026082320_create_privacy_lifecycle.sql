CREATE FUNCTION public.privacy_uuid_is_v7(candidate uuid)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
RETURN (
    (get_byte(uuid_send(candidate), 6) >> 4) = 7
    AND (get_byte(uuid_send(candidate), 8) & 192) = 128
);

CREATE FUNCTION public.reject_privacy_immutable_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'immutable privacy evidence cannot be changed';
END;
$$;

CREATE TABLE public.privacy_legal_holds (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    subject_id uuid,
    basis varchar(32) NOT NULL,
    policy_version varchar(64) NOT NULL,
    state varchar(24) NOT NULL,
    requested_at timestamptz NOT NULL,
    activated_at timestamptz,
    release_requested_at timestamptz,
    released_at timestamptz,
    created_by_kind varchar(24) NOT NULL,
    created_by_subject_id uuid,
    CONSTRAINT privacy_legal_holds_id_v7 CHECK (public.privacy_uuid_is_v7(id)),
    CONSTRAINT privacy_legal_holds_tenant_fkey
        FOREIGN KEY (tenant_id) REFERENCES public.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT privacy_legal_holds_tenant_v7 CHECK (public.privacy_uuid_is_v7(tenant_id)),
    CONSTRAINT privacy_legal_holds_subject_v7 CHECK (
        subject_id IS NULL OR public.privacy_uuid_is_v7(subject_id)
    ),
    CONSTRAINT privacy_legal_holds_basis_check CHECK (
        basis IN ('litigation', 'regulatory', 'investigation', 'contractual')
    ),
    CONSTRAINT privacy_legal_holds_policy_version_check CHECK (
        policy_version ~ '^[[:alnum:]][[:alnum:]._-]{0,63}$'
    ),
    CONSTRAINT privacy_legal_holds_state_check CHECK (
        state IN ('pending_active', 'active', 'release_pending', 'released')
    ),
    CONSTRAINT privacy_legal_holds_actor_check CHECK (
        (created_by_kind = 'system' AND created_by_subject_id IS NULL)
        OR (
            created_by_kind IN ('user', 'service_account')
            AND created_by_subject_id IS NOT NULL
            AND public.privacy_uuid_is_v7(created_by_subject_id)
        )
    ),
    CONSTRAINT privacy_legal_holds_time_check CHECK (
        (state = 'pending_active' AND activated_at IS NULL AND release_requested_at IS NULL AND released_at IS NULL)
        OR (state = 'active' AND activated_at IS NOT NULL AND release_requested_at IS NULL AND released_at IS NULL)
        OR (state = 'release_pending' AND activated_at IS NOT NULL AND release_requested_at IS NOT NULL AND released_at IS NULL)
        OR (state = 'released' AND activated_at IS NOT NULL AND release_requested_at IS NOT NULL AND released_at IS NOT NULL)
    ),
    CONSTRAINT privacy_legal_holds_time_order_check CHECK (
        (activated_at IS NULL OR activated_at >= requested_at)
        AND (release_requested_at IS NULL OR release_requested_at >= activated_at)
        AND (released_at IS NULL OR released_at >= release_requested_at)
    )
);

CREATE UNIQUE INDEX privacy_legal_holds_one_open_target_idx
    ON public.privacy_legal_holds (
        tenant_id,
        COALESCE(subject_id, '00000000-0000-0000-0000-000000000000'::uuid)
    )
    WHERE state <> 'released';

CREATE INDEX privacy_legal_holds_blocking_lookup_idx
    ON public.privacy_legal_holds (tenant_id, subject_id, state)
    WHERE state IN ('pending_active', 'active', 'release_pending');
CREATE FUNCTION public.protect_privacy_legal_hold_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'privacy legal hold provenance is immutable';
    END IF;
    IF NEW.id <> OLD.id
        OR NEW.tenant_id <> OLD.tenant_id
        OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
        OR NEW.basis <> OLD.basis
        OR NEW.policy_version <> OLD.policy_version
        OR NEW.requested_at <> OLD.requested_at
        OR NEW.created_by_kind <> OLD.created_by_kind
        OR NEW.created_by_subject_id IS DISTINCT FROM OLD.created_by_subject_id
        OR (OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at)
        OR (
            OLD.release_requested_at IS NOT NULL
            AND NEW.release_requested_at IS DISTINCT FROM OLD.release_requested_at
        )
        OR (OLD.released_at IS NOT NULL AND NEW.released_at IS DISTINCT FROM OLD.released_at)
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'privacy legal hold provenance is immutable';
    END IF;
    IF (OLD.state = 'pending_active' AND NEW.state NOT IN ('pending_active', 'active'))
        OR (OLD.state = 'active' AND NEW.state NOT IN ('active', 'release_pending'))
        OR (OLD.state = 'release_pending' AND NEW.state NOT IN ('release_pending', 'released'))
        OR (OLD.state = 'released' AND NEW.state <> 'released')
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'privacy legal hold state transition is invalid';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER privacy_legal_holds_provenance_immutable
BEFORE UPDATE OR DELETE ON public.privacy_legal_holds
FOR EACH ROW EXECUTE FUNCTION public.protect_privacy_legal_hold_provenance();


CREATE TABLE public.privacy_lifecycle_requests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    subject_id uuid,
    operation varchar(32) NOT NULL,
    retention_before timestamptz,
    legal_hold_id uuid,
    state varchar(24) NOT NULL,
    attempt_count smallint NOT NULL DEFAULT 0,
    max_attempts smallint NOT NULL,
    inventory_count smallint NOT NULL,
    fence bigint NOT NULL DEFAULT 0,
    lease_owner varchar(64),
    lease_expires_at timestamptz,
    next_attempt_at timestamptz,
    last_failure_code varchar(32),
    created_by_kind varchar(24) NOT NULL,
    created_by_subject_id uuid,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    completed_at timestamptz,
    CONSTRAINT privacy_lifecycle_requests_id_v7 CHECK (public.privacy_uuid_is_v7(id)),
    CONSTRAINT privacy_lifecycle_requests_tenant_fkey
        FOREIGN KEY (tenant_id) REFERENCES public.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT privacy_lifecycle_requests_tenant_v7 CHECK (public.privacy_uuid_is_v7(tenant_id)),
    CONSTRAINT privacy_lifecycle_requests_subject_v7 CHECK (
        subject_id IS NULL OR public.privacy_uuid_is_v7(subject_id)
    ),
    CONSTRAINT privacy_lifecycle_requests_operation_check CHECK (
        operation IN (
            'export', 'delete', 'anonymize', 'retention',
            'legal_hold_apply', 'legal_hold_release'
        )
    ),
    CONSTRAINT privacy_lifecycle_requests_retention_check CHECK (
        (operation = 'retention' AND retention_before IS NOT NULL)
        OR (operation <> 'retention' AND retention_before IS NULL)
    ),
    CONSTRAINT privacy_lifecycle_requests_retention_time_check CHECK (
        retention_before IS NULL OR retention_before < created_at
    ),
    CONSTRAINT privacy_lifecycle_requests_hold_check CHECK (
        (operation IN ('legal_hold_apply', 'legal_hold_release') AND legal_hold_id IS NOT NULL)
        OR (operation NOT IN ('legal_hold_apply', 'legal_hold_release') AND legal_hold_id IS NULL)
    ),
    CONSTRAINT privacy_lifecycle_requests_legal_hold_fkey
        FOREIGN KEY (legal_hold_id) REFERENCES public.privacy_legal_holds (id) ON DELETE RESTRICT,
    CONSTRAINT privacy_lifecycle_requests_state_check CHECK (
        state IN ('pending', 'running', 'retry_wait', 'hold_wait', 'completed', 'dead_letter')
    ),
    CONSTRAINT privacy_lifecycle_requests_attempts_check CHECK (
        max_attempts BETWEEN 1 AND 100
        AND attempt_count BETWEEN 0 AND max_attempts
    ),
    CONSTRAINT privacy_lifecycle_requests_inventory_count_check CHECK (
        inventory_count BETWEEN 1 AND 64
    ),
    CONSTRAINT privacy_lifecycle_requests_fence_check CHECK (fence >= 0),
    CONSTRAINT privacy_lifecycle_requests_lease_check CHECK (
        (state = 'running' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (state <> 'running' AND lease_owner IS NULL AND lease_expires_at IS NULL)
    ),
    CONSTRAINT privacy_lifecycle_requests_lease_owner_check CHECK (
        lease_owner IS NULL OR lease_owner ~ '^[[:alnum:]][[:alnum:]._-]{0,63}$'
    ),
    CONSTRAINT privacy_lifecycle_requests_schedule_check CHECK (
        (state IN ('pending', 'retry_wait') AND next_attempt_at IS NOT NULL)
        OR (state NOT IN ('pending', 'retry_wait') AND next_attempt_at IS NULL)
    ),
    CONSTRAINT privacy_lifecycle_requests_failure_check CHECK (
        last_failure_code IS NULL
        OR last_failure_code IN (
            'unavailable', 'timeout', 'rate_limited', 'invalid_state',
            'incompatible_revision', 'permission_denied', 'unsupported_operation',
            'adapter_missing', 'lease_expired', 'attempts_exhausted'
        )
    ),
    CONSTRAINT privacy_lifecycle_requests_actor_check CHECK (
        (created_by_kind = 'system' AND created_by_subject_id IS NULL)
        OR (
            created_by_kind IN ('user', 'service_account')
            AND created_by_subject_id IS NOT NULL
            AND public.privacy_uuid_is_v7(created_by_subject_id)
        )
    ),
    CONSTRAINT privacy_lifecycle_requests_completion_check CHECK (
        (state IN ('completed', 'dead_letter') AND completed_at IS NOT NULL)
        OR (state NOT IN ('completed', 'dead_letter') AND completed_at IS NULL)
    ),
    CONSTRAINT privacy_lifecycle_requests_time_order_check CHECK (
        updated_at >= created_at
        AND (completed_at IS NULL OR completed_at >= created_at)
    )
);

CREATE INDEX privacy_lifecycle_claim_idx
    ON public.privacy_lifecycle_requests (next_attempt_at, created_at, id)
    WHERE state IN ('pending', 'retry_wait');

CREATE INDEX privacy_lifecycle_expired_lease_idx
    ON public.privacy_lifecycle_requests (lease_expires_at, id)
    WHERE state = 'running';

CREATE INDEX privacy_lifecycle_subject_history_idx
    ON public.privacy_lifecycle_requests (tenant_id, subject_id, created_at DESC, id DESC);

CREATE FUNCTION public.protect_privacy_lifecycle_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.tenant_id <> OLD.tenant_id
        OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
        OR NEW.operation <> OLD.operation
        OR NEW.retention_before IS DISTINCT FROM OLD.retention_before
        OR NEW.legal_hold_id IS DISTINCT FROM OLD.legal_hold_id
        OR NEW.max_attempts <> OLD.max_attempts
        OR NEW.inventory_count <> OLD.inventory_count
        OR NEW.created_by_kind <> OLD.created_by_kind
        OR NEW.created_by_subject_id IS DISTINCT FROM OLD.created_by_subject_id
        OR NEW.created_at <> OLD.created_at
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'privacy lifecycle request identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER privacy_lifecycle_identity_immutable
BEFORE UPDATE ON public.privacy_lifecycle_requests
FOR EACH ROW EXECUTE FUNCTION public.protect_privacy_lifecycle_identity();

CREATE TABLE public.privacy_inventory_reconciliations (
    request_id uuid NOT NULL,
    adapter_name varchar(64) NOT NULL,
    category varchar(16) NOT NULL,
    adapter_revision integer NOT NULL,
    state varchar(24) NOT NULL,
    attempt_count smallint NOT NULL DEFAULT 0,
    evidence_effect varchar(16),
    artifact_id uuid,
    evidence_sha256 bytea,
    affected_records bigint,
    failure_code varchar(32),
    reconciled_at timestamptz,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (request_id, adapter_name),
    CONSTRAINT privacy_inventory_request_fkey
        FOREIGN KEY (request_id) REFERENCES public.privacy_lifecycle_requests (id) ON DELETE RESTRICT,
    CONSTRAINT privacy_inventory_adapter_name_check CHECK (
        adapter_name ~ '^[[:alnum:]][[:alnum:]._-]{0,63}$'
    ),
    CONSTRAINT privacy_inventory_category_check CHECK (
        category IN ('postgresql', 'object', 'search', 'queue', 'provider')
    ),
    CONSTRAINT privacy_inventory_revision_check CHECK (adapter_revision BETWEEN 1 AND 65535),
    CONSTRAINT privacy_inventory_state_check CHECK (
        state IN ('pending', 'succeeded', 'retryable_failed', 'permanent_failed')
    ),
    CONSTRAINT privacy_inventory_attempts_check CHECK (attempt_count BETWEEN 0 AND 100),
    CONSTRAINT privacy_inventory_effect_check CHECK (
        evidence_effect IS NULL OR evidence_effect IN ('no_data', 'exported', 'mutated')
    ),
    CONSTRAINT privacy_inventory_artifact_v7 CHECK (
        artifact_id IS NULL OR public.privacy_uuid_is_v7(artifact_id)
    ),
    CONSTRAINT privacy_inventory_evidence_check CHECK (
        evidence_sha256 IS NULL OR octet_length(evidence_sha256) = 32
    ),
    CONSTRAINT privacy_inventory_records_check CHECK (
        affected_records IS NULL OR affected_records >= 0
    ),
    CONSTRAINT privacy_inventory_failure_check CHECK (
        failure_code IS NULL
        OR failure_code IN (
            'unavailable', 'timeout', 'rate_limited', 'invalid_state',
            'incompatible_revision', 'permission_denied', 'unsupported_operation',
            'adapter_missing'
        )
    ),
    CONSTRAINT privacy_inventory_success_shape_check CHECK (
        (
            state = 'succeeded'
            AND evidence_effect IS NOT NULL
            AND evidence_sha256 IS NOT NULL
            AND affected_records IS NOT NULL
            AND failure_code IS NULL
            AND (evidence_effect <> 'no_data' OR affected_records = 0)
            AND (
                (evidence_effect = 'exported' AND artifact_id IS NOT NULL)
                OR (evidence_effect <> 'exported' AND artifact_id IS NULL)
            )
            AND reconciled_at IS NOT NULL
        )
        OR (
            state <> 'succeeded'
            AND evidence_effect IS NULL
            AND artifact_id IS NULL
            AND evidence_sha256 IS NULL
            AND affected_records IS NULL
            AND reconciled_at IS NULL
        )
    )
);

CREATE INDEX privacy_inventory_incomplete_idx
    ON public.privacy_inventory_reconciliations (request_id, state)
    WHERE state <> 'succeeded';

CREATE FUNCTION public.protect_privacy_inventory_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'privacy inventory membership is immutable';
    END IF;
    IF NEW.request_id <> OLD.request_id
        OR NEW.adapter_name <> OLD.adapter_name
        OR NEW.category <> OLD.category
        OR NEW.adapter_revision <> OLD.adapter_revision
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'privacy inventory identity is immutable';
    END IF;
    IF OLD.state = 'succeeded' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'successful privacy inventory evidence is immutable';
    END IF;
    IF (OLD.state = 'pending'
            AND NEW.state NOT IN ('pending', 'succeeded', 'retryable_failed', 'permanent_failed'))
        OR (OLD.state = 'retryable_failed'
            AND NEW.state NOT IN ('pending', 'succeeded', 'retryable_failed', 'permanent_failed'))
        OR (OLD.state = 'permanent_failed' AND NEW.state <> 'pending')
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'privacy inventory state transition is invalid';
    END IF;
    IF NEW.state = 'pending' THEN
        IF NEW.attempt_count <> 0
            OR NEW.evidence_effect IS NOT NULL
            OR NEW.artifact_id IS NOT NULL
            OR NEW.evidence_sha256 IS NOT NULL
            OR NEW.affected_records IS NOT NULL
            OR NEW.failure_code IS NOT NULL
            OR NEW.reconciled_at IS NOT NULL
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'redriven privacy inventory state must be cleared';
        END IF;
    ELSIF NEW.attempt_count < OLD.attempt_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'privacy inventory attempt count cannot decrease';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER privacy_inventory_identity_immutable
BEFORE UPDATE OR DELETE ON public.privacy_inventory_reconciliations
FOR EACH ROW EXECUTE FUNCTION public.protect_privacy_inventory_identity();

CREATE TABLE public.privacy_lifecycle_transitions (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    from_state varchar(24),
    to_state varchar(24) NOT NULL,
    fence bigint NOT NULL,
    actor_kind varchar(24) NOT NULL,
    failure_code varchar(32),
    occurred_at timestamptz NOT NULL,
    CONSTRAINT privacy_lifecycle_transitions_id_v7 CHECK (public.privacy_uuid_is_v7(id)),
    CONSTRAINT privacy_lifecycle_transitions_request_fkey
        FOREIGN KEY (request_id) REFERENCES public.privacy_lifecycle_requests (id) ON DELETE RESTRICT,
    CONSTRAINT privacy_lifecycle_transitions_from_check CHECK (
        from_state IS NULL OR from_state IN (
            'pending', 'running', 'retry_wait', 'hold_wait', 'completed', 'dead_letter'
        )
    ),
    CONSTRAINT privacy_lifecycle_transitions_to_check CHECK (
        to_state IN ('pending', 'running', 'retry_wait', 'hold_wait', 'completed', 'dead_letter')
    ),
    CONSTRAINT privacy_lifecycle_transitions_fence_check CHECK (fence >= 0),
    CONSTRAINT privacy_lifecycle_transitions_actor_check CHECK (
        actor_kind IN ('user', 'service_account', 'system')
    ),
    CONSTRAINT privacy_lifecycle_transitions_failure_check CHECK (
        failure_code IS NULL
        OR failure_code IN (
            'unavailable', 'timeout', 'rate_limited', 'invalid_state',
            'incompatible_revision', 'permission_denied', 'unsupported_operation',
            'adapter_missing', 'lease_expired', 'attempts_exhausted'
        )
    )
);

CREATE INDEX privacy_lifecycle_transitions_history_idx
    ON public.privacy_lifecycle_transitions (request_id, occurred_at, id);

CREATE TRIGGER privacy_lifecycle_transitions_immutable
BEFORE UPDATE OR DELETE ON public.privacy_lifecycle_transitions
FOR EACH ROW EXECUTE FUNCTION public.reject_privacy_immutable_change();

CREATE TABLE public.privacy_consent_records (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    subject_id uuid NOT NULL,
    document_kind varchar(32) NOT NULL,
    document_version varchar(64) NOT NULL,
    jurisdiction varchar(16) NOT NULL,
    source varchar(24) NOT NULL,
    evidence_format varchar(32) NOT NULL,
    evidence_sha256 bytea NOT NULL,
    withdrawal_permitted boolean NOT NULL,
    accepted_at timestamptz NOT NULL,
    recorded_by_kind varchar(24) NOT NULL,
    recorded_by_subject_id uuid,
    created_at timestamptz NOT NULL,
    CONSTRAINT privacy_consent_records_id_v7 CHECK (public.privacy_uuid_is_v7(id)),
    CONSTRAINT privacy_consent_records_tenant_fkey
        FOREIGN KEY (tenant_id) REFERENCES public.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT privacy_consent_records_tenant_v7 CHECK (public.privacy_uuid_is_v7(tenant_id)),
    CONSTRAINT privacy_consent_records_subject_v7 CHECK (public.privacy_uuid_is_v7(subject_id)),
    CONSTRAINT privacy_consent_records_kind_check CHECK (
        document_kind IN ('terms', 'privacy_policy', 'marketing', 'data_processing', 'cookies')
    ),
    CONSTRAINT privacy_consent_records_version_check CHECK (
        document_version ~ '^[[:alnum:]][[:alnum:]._-]{0,63}$'
    ),
    CONSTRAINT privacy_consent_records_jurisdiction_check CHECK (
        jurisdiction ~ '^[A-Z0-9][A-Z0-9-]{1,15}$'
    ),
    CONSTRAINT privacy_consent_records_source_check CHECK (
        source IN ('web', 'mobile', 'api', 'import', 'support', 'system_policy')
    ),
    CONSTRAINT privacy_consent_records_evidence_format_check CHECK (
        evidence_format IN ('checkbox', 'electronic_signature', 'imported_attestation', 'policy_record')
    ),
    CONSTRAINT privacy_consent_records_evidence_check CHECK (octet_length(evidence_sha256) = 32),
    CONSTRAINT privacy_consent_records_actor_check CHECK (
        (recorded_by_kind = 'system' AND recorded_by_subject_id IS NULL)
        OR (
            recorded_by_kind IN ('user', 'service_account')
            AND recorded_by_subject_id IS NOT NULL
            AND public.privacy_uuid_is_v7(recorded_by_subject_id)
        )
    ),
    CONSTRAINT privacy_consent_records_accepted_time_check CHECK (accepted_at <= created_at),
    CONSTRAINT privacy_consent_records_unique_evidence
        UNIQUE (
            tenant_id, subject_id, document_kind, document_version, evidence_sha256
        )
);

CREATE INDEX privacy_consent_subject_history_idx
    ON public.privacy_consent_records (
        tenant_id, subject_id, document_kind, accepted_at DESC, id DESC
    );

CREATE TRIGGER privacy_consent_records_immutable
BEFORE UPDATE OR DELETE ON public.privacy_consent_records
FOR EACH ROW EXECUTE FUNCTION public.reject_privacy_immutable_change();

CREATE TABLE public.privacy_consent_withdrawals (
    id uuid PRIMARY KEY,
    consent_id uuid NOT NULL UNIQUE,
    jurisdiction varchar(16) NOT NULL,
    source varchar(24) NOT NULL,
    evidence_format varchar(32) NOT NULL,
    evidence_sha256 bytea NOT NULL,
    withdrawn_at timestamptz NOT NULL,
    recorded_by_kind varchar(24) NOT NULL,
    recorded_by_subject_id uuid,
    created_at timestamptz NOT NULL,
    CONSTRAINT privacy_consent_withdrawals_id_v7 CHECK (public.privacy_uuid_is_v7(id)),
    CONSTRAINT privacy_consent_withdrawals_consent_fkey
        FOREIGN KEY (consent_id) REFERENCES public.privacy_consent_records (id) ON DELETE RESTRICT,
    CONSTRAINT privacy_consent_withdrawals_jurisdiction_check CHECK (
        jurisdiction ~ '^[A-Z0-9][A-Z0-9-]{1,15}$'
    ),
    CONSTRAINT privacy_consent_withdrawals_source_check CHECK (
        source IN ('web', 'mobile', 'api', 'import', 'support', 'system_policy')
    ),
    CONSTRAINT privacy_consent_withdrawals_evidence_format_check CHECK (
        evidence_format IN ('checkbox', 'electronic_signature', 'imported_attestation', 'policy_record')
    ),
    CONSTRAINT privacy_consent_withdrawals_evidence_check CHECK (octet_length(evidence_sha256) = 32),
    CONSTRAINT privacy_consent_withdrawals_actor_check CHECK (
        (recorded_by_kind = 'system' AND recorded_by_subject_id IS NULL)
        OR (
            recorded_by_kind IN ('user', 'service_account')
            AND recorded_by_subject_id IS NOT NULL
            AND public.privacy_uuid_is_v7(recorded_by_subject_id)
        )
    ),
    CONSTRAINT privacy_consent_withdrawals_time_check CHECK (withdrawn_at <= created_at)
);

CREATE TRIGGER privacy_consent_withdrawals_immutable
BEFORE UPDATE OR DELETE ON public.privacy_consent_withdrawals
FOR EACH ROW EXECUTE FUNCTION public.reject_privacy_immutable_change();

CREATE TABLE public.privacy_moderation_reports (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    reporter_subject_id uuid NOT NULL,
    subject_id uuid NOT NULL,
    reason_code varchar(64) NOT NULL,
    policy_version varchar(64) NOT NULL,
    state varchar(24) NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT privacy_moderation_reports_id_v7 CHECK (public.privacy_uuid_is_v7(id)),
    CONSTRAINT privacy_moderation_reports_tenant_fkey
        FOREIGN KEY (tenant_id) REFERENCES public.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT privacy_moderation_reports_tenant_v7 CHECK (public.privacy_uuid_is_v7(tenant_id)),
    CONSTRAINT privacy_moderation_reports_reporter_v7 CHECK (public.privacy_uuid_is_v7(reporter_subject_id)),
    CONSTRAINT privacy_moderation_reports_subject_v7 CHECK (public.privacy_uuid_is_v7(subject_id)),
    CONSTRAINT privacy_moderation_reports_reason_check CHECK (
        reason_code ~ '^[[:alnum:]][[:alnum:]._-]{0,63}$'
    ),
    CONSTRAINT privacy_moderation_reports_policy_check CHECK (
        policy_version ~ '^[[:alnum:]][[:alnum:]._-]{0,63}$'
    ),
    CONSTRAINT privacy_moderation_reports_state_check CHECK (
        state IN ('submitted', 'under_review', 'actioned', 'dismissed', 'appealed', 'resolved')
    ),
    CONSTRAINT privacy_moderation_reports_version_check CHECK (version > 0),
    CONSTRAINT privacy_moderation_reports_time_check CHECK (updated_at >= created_at),
    CONSTRAINT privacy_moderation_reports_id_subject_unique UNIQUE (id, subject_id)
);

CREATE INDEX privacy_moderation_reports_queue_idx
    ON public.privacy_moderation_reports (tenant_id, state, created_at, id)
    WHERE state IN ('submitted', 'under_review', 'appealed');

CREATE INDEX privacy_moderation_subject_history_idx
    ON public.privacy_moderation_reports (tenant_id, subject_id, created_at DESC, id DESC);
CREATE FUNCTION public.protect_privacy_moderation_report_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'privacy moderation report provenance is immutable';
    END IF;
    IF NEW.id <> OLD.id
        OR NEW.tenant_id <> OLD.tenant_id
        OR NEW.reporter_subject_id <> OLD.reporter_subject_id
        OR NEW.subject_id <> OLD.subject_id
        OR NEW.reason_code <> OLD.reason_code
        OR NEW.policy_version <> OLD.policy_version
        OR NEW.created_at <> OLD.created_at
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'privacy moderation report provenance is immutable';
    END IF;
    IF NOT (
        (OLD.state = 'submitted' AND NEW.state IN ('under_review', 'actioned', 'dismissed'))
        OR (OLD.state = 'under_review' AND NEW.state IN ('actioned', 'dismissed'))
        OR (OLD.state = 'actioned' AND NEW.state = 'appealed')
        OR (OLD.state = 'appealed' AND NEW.state = 'resolved')
    )
        OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'privacy moderation report transition is invalid';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER privacy_moderation_reports_provenance_immutable
BEFORE UPDATE OR DELETE ON public.privacy_moderation_reports
FOR EACH ROW EXECUTE FUNCTION public.protect_privacy_moderation_report_provenance();


CREATE TABLE public.privacy_moderation_actions (
    id uuid PRIMARY KEY,
    report_id uuid NOT NULL,
    subject_id uuid NOT NULL,
    actor_role varchar(24) NOT NULL,
    actor_kind varchar(24) NOT NULL,
    actor_subject_id uuid,
    action_kind varchar(32) NOT NULL,
    reason_code varchar(64) NOT NULL,
    policy_version varchar(64) NOT NULL,
    effective_until timestamptz,
    created_at timestamptz NOT NULL,
    CONSTRAINT privacy_moderation_actions_id_v7 CHECK (public.privacy_uuid_is_v7(id)),
    CONSTRAINT privacy_moderation_actions_report_fkey
        FOREIGN KEY (report_id) REFERENCES public.privacy_moderation_reports (id) ON DELETE RESTRICT,
    CONSTRAINT privacy_moderation_actions_report_subject_fkey
        FOREIGN KEY (report_id, subject_id)
        REFERENCES public.privacy_moderation_reports (id, subject_id) ON DELETE RESTRICT,
    CONSTRAINT privacy_moderation_actions_subject_v7 CHECK (public.privacy_uuid_is_v7(subject_id)),
    CONSTRAINT privacy_moderation_actions_actor_role_check CHECK (
        actor_role IN ('moderator', 'administrator', 'automated')
    ),
    CONSTRAINT privacy_moderation_actions_actor_check CHECK (
        (actor_role = 'automated' AND actor_kind IN ('system', 'service_account'))
        OR (actor_role IN ('moderator', 'administrator') AND actor_kind = 'user')
    ),
    CONSTRAINT privacy_moderation_actions_actor_subject_check CHECK (
        (actor_kind = 'system' AND actor_subject_id IS NULL)
        OR (
            actor_kind IN ('user', 'service_account')
            AND actor_subject_id IS NOT NULL
            AND public.privacy_uuid_is_v7(actor_subject_id)
        )
    ),
    CONSTRAINT privacy_moderation_actions_kind_check CHECK (
        action_kind IN (
            'warning', 'content_removed', 'account_restricted',
            'account_suspended', 'report_dismissed', 'escalated'
        )
    ),
    CONSTRAINT privacy_moderation_actions_reason_check CHECK (
        reason_code ~ '^[[:alnum:]][[:alnum:]._-]{0,63}$'
    ),
    CONSTRAINT privacy_moderation_actions_policy_check CHECK (
        policy_version ~ '^[[:alnum:]][[:alnum:]._-]{0,63}$'
    ),
    CONSTRAINT privacy_moderation_actions_time_check CHECK (
        effective_until IS NULL OR effective_until > created_at
    ),
    CONSTRAINT privacy_moderation_actions_identity_unique UNIQUE (id, report_id, subject_id)
);

CREATE INDEX privacy_moderation_actions_report_idx
    ON public.privacy_moderation_actions (report_id, created_at, id);

CREATE TRIGGER privacy_moderation_actions_immutable
BEFORE UPDATE OR DELETE ON public.privacy_moderation_actions
FOR EACH ROW EXECUTE FUNCTION public.reject_privacy_immutable_change();

CREATE TABLE public.privacy_moderation_appeals (
    id uuid PRIMARY KEY,
    report_id uuid NOT NULL,
    action_id uuid NOT NULL UNIQUE,
    subject_id uuid NOT NULL,
    reason_code varchar(64) NOT NULL,
    policy_version varchar(64) NOT NULL,
    state varchar(16) NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    submitted_at timestamptz NOT NULL,
    decided_at timestamptz,
    CONSTRAINT privacy_moderation_appeals_id_v7 CHECK (public.privacy_uuid_is_v7(id)),
    CONSTRAINT privacy_moderation_appeals_report_fkey
        FOREIGN KEY (report_id) REFERENCES public.privacy_moderation_reports (id) ON DELETE RESTRICT,
    CONSTRAINT privacy_moderation_appeals_action_fkey
        FOREIGN KEY (action_id) REFERENCES public.privacy_moderation_actions (id) ON DELETE RESTRICT,
    CONSTRAINT privacy_moderation_appeals_action_scope_fkey
        FOREIGN KEY (action_id, report_id, subject_id)
        REFERENCES public.privacy_moderation_actions (id, report_id, subject_id) ON DELETE RESTRICT,
    CONSTRAINT privacy_moderation_appeals_subject_v7 CHECK (public.privacy_uuid_is_v7(subject_id)),
    CONSTRAINT privacy_moderation_appeals_reason_check CHECK (
        reason_code ~ '^[[:alnum:]][[:alnum:]._-]{0,63}$'
    ),
    CONSTRAINT privacy_moderation_appeals_policy_check CHECK (
        policy_version ~ '^[[:alnum:]][[:alnum:]._-]{0,63}$'
    ),
    CONSTRAINT privacy_moderation_appeals_state_check CHECK (
        state IN ('submitted', 'upheld', 'denied')
    ),
    CONSTRAINT privacy_moderation_appeals_time_check CHECK (
        (state = 'submitted' AND decided_at IS NULL)
        OR (
            state IN ('upheld', 'denied')
            AND decided_at IS NOT NULL
            AND decided_at >= submitted_at
        )
    ),
    CONSTRAINT privacy_moderation_appeals_version_check CHECK (version > 0),
    CONSTRAINT privacy_moderation_appeals_report_identity_unique UNIQUE (id, report_id)
);

CREATE INDEX privacy_moderation_appeals_queue_idx
    ON public.privacy_moderation_appeals (state, submitted_at, id)
    WHERE state = 'submitted';
CREATE FUNCTION public.protect_privacy_moderation_appeal_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'privacy moderation appeal provenance is immutable';
    END IF;
    IF NEW.id <> OLD.id
        OR NEW.report_id <> OLD.report_id
        OR NEW.action_id <> OLD.action_id
        OR NEW.subject_id <> OLD.subject_id
        OR NEW.reason_code <> OLD.reason_code
        OR NEW.policy_version <> OLD.policy_version
        OR NEW.submitted_at <> OLD.submitted_at
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'privacy moderation appeal provenance is immutable';
    END IF;
    IF OLD.state <> 'submitted'
        OR NEW.state NOT IN ('upheld', 'denied')
        OR NEW.version <> OLD.version + 1
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'privacy moderation appeal transition is invalid';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER privacy_moderation_appeals_provenance_immutable
BEFORE UPDATE OR DELETE ON public.privacy_moderation_appeals
FOR EACH ROW EXECUTE FUNCTION public.protect_privacy_moderation_appeal_provenance();


CREATE TABLE public.privacy_moderation_appeal_decisions (
    id uuid PRIMARY KEY,
    appeal_id uuid NOT NULL UNIQUE,
    actor_role varchar(24) NOT NULL,
    actor_kind varchar(24) NOT NULL,
    actor_subject_id uuid NOT NULL,
    decision varchar(16) NOT NULL,
    reason_code varchar(64) NOT NULL,
    policy_version varchar(64) NOT NULL,
    decided_at timestamptz NOT NULL,
    CONSTRAINT privacy_moderation_decisions_id_v7 CHECK (public.privacy_uuid_is_v7(id)),
    CONSTRAINT privacy_moderation_decisions_appeal_fkey
        FOREIGN KEY (appeal_id) REFERENCES public.privacy_moderation_appeals (id) ON DELETE RESTRICT,
    CONSTRAINT privacy_moderation_decisions_actor_role_check CHECK (
        actor_role IN ('moderator', 'administrator')
    ),
    CONSTRAINT privacy_moderation_decisions_actor_check CHECK (
        actor_kind = 'user' AND public.privacy_uuid_is_v7(actor_subject_id)
    ),
    CONSTRAINT privacy_moderation_decisions_decision_check CHECK (
        decision IN ('upheld', 'denied')
    ),
    CONSTRAINT privacy_moderation_decisions_reason_check CHECK (
        reason_code ~ '^[[:alnum:]][[:alnum:]._-]{0,63}$'
    ),
    CONSTRAINT privacy_moderation_decisions_policy_check CHECK (
        policy_version ~ '^[[:alnum:]][[:alnum:]._-]{0,63}$'
    )
);

CREATE TRIGGER privacy_moderation_decisions_immutable
BEFORE UPDATE OR DELETE ON public.privacy_moderation_appeal_decisions
FOR EACH ROW EXECUTE FUNCTION public.reject_privacy_immutable_change();

CREATE TABLE public.privacy_moderation_evidence (
    id uuid PRIMARY KEY,
    report_id uuid NOT NULL,
    appeal_id uuid,
    evidence_kind varchar(24) NOT NULL,
    object_reference varchar(128) NOT NULL,
    evidence_sha256 bytea NOT NULL,
    policy_version varchar(64) NOT NULL,
    collected_by_kind varchar(24) NOT NULL,
    collected_by_subject_id uuid,
    collected_at timestamptz NOT NULL,
    CONSTRAINT privacy_moderation_evidence_id_v7 CHECK (public.privacy_uuid_is_v7(id)),
    CONSTRAINT privacy_moderation_evidence_report_fkey
        FOREIGN KEY (report_id) REFERENCES public.privacy_moderation_reports (id) ON DELETE RESTRICT,
    CONSTRAINT privacy_moderation_evidence_appeal_fkey
        FOREIGN KEY (appeal_id) REFERENCES public.privacy_moderation_appeals (id) ON DELETE RESTRICT,
    CONSTRAINT privacy_moderation_evidence_appeal_report_fkey
        FOREIGN KEY (appeal_id, report_id)
        REFERENCES public.privacy_moderation_appeals (id, report_id) ON DELETE RESTRICT,
    CONSTRAINT privacy_moderation_evidence_kind_check CHECK (
        evidence_kind IN ('content', 'account', 'message', 'object', 'provider_attestation')
    ),
    CONSTRAINT privacy_moderation_evidence_reference_check CHECK (
        object_reference ~ '^[[:alnum:]][[:alnum:].:_/-]{0,127}$'
    ),
    CONSTRAINT privacy_moderation_evidence_sha_check CHECK (octet_length(evidence_sha256) = 32),
    CONSTRAINT privacy_moderation_evidence_policy_check CHECK (
        policy_version ~ '^[[:alnum:]][[:alnum:]._-]{0,63}$'
    ),
    CONSTRAINT privacy_moderation_evidence_actor_check CHECK (
        (collected_by_kind = 'system' AND collected_by_subject_id IS NULL)
        OR (
            collected_by_kind IN ('user', 'service_account')
            AND collected_by_subject_id IS NOT NULL
            AND public.privacy_uuid_is_v7(collected_by_subject_id)
        )
    )
);

CREATE INDEX privacy_moderation_evidence_report_idx
    ON public.privacy_moderation_evidence (report_id, collected_at, id);

CREATE TRIGGER privacy_moderation_evidence_immutable
BEFORE UPDATE OR DELETE ON public.privacy_moderation_evidence
FOR EACH ROW EXECUTE FUNCTION public.reject_privacy_immutable_change();
