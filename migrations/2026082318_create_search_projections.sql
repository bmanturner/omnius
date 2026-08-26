CREATE TABLE public.search_index_versions (
    index_alias varchar(64) NOT NULL,
    schema_version integer NOT NULL,
    schema_digest bytea NOT NULL,
    status varchar(16) NOT NULL,
    backfill_cursor varchar(1024),
    projected_count bigint NOT NULL DEFAULT 0,
    generation bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    activated_at timestamptz,
    PRIMARY KEY (index_alias, schema_version),
    CONSTRAINT search_index_versions_alias_identifier CHECK (
        octet_length(index_alias) BETWEEN 1 AND 64
        AND index_alias ~ '^[a-z0-9][a-z0-9_-]*$'
    ),
    CONSTRAINT search_index_versions_version_positive CHECK (schema_version > 0),
    CONSTRAINT search_index_versions_digest_size CHECK (octet_length(schema_digest) = 32),
    CONSTRAINT search_index_versions_status_known CHECK (
        status IN ('preparing', 'backfilling', 'ready', 'active', 'retired')
    ),
    CONSTRAINT search_index_versions_cursor_bounded CHECK (
        backfill_cursor IS NULL
        OR (
            octet_length(backfill_cursor) BETWEEN 1 AND 1024
            AND backfill_cursor !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT search_index_versions_counts_nonnegative CHECK (
        projected_count >= 0 AND generation > 0
    ),
    CONSTRAINT search_index_versions_state_coherent CHECK (
        (
            status IN ('preparing', 'backfilling')
            AND activated_at IS NULL
        )
        OR (
            status = 'ready'
            AND backfill_cursor IS NULL
            AND activated_at IS NULL
        )
        OR (
            status IN ('active', 'retired')
            AND backfill_cursor IS NULL
            AND activated_at IS NOT NULL
        )
    ),
    CONSTRAINT search_index_versions_timestamp_order CHECK (
        updated_at >= created_at
        AND (activated_at IS NULL OR activated_at >= created_at)
    )
);

CREATE UNIQUE INDEX search_index_versions_one_active_idx
    ON public.search_index_versions (index_alias)
    WHERE status = 'active';

CREATE INDEX search_index_versions_recovery_idx
    ON public.search_index_versions (status, updated_at, index_alias, schema_version)
    WHERE status IN ('preparing', 'backfilling', 'ready');

CREATE TABLE public.search_index_aliases (
    index_alias varchar(64) PRIMARY KEY,
    active_schema_version integer NOT NULL,
    activated_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT search_index_aliases_alias_identifier CHECK (
        octet_length(index_alias) BETWEEN 1 AND 64
        AND index_alias ~ '^[a-z0-9][a-z0-9_-]*$'
    ),
    CONSTRAINT search_index_aliases_version_positive CHECK (active_schema_version > 0),
    CONSTRAINT search_index_aliases_timestamp_order CHECK (updated_at >= activated_at),
    CONSTRAINT search_index_aliases_version_fk FOREIGN KEY (index_alias, active_schema_version)
        REFERENCES public.search_index_versions (index_alias, schema_version)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE public.search_projection_events (
    event_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    index_alias varchar(64) NOT NULL,
    schema_version integer NOT NULL,
    source_id varchar(256) NOT NULL,
    source_revision bigint NOT NULL,
    operation varchar(16) NOT NULL,
    occurred_at timestamptz NOT NULL,
    status varchar(16) NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    lease_token uuid,
    lease_expires_at timestamptz,
    completed_at timestamptz,
    last_error_class varchar(64),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (event_id, index_alias, schema_version),
    CONSTRAINT search_projection_events_event_id_uuid_v7 CHECK (
        (get_byte(uuid_send(event_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(event_id), 8) & 192) = 128
    ),
    CONSTRAINT search_projection_events_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES public.organizations (id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT search_projection_events_version_fk FOREIGN KEY (index_alias, schema_version)
        REFERENCES public.search_index_versions (index_alias, schema_version)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT search_projection_events_schema_version_positive CHECK (schema_version > 0),
    CONSTRAINT search_projection_events_source_identifier CHECK (
        octet_length(source_id) BETWEEN 1 AND 256
        AND source_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    CONSTRAINT search_projection_events_revision_positive CHECK (source_revision > 0),
    CONSTRAINT search_projection_events_operation_known CHECK (operation IN ('upsert', 'delete')),
    CONSTRAINT search_projection_events_status_known CHECK (
        status IN ('pending', 'processing', 'completed', 'superseded')
    ),
    CONSTRAINT search_projection_events_attempts_nonnegative CHECK (
        attempt_count >= 0
    ),
    CONSTRAINT search_projection_events_lease_token_uuid_v7 CHECK (
        lease_token IS NULL
        OR (
            (get_byte(uuid_send(lease_token), 6) >> 4) = 7
            AND (get_byte(uuid_send(lease_token), 8) & 192) = 128
        )
    ),
    CONSTRAINT search_projection_events_lease_pair CHECK (
        (lease_token IS NULL) = (lease_expires_at IS NULL)
    ),
    CONSTRAINT search_projection_events_failure_class_identifier CHECK (
        last_error_class IS NULL
        OR (
            octet_length(last_error_class) BETWEEN 1 AND 64
            AND last_error_class ~ '^[a-z][a-z0-9._-]*$'
        )
    ),
    CONSTRAINT search_projection_events_failure_state CHECK (
        last_error_class IS NULL OR status = 'pending'
    ),
    CONSTRAINT search_projection_events_state_coherent CHECK (
        (
            status = 'pending'
            AND lease_token IS NULL
            AND completed_at IS NULL
        )
        OR (
            status = 'processing'
            AND lease_token IS NOT NULL
            AND completed_at IS NULL
            AND attempt_count > 0
        )
        OR (
            status IN ('completed', 'superseded')
            AND lease_token IS NULL
            AND completed_at IS NOT NULL
        )
    ),
    CONSTRAINT search_projection_events_timestamp_order CHECK (
        updated_at >= created_at
        AND (lease_expires_at IS NULL OR lease_expires_at > updated_at)
        AND (completed_at IS NULL OR completed_at >= created_at)
    )
);

CREATE INDEX search_projection_events_source_revision_idx
    ON public.search_projection_events
       (tenant_id, index_alias, schema_version, source_id, source_revision DESC, event_id DESC)
    WHERE status = 'completed';

CREATE INDEX search_projection_events_live_lease_idx
    ON public.search_projection_events (lease_expires_at, event_id)
    WHERE status = 'processing';

CREATE UNIQUE INDEX search_projection_events_lease_token_idx
    ON public.search_projection_events (lease_token)
    WHERE lease_token IS NOT NULL;

CREATE INDEX search_projection_events_freshness_idx
    ON public.search_projection_events (index_alias, schema_version, completed_at DESC)
    WHERE status = 'completed';

CREATE FUNCTION public.search_index_versions_preserve_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.index_alias IS DISTINCT FROM OLD.index_alias
        OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
        OR NEW.schema_digest IS DISTINCT FROM OLD.schema_digest
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION 'search index version identity cannot be changed'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER search_index_versions_preserve_identity
BEFORE UPDATE ON public.search_index_versions
FOR EACH ROW
EXECUTE FUNCTION public.search_index_versions_preserve_identity();

CREATE FUNCTION public.search_projection_events_preserve_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.event_id IS DISTINCT FROM OLD.event_id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.index_alias IS DISTINCT FROM OLD.index_alias
        OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
        OR NEW.source_id IS DISTINCT FROM OLD.source_id
        OR NEW.source_revision IS DISTINCT FROM OLD.source_revision
        OR NEW.operation IS DISTINCT FROM OLD.operation
        OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION 'search projection event identity cannot be changed'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER search_projection_events_preserve_identity
BEFORE UPDATE ON public.search_projection_events
FOR EACH ROW
EXECUTE FUNCTION public.search_projection_events_preserve_identity();
