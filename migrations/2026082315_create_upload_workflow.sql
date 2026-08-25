CREATE TABLE uploads (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    owner_id uuid NOT NULL,
    object_key uuid NOT NULL,
    published_object_key uuid NOT NULL,
    filename varchar(180) NOT NULL,
    declared_size bigint NOT NULL,
    expected_sha256 bytea NOT NULL,
    declared_mime varchar(64) NOT NULL,
    direct_credential_expires_at timestamptz,
    pending_expires_at timestamptz NOT NULL,
    detected_mime varchar(64),
    state varchar(24) NOT NULL,
    rejection_reason varchar(32),
    revision bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    verified_at timestamptz,
    scanned_at timestamptz,
    completed_at timestamptz,
    deleted_at timestamptz,
    CONSTRAINT uploads_id_uuid_v7 CHECK ((get_byte(uuid_send(id), 6) >> 4) = 7 AND (get_byte(uuid_send(id), 8) & 192) = 128),
    CONSTRAINT uploads_owner_id_uuid_v7 CHECK ((get_byte(uuid_send(owner_id), 6) >> 4) = 7 AND (get_byte(uuid_send(owner_id), 8) & 192) = 128),
    CONSTRAINT uploads_object_key_uuid_v7 CHECK ((get_byte(uuid_send(object_key), 6) >> 4) = 7 AND (get_byte(uuid_send(object_key), 8) & 192) = 128),
    CONSTRAINT uploads_published_object_key_uuid_v7 CHECK ((get_byte(uuid_send(published_object_key), 6) >> 4) = 7 AND (get_byte(uuid_send(published_object_key), 8) & 192) = 128),
    CONSTRAINT uploads_staging_publication_keys_distinct CHECK (object_key <> published_object_key),
    CONSTRAINT uploads_tenant_object_key_unique UNIQUE (organization_id, object_key),
    CONSTRAINT uploads_tenant_published_object_key_unique UNIQUE (organization_id, published_object_key),
    CONSTRAINT uploads_identity_tuple_unique UNIQUE (id, organization_id, object_key),
    CONSTRAINT uploads_filename_bounds CHECK (
        octet_length(filename) BETWEEN 1 AND 180 AND filename = btrim(filename)
        AND filename !~ '[[:cntrl:]/\\]' AND filename !~ '[[:space:]]{2,}'
        AND filename NOT IN ('.', '..')
    ),
    CONSTRAINT uploads_declared_size_bounds CHECK (declared_size BETWEEN 0 AND 5368709120),
    CONSTRAINT uploads_expected_sha256_length CHECK (octet_length(expected_sha256) = 32),
    CONSTRAINT uploads_declared_mime_allowed CHECK (declared_mime IN ('image/png', 'image/jpeg', 'image/gif', 'application/pdf', 'application/zip')),
    CONSTRAINT uploads_detected_mime_allowed CHECK (detected_mime IS NULL OR detected_mime IN ('image/png', 'image/jpeg', 'image/gif', 'application/pdf', 'application/zip')),
    CONSTRAINT uploads_state_allowed CHECK (state IN ('pending_upload', 'quarantined', 'available', 'rejected', 'deleted')),
    CONSTRAINT uploads_rejection_reason_allowed CHECK (rejection_reason IS NULL OR rejection_reason IN ('missing_object', 'size_mismatch', 'checksum_mismatch', 'mime_mismatch', 'malware', 'scanner_failure', 'pending_expired')),
    CONSTRAINT uploads_revision_positive CHECK (revision >= 1),
    CONSTRAINT uploads_timestamps_ordered CHECK (
        updated_at >= created_at
        AND pending_expires_at > created_at
        AND pending_expires_at <= updated_at + INTERVAL '24 hours'
        AND (direct_credential_expires_at IS NULL OR (
            direct_credential_expires_at >= created_at
            AND direct_credential_expires_at <= pending_expires_at
        ))
        AND (verified_at IS NULL OR verified_at >= created_at)
        AND (scanned_at IS NULL OR scanned_at >= created_at)
        AND (completed_at IS NULL OR completed_at >= created_at)
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    CONSTRAINT uploads_state_coherent CHECK (
        (state = 'pending_upload' AND detected_mime IS NULL AND rejection_reason IS NULL AND verified_at IS NULL AND scanned_at IS NULL AND completed_at IS NULL AND deleted_at IS NULL)
        OR (state = 'quarantined' AND rejection_reason IS NULL AND scanned_at IS NULL AND completed_at IS NULL AND deleted_at IS NULL AND ((verified_at IS NULL AND detected_mime IS NULL) OR (verified_at IS NOT NULL AND detected_mime = declared_mime)))
        OR (state = 'available' AND detected_mime = declared_mime AND rejection_reason IS NULL AND verified_at IS NOT NULL AND scanned_at IS NOT NULL AND completed_at IS NOT NULL AND deleted_at IS NULL)
        OR (state = 'rejected' AND rejection_reason IS NOT NULL AND completed_at IS NOT NULL AND deleted_at IS NULL)
        OR (state = 'deleted' AND rejection_reason IS NOT NULL AND completed_at IS NOT NULL AND deleted_at IS NOT NULL)
    )
);

CREATE INDEX uploads_tenant_state_updated_idx ON uploads (organization_id, state, updated_at, id);
CREATE INDEX uploads_expired_pending_idx ON uploads (pending_expires_at, id) WHERE state = 'pending_upload';

CREATE TABLE upload_reconciliation (
    id uuid PRIMARY KEY,
    upload_id uuid,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    object_key uuid NOT NULL,
    kind varchar(16) NOT NULL,
    available_at timestamptz,
    attempt_count integer NOT NULL DEFAULT 0,
    lease_owner varchar(128),
    lease_token uuid,
    lease_expires_at timestamptz,
    completed_at timestamptz,
    last_error_code varchar(32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT upload_reconciliation_upload_identity_fk FOREIGN KEY (upload_id, organization_id, object_key) REFERENCES uploads (id, organization_id, object_key) ON DELETE RESTRICT,
    CONSTRAINT upload_reconciliation_id_uuid_v7 CHECK ((get_byte(uuid_send(id), 6) >> 4) = 7 AND (get_byte(uuid_send(id), 8) & 192) = 128),
    CONSTRAINT upload_reconciliation_object_key_uuid_v7 CHECK ((get_byte(uuid_send(object_key), 6) >> 4) = 7 AND (get_byte(uuid_send(object_key), 8) & 192) = 128),
    CONSTRAINT upload_reconciliation_kind_allowed CHECK (kind IN ('verify', 'scan', 'delete')),
    CONSTRAINT upload_reconciliation_orphan_delete_only CHECK (upload_id IS NOT NULL OR kind = 'delete'),
    CONSTRAINT upload_reconciliation_available_coherent CHECK (available_at IS NOT NULL OR (kind = 'verify' AND attempt_count = 0)),
    CONSTRAINT upload_reconciliation_attempt_bounds CHECK (attempt_count BETWEEN 0 AND 100),
    CONSTRAINT upload_reconciliation_lease_coherent CHECK ((lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) OR (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CONSTRAINT upload_reconciliation_lease_owner_bounded CHECK (lease_owner IS NULL OR (octet_length(lease_owner) BETWEEN 1 AND 128 AND lease_owner ~ '^[A-Za-z0-9_.-]+$')),
    CONSTRAINT upload_reconciliation_lease_token_uuid_v7 CHECK (lease_token IS NULL OR ((get_byte(uuid_send(lease_token), 6) >> 4) = 7 AND (get_byte(uuid_send(lease_token), 8) & 192) = 128)),
    CONSTRAINT upload_reconciliation_completed_unleased CHECK (completed_at IS NULL OR (lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)),
    CONSTRAINT upload_reconciliation_error_allowed CHECK (last_error_code IS NULL OR last_error_code IN ('storage_unavailable', 'scanner_unavailable', 'timeout', 'cancelled')),
    CONSTRAINT upload_reconciliation_timestamps_ordered CHECK (updated_at >= created_at AND (available_at IS NULL OR available_at >= created_at) AND (lease_expires_at IS NULL OR lease_expires_at >= created_at) AND (completed_at IS NULL OR completed_at >= created_at))
);

CREATE UNIQUE INDEX upload_reconciliation_unfinished_identity_idx ON upload_reconciliation (organization_id, object_key, kind) WHERE completed_at IS NULL;
CREATE INDEX upload_reconciliation_ready_idx ON upload_reconciliation (available_at, created_at, id) WHERE completed_at IS NULL;
CREATE INDEX upload_reconciliation_expired_lease_idx ON upload_reconciliation (lease_expires_at, id) WHERE completed_at IS NULL AND lease_token IS NOT NULL;

CREATE FUNCTION prevent_upload_identity_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.owner_id IS DISTINCT FROM OLD.owner_id OR NEW.object_key IS DISTINCT FROM OLD.object_key
       OR NEW.published_object_key IS DISTINCT FROM OLD.published_object_key
       OR NEW.filename IS DISTINCT FROM OLD.filename OR NEW.declared_size IS DISTINCT FROM OLD.declared_size
       OR NEW.expected_sha256 IS DISTINCT FROM OLD.expected_sha256 OR NEW.declared_mime IS DISTINCT FROM OLD.declared_mime
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'upload immutable identity cannot be changed' USING ERRCODE = '23514';
    END IF;
    IF NEW.pending_expires_at < OLD.pending_expires_at
       OR (OLD.direct_credential_expires_at IS NOT NULL AND (
           NEW.direct_credential_expires_at IS NULL
           OR NEW.direct_credential_expires_at < OLD.direct_credential_expires_at
       )) THEN
        RAISE EXCEPTION 'upload credential deadlines cannot move backward' USING ERRCODE = '23514';
    END IF;
    IF (
        NEW.pending_expires_at IS DISTINCT FROM OLD.pending_expires_at
        OR NEW.direct_credential_expires_at IS DISTINCT FROM OLD.direct_credential_expires_at
       ) AND (OLD.state <> 'pending_upload' OR NEW.state <> 'pending_upload') THEN
        RAISE EXCEPTION 'upload credential deadlines are mutable only while pending' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER uploads_immutable_identity BEFORE UPDATE ON uploads FOR EACH ROW EXECUTE FUNCTION prevent_upload_identity_mutation();

CREATE FUNCTION prevent_upload_reconciliation_identity_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.upload_id IS DISTINCT FROM OLD.upload_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id OR NEW.object_key IS DISTINCT FROM OLD.object_key
       OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'upload work immutable identity cannot be changed' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER upload_reconciliation_immutable_identity BEFORE UPDATE ON upload_reconciliation FOR EACH ROW EXECUTE FUNCTION prevent_upload_reconciliation_identity_mutation();
