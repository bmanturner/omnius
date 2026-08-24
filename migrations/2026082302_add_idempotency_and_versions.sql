ALTER TABLE reference_records
    ADD COLUMN version bigint NOT NULL DEFAULT 1,
    ADD CONSTRAINT reference_records_version_positive CHECK (version > 0);

CREATE FUNCTION reference_records_increment_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.version := OLD.version + 1;
    RETURN NEW;
END;
$$;

CREATE TRIGGER reference_records_increment_version_before_update
BEFORE UPDATE ON reference_records
FOR EACH ROW
EXECUTE FUNCTION reference_records_increment_version();

CREATE TABLE idempotency_records (
    principal_scope text,
    tenant_scope text,
    operation varchar(128) NOT NULL,
    idempotency_key varchar(128) NOT NULL,
    request_hash bytea NOT NULL,
    status text NOT NULL,
    response_status smallint,
    response_content_type varchar(255),
    response_body bytea,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    CONSTRAINT idempotency_records_scope_principal_bounded CHECK (
        principal_scope IS NULL OR (
            char_length(principal_scope) BETWEEN 1 AND 128
            AND principal_scope = btrim(principal_scope)
        )
    ),
    CONSTRAINT idempotency_records_scope_tenant_bounded CHECK (
        tenant_scope IS NULL OR (
            char_length(tenant_scope) BETWEEN 1 AND 128
            AND tenant_scope = btrim(tenant_scope)
        )
    ),
    CONSTRAINT idempotency_records_operation_bounded CHECK (
        char_length(operation) BETWEEN 1 AND 128
        AND operation = btrim(operation)
    ),
    CONSTRAINT idempotency_records_key_bounded CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key = btrim(idempotency_key)
    ),
    CONSTRAINT idempotency_records_hash_length CHECK (octet_length(request_hash) = 32),
    CONSTRAINT idempotency_records_status_known CHECK (status IN ('in_progress', 'completed')),
    CONSTRAINT idempotency_records_response_status_valid CHECK (
        response_status IS NULL OR response_status BETWEEN 100 AND 599
    ),
    CONSTRAINT idempotency_records_response_body_bounded CHECK (
        response_body IS NULL OR octet_length(response_body) <= 2097152
    ),
    CONSTRAINT idempotency_records_state_consistent CHECK (
        (status = 'in_progress'
            AND response_status IS NULL
            AND response_content_type IS NULL
            AND response_body IS NULL
            AND completed_at IS NULL)
        OR
        (status = 'completed'
            AND response_status IS NOT NULL
            AND response_body IS NOT NULL
            AND completed_at IS NOT NULL)
    ),
    CONSTRAINT idempotency_records_expiry_valid CHECK (
        expires_at > created_at
        AND (completed_at IS NULL OR completed_at <= expires_at)
    ),
    CONSTRAINT idempotency_records_unique_scope
        UNIQUE NULLS NOT DISTINCT (principal_scope, tenant_scope, operation, idempotency_key)
);

CREATE INDEX idempotency_records_expiry_idx ON idempotency_records (expires_at);
