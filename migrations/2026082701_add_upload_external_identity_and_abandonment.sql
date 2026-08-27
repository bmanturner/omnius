CREATE TABLE upload_external_identities (
    organization_id uuid NOT NULL,
    owner_id uuid NOT NULL,
    workflow_key_hash bytea NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    upload_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, workflow_key_hash),
    CONSTRAINT upload_external_identities_organization_fk
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT,
    CONSTRAINT upload_external_identities_owner_fk
        FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT upload_external_identities_workflow_hash_size
        CHECK (octet_length(workflow_key_hash) = 32),
    CONSTRAINT upload_external_identities_idempotency_hash_size
        CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT upload_external_identities_idempotency_unique
        UNIQUE (organization_id, idempotency_key_hash),
    CONSTRAINT upload_external_identities_upload_unique
        UNIQUE (organization_id, upload_id)
);

ALTER TABLE uploads DROP CONSTRAINT uploads_rejection_reason_allowed;
ALTER TABLE uploads ADD CONSTRAINT uploads_rejection_reason_allowed CHECK (
    rejection_reason IS NULL OR rejection_reason IN (
        'missing_object',
        'size_mismatch',
        'checksum_mismatch',
        'mime_mismatch',
        'malware',
        'scanner_failure',
        'abandoned',
        'pending_expired'
    )
);
