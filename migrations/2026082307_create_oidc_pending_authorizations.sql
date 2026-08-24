CREATE TABLE oidc_pending_authorizations (
    id uuid PRIMARY KEY,
    state_digest bytea NOT NULL UNIQUE,
    payload jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT oidc_pending_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT oidc_pending_state_digest_length CHECK (octet_length(state_digest) = 32),
    CONSTRAINT oidc_pending_payload_object CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT oidc_pending_expiry_order CHECK (expires_at > created_at)
);

CREATE INDEX oidc_pending_authorizations_expires_at_idx
    ON oidc_pending_authorizations (expires_at);
