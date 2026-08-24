CREATE FUNCTION webauthn_transports_are_canonical(candidate text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT cardinality(candidate) <= 7
        AND array_position(candidate, NULL) IS NULL
        AND candidate <@ ARRAY['ble', 'hybrid', 'internal', 'nfc', 'test', 'unknown', 'usb']::text[]
        AND candidate = ARRAY(
            SELECT DISTINCT transport COLLATE "C" AS transport
            FROM unnest(candidate) AS value(transport)
            ORDER BY transport
        );
$$;

CREATE TABLE webauthn_credentials (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    credential_id bytea NOT NULL,
    passkey jsonb NOT NULL,
    name text NOT NULL,
    transports text[] NOT NULL DEFAULT '{}',
    sign_count bigint NOT NULL,
    user_verified boolean NOT NULL,
    backup_eligible boolean NOT NULL,
    backup_state boolean NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    last_used_at timestamptz,
    disabled_at timestamptz,
    CONSTRAINT webauthn_credentials_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT webauthn_credentials_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT webauthn_credentials_credential_id_key UNIQUE (credential_id),
    CONSTRAINT webauthn_credentials_credential_id_size
        CHECK (octet_length(credential_id) BETWEEN 1 AND 1024),
    CONSTRAINT webauthn_credentials_passkey_shape CHECK (
        jsonb_typeof(passkey) = 'object'
        AND octet_length(passkey::text) BETWEEN 2 AND 65536
    ),
    CONSTRAINT webauthn_credentials_name_size CHECK (
        octet_length(name) BETWEEN 1 AND 255
        AND name !~ '^[[:space:]]'
        AND name !~ '[[:space:]]$'
        AND name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT webauthn_credentials_transports_canonical
        CHECK (webauthn_transports_are_canonical(transports)),
    CONSTRAINT webauthn_credentials_sign_count_range
        CHECK (sign_count BETWEEN 0 AND 4294967295),
    CONSTRAINT webauthn_credentials_backup_consistent
        CHECK (NOT backup_state OR backup_eligible),
    CONSTRAINT webauthn_credentials_timestamps_ordered CHECK (
        updated_at >= created_at
        AND (last_used_at IS NULL OR last_used_at >= created_at)
        AND (disabled_at IS NULL OR disabled_at >= created_at)
        AND (last_used_at IS NULL OR disabled_at IS NULL OR last_used_at <= disabled_at)
    )
);

CREATE INDEX webauthn_credentials_active_user_created_idx
    ON webauthn_credentials (user_id, created_at, id)
    WHERE disabled_at IS NULL;

CREATE TABLE webauthn_ceremonies (
    id uuid PRIMARY KEY,
    handle_hash bytea NOT NULL,
    kind text NOT NULL,
    user_id uuid,
    credential_name text,
    state jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT webauthn_ceremonies_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT webauthn_ceremonies_handle_hash_key UNIQUE (handle_hash),
    CONSTRAINT webauthn_ceremonies_handle_hash_size CHECK (octet_length(handle_hash) = 32),
    CONSTRAINT webauthn_ceremonies_kind CHECK (
        kind IN ('registration', 'authentication', 'discoverable_authentication')
    ),
    CONSTRAINT webauthn_ceremonies_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT webauthn_ceremonies_kind_payload CHECK (
        (kind = 'registration' AND user_id IS NOT NULL AND credential_name IS NOT NULL)
        OR (kind = 'authentication' AND user_id IS NOT NULL AND credential_name IS NULL)
        OR (kind = 'discoverable_authentication' AND user_id IS NULL AND credential_name IS NULL)
    ),
    CONSTRAINT webauthn_ceremonies_credential_name_size CHECK (
        credential_name IS NULL
        OR (
            octet_length(credential_name) BETWEEN 1 AND 255
            AND credential_name !~ '^[[:space:]]'
            AND credential_name !~ '[[:space:]]$'
            AND credential_name !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT webauthn_ceremonies_state_shape CHECK (
        jsonb_typeof(state) = 'object'
        AND octet_length(state::text) BETWEEN 2 AND 65536
    ),
    CONSTRAINT webauthn_ceremonies_expiry_window CHECK (
        expires_at > created_at
        AND expires_at <= created_at + INTERVAL '10 minutes'
    )
);

CREATE INDEX webauthn_ceremonies_expires_at_idx ON webauthn_ceremonies (expires_at);
CREATE INDEX webauthn_ceremonies_user_kind_idx ON webauthn_ceremonies (user_id, kind)
    WHERE user_id IS NOT NULL;
