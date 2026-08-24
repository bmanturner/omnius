CREATE TABLE totp_credentials (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    account_name text NOT NULL,
    seed_ciphertext bytea NOT NULL,
    seed_nonce bytea NOT NULL,
    seed_encryption_version smallint NOT NULL,
    created_at timestamptz NOT NULL,
    confirmed_at timestamptz,
    last_used_step bigint,
    failure_window_started_at timestamptz,
    failure_count integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    updated_at timestamptz NOT NULL,
    disabled_at timestamptz,
    CONSTRAINT totp_credentials_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT totp_credentials_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT,
    CONSTRAINT totp_credentials_account_name_bounded CHECK (
        octet_length(account_name) BETWEEN 1 AND 128
        AND btrim(account_name) = account_name
        AND strpos(account_name, ':') = 0
        AND account_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT totp_credentials_ciphertext_length CHECK (
        octet_length(seed_ciphertext) = 36
    ),
    CONSTRAINT totp_credentials_nonce_length CHECK (
        octet_length(seed_nonce) = 12
    ),
    CONSTRAINT totp_credentials_encryption_version CHECK (
        seed_encryption_version = 1
    ),
    CONSTRAINT totp_credentials_confirmation_state CHECK (
        (confirmed_at IS NULL AND last_used_step IS NULL)
        OR (
            confirmed_at IS NOT NULL
            AND confirmed_at >= created_at
            AND confirmed_at <= updated_at
            AND last_used_step IS NOT NULL
            AND last_used_step >= 0
        )
    ),
    CONSTRAINT totp_credentials_failure_count_bounded CHECK (
        failure_count BETWEEN 0 AND 1000000
    ),
    CONSTRAINT totp_credentials_failure_state CHECK (
        (failure_count = 0 AND failure_window_started_at IS NULL AND locked_until IS NULL)
        OR (
            failure_count > 0
            AND failure_window_started_at IS NOT NULL
            AND failure_window_started_at >= created_at
            AND failure_window_started_at <= updated_at
            AND (locked_until IS NULL OR locked_until >= failure_window_started_at)
        )
    ),
    CONSTRAINT totp_credentials_updated_at_order CHECK (
        updated_at >= created_at
    ),
    CONSTRAINT totp_credentials_disabled_at_order CHECK (
        disabled_at IS NULL OR (disabled_at >= created_at AND disabled_at <= updated_at)
    )
);

CREATE UNIQUE INDEX totp_credentials_one_active_per_user
    ON totp_credentials (user_id)
    WHERE disabled_at IS NULL;

CREATE INDEX totp_credentials_user_created_idx
    ON totp_credentials (user_id, created_at DESC);

CREATE TABLE recovery_codes (
    id uuid PRIMARY KEY,
    credential_id uuid NOT NULL,
    lookup_id text NOT NULL,
    code_hash text NOT NULL,
    created_at timestamptz NOT NULL,
    used_at timestamptz,
    invalidated_at timestamptz,
    CONSTRAINT recovery_codes_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT recovery_codes_credential_id_fkey
        FOREIGN KEY (credential_id) REFERENCES totp_credentials (id) ON DELETE RESTRICT,
    CONSTRAINT recovery_codes_lookup_format CHECK (
        octet_length(lookup_id) = 11
        AND lookup_id COLLATE "C" ~ '^[A-Za-z0-9_-]{11}$'
    ),
    CONSTRAINT recovery_codes_hash_bounded CHECK (
        octet_length(code_hash) BETWEEN 64 AND 255
        AND code_hash LIKE '$argon2id$v=19$%'
    ),
    CONSTRAINT recovery_codes_terminal_state CHECK (
        NOT (used_at IS NOT NULL AND invalidated_at IS NOT NULL)
        AND (used_at IS NULL OR used_at >= created_at)
        AND (invalidated_at IS NULL OR invalidated_at >= created_at)
    ),
    CONSTRAINT recovery_codes_credential_lookup_key
        UNIQUE (credential_id, lookup_id)
);

CREATE INDEX recovery_codes_active_lookup_idx
    ON recovery_codes (credential_id, lookup_id)
    WHERE used_at IS NULL AND invalidated_at IS NULL;
