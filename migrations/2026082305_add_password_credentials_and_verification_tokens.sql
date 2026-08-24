ALTER TABLE users
    ADD COLUMN authentication_version bigint NOT NULL DEFAULT 1,
    ADD CONSTRAINT users_authentication_version_positive CHECK (authentication_version > 0);

CREATE TABLE password_credentials (
    user_id uuid PRIMARY KEY,
    password_hash text NOT NULL,
    pepper_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    changed_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT password_credentials_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT,
    CONSTRAINT password_credentials_hash_nonblank CHECK (
        password_hash ~ '[^[:space:]]'
    ),
    CONSTRAINT password_credentials_hash_trimmed CHECK (
        password_hash !~ '^[[:space:]]'
        AND password_hash !~ '[[:space:]]$'
    ),
    CONSTRAINT password_credentials_hash_length CHECK (
        octet_length(password_hash) <= 1024
    ),
    CONSTRAINT password_credentials_hash_algorithm CHECK (
        password_hash LIKE '$argon2id$v=19$%'
    ),
    CONSTRAINT password_credentials_pepper_version_nonnegative CHECK (
        pepper_version >= 0
    ),
    CONSTRAINT password_credentials_timeline CHECK (
        changed_at >= created_at AND updated_at >= changed_at
    )
);

CREATE TABLE verification_tokens (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    purpose text NOT NULL,
    token_hash bytea NOT NULL,
    security_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    invalidated_at timestamptz,
    CONSTRAINT verification_tokens_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT verification_tokens_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT,
    CONSTRAINT verification_tokens_purpose_known CHECK (
        purpose IN ('email_verification', 'password_recovery')
    ),
    CONSTRAINT verification_tokens_hash_length CHECK (
        octet_length(token_hash) = 32
    ),
    CONSTRAINT verification_tokens_hash_key UNIQUE (token_hash),
    CONSTRAINT verification_tokens_security_version_positive CHECK (
        security_version > 0
    ),
    CONSTRAINT verification_tokens_expiry_valid CHECK (expires_at > created_at),
    CONSTRAINT verification_tokens_terminal_state_valid CHECK (
        NOT (consumed_at IS NOT NULL AND invalidated_at IS NOT NULL)
        AND (consumed_at IS NULL OR (
            consumed_at >= created_at AND consumed_at <= expires_at
        ))
        AND (invalidated_at IS NULL OR invalidated_at >= created_at)
    )
);

CREATE UNIQUE INDEX verification_tokens_active_subject_purpose_idx
    ON verification_tokens (user_id, purpose)
    WHERE consumed_at IS NULL AND invalidated_at IS NULL;

CREATE INDEX verification_tokens_expiry_idx
    ON verification_tokens (expires_at)
    WHERE consumed_at IS NULL AND invalidated_at IS NULL;
