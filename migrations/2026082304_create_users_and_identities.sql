CREATE TABLE users (
    id uuid PRIMARY KEY,
    created_at timestamptz NOT NULL,
    CONSTRAINT users_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    )
);

CREATE TABLE identities (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    provider text NOT NULL,
    provider_subject text NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT identities_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT identities_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT,
    CONSTRAINT identities_provider_trimmed CHECK (
        provider !~ '^[[:space:]]' AND provider !~ '[[:space:]]$'
    ),
    CONSTRAINT identities_provider_nonblank CHECK (provider ~ '[^[:space:]]'),
    CONSTRAINT identities_provider_length CHECK (octet_length(provider) <= 2048),
    CONSTRAINT identities_provider_subject_trimmed CHECK (
        provider_subject !~ '^[[:space:]]'
        AND provider_subject !~ '[[:space:]]$'
    ),
    CONSTRAINT identities_provider_subject_nonblank CHECK (
        provider_subject ~ '[^[:space:]]'
    ),
    CONSTRAINT identities_provider_subject_length CHECK (
        octet_length(provider_subject) <= 255
    ),
    CONSTRAINT identities_provider_subject_key_bytes CHECK (
        octet_length(provider) + octet_length(provider_subject) <= 2303
    ),
    CONSTRAINT identities_provider_provider_subject_key UNIQUE (provider, provider_subject)
);

CREATE INDEX identities_user_id_idx ON identities (user_id);
