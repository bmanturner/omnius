CREATE FUNCTION api_key_scopes_are_canonical(candidate text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT cardinality(candidate) <= 128
        AND NOT EXISTS (
            SELECT 1
            FROM unnest(candidate) AS value(scope)
            WHERE octet_length(scope) NOT BETWEEN 1 AND 128
                OR scope COLLATE "C" !~ '^[!-~]+$'
                OR strpos(scope, '"') <> 0
                OR strpos(scope, E'\\') <> 0
        )
        AND candidate = ARRAY(
            SELECT scope
            FROM unnest(candidate) AS value(scope)
            ORDER BY scope COLLATE "C"
        )
        AND cardinality(candidate) = (
            SELECT count(DISTINCT scope COLLATE "C")::integer
            FROM unnest(candidate) AS value(scope)
        );
$$;

CREATE TABLE service_accounts (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    tenant_id uuid,
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    disabled_at timestamptz,
    CONSTRAINT service_accounts_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT service_accounts_tenant_id_uuid_v7 CHECK (
        tenant_id IS NULL
        OR (
            (get_byte(uuid_send(tenant_id), 6) >> 4) = 7
            AND (get_byte(uuid_send(tenant_id), 8) & 192) = 128
        )
    ),
    CONSTRAINT service_accounts_created_by_user_id_fkey
        FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE RESTRICT,
    CONSTRAINT service_accounts_name_trimmed CHECK (
        name !~ '^[[:space:]]' AND name !~ '[[:space:]]$'
    ),
    CONSTRAINT service_accounts_name_nonblank CHECK (name ~ '[^[:space:]]'),
    CONSTRAINT service_accounts_name_length CHECK (octet_length(name) <= 255),
    CONSTRAINT service_accounts_disabled_order CHECK (
        disabled_at IS NULL OR disabled_at >= created_at
    )
);

CREATE TABLE api_keys (
    id uuid PRIMARY KEY,
    service_account_id uuid NOT NULL,
    key_prefix text NOT NULL,
    secret_hash bytea NOT NULL,
    name text NOT NULL,
    scopes text[] NOT NULL,
    expires_at timestamptz,
    created_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    rotated_from_id uuid,
    CONSTRAINT api_keys_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT api_keys_service_account_id_fkey
        FOREIGN KEY (service_account_id) REFERENCES service_accounts (id) ON DELETE RESTRICT,
    CONSTRAINT api_keys_key_prefix_key UNIQUE (key_prefix),
    CONSTRAINT api_keys_key_prefix_canonical CHECK (
        octet_length(key_prefix) = 16
        AND key_prefix COLLATE "C" ~ '^rsk_[A-Za-z0-9_-]{12}$'
    ),
    CONSTRAINT api_keys_secret_hash_length CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT api_keys_name_trimmed CHECK (
        name !~ '^[[:space:]]' AND name !~ '[[:space:]]$'
    ),
    CONSTRAINT api_keys_name_nonblank CHECK (name ~ '[^[:space:]]'),
    CONSTRAINT api_keys_name_length CHECK (octet_length(name) <= 255),
    CONSTRAINT api_keys_scopes_canonical CHECK (api_key_scopes_are_canonical(scopes)),
    CONSTRAINT api_keys_expiry_order CHECK (
        expires_at IS NULL OR expires_at > created_at
    ),
    CONSTRAINT api_keys_last_used_order CHECK (
        last_used_at IS NULL OR last_used_at >= created_at
    ),
    CONSTRAINT api_keys_last_used_before_expiry CHECK (
        last_used_at IS NULL OR expires_at IS NULL OR last_used_at < expires_at
    ),
    CONSTRAINT api_keys_revoke_order CHECK (
        revoked_at IS NULL OR revoked_at >= created_at
    ),
    CONSTRAINT api_keys_last_used_before_revoke CHECK (
        last_used_at IS NULL OR revoked_at IS NULL OR last_used_at <= revoked_at
    ),
    CONSTRAINT api_keys_not_self_rotated CHECK (
        rotated_from_id IS NULL OR rotated_from_id <> id
    ),
    CONSTRAINT api_keys_id_service_account_key UNIQUE (id, service_account_id),
    CONSTRAINT api_keys_rotated_from_owner_fkey
        FOREIGN KEY (rotated_from_id, service_account_id)
        REFERENCES api_keys (id, service_account_id) ON DELETE RESTRICT
);

CREATE INDEX service_accounts_created_by_user_id_idx
    ON service_accounts (created_by_user_id, created_at DESC, id DESC);

CREATE INDEX service_accounts_tenant_id_idx
    ON service_accounts (tenant_id, created_at DESC, id DESC)
    WHERE tenant_id IS NOT NULL;

CREATE INDEX api_keys_service_account_created_idx
    ON api_keys (service_account_id, created_at DESC, id DESC);

CREATE INDEX api_keys_active_expiry_idx
    ON api_keys (expires_at, id)
    WHERE revoked_at IS NULL AND expires_at IS NOT NULL;

CREATE INDEX api_keys_revoked_at_idx
    ON api_keys (revoked_at, id)
    WHERE revoked_at IS NOT NULL;
