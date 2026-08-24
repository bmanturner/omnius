CREATE SCHEMA tower_sessions;

CREATE TABLE tower_sessions.session (
    id text PRIMARY KEY,
    data bytea NOT NULL,
    expiry_date timestamptz NOT NULL
);

CREATE INDEX session_expiry_date_idx
    ON tower_sessions.session (expiry_date);

CREATE TABLE sessions (
    session_id text PRIMARY KEY,
    user_id uuid NOT NULL,
    device_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    user_agent_hash bytea,
    ip_prefix inet,
    CONSTRAINT sessions_session_id_length CHECK (octet_length(session_id) = 22),
    CONSTRAINT sessions_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT,
    CONSTRAINT sessions_device_id_uuid_v7 CHECK (
        (get_byte(uuid_send(device_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(device_id), 8) & 192) = 128
    ),
    CONSTRAINT sessions_absolute_expiry_valid CHECK (
        absolute_expires_at > created_at
    ),
    CONSTRAINT sessions_user_agent_hash_length CHECK (
        user_agent_hash IS NULL OR octet_length(user_agent_hash) = 32
    ),
    CONSTRAINT sessions_timeline CHECK (
        last_seen_at >= created_at AND last_seen_at <= absolute_expires_at
    ),
    CONSTRAINT sessions_revocation_timeline CHECK (
        revoked_at IS NULL OR revoked_at >= created_at
    )
);

CREATE INDEX sessions_revoked_cleanup_idx
    ON sessions (revoked_at)
    WHERE revoked_at IS NOT NULL;

CREATE INDEX sessions_last_seen_cleanup_idx
    ON sessions (last_seen_at);

-- The provider persists after request handlers, so metadata cannot reference its row.
CREATE INDEX sessions_active_user_idx
    ON sessions (user_id, created_at DESC)
    WHERE revoked_at IS NULL;

CREATE INDEX sessions_active_device_idx
    ON sessions (user_id, device_id)
    WHERE revoked_at IS NULL;

CREATE INDEX sessions_active_expiry_idx
    ON sessions (absolute_expires_at)
    WHERE revoked_at IS NULL;
