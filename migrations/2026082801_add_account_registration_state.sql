ALTER TABLE users
    ADD COLUMN status text;

UPDATE users
SET status = 'active';

ALTER TABLE users
    ALTER COLUMN status SET NOT NULL,
    ALTER COLUMN status SET DEFAULT 'pending_verification',
    ADD CONSTRAINT users_status_known CHECK (
        status IN ('pending_verification', 'active', 'disabled')
    );

ALTER TABLE identities
    ADD COLUMN verified_at timestamptz,
    ADD CONSTRAINT identities_verified_order CHECK (
        verified_at IS NULL OR verified_at >= created_at
    );

UPDATE identities AS identity
SET verified_at = identity.created_at
WHERE identity.verified_at IS NULL
    AND identity.provider = 'email'
    AND EXISTS (
        SELECT 1
        FROM password_credentials AS credential
        WHERE credential.user_id = identity.user_id
    );

CREATE FUNCTION advance_authentication_version_when_user_disabled()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'disabled'
        AND OLD.status IS DISTINCT FROM 'disabled'
        AND (
            NEW.authentication_version IS NULL
            OR NEW.authentication_version <= OLD.authentication_version
        )
    THEN
        NEW.authentication_version := OLD.authentication_version + 1;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER users_disable_advances_authentication_version
BEFORE UPDATE OF status ON users
FOR EACH ROW
EXECUTE FUNCTION advance_authentication_version_when_user_disabled();

CREATE TABLE registration_invitations (
    id uuid PRIMARY KEY,
    identity_provider text NOT NULL,
    identity_subject text NOT NULL,
    token_digest bytea NOT NULL,
    issuer_kind text NOT NULL,
    issued_by_user_id uuid,
    issued_by_service_account_id uuid,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz,
    CONSTRAINT registration_invitations_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT registration_invitations_identity_provider_trimmed CHECK (
        identity_provider !~ '^[[:space:]]'
        AND identity_provider !~ '[[:space:]]$'
    ),
    CONSTRAINT registration_invitations_identity_provider_nonblank CHECK (
        identity_provider ~ '[^[:space:]]'
    ),
    CONSTRAINT registration_invitations_identity_provider_length CHECK (
        octet_length(identity_provider) <= 2048
    ),
    CONSTRAINT registration_invitations_identity_subject_canonical_email CHECK (
        octet_length(identity_subject) BETWEEN 3 AND 320
        AND identity_subject = lower(identity_subject)
        AND identity_subject COLLATE "C"
            ~ '^[^@[:space:][:cntrl:]]+@[^@[:space:][:cntrl:]]+$'
    ),
    CONSTRAINT registration_invitations_identity_key_bytes CHECK (
        octet_length(identity_provider) + octet_length(identity_subject) <= 2368
    ),
    CONSTRAINT registration_invitations_token_digest_length CHECK (
        octet_length(token_digest) = 32
    ),
    CONSTRAINT registration_invitations_token_digest_key UNIQUE (token_digest),
    CONSTRAINT registration_invitations_issuer_kind_known CHECK (
        issuer_kind IN ('system', 'user', 'service_account')
    ),
    CONSTRAINT registration_invitations_issued_by_user_id_fkey
        FOREIGN KEY (issued_by_user_id) REFERENCES users (id) ON DELETE RESTRICT,
    CONSTRAINT registration_invitations_issued_by_service_account_id_fkey
        FOREIGN KEY (issued_by_service_account_id)
        REFERENCES service_accounts (id) ON DELETE RESTRICT,
    CONSTRAINT registration_invitations_issuer_actor_valid CHECK (
        (issuer_kind = 'system'
            AND issued_by_user_id IS NULL
            AND issued_by_service_account_id IS NULL)
        OR (issuer_kind = 'user'
            AND issued_by_user_id IS NOT NULL
            AND issued_by_service_account_id IS NULL)
        OR (issuer_kind = 'service_account'
            AND issued_by_user_id IS NULL
            AND issued_by_service_account_id IS NOT NULL)
    ),
    CONSTRAINT registration_invitations_expiry_valid CHECK (
        expires_at >= created_at + interval '1 hour'
        AND expires_at <= created_at + interval '30 days'
    ),
    CONSTRAINT registration_invitations_terminal_state_valid CHECK (
        NOT (consumed_at IS NOT NULL AND revoked_at IS NOT NULL)
        AND (
            consumed_at IS NULL
            OR (consumed_at >= created_at AND consumed_at <= expires_at)
        )
        AND (revoked_at IS NULL OR revoked_at >= created_at)
    )
);

CREATE UNIQUE INDEX registration_invitations_active_identity_idx
    ON registration_invitations (identity_provider, identity_subject)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX registration_invitations_expiry_idx
    ON registration_invitations (expires_at, id)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;
