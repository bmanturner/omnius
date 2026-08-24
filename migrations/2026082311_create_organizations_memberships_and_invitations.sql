CREATE TABLE organizations (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    status text NOT NULL,
    version bigint NOT NULL,
    owner_guard_version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    CONSTRAINT organizations_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT organizations_name_trimmed CHECK (
        name !~ '^[[:space:]]' AND name !~ '[[:space:]]$'
    ),
    CONSTRAINT organizations_name_nonblank CHECK (name ~ '[^[:space:]]'),
    CONSTRAINT organizations_name_length CHECK (octet_length(name) <= 255),
    CONSTRAINT organizations_status_check CHECK (
        status IN ('active', 'suspended', 'deleted')
    ),
    CONSTRAINT organizations_version_positive CHECK (version >= 1),
    CONSTRAINT organizations_owner_guard_version_nonnegative CHECK (
        owner_guard_version >= 0
    ),
    CONSTRAINT organizations_updated_order CHECK (updated_at >= created_at),
    CONSTRAINT organizations_deleted_state CHECK (
        (status = 'deleted') = (deleted_at IS NOT NULL)
        AND (
            deleted_at IS NULL
            OR (deleted_at >= created_at AND deleted_at <= updated_at)
        )
    )
);

CREATE TABLE memberships (
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role text NOT NULL,
    status text NOT NULL,
    grant_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT memberships_pkey PRIMARY KEY (organization_id, user_id),
    CONSTRAINT memberships_organization_id_fkey
        FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE RESTRICT,
    CONSTRAINT memberships_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT,
    CONSTRAINT memberships_role_check CHECK (role IN ('owner', 'admin', 'member')),
    CONSTRAINT memberships_status_check CHECK (
        status IN ('active', 'suspended', 'removed')
    ),
    CONSTRAINT memberships_grant_version_positive CHECK (grant_version >= 1),
    CONSTRAINT memberships_updated_order CHECK (updated_at >= created_at)
);

CREATE TABLE invitations (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    invited_user_id uuid NOT NULL,
    invited_by_user_id uuid NOT NULL,
    role text NOT NULL,
    status text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    accepted_at timestamptz,
    revoked_at timestamptz,
    CONSTRAINT invitations_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT invitations_organization_id_fkey
        FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE RESTRICT,
    CONSTRAINT invitations_invited_user_id_fkey
        FOREIGN KEY (invited_user_id) REFERENCES users (id) ON DELETE RESTRICT,
    CONSTRAINT invitations_invited_by_user_id_fkey
        FOREIGN KEY (invited_by_user_id) REFERENCES users (id) ON DELETE RESTRICT,
    CONSTRAINT invitations_role_check CHECK (role IN ('admin', 'member')),
    CONSTRAINT invitations_status_check CHECK (
        status IN ('pending', 'accepted', 'revoked', 'expired')
    ),
    CONSTRAINT invitations_expiry_order CHECK (expires_at > created_at),
    CONSTRAINT invitations_updated_order CHECK (updated_at >= created_at),
    CONSTRAINT invitations_terminal_state CHECK (
        CASE status
            WHEN 'accepted' THEN
                accepted_at IS NOT NULL
                AND revoked_at IS NULL
                AND accepted_at >= created_at
                AND accepted_at <= updated_at
                AND accepted_at <= expires_at
            WHEN 'revoked' THEN
                accepted_at IS NULL
                AND revoked_at IS NOT NULL
                AND revoked_at >= created_at
                AND revoked_at <= updated_at
            ELSE accepted_at IS NULL AND revoked_at IS NULL
        END
    )
);

CREATE INDEX memberships_organization_status_idx
    ON memberships (organization_id, status, role, user_id);

CREATE INDEX memberships_user_status_idx
    ON memberships (user_id, status, organization_id);

CREATE INDEX invitations_organization_status_idx
    ON invitations (organization_id, status, created_at DESC, id DESC);

CREATE INDEX invitations_invited_user_status_idx
    ON invitations (invited_user_id, status, created_at DESC, id DESC);

CREATE UNIQUE INDEX invitations_pending_organization_invited_user_key
    ON invitations (organization_id, invited_user_id)
    WHERE status = 'pending';

INSERT INTO organizations (id, name, status, version, created_at, updated_at, deleted_at)
SELECT
    tenant_id,
    'Legacy tenant ' || tenant_id::text,
    'suspended',
    1,
    min(created_at),
    min(created_at),
    NULL
FROM service_accounts
WHERE tenant_id IS NOT NULL
GROUP BY tenant_id;


ALTER TABLE service_accounts
    ADD CONSTRAINT service_accounts_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES organizations (id) ON DELETE RESTRICT;

CREATE FUNCTION enforce_organization_active_owner()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate_organization_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'organizations' THEN
        IF TG_OP = 'DELETE' THEN
            candidate_organization_id := OLD.id;
        ELSE
            candidate_organization_id := NEW.id;
        END IF;
    ELSIF TG_OP = 'DELETE' THEN
        candidate_organization_id := OLD.organization_id;
    ELSIF TG_OP = 'INSERT' THEN
        candidate_organization_id := NEW.organization_id;
    ELSE
        candidate_organization_id := OLD.organization_id;

        IF NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
            IF TG_TABLE_NAME = 'memberships' THEN
                UPDATE organizations
                SET owner_guard_version = owner_guard_version + 1
                WHERE id = candidate_organization_id
                    AND status = 'active';
            END IF;

            PERFORM id
            FROM organizations
            WHERE id = candidate_organization_id
                AND status = 'active'
            FOR UPDATE;

            IF FOUND AND NOT EXISTS (
                SELECT 1
                FROM memberships
                WHERE organization_id = candidate_organization_id
                    AND role = 'owner'
                    AND status = 'active'
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    CONSTRAINT = 'organizations_active_owner_required',
                    TABLE = 'organizations',
                    MESSAGE = 'active organization must have an active owner';
            END IF;

            candidate_organization_id := NEW.organization_id;
        END IF;
    END IF;

    IF TG_TABLE_NAME = 'memberships' THEN
        UPDATE organizations
        SET owner_guard_version = owner_guard_version + 1
        WHERE id = candidate_organization_id
            AND status = 'active';
    END IF;

    PERFORM id
    FROM organizations
    WHERE id = candidate_organization_id
        AND status = 'active'
    FOR UPDATE;

    IF FOUND AND NOT EXISTS (
        SELECT 1
        FROM memberships
        WHERE organization_id = candidate_organization_id
            AND role = 'owner'
            AND status = 'active'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'organizations_active_owner_required',
            TABLE = 'organizations',
            MESSAGE = 'active organization must have an active owner';
    END IF;

    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER organizations_active_owner_check
AFTER INSERT OR UPDATE OR DELETE ON organizations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION enforce_organization_active_owner();

CREATE CONSTRAINT TRIGGER memberships_active_owner_check
AFTER INSERT OR UPDATE OR DELETE ON memberships
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION enforce_organization_active_owner();
