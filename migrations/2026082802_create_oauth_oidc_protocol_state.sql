CREATE FUNCTION oauth_text_array_is_canonical(
    candidate text[],
    maximum_count integer,
    maximum_octets integer
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT cardinality(candidate) <= maximum_count
        AND NOT EXISTS (
            SELECT 1
            FROM unnest(candidate) AS value(item)
            WHERE item IS NULL
                OR octet_length(item) NOT BETWEEN 1 AND maximum_octets
                OR item COLLATE "C" !~ '^[!-~]+$'
                OR strpos(item, '"') <> 0
                OR strpos(item, E'\\') <> 0
        )
        AND candidate = ARRAY(
            SELECT item
            FROM unnest(candidate) AS value(item)
            ORDER BY item COLLATE "C"
        )
        AND cardinality(candidate) = (
            SELECT count(DISTINCT item COLLATE "C")::integer
            FROM unnest(candidate) AS value(item)
        );
$$;

CREATE FUNCTION oauth_display_text_array_is_bounded(
    candidate text[],
    maximum_count integer,
    maximum_octets integer
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT cardinality(candidate) BETWEEN 1 AND maximum_count
        AND NOT EXISTS (
            SELECT 1
            FROM unnest(candidate) AS value(item)
            WHERE item IS NULL
                OR octet_length(item) NOT BETWEEN 1 AND maximum_octets
                OR item ~ '[[:cntrl:]]'
                OR item ~ '^[[:space:]]'
                OR item ~ '[[:space:]]$'
        );
$$;

CREATE FUNCTION oauth_resource_uris_are_canonical(candidate text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT oauth_text_array_is_canonical(candidate, 16, 2048)
        AND NOT EXISTS (
            SELECT 1
            FROM unnest(candidate) AS value(uri)
            WHERE (
                uri COLLATE "C" !~ '^https://[!-~]+$'
                AND uri COLLATE "C" !~ '^http://(127\.0\.0\.1|\[::1\]|localhost)(:[0-9]{1,5})?([/?][!-~]*)?$'
            )
            OR strpos(uri, '#') <> 0
        );
$$;

CREATE TABLE oauth_clients (
    id uuid PRIMARY KEY,
    client_id text NOT NULL,
    source text NOT NULL,
    status text NOT NULL,
    display_name text NOT NULL,
    client_uri text,
    logo_uri text,
    application_type text NOT NULL,
    token_endpoint_auth_method text NOT NULL,
    client_secret_digest bytea,
    response_types text[] NOT NULL,
    grant_types text[] NOT NULL,
    allowed_scopes text[] NOT NULL,
    public_jwks jsonb,
    metadata_document_uri text,
    metadata_cache_body jsonb,
    metadata_cache_etag text,
    metadata_cache_last_modified text,
    metadata_cached_at timestamptz,
    metadata_cache_expires_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    disabled_at timestamptz,
    CONSTRAINT oauth_clients_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT oauth_clients_client_id_key UNIQUE (client_id),
    CONSTRAINT oauth_clients_client_id_canonical CHECK (
        octet_length(client_id) BETWEEN 1 AND 2048
        AND client_id COLLATE "C" ~ '^[!-~]+$'
        AND strpos(client_id, '"') = 0
        AND strpos(client_id, E'\\') = 0
    ),
    CONSTRAINT oauth_clients_source_known CHECK (
        source IN ('pre_registered', 'client_id_metadata', 'dynamic')
    ),
    CONSTRAINT oauth_clients_status_known CHECK (status IN ('active', 'disabled')),
    CONSTRAINT oauth_clients_display_name_canonical CHECK (
        octet_length(display_name) BETWEEN 1 AND 255
        AND display_name !~ '^[[:space:]]'
        AND display_name !~ '[[:space:]]$'
        AND display_name ~ '[^[:space:]]'
    ),
    CONSTRAINT oauth_clients_client_uri_canonical CHECK (
        client_uri IS NULL
        OR (
            octet_length(client_uri) BETWEEN 8 AND 2048
            AND client_uri COLLATE "C" ~ '^https://[!-~]+$'
            AND strpos(client_uri, '"') = 0
            AND strpos(client_uri, E'\\') = 0
        )
    ),
    CONSTRAINT oauth_clients_logo_uri_canonical CHECK (
        logo_uri IS NULL
        OR (
            octet_length(logo_uri) BETWEEN 8 AND 2048
            AND logo_uri COLLATE "C" ~ '^https://[!-~]+$'
            AND strpos(logo_uri, '"') = 0
            AND strpos(logo_uri, E'\\') = 0
        )
    ),
    CONSTRAINT oauth_clients_application_type_known CHECK (
        application_type IN ('web', 'native')
    ),
    CONSTRAINT oauth_clients_token_auth_method_known CHECK (
        token_endpoint_auth_method IN ('none', 'client_secret_basic', 'private_key_jwt')
    ),
    CONSTRAINT oauth_clients_secret_digest_length CHECK (
        client_secret_digest IS NULL OR octet_length(client_secret_digest) = 32
    ),
    CONSTRAINT oauth_clients_secret_digest_key UNIQUE (client_secret_digest),
    CONSTRAINT oauth_clients_response_types_valid CHECK (
        oauth_text_array_is_canonical(response_types, 1, 32)
        AND response_types = ARRAY['code']::text[]
    ),
    CONSTRAINT oauth_clients_grant_types_valid CHECK (
        oauth_text_array_is_canonical(grant_types, 2, 64)
        AND cardinality(grant_types) BETWEEN 1 AND 2
        AND grant_types <@ ARRAY['authorization_code', 'refresh_token']::text[]
        AND grant_types @> ARRAY['authorization_code']::text[]
    ),
    CONSTRAINT oauth_clients_allowed_scopes_valid CHECK (
        array_position(allowed_scopes, NULL) IS NULL
        AND api_key_scopes_are_canonical(allowed_scopes)
        AND cardinality(allowed_scopes) <= 128
    ),
    CONSTRAINT oauth_clients_public_jwks_bounded CHECK (
        public_jwks IS NULL
        OR (
            jsonb_typeof(public_jwks) = 'object'
            AND octet_length(public_jwks::text) BETWEEN 2 AND 262144
        )
    ),
    CONSTRAINT oauth_clients_auth_material_valid CHECK (
        (token_endpoint_auth_method = 'none'
            AND client_secret_digest IS NULL)
        OR (token_endpoint_auth_method = 'client_secret_basic'
            AND client_secret_digest IS NOT NULL)
        OR (token_endpoint_auth_method = 'private_key_jwt'
            AND client_secret_digest IS NULL
            AND public_jwks IS NOT NULL)
    ),
    CONSTRAINT oauth_clients_metadata_document_uri_valid CHECK (
        (source = 'client_id_metadata'
            AND metadata_document_uri IS NOT NULL
            AND metadata_document_uri = client_id
            AND metadata_document_uri COLLATE "C" ~ '^https://[!-~]+$')
        OR (source <> 'client_id_metadata' AND metadata_document_uri IS NULL)
    ),
    CONSTRAINT oauth_clients_metadata_cache_body_bounded CHECK (
        metadata_cache_body IS NULL
        OR (
            jsonb_typeof(metadata_cache_body) = 'object'
            AND octet_length(metadata_cache_body::text) BETWEEN 2 AND 262144
        )
    ),
    CONSTRAINT oauth_clients_metadata_etag_bounded CHECK (
        metadata_cache_etag IS NULL
        OR octet_length(metadata_cache_etag) BETWEEN 1 AND 1024
    ),
    CONSTRAINT oauth_clients_metadata_modified_bounded CHECK (
        metadata_cache_last_modified IS NULL
        OR octet_length(metadata_cache_last_modified) BETWEEN 1 AND 128
    ),
    CONSTRAINT oauth_clients_metadata_cache_valid CHECK (
        (metadata_cache_body IS NULL
            AND metadata_cache_etag IS NULL
            AND metadata_cache_last_modified IS NULL
            AND metadata_cached_at IS NULL
            AND metadata_cache_expires_at IS NULL)
        OR (source = 'client_id_metadata'
            AND metadata_cache_body IS NOT NULL
            AND metadata_cached_at IS NOT NULL
            AND metadata_cache_expires_at > metadata_cached_at)
    ),
    CONSTRAINT oauth_clients_timeline_valid CHECK (
        updated_at >= created_at
        AND (metadata_cached_at IS NULL OR metadata_cached_at >= created_at)
        AND (disabled_at IS NULL OR disabled_at BETWEEN created_at AND updated_at)
    ),
    CONSTRAINT oauth_clients_disabled_state_valid CHECK (
        (status = 'active' AND disabled_at IS NULL)
        OR (status = 'disabled' AND disabled_at IS NOT NULL)
    )
);

CREATE TABLE oauth_client_redirect_uris (
    id uuid PRIMARY KEY,
    client_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT oauth_client_redirect_uris_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT oauth_client_redirect_uris_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE RESTRICT,
    CONSTRAINT oauth_client_redirect_uris_uri_canonical CHECK (
        octet_length(redirect_uri) BETWEEN 8 AND 2048
        AND redirect_uri COLLATE "C" ~ '^(https://[!-~]+|http://(127\.0\.0\.1|\[::1\]|localhost)(:[0-9]{1,5})?([/?][!-~]*)?)$'
        AND strpos(redirect_uri, '#') = 0
        AND strpos(redirect_uri, '"') = 0
        AND strpos(redirect_uri, E'\\') = 0
    ),
    CONSTRAINT oauth_client_redirect_uris_client_uri_key UNIQUE (client_id, redirect_uri)
);

CREATE TABLE oauth_client_post_logout_redirect_uris (
    id uuid PRIMARY KEY,
    client_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT oauth_client_post_logout_uris_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT oauth_client_post_logout_uris_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE RESTRICT,
    CONSTRAINT oauth_client_post_logout_uris_uri_canonical CHECK (
        octet_length(redirect_uri) BETWEEN 8 AND 2048
        AND redirect_uri COLLATE "C" ~ '^(https://[!-~]+|http://(127\.0\.0\.1|\[::1\]|localhost)(:[0-9]{1,5})?([/?][!-~]*)?)$'
        AND strpos(redirect_uri, '#') = 0
        AND strpos(redirect_uri, '"') = 0
        AND strpos(redirect_uri, E'\\') = 0
    ),
    CONSTRAINT oauth_client_post_logout_uris_client_uri_key UNIQUE (client_id, redirect_uri)
);

CREATE TABLE oauth_client_assertions (
    id uuid PRIMARY KEY,
    client_id uuid NOT NULL,
    jti text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT oauth_client_assertions_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT oauth_client_assertions_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE RESTRICT,
    CONSTRAINT oauth_client_assertions_jti_canonical CHECK (
        octet_length(jti) BETWEEN 1 AND 255
        AND jti COLLATE "C" ~ '^[!-~]+$'
    ),
    CONSTRAINT oauth_client_assertions_client_jti_key UNIQUE (client_id, jti),
    CONSTRAINT oauth_client_assertions_expiry_valid CHECK (
        expires_at > issued_at AND expires_at <= issued_at + interval '10 minutes'
    )
);

CREATE TABLE oauth_subjects (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    public_subject text NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT oauth_subjects_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT oauth_subjects_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT,
    CONSTRAINT oauth_subjects_user_id_key UNIQUE (user_id),
    CONSTRAINT oauth_subjects_public_subject_key UNIQUE (public_subject),
    CONSTRAINT oauth_subjects_public_subject_canonical CHECK (
        octet_length(public_subject) = 43
        AND public_subject COLLATE "C" ~ '^[A-Za-z0-9_-]{43}$'
    )
);

CREATE TABLE oauth_grants (
    id uuid PRIMARY KEY,
    subject_id uuid NOT NULL,
    tenant_id uuid,
    client_id uuid NOT NULL,
    resources text[] NOT NULL,
    granted_scopes text[] NOT NULL,
    authenticated_at timestamptz NOT NULL,
    assurance_level text NOT NULL,
    authentication_methods text[] NOT NULL,
    consented_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    revoked_at timestamptz,
    version bigint NOT NULL,
    CONSTRAINT oauth_grants_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT oauth_grants_subject_id_fkey
        FOREIGN KEY (subject_id) REFERENCES oauth_subjects (id) ON DELETE RESTRICT,
    CONSTRAINT oauth_grants_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES organizations (id) ON DELETE RESTRICT,
    CONSTRAINT oauth_grants_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE RESTRICT,
    CONSTRAINT oauth_grants_resources_canonical CHECK (
        oauth_resource_uris_are_canonical(resources)
        AND cardinality(resources) <= 16
    ),
    CONSTRAINT oauth_grants_scopes_canonical CHECK (
        array_position(granted_scopes, NULL) IS NULL
        AND api_key_scopes_are_canonical(granted_scopes)
        AND cardinality(granted_scopes) BETWEEN 1 AND 128
    ),
    CONSTRAINT oauth_grants_assurance_level_known CHECK (
        assurance_level IN ('aal1', 'aal2', 'aal3')
    ),
    CONSTRAINT oauth_grants_auth_methods_canonical CHECK (
        oauth_text_array_is_canonical(authentication_methods, 16, 64)
        AND cardinality(authentication_methods) BETWEEN 1 AND 16
    ),
    CONSTRAINT oauth_grants_version_positive CHECK (version >= 1),
    CONSTRAINT oauth_grants_timeline_valid CHECK (
        authenticated_at <= consented_at
        AND consented_at <= created_at
        AND updated_at >= created_at
        AND (revoked_at IS NULL OR revoked_at BETWEEN created_at AND updated_at)
    ),
    CONSTRAINT oauth_grants_id_client_id_key UNIQUE (id, client_id)
);

CREATE TABLE oauth_authorization_requests (
    id uuid PRIMARY KEY,
    request_handle_digest bytea NOT NULL,
    client_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    response_type text NOT NULL,
    response_mode text NOT NULL,
    client_state text,
    requested_scopes text[] NOT NULL,
    resource_uris text[] NOT NULL,
    pkce_code_challenge text NOT NULL,
    nonce text,
    prompt_values text[] NOT NULL,
    max_age_seconds bigint,
    expected_issuer text NOT NULL,
    interaction_resource_name text NOT NULL,
    interaction_resource_description text NOT NULL,
    interaction_minimum_assurance text NOT NULL,
    interaction_scope_descriptions text[] NOT NULL,
    interaction_scope_newly_requested boolean[] NOT NULL,
    interaction_requirement text NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    completed_at timestamptz,
    CONSTRAINT oauth_authorization_requests_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT oauth_authorization_requests_digest_length CHECK (
        octet_length(request_handle_digest) = 32
    ),
    CONSTRAINT oauth_authorization_requests_digest_key UNIQUE (request_handle_digest),
    CONSTRAINT oauth_authorization_requests_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_requests_registered_redirect_fkey
        FOREIGN KEY (client_id, redirect_uri)
        REFERENCES oauth_client_redirect_uris (client_id, redirect_uri)
        ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_requests_redirect_uri_valid CHECK (
        octet_length(redirect_uri) BETWEEN 8 AND 2048
        AND redirect_uri COLLATE "C" ~ '^(https://[!-~]+|http://(127\.0\.0\.1|\[::1\]|localhost)(:[0-9]{1,5})?([/?][!-~]*)?)$'
        AND strpos(redirect_uri, '#') = 0
    ),
    CONSTRAINT oauth_authorization_requests_response_type_known CHECK (
        response_type = 'code'
    ),
    CONSTRAINT oauth_authorization_requests_response_mode_known CHECK (
        response_mode = 'query'
    ),
    CONSTRAINT oauth_authorization_requests_state_bounded CHECK (
        client_state IS NULL OR octet_length(client_state) BETWEEN 1 AND 2048
    ),
    CONSTRAINT oauth_authorization_requests_scopes_canonical CHECK (
        array_position(requested_scopes, NULL) IS NULL
        AND api_key_scopes_are_canonical(requested_scopes)
        AND cardinality(requested_scopes) BETWEEN 1 AND 128
    ),
    CONSTRAINT oauth_authorization_requests_resources_canonical CHECK (
        oauth_resource_uris_are_canonical(resource_uris)
    ),
    CONSTRAINT oauth_authorization_requests_pkce_s256 CHECK (
        octet_length(pkce_code_challenge) = 43
        AND pkce_code_challenge COLLATE "C" ~ '^[A-Za-z0-9_-]{43}$'
    ),
    CONSTRAINT oauth_authorization_requests_nonce_bounded CHECK (
        nonce IS NULL
        OR (octet_length(nonce) BETWEEN 1 AND 255 AND nonce COLLATE "C" ~ '^[!-~]+$')
    ),
    CONSTRAINT oauth_authorization_requests_prompts_valid CHECK (
        oauth_text_array_is_canonical(prompt_values, 3, 16)
        AND prompt_values <@ ARRAY['consent', 'login', 'none']::text[]
        AND (prompt_values <> ARRAY['none']::text[] OR cardinality(prompt_values) = 1)
        AND (NOT (prompt_values @> ARRAY['none']::text[]) OR cardinality(prompt_values) = 1)
    ),
    CONSTRAINT oauth_authorization_requests_max_age_valid CHECK (
        max_age_seconds IS NULL OR max_age_seconds BETWEEN 0 AND 31536000
    ),
    CONSTRAINT oauth_authorization_requests_issuer_canonical CHECK (
        octet_length(expected_issuer) BETWEEN 8 AND 2048
        AND (
            expected_issuer COLLATE "C" ~ '^https://[!-~]+$'
            OR expected_issuer COLLATE "C" ~ '^http://(127\.0\.0\.1|\[::1\]|localhost)(:[0-9]{1,5})?$'
        )
        AND strpos(expected_issuer, '?') = 0
        AND strpos(expected_issuer, '#') = 0
        AND strpos(expected_issuer, '"') = 0
        AND strpos(expected_issuer, E'\\') = 0
    ),
    CONSTRAINT oauth_authorization_requests_interaction_resource_name_valid CHECK (
        octet_length(interaction_resource_name) BETWEEN 1 AND 128
        AND interaction_resource_name !~ '[[:cntrl:]]'
        AND interaction_resource_name !~ '^[[:space:]]'
        AND interaction_resource_name !~ '[[:space:]]$'
    ),
    CONSTRAINT oauth_auth_requests_interaction_resource_desc_valid CHECK (
        octet_length(interaction_resource_description) BETWEEN 1 AND 1024
        AND interaction_resource_description !~ '[[:cntrl:]]'
        AND interaction_resource_description !~ '^[[:space:]]'
        AND interaction_resource_description !~ '[[:space:]]$'
    ),
    CONSTRAINT oauth_authorization_requests_interaction_assurance_known CHECK (
        interaction_minimum_assurance IN ('aal1', 'aal2', 'aal3')
    ),
    CONSTRAINT oauth_authorization_requests_interaction_scopes_valid CHECK (
        oauth_display_text_array_is_bounded(interaction_scope_descriptions, 128, 512)
        AND cardinality(interaction_scope_descriptions) = cardinality(requested_scopes)
        AND array_position(interaction_scope_newly_requested, NULL) IS NULL
        AND cardinality(interaction_scope_newly_requested) = cardinality(requested_scopes)
    ),
    CONSTRAINT oauth_authorization_requests_interaction_requirement_known CHECK (
        interaction_requirement IN ('login', 'consent', 'ready')
    ),
    CONSTRAINT oauth_authorization_requests_status_known CHECK (
        status IN ('pending', 'approved', 'denied', 'expired')
    ),
    CONSTRAINT oauth_authorization_requests_expiry_valid CHECK (
        expires_at > created_at
        AND expires_at <= created_at + interval '15 minutes'
    ),
    CONSTRAINT oauth_authorization_requests_terminal_state_valid CHECK (
        (status = 'pending' AND completed_at IS NULL)
        OR (status IN ('approved', 'denied')
            AND completed_at IS NOT NULL
            AND completed_at BETWEEN created_at AND expires_at)
        OR (status = 'expired'
            AND completed_at IS NOT NULL
            AND completed_at >= expires_at)
    )
);

CREATE TABLE oauth_authorization_codes (
    id uuid PRIMARY KEY,
    code_digest bytea NOT NULL,
    grant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    resource_uris text[] NOT NULL,
    granted_scopes text[] NOT NULL,
    pkce_code_challenge text NOT NULL,
    nonce text,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    exchange_outcome text,
    CONSTRAINT oauth_authorization_codes_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT oauth_authorization_codes_digest_length CHECK (
        octet_length(code_digest) = 32
    ),
    CONSTRAINT oauth_authorization_codes_digest_key UNIQUE (code_digest),
    CONSTRAINT oauth_authorization_codes_grant_client_fkey
        FOREIGN KEY (grant_id, client_id)
        REFERENCES oauth_grants (id, client_id) ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_codes_registered_redirect_fkey
        FOREIGN KEY (client_id, redirect_uri)
        REFERENCES oauth_client_redirect_uris (client_id, redirect_uri)
        ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_codes_redirect_uri_valid CHECK (
        octet_length(redirect_uri) BETWEEN 8 AND 2048
        AND redirect_uri COLLATE "C" ~ '^(https://[!-~]+|http://(127\.0\.0\.1|\[::1\]|localhost)(:[0-9]{1,5})?([/?][!-~]*)?)$'
        AND strpos(redirect_uri, '#') = 0
    ),
    CONSTRAINT oauth_authorization_codes_resources_canonical CHECK (
        oauth_resource_uris_are_canonical(resource_uris)
    ),
    CONSTRAINT oauth_authorization_codes_scopes_canonical CHECK (
        array_position(granted_scopes, NULL) IS NULL
        AND api_key_scopes_are_canonical(granted_scopes)
        AND cardinality(granted_scopes) BETWEEN 1 AND 128
    ),
    CONSTRAINT oauth_authorization_codes_pkce_s256 CHECK (
        octet_length(pkce_code_challenge) = 43
        AND pkce_code_challenge COLLATE "C" ~ '^[A-Za-z0-9_-]{43}$'
    ),
    CONSTRAINT oauth_authorization_codes_nonce_bounded CHECK (
        nonce IS NULL
        OR (octet_length(nonce) BETWEEN 1 AND 255 AND nonce COLLATE "C" ~ '^[!-~]+$')
    ),
    CONSTRAINT oauth_authorization_codes_expiry_valid CHECK (
        expires_at > issued_at
        AND expires_at <= issued_at + interval '10 minutes'
    ),
    CONSTRAINT oauth_authorization_codes_outcome_known CHECK (
        exchange_outcome IS NULL OR exchange_outcome IN ('issued', 'rejected')
    ),
    CONSTRAINT oauth_authorization_codes_one_use_state CHECK (
        (consumed_at IS NULL AND exchange_outcome IS NULL)
        OR (consumed_at IS NOT NULL
            AND consumed_at >= issued_at
            AND exchange_outcome IS NOT NULL)
    )
);

CREATE TABLE oauth_refresh_token_families (
    id uuid PRIMARY KEY,
    grant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    resource_uri text NOT NULL,
    granted_scopes text[] NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revocation_reason text,
    reuse_detected_at timestamptz,
    version bigint NOT NULL,
    CONSTRAINT oauth_refresh_token_families_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT oauth_refresh_token_families_grant_client_fkey
        FOREIGN KEY (grant_id, client_id)
        REFERENCES oauth_grants (id, client_id) ON DELETE RESTRICT,
    CONSTRAINT oauth_refresh_token_families_resource_uri_valid CHECK (
        octet_length(resource_uri) BETWEEN 8 AND 2048
        AND (
            resource_uri COLLATE "C" ~ '^https://[!-~]+$'
            OR resource_uri COLLATE "C" ~ '^http://(127\.0\.0\.1|\[::1\]|localhost)(:[0-9]{1,5})?([/?][!-~]*)?$'
        )
        AND strpos(resource_uri, '#') = 0
    ),
    CONSTRAINT oauth_refresh_token_families_scopes_canonical CHECK (
        array_position(granted_scopes, NULL) IS NULL
        AND api_key_scopes_are_canonical(granted_scopes)
        AND cardinality(granted_scopes) BETWEEN 1 AND 128
    ),
    CONSTRAINT oauth_refresh_token_families_version_positive CHECK (version >= 1),
    CONSTRAINT oauth_refresh_token_families_expiry_valid CHECK (
        expires_at > created_at
        AND expires_at <= created_at + interval '90 days'
    ),
    CONSTRAINT oauth_refresh_token_families_reason_known CHECK (
        revocation_reason IS NULL
        OR revocation_reason IN (
            'client_disabled', 'grant_revoked', 'logout', 'manual',
            'refresh_reuse', 'token_revoked', 'user_disabled'
        )
    ),
    CONSTRAINT oauth_refresh_token_families_revocation_state CHECK (
        (revoked_at IS NULL AND revocation_reason IS NULL AND reuse_detected_at IS NULL)
        OR (revoked_at IS NOT NULL
            AND revoked_at >= created_at
            AND revocation_reason IS NOT NULL
            AND (
                (revocation_reason = 'refresh_reuse'
                    AND reuse_detected_at IS NOT NULL
                    AND reuse_detected_at >= revoked_at)
                OR (revocation_reason <> 'refresh_reuse' AND reuse_detected_at IS NULL)
            ))
    ),
    CONSTRAINT oauth_refresh_token_families_id_grant_key UNIQUE (id, grant_id)
);

CREATE TABLE oauth_refresh_tokens (
    id uuid PRIMARY KEY,
    family_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    token_digest bytea NOT NULL,
    rotation_sequence bigint NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    replaced_by_id uuid,
    revoked_at timestamptz,
    reuse_detected_at timestamptz,
    CONSTRAINT oauth_refresh_tokens_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT oauth_refresh_tokens_family_grant_fkey
        FOREIGN KEY (family_id, grant_id)
        REFERENCES oauth_refresh_token_families (id, grant_id) ON DELETE RESTRICT,
    CONSTRAINT oauth_refresh_tokens_digest_length CHECK (octet_length(token_digest) = 32),
    CONSTRAINT oauth_refresh_tokens_digest_key UNIQUE (token_digest),
    CONSTRAINT oauth_refresh_tokens_sequence_nonnegative CHECK (rotation_sequence >= 0),
    CONSTRAINT oauth_refresh_tokens_family_sequence_key UNIQUE (family_id, rotation_sequence),
    CONSTRAINT oauth_refresh_tokens_id_family_key UNIQUE (id, family_id),
    CONSTRAINT oauth_refresh_tokens_not_self_replaced CHECK (
        replaced_by_id IS NULL OR replaced_by_id <> id
    ),
    CONSTRAINT oauth_refresh_tokens_replacement_fkey
        FOREIGN KEY (replaced_by_id, family_id)
        REFERENCES oauth_refresh_tokens (id, family_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY IMMEDIATE,
    CONSTRAINT oauth_refresh_tokens_expiry_valid CHECK (expires_at > issued_at),
    CONSTRAINT oauth_refresh_tokens_rotation_state CHECK (
        (consumed_at IS NULL AND replaced_by_id IS NULL)
        OR (consumed_at IS NOT NULL
            AND consumed_at >= issued_at
            AND replaced_by_id IS NOT NULL)
    ),
    CONSTRAINT oauth_refresh_tokens_revocation_state CHECK (
        revoked_at IS NULL
        OR (revoked_at >= issued_at AND consumed_at IS NULL AND replaced_by_id IS NULL)
    ),
    CONSTRAINT oauth_refresh_tokens_reuse_state CHECK (
        reuse_detected_at IS NULL
        OR (consumed_at IS NOT NULL AND reuse_detected_at >= consumed_at)
    )
);

CREATE TABLE oauth_access_token_revocations (
    jti uuid PRIMARY KEY,
    grant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NOT NULL,
    reason text NOT NULL,
    CONSTRAINT oauth_access_token_revocations_jti_uuid_v7 CHECK (
        (get_byte(uuid_send(jti), 6) >> 4) = 7
        AND (get_byte(uuid_send(jti), 8) & 192) = 128
    ),
    CONSTRAINT oauth_access_token_revocations_grant_client_fkey
        FOREIGN KEY (grant_id, client_id)
        REFERENCES oauth_grants (id, client_id) ON DELETE RESTRICT,
    CONSTRAINT oauth_access_token_revocations_reason_known CHECK (
        reason IN ('client_disabled', 'grant_revoked', 'logout', 'manual', 'token_revoked', 'user_disabled')
    ),
    CONSTRAINT oauth_access_token_revocations_timeline_valid CHECK (
        revoked_at >= issued_at
        AND expires_at > revoked_at
    )
);

CREATE INDEX oauth_clients_active_client_id_idx
    ON oauth_clients (client_id) WHERE status = 'active';
CREATE INDEX oauth_clients_metadata_expiry_idx
    ON oauth_clients (metadata_cache_expires_at, id)
    WHERE source = 'client_id_metadata' AND metadata_cache_expires_at IS NOT NULL;
CREATE INDEX oauth_client_redirect_uris_client_idx
    ON oauth_client_redirect_uris (client_id, id);
CREATE INDEX oauth_client_post_logout_uris_client_idx
    ON oauth_client_post_logout_redirect_uris (client_id, id);
CREATE INDEX oauth_client_assertions_expiry_idx
    ON oauth_client_assertions (expires_at, id);
CREATE INDEX oauth_subjects_user_idx ON oauth_subjects (user_id, id);
CREATE INDEX oauth_grants_active_subject_client_idx
    ON oauth_grants (subject_id, client_id, created_at DESC, id DESC)
    WHERE revoked_at IS NULL;
CREATE INDEX oauth_grants_active_tenant_idx
    ON oauth_grants (tenant_id, client_id, id)
    WHERE tenant_id IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX oauth_authorization_requests_active_expiry_idx
    ON oauth_authorization_requests (expires_at, id)
    WHERE status = 'pending';
CREATE INDEX oauth_authorization_codes_active_expiry_idx
    ON oauth_authorization_codes (expires_at, id)
    WHERE consumed_at IS NULL;
CREATE INDEX oauth_authorization_codes_grant_idx
    ON oauth_authorization_codes (grant_id, issued_at DESC, id DESC);
CREATE INDEX oauth_refresh_token_families_active_expiry_idx
    ON oauth_refresh_token_families (expires_at, id)
    WHERE revoked_at IS NULL;
CREATE INDEX oauth_refresh_token_families_grant_idx
    ON oauth_refresh_token_families (grant_id, created_at DESC, id DESC);
CREATE INDEX oauth_refresh_tokens_active_expiry_idx
    ON oauth_refresh_tokens (expires_at, id)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;
CREATE INDEX oauth_refresh_tokens_family_idx
    ON oauth_refresh_tokens (family_id, rotation_sequence DESC, id DESC);
CREATE INDEX oauth_refresh_tokens_tombstone_idx
    ON oauth_refresh_tokens (expires_at, id)
    WHERE consumed_at IS NOT NULL OR revoked_at IS NOT NULL;
CREATE INDEX oauth_access_token_revocations_expiry_idx
    ON oauth_access_token_revocations (expires_at, jti);
CREATE INDEX oauth_access_token_revocations_grant_idx
    ON oauth_access_token_revocations (grant_id, expires_at, jti);
