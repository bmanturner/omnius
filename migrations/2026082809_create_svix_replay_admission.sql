CREATE TABLE public.svix_replay_tenants (
    tenant_id text PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT svix_replay_tenants_tenant_id_valid
        CHECK (octet_length(tenant_id) BETWEEN 1 AND 256)
);

CREATE TABLE public.svix_replay_cooldowns (
    tenant_id text NOT NULL REFERENCES public.svix_replay_tenants (tenant_id) ON DELETE RESTRICT,
    application_id text NOT NULL,
    endpoint_id text NOT NULL,
    cooldown_until timestamptz,
    last_lease_id uuid,
    last_completion text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, application_id, endpoint_id),
    CONSTRAINT svix_replay_cooldowns_application_id_valid
        CHECK (octet_length(application_id) BETWEEN 1 AND 256),
    CONSTRAINT svix_replay_cooldowns_endpoint_id_valid
        CHECK (octet_length(endpoint_id) BETWEEN 1 AND 256),
    CONSTRAINT svix_replay_cooldowns_completion_valid
        CHECK (last_completion IS NULL OR last_completion IN ('finished', 'failed', 'missing')),
    CONSTRAINT svix_replay_cooldowns_terminal_fields_coherent
        CHECK (
            (cooldown_until IS NULL AND last_lease_id IS NULL AND last_completion IS NULL)
            OR
            (cooldown_until IS NOT NULL AND last_lease_id IS NOT NULL AND last_completion IS NOT NULL)
        )
);

CREATE TABLE public.svix_replay_leases (
    lease_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    application_id text NOT NULL,
    endpoint_id text NOT NULL,
    fingerprint text NOT NULL,
    replay_mode text NOT NULL,
    window_since timestamptz NOT NULL,
    window_until timestamptz NOT NULL,
    state text NOT NULL,
    terminal_completion text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    UNIQUE (lease_id, tenant_id, application_id),
    UNIQUE (tenant_id, application_id, endpoint_id, fingerprint),
    FOREIGN KEY (tenant_id, application_id, endpoint_id)
        REFERENCES public.svix_replay_cooldowns (tenant_id, application_id, endpoint_id)
        ON DELETE RESTRICT,
    CONSTRAINT svix_replay_leases_application_id_valid
        CHECK (octet_length(application_id) BETWEEN 1 AND 256),
    CONSTRAINT svix_replay_leases_endpoint_id_valid
        CHECK (octet_length(endpoint_id) BETWEEN 1 AND 256),
    CONSTRAINT svix_replay_leases_fingerprint_valid
        CHECK (octet_length(fingerprint) BETWEEN 1 AND 256),
    CONSTRAINT svix_replay_leases_mode_valid
        CHECK (replay_mode IN ('missing', 'all', 'failed')),
    CONSTRAINT svix_replay_leases_window_valid
        CHECK (
            window_since = date_trunc('minute', window_since)
            AND window_until = date_trunc('minute', window_until)
            AND window_until >= window_since
            AND window_until - window_since <= interval '90 days'
        ),
    CONSTRAINT svix_replay_leases_state_valid
        CHECK (state IN ('reserved', 'bound', 'completed')),
    CONSTRAINT svix_replay_leases_completion_valid
        CHECK (terminal_completion IS NULL OR terminal_completion IN ('finished', 'failed', 'missing')),
    CONSTRAINT svix_replay_leases_terminal_fields_coherent
        CHECK (
            (state = 'completed' AND terminal_completion IS NOT NULL AND completed_at IS NOT NULL)
            OR
            (state <> 'completed' AND terminal_completion IS NULL AND completed_at IS NULL)
        )
);

CREATE TABLE public.svix_replay_task_bindings (
    lease_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    application_id text NOT NULL,
    task_id text NOT NULL,
    bound_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, application_id, task_id),
    FOREIGN KEY (lease_id, tenant_id, application_id)
        REFERENCES public.svix_replay_leases (lease_id, tenant_id, application_id)
        ON DELETE CASCADE,
    CONSTRAINT svix_replay_task_bindings_application_id_valid
        CHECK (octet_length(application_id) BETWEEN 1 AND 256),
    CONSTRAINT svix_replay_task_bindings_task_id_valid
        CHECK (octet_length(task_id) BETWEEN 1 AND 256)
);

ALTER TABLE public.svix_replay_cooldowns
    ADD CONSTRAINT svix_replay_cooldowns_last_lease_fk
    FOREIGN KEY (last_lease_id)
    REFERENCES public.svix_replay_leases (lease_id)
    ON DELETE RESTRICT;

CREATE INDEX svix_replay_leases_active_tenant_idx
    ON public.svix_replay_leases (tenant_id, state)
    WHERE state IN ('reserved', 'bound');

CREATE INDEX svix_replay_leases_active_endpoint_window_idx
    ON public.svix_replay_leases
        (tenant_id, application_id, endpoint_id, window_since, window_until)
    WHERE state IN ('reserved', 'bound');

CREATE INDEX svix_replay_cooldowns_until_idx
    ON public.svix_replay_cooldowns (cooldown_until)
    WHERE cooldown_until IS NOT NULL;
