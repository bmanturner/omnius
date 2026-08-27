CREATE TABLE public.notification_preferences (
    id uuid PRIMARY KEY,
    recipient_id uuid NOT NULL,
    scope text NOT NULL,
    tenant_id uuid,
    category varchar(64) NOT NULL,
    channel varchar(16) NOT NULL,
    enabled boolean NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT notification_preferences_recipient_id_fkey
        FOREIGN KEY (recipient_id) REFERENCES public.users (id) ON DELETE RESTRICT,
    CONSTRAINT notification_preferences_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES public.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT notification_preferences_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT notification_preferences_recipient_id_uuid_v7 CHECK (
        (get_byte(uuid_send(recipient_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(recipient_id), 8) & 192) = 128
    ),
    CONSTRAINT notification_preferences_scope_known CHECK (scope IN ('global', 'tenant')),
    CONSTRAINT notification_preferences_scope_coherent CHECK (
        (scope = 'global' AND tenant_id IS NULL)
        OR (scope = 'tenant' AND tenant_id IS NOT NULL)
    ),
    CONSTRAINT notification_preferences_tenant_id_uuid_v7 CHECK (
        tenant_id IS NULL
        OR (
            (get_byte(uuid_send(tenant_id), 6) >> 4) = 7
            AND (get_byte(uuid_send(tenant_id), 8) & 192) = 128
        )
    ),
    CONSTRAINT notification_preferences_category_identifier CHECK (
        octet_length(category) BETWEEN 1 AND 64
        AND category ~ '^[a-z][a-z0-9._-]*$'
    ),
    CONSTRAINT notification_preferences_channel_known CHECK (channel = 'email'),
    CONSTRAINT notification_preferences_updated_order CHECK (updated_at >= created_at),
    CONSTRAINT notification_preferences_scope_key
        UNIQUE NULLS NOT DISTINCT (recipient_id, tenant_id, category, channel)
);

CREATE TABLE public.notification_digest_buckets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    recipient_id uuid NOT NULL,
    category varchar(64) NOT NULL,
    channel varchar(16) NOT NULL,
    digest_key varchar(128) NOT NULL,
    window_seconds integer NOT NULL,
    bucket_started_at timestamptz NOT NULL,
    bucket_ends_at timestamptz NOT NULL,
    presentation_fingerprint bytea NOT NULL,
    leader_delivery_id uuid,
    member_count integer NOT NULL DEFAULT 0,
    released_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT notification_digest_buckets_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES public.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT notification_digest_buckets_recipient_id_fkey
        FOREIGN KEY (recipient_id) REFERENCES public.users (id) ON DELETE RESTRICT,
    CONSTRAINT notification_digest_buckets_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT notification_digest_buckets_tenant_id_uuid_v7 CHECK (
        (get_byte(uuid_send(tenant_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(tenant_id), 8) & 192) = 128
    ),
    CONSTRAINT notification_digest_buckets_recipient_id_uuid_v7 CHECK (
        (get_byte(uuid_send(recipient_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(recipient_id), 8) & 192) = 128
    ),
    CONSTRAINT notification_digest_buckets_leader_id_uuid_v7 CHECK (
        leader_delivery_id IS NULL
        OR (
            (get_byte(uuid_send(leader_delivery_id), 6) >> 4) = 7
            AND (get_byte(uuid_send(leader_delivery_id), 8) & 192) = 128
        )
    ),
    CONSTRAINT notification_digest_buckets_category_identifier CHECK (
        octet_length(category) BETWEEN 1 AND 64
        AND category ~ '^[a-z][a-z0-9._-]*$'
    ),
    CONSTRAINT notification_digest_buckets_channel_known CHECK (channel = 'email'),
    CONSTRAINT notification_digest_buckets_key_identifier CHECK (
        octet_length(digest_key) BETWEEN 1 AND 128
        AND digest_key ~ '^[A-Za-z0-9._:-]+$'
    ),
    CONSTRAINT notification_digest_buckets_window_bounded CHECK (
        window_seconds BETWEEN 60 AND 604800
        AND bucket_ends_at = bucket_started_at + make_interval(secs => window_seconds)
    ),
    CONSTRAINT notification_digest_buckets_fingerprint_size CHECK (
        octet_length(presentation_fingerprint) = 32
    ),
    CONSTRAINT notification_digest_buckets_members_bounded CHECK (
        member_count BETWEEN 0 AND 256
        AND (member_count = 0) = (leader_delivery_id IS NULL)
    ),
    CONSTRAINT notification_digest_buckets_release_order CHECK (
        released_at IS NULL OR released_at >= bucket_ends_at
    ),
    CONSTRAINT notification_digest_buckets_id_tenant_key UNIQUE (id, tenant_id),
    CONSTRAINT notification_digest_buckets_scope_key UNIQUE (
        tenant_id,
        recipient_id,
        category,
        channel,
        digest_key,
        bucket_started_at
    )
);

CREATE TABLE public.deliveries (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    recipient_id uuid NOT NULL,
    event_name varchar(128) NOT NULL,
    channel varchar(16) NOT NULL,
    classification varchar(24) NOT NULL,
    preference_category varchar(64),
    locale varchar(35) NOT NULL,
    time_zone varchar(64) NOT NULL,
    template_name varchar(96) NOT NULL,
    template_version integer NOT NULL,
    recipient_email varchar(320) NOT NULL,
    recipient_display_name varchar(256),
    from_email varchar(320) NOT NULL,
    from_display_name varchar(256),
    subject varchar(998) NOT NULL,
    template_context jsonb NOT NULL,
    dedupe_key varchar(255) NOT NULL,
    dedupe_bucket_started_at timestamptz NOT NULL,
    digest_bucket_id uuid,
    effect_key varchar(255) NOT NULL,
    client_message_id varchar(64) NOT NULL,
    status varchar(32) NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    last_failure_code varchar(64),
    last_job_id uuid,
    send_lease_token uuid,
    send_lease_expires_at timestamptz,
    enqueued_at timestamptz,
    accepted_at timestamptz,
    delivered_at timestamptz,
    final_at timestamptz,
    provider_scope varchar(64),
    provider_message_id varchar(255),
    correlation_id uuid NOT NULL,
    causation_id uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT deliveries_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES public.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT deliveries_recipient_id_fkey
        FOREIGN KEY (recipient_id) REFERENCES public.users (id) ON DELETE RESTRICT,
    CONSTRAINT deliveries_digest_bucket_tenant_fkey
        FOREIGN KEY (digest_bucket_id, tenant_id)
        REFERENCES public.notification_digest_buckets (id, tenant_id) ON DELETE RESTRICT,
    CONSTRAINT deliveries_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT deliveries_tenant_id_uuid_v7 CHECK (
        (get_byte(uuid_send(tenant_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(tenant_id), 8) & 192) = 128
    ),
    CONSTRAINT deliveries_recipient_id_uuid_v7 CHECK (
        (get_byte(uuid_send(recipient_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(recipient_id), 8) & 192) = 128
    ),
    CONSTRAINT deliveries_event_identifier CHECK (
        octet_length(event_name) BETWEEN 1 AND 128
        AND event_name ~ '^[a-z][a-z0-9._-]*$'
    ),
    CONSTRAINT deliveries_channel_known CHECK (channel = 'email'),
    CONSTRAINT deliveries_classification_known CHECK (
        classification IN ('optional', 'mandatory', 'security', 'transactional')
    ),
    CONSTRAINT deliveries_preference_coherent CHECK (
        (classification = 'optional' AND preference_category IS NOT NULL)
        OR (classification <> 'optional' AND preference_category IS NULL)
    ),
    CONSTRAINT deliveries_preference_category_identifier CHECK (
        preference_category IS NULL
        OR (
            octet_length(preference_category) BETWEEN 1 AND 64
            AND preference_category ~ '^[a-z][a-z0-9._-]*$'
        )
    ),
    CONSTRAINT deliveries_locale_bounded CHECK (
        octet_length(locale) BETWEEN 2 AND 35
        AND locale ~ '^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$'
    ),
    CONSTRAINT deliveries_time_zone_bounded CHECK (
        octet_length(time_zone) BETWEEN 1 AND 64
        AND time_zone ~ '^[A-Za-z0-9_+.-]+(/[A-Za-z0-9_+.-]+)*$'
        AND time_zone !~ '(^|/)\.\.?(/|$)'
    ),
    CONSTRAINT deliveries_template_name_identifier CHECK (
        octet_length(template_name) BETWEEN 1 AND 96
        AND template_name ~ '^[A-Za-z0-9][A-Za-z0-9_-]*$'
    ),
    CONSTRAINT deliveries_template_version_positive CHECK (template_version BETWEEN 1 AND 2147483647),
    CONSTRAINT deliveries_recipient_email_bounded CHECK (
        octet_length(recipient_email) BETWEEN 3 AND 320
        AND recipient_email = btrim(recipient_email)
        AND recipient_email !~ '[[:space:][:cntrl:]]'
    ),
    CONSTRAINT deliveries_from_email_bounded CHECK (
        octet_length(from_email) BETWEEN 3 AND 320
        AND from_email = btrim(from_email)
        AND from_email !~ '[[:space:][:cntrl:]]'
    ),
    CONSTRAINT deliveries_display_names_bounded CHECK (
        (recipient_display_name IS NULL OR (
            octet_length(recipient_display_name) BETWEEN 1 AND 256
            AND recipient_display_name !~ '[[:cntrl:]]'
        ))
        AND (from_display_name IS NULL OR (
            octet_length(from_display_name) BETWEEN 1 AND 256
            AND from_display_name !~ '[[:cntrl:]]'
        ))
    ),
    CONSTRAINT deliveries_subject_bounded CHECK (
        octet_length(subject) BETWEEN 1 AND 998
        AND subject !~ '[[:cntrl:]]'
    ),
    CONSTRAINT deliveries_context_bounded CHECK (
        jsonb_typeof(template_context) = 'object'
        AND octet_length(template_context::text) <= 65536
    ),
    CONSTRAINT deliveries_dedupe_key_bounded CHECK (
        octet_length(dedupe_key) BETWEEN 1 AND 255
        AND dedupe_key = btrim(dedupe_key)
        AND dedupe_key !~ '[[:space:][:cntrl:]]'
    ),
    CONSTRAINT deliveries_digest_coherent CHECK (
        (digest_bucket_id IS NULL AND dedupe_bucket_started_at = '1970-01-01 00:00:00+00'::timestamptz)
        OR (digest_bucket_id IS NOT NULL AND classification = 'optional')
    ),
    CONSTRAINT deliveries_effect_key_bounded CHECK (
        octet_length(effect_key) BETWEEN 1 AND 255
        AND effect_key !~ '[[:space:][:cntrl:]]'
    ),
    CONSTRAINT deliveries_client_message_id_canonical CHECK (
        client_message_id ~ '^<[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@omnius\.invalid>$'
    ),
    CONSTRAINT deliveries_status_known CHECK (
        status IN (
            'digest_pending', 'pending_dispatch', 'queued', 'sending', 'retryable',
            'accepted', 'delivered', 'permanent_failed', 'suppressed', 'coalesced',
            'cancelled', 'bounced', 'complained'
        )
    ),
    CONSTRAINT deliveries_attempt_count_bounded CHECK (attempt_count BETWEEN 0 AND 2147483647),
    CONSTRAINT deliveries_failure_code_identifier CHECK (
        last_failure_code IS NULL
        OR (
            octet_length(last_failure_code) BETWEEN 1 AND 64
            AND last_failure_code ~ '^[a-z][a-z0-9._-]*$'
        )
    ),
    CONSTRAINT deliveries_last_job_id_uuid_v7 CHECK (
        last_job_id IS NULL
        OR (
            (get_byte(uuid_send(last_job_id), 6) >> 4) = 7
            AND (get_byte(uuid_send(last_job_id), 8) & 192) = 128
        )
    ),
    CONSTRAINT deliveries_send_lease_uuid_v7 CHECK (
        send_lease_token IS NULL
        OR (
            (get_byte(uuid_send(send_lease_token), 6) >> 4) = 7
            AND (get_byte(uuid_send(send_lease_token), 8) & 192) = 128
        )
    ),
    CONSTRAINT deliveries_send_lease_coherent CHECK (
        (status = 'sending') = (send_lease_token IS NOT NULL AND send_lease_expires_at IS NOT NULL)
    ),
    CONSTRAINT deliveries_accepted_coherent CHECK (
        status <> 'accepted' OR accepted_at IS NOT NULL
    ),
    CONSTRAINT deliveries_delivered_coherent CHECK (
        status <> 'delivered' OR (accepted_at IS NOT NULL AND delivered_at IS NOT NULL)
    ),
    CONSTRAINT deliveries_final_coherent CHECK (
        status NOT IN ('delivered', 'permanent_failed', 'suppressed', 'coalesced', 'cancelled', 'bounced', 'complained')
        OR final_at IS NOT NULL
    ),
    CONSTRAINT deliveries_provider_scope_identifier CHECK (
        provider_scope IS NULL
        OR (
            octet_length(provider_scope) BETWEEN 1 AND 64
            AND provider_scope ~ '^[a-z][a-z0-9._-]*$'
        )
    ),
    CONSTRAINT deliveries_provider_identity_coherent CHECK (
        (provider_scope IS NULL) = (provider_message_id IS NULL)
    ),
    CONSTRAINT deliveries_provider_message_id_bounded CHECK (
        provider_message_id IS NULL
        OR (
            octet_length(provider_message_id) BETWEEN 1 AND 255
            AND provider_message_id ~ '^[A-Za-z0-9._@<>:+-]+$'
        )
    ),
    CONSTRAINT deliveries_correlation_id_uuid_v7 CHECK (
        (get_byte(uuid_send(correlation_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(correlation_id), 8) & 192) = 128
    ),
    CONSTRAINT deliveries_causation_id_uuid_v7 CHECK (
        causation_id IS NULL
        OR (
            (get_byte(uuid_send(causation_id), 6) >> 4) = 7
            AND (get_byte(uuid_send(causation_id), 8) & 192) = 128
        )
    ),
    CONSTRAINT deliveries_updated_order CHECK (updated_at >= created_at),
    CONSTRAINT deliveries_id_tenant_key UNIQUE (id, tenant_id),
    CONSTRAINT deliveries_dedupe_key_unique UNIQUE (
        tenant_id, channel, dedupe_key, dedupe_bucket_started_at
    )
);

ALTER TABLE public.notification_digest_buckets
    ADD CONSTRAINT notification_digest_buckets_leader_delivery_tenant_fkey
    FOREIGN KEY (leader_delivery_id, tenant_id)
    REFERENCES public.deliveries (id, tenant_id) ON DELETE RESTRICT;

CREATE TABLE public.notification_job_outbox (
    delivery_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    job_id uuid NOT NULL UNIQUE,
    envelope bytea NOT NULL,
    available_at timestamptz NOT NULL,
    dispatch_attempts integer NOT NULL DEFAULT 0,
    lease_token uuid,
    lease_expires_at timestamptz,
    dispatched_at timestamptz,
    last_error_code varchar(64),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT notification_job_outbox_delivery_tenant_fkey
        FOREIGN KEY (delivery_id, tenant_id)
        REFERENCES public.deliveries (id, tenant_id) ON DELETE RESTRICT,
    CONSTRAINT notification_job_outbox_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES public.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT notification_job_outbox_delivery_id_uuid_v7 CHECK (
        (get_byte(uuid_send(delivery_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(delivery_id), 8) & 192) = 128
    ),
    CONSTRAINT notification_job_outbox_tenant_id_uuid_v7 CHECK (
        (get_byte(uuid_send(tenant_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(tenant_id), 8) & 192) = 128
    ),
    CONSTRAINT notification_job_outbox_job_id_uuid_v7 CHECK (
        (get_byte(uuid_send(job_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(job_id), 8) & 192) = 128
    ),
    CONSTRAINT notification_job_outbox_envelope_bounded CHECK (
        octet_length(envelope) BETWEEN 2 AND 1048576
        AND get_byte(envelope, 0) = 123
    ),
    CONSTRAINT notification_job_outbox_attempts_bounded CHECK (
        dispatch_attempts BETWEEN 0 AND 2147483647
    ),
    CONSTRAINT notification_job_outbox_lease_uuid_v7 CHECK (
        lease_token IS NULL
        OR (
            (get_byte(uuid_send(lease_token), 6) >> 4) = 7
            AND (get_byte(uuid_send(lease_token), 8) & 192) = 128
        )
    ),
    CONSTRAINT notification_job_outbox_lease_coherent CHECK (
        (lease_token IS NULL) = (lease_expires_at IS NULL)
        AND (dispatched_at IS NULL OR lease_token IS NULL)
    ),
    CONSTRAINT notification_job_outbox_error_identifier CHECK (
        last_error_code IS NULL
        OR (
            octet_length(last_error_code) BETWEEN 1 AND 64
            AND last_error_code ~ '^[a-z][a-z0-9._-]*$'
        )
    ),
    CONSTRAINT notification_job_outbox_updated_order CHECK (updated_at >= created_at)
);

CREATE TABLE public.notification_unsubscribe_tokens (
    id uuid PRIMARY KEY,
    token_digest bytea NOT NULL UNIQUE,
    purpose varchar(32) NOT NULL,
    recipient_id uuid NOT NULL,
    scope text NOT NULL,
    tenant_id uuid,
    category varchar(64) NOT NULL,
    channel varchar(16) NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz,
    CONSTRAINT notification_unsubscribe_tokens_recipient_id_fkey
        FOREIGN KEY (recipient_id) REFERENCES public.users (id) ON DELETE RESTRICT,
    CONSTRAINT notification_unsubscribe_tokens_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES public.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT notification_unsubscribe_tokens_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT notification_unsubscribe_tokens_digest_size CHECK (
        octet_length(token_digest) = 32
    ),
    CONSTRAINT notification_unsubscribe_tokens_purpose_known CHECK (purpose = 'unsubscribe'),
    CONSTRAINT notification_unsubscribe_tokens_recipient_id_uuid_v7 CHECK (
        (get_byte(uuid_send(recipient_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(recipient_id), 8) & 192) = 128
    ),
    CONSTRAINT notification_unsubscribe_tokens_scope_known CHECK (scope IN ('global', 'tenant')),
    CONSTRAINT notification_unsubscribe_tokens_scope_coherent CHECK (
        (scope = 'global' AND tenant_id IS NULL)
        OR (scope = 'tenant' AND tenant_id IS NOT NULL)
    ),
    CONSTRAINT notification_unsubscribe_tokens_tenant_id_uuid_v7 CHECK (
        tenant_id IS NULL
        OR (
            (get_byte(uuid_send(tenant_id), 6) >> 4) = 7
            AND (get_byte(uuid_send(tenant_id), 8) & 192) = 128
        )
    ),
    CONSTRAINT notification_unsubscribe_tokens_category_identifier CHECK (
        octet_length(category) BETWEEN 1 AND 64
        AND category ~ '^[a-z][a-z0-9._-]*$'
    ),
    CONSTRAINT notification_unsubscribe_tokens_channel_known CHECK (channel = 'email'),
    CONSTRAINT notification_unsubscribe_tokens_lifetime_bounded CHECK (
        expires_at > issued_at
        AND expires_at <= issued_at + interval '30 days'
    ),
    CONSTRAINT notification_unsubscribe_tokens_consumed_order CHECK (
        consumed_at IS NULL OR consumed_at >= issued_at
    ),
    CONSTRAINT notification_unsubscribe_tokens_revoked_order CHECK (
        revoked_at IS NULL OR revoked_at >= issued_at
    )
);

CREATE TABLE public.notification_provider_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    delivery_id uuid NOT NULL,
    event_id varchar(255) NOT NULL,
    provider_scope varchar(64) NOT NULL,
    provider_message_id varchar(255) NOT NULL,
    kind varchar(16) NOT NULL,
    bounce_class varchar(16),
    occurred_at timestamptz NOT NULL,
    applied boolean NOT NULL,
    resulting_status varchar(32) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT notification_provider_events_delivery_tenant_fkey
        FOREIGN KEY (delivery_id, tenant_id)
        REFERENCES public.deliveries (id, tenant_id) ON DELETE RESTRICT,
    CONSTRAINT notification_provider_events_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT notification_provider_events_tenant_id_uuid_v7 CHECK (
        (get_byte(uuid_send(tenant_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(tenant_id), 8) & 192) = 128
    ),
    CONSTRAINT notification_provider_events_delivery_id_uuid_v7 CHECK (
        (get_byte(uuid_send(delivery_id), 6) >> 4) = 7
        AND (get_byte(uuid_send(delivery_id), 8) & 192) = 128
    ),
    CONSTRAINT notification_provider_events_event_id_bounded CHECK (
        octet_length(event_id) BETWEEN 1 AND 255
        AND event_id ~ '^[A-Za-z0-9._@<>:+-]+$'
    ),
    CONSTRAINT notification_provider_events_provider_scope_identifier CHECK (
        octet_length(provider_scope) BETWEEN 1 AND 64
        AND provider_scope ~ '^[a-z][a-z0-9._-]*$'
    ),
    CONSTRAINT notification_provider_events_provider_message_id_bounded CHECK (
        octet_length(provider_message_id) BETWEEN 1 AND 255
        AND provider_message_id ~ '^[A-Za-z0-9._@<>:+-]+$'
    ),
    CONSTRAINT notification_provider_events_kind_known CHECK (
        kind IN ('delivered', 'bounce', 'complaint')
    ),
    CONSTRAINT notification_provider_events_status_known CHECK (
        resulting_status IN ('accepted', 'delivered', 'bounced', 'complained')
    ),
    CONSTRAINT notification_provider_events_bounce_class_coherent CHECK (
        (kind = 'bounce' AND bounce_class IN ('transient', 'permanent', 'undetermined'))
        OR (kind <> 'bounce' AND bounce_class IS NULL)
    ),
    CONSTRAINT notification_provider_events_applied_coherent CHECK (
        (applied AND resulting_status IN ('delivered', 'bounced', 'complained'))
        OR (NOT applied)
    ),
    CONSTRAINT notification_provider_events_scope_event_key UNIQUE (provider_scope, event_id)
);


CREATE INDEX deliveries_tenant_status_schedule_idx
    ON public.deliveries (tenant_id, status, created_at, id);
CREATE INDEX deliveries_recipient_status_idx
    ON public.deliveries (tenant_id, recipient_id, status, created_at DESC, id DESC);
CREATE UNIQUE INDEX deliveries_provider_message_identity_key
    ON public.deliveries (provider_scope, provider_message_id)
    WHERE provider_scope IS NOT NULL AND provider_message_id IS NOT NULL;
CREATE INDEX deliveries_tenant_provider_message_idx
    ON public.deliveries (tenant_id, provider_scope, provider_message_id)
    WHERE provider_scope IS NOT NULL AND provider_message_id IS NOT NULL;
CREATE INDEX notification_provider_events_delivery_idx
    ON public.notification_provider_events (tenant_id, delivery_id, created_at, id);
CREATE INDEX notification_digest_buckets_due_idx
    ON public.notification_digest_buckets (bucket_ends_at, id)
    WHERE released_at IS NULL;
CREATE INDEX notification_job_outbox_pending_idx
    ON public.notification_job_outbox (available_at, delivery_id)
    WHERE dispatched_at IS NULL;
CREATE INDEX notification_unsubscribe_tokens_active_idx
    ON public.notification_unsubscribe_tokens (token_digest, expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE FUNCTION public.enforce_notification_delivery_identity_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(
        OLD.id, OLD.tenant_id, OLD.recipient_id, OLD.event_name, OLD.channel,
        OLD.classification, OLD.preference_category, OLD.locale, OLD.time_zone,
        OLD.template_name, OLD.template_version, OLD.recipient_email,
        OLD.recipient_display_name, OLD.from_email, OLD.from_display_name, OLD.subject,
        OLD.template_context, OLD.dedupe_key, OLD.dedupe_bucket_started_at,
        OLD.digest_bucket_id, OLD.effect_key, OLD.client_message_id, OLD.correlation_id,
        OLD.causation_id, OLD.created_at
    ) IS DISTINCT FROM ROW(
        NEW.id, NEW.tenant_id, NEW.recipient_id, NEW.event_name, NEW.channel,
        NEW.classification, NEW.preference_category, NEW.locale, NEW.time_zone,
        NEW.template_name, NEW.template_version, NEW.recipient_email,
        NEW.recipient_display_name, NEW.from_email, NEW.from_display_name, NEW.subject,
        NEW.template_context, NEW.dedupe_key, NEW.dedupe_bucket_started_at,
        NEW.digest_bucket_id, NEW.effect_key, NEW.client_message_id, NEW.correlation_id,
        NEW.causation_id, NEW.created_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            TABLE = 'deliveries',
            MESSAGE = 'notification delivery identity is immutable';
    END IF;
    IF OLD.provider_scope IS NOT NULL
       AND ROW(OLD.provider_scope, OLD.provider_message_id)
           IS DISTINCT FROM ROW(NEW.provider_scope, NEW.provider_message_id) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            TABLE = 'deliveries',
            MESSAGE = 'notification provider identity is immutable once accepted';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER deliveries_identity_immutable
BEFORE UPDATE ON public.deliveries
FOR EACH ROW
EXECUTE FUNCTION public.enforce_notification_delivery_identity_immutable();

CREATE FUNCTION public.enforce_unsubscribe_token_identity_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(
        OLD.id, OLD.token_digest, OLD.purpose, OLD.recipient_id, OLD.scope,
        OLD.tenant_id, OLD.category, OLD.channel, OLD.issued_at, OLD.expires_at
    ) IS DISTINCT FROM ROW(
        NEW.id, NEW.token_digest, NEW.purpose, NEW.recipient_id, NEW.scope,
        NEW.tenant_id, NEW.category, NEW.channel, NEW.issued_at, NEW.expires_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            TABLE = 'notification_unsubscribe_tokens',
            MESSAGE = 'unsubscribe token identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER notification_unsubscribe_tokens_identity_immutable
BEFORE UPDATE ON public.notification_unsubscribe_tokens
FOR EACH ROW
EXECUTE FUNCTION public.enforce_unsubscribe_token_identity_immutable();

REVOKE ALL ON TABLE public.notification_preferences FROM PUBLIC;
REVOKE ALL ON TABLE public.notification_digest_buckets FROM PUBLIC;
REVOKE ALL ON TABLE public.deliveries FROM PUBLIC;
REVOKE ALL ON TABLE public.notification_job_outbox FROM PUBLIC;
REVOKE ALL ON TABLE public.notification_unsubscribe_tokens FROM PUBLIC;
REVOKE ALL ON TABLE public.notification_provider_events FROM PUBLIC;
REVOKE ALL ON FUNCTION public.enforce_notification_delivery_identity_immutable() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.enforce_unsubscribe_token_identity_immutable() FROM PUBLIC;
