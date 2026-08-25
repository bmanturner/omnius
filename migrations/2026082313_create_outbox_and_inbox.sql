CREATE TABLE outbox_events (
    id uuid PRIMARY KEY,
    aggregate_type varchar(128) NOT NULL,
    aggregate_id varchar(256) NOT NULL,
    event_type varchar(128) NOT NULL,
    event_version smallint NOT NULL,
    source varchar(128) NOT NULL,
    subject varchar(256) NOT NULL,
    tenant_id uuid,
    occurred_at timestamptz NOT NULL,
    correlation_id uuid NOT NULL,
    causation_id uuid,
    traceparent varchar(55),
    payload jsonb NOT NULL,
    destination varchar(256) NOT NULL,
    available_at timestamptz NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    lease_owner varchar(128),
    lease_token uuid,
    lease_expires_at timestamptz,
    published_at timestamptz,
    last_error_class varchar(64),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT outbox_events_id_uuid_v7 CHECK (get_byte(uuid_send(id), 6) >> 4 = 7),
    CONSTRAINT outbox_events_event_version_positive CHECK (event_version > 0),
    CONSTRAINT outbox_events_attempt_count_nonnegative CHECK (attempt_count >= 0),
    CONSTRAINT outbox_events_payload_object CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT outbox_events_payload_bounded CHECK (octet_length(payload::text) <= 2097152),
    CONSTRAINT outbox_events_aggregate_type_portable CHECK (aggregate_type ~ '^[a-z0-9][a-z0-9_.-]*$'),
    CONSTRAINT outbox_events_event_type_portable CHECK (event_type ~ '^[a-z0-9][a-z0-9_.-]*$'),
    CONSTRAINT outbox_events_source_portable CHECK (source ~ '^[A-Za-z0-9][A-Za-z0-9_.-]*$'),
    CONSTRAINT outbox_events_destination_portable CHECK (destination ~ '^[A-Za-z0-9][A-Za-z0-9_./:-]*$'),
    CONSTRAINT outbox_events_lease_complete CHECK (
        (lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
        OR (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
    ),
    CONSTRAINT outbox_events_published_not_leased CHECK (
        published_at IS NULL OR (lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
    ),
    CONSTRAINT outbox_events_error_class_portable CHECK (
        last_error_class IS NULL OR last_error_class ~ '^[a-z0-9][a-z0-9_.-]*$'
    )
);

CREATE INDEX outbox_events_ready_idx
    ON outbox_events (available_at, occurred_at, id)
    WHERE published_at IS NULL;
CREATE INDEX outbox_events_lease_expiry_idx
    ON outbox_events (lease_expires_at)
    WHERE lease_expires_at IS NOT NULL AND published_at IS NULL;
CREATE INDEX outbox_events_tenant_time_idx
    ON outbox_events (tenant_id, occurred_at DESC, id DESC);

CREATE TABLE inbox_receipts (
    producer varchar(128) NOT NULL,
    event_id uuid NOT NULL,
    event_type varchar(128) NOT NULL,
    event_version smallint NOT NULL,
    tenant_id uuid,
    correlation_id uuid NOT NULL,
    causation_id uuid,
    payload_sha256 bytea NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    processed_at timestamptz,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (producer, event_id),
    CONSTRAINT inbox_receipts_event_id_uuid_v7 CHECK (get_byte(uuid_send(event_id), 6) >> 4 = 7),
    CONSTRAINT inbox_receipts_event_version_positive CHECK (event_version > 0),
    CONSTRAINT inbox_receipts_producer_portable CHECK (producer ~ '^[A-Za-z0-9][A-Za-z0-9_.-]*$'),
    CONSTRAINT inbox_receipts_event_type_portable CHECK (event_type ~ '^[a-z0-9][a-z0-9_.-]*$'),
    CONSTRAINT inbox_receipts_payload_sha256_length CHECK (octet_length(payload_sha256) = 32),
    CONSTRAINT inbox_receipts_expiry_after_receive CHECK (expires_at > received_at),
    CONSTRAINT inbox_receipts_processed_after_receive CHECK (
        processed_at IS NULL OR processed_at >= received_at
    )
);

CREATE INDEX inbox_receipts_expiry_idx ON inbox_receipts (expires_at);
CREATE INDEX inbox_receipts_unprocessed_idx
    ON inbox_receipts (received_at, event_id)
    WHERE processed_at IS NULL;
