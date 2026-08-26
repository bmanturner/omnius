\set ON_ERROR_STOP on

BEGIN;

CREATE SCHEMA recovery_rehearsal;

CREATE TABLE recovery_rehearsal.metadata (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    fixture_created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    backup_started_at timestamptz
);

CREATE TABLE recovery_rehearsal.records (
    id uuid PRIMARY KEY,
    business_key text NOT NULL UNIQUE,
    amount bigint NOT NULL CHECK (amount >= 0),
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE recovery_rehearsal.audit_events (
    sequence bigint PRIMARY KEY,
    record_id uuid NOT NULL REFERENCES recovery_rehearsal.records(id),
    payload jsonb NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO recovery_rehearsal.metadata (singleton) VALUES (true);

INSERT INTO recovery_rehearsal.records (id, business_key, amount) VALUES
    ('00000000-0000-4000-8000-000000000001', 'invoice-alpha', 100),
    ('00000000-0000-4000-8000-000000000002', 'invoice-beta', 200),
    ('00000000-0000-4000-8000-000000000003', 'invoice-gamma', 300);

INSERT INTO recovery_rehearsal.audit_events (sequence, record_id, payload) VALUES
    (1, '00000000-0000-4000-8000-000000000001', '{"event":"created","version":1}'),
    (2, '00000000-0000-4000-8000-000000000002', '{"event":"created","version":1}'),
    (3, '00000000-0000-4000-8000-000000000003', '{"event":"created","version":1}');

COMMIT;
