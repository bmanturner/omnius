\set ON_ERROR_STOP on

BEGIN;

ALTER TABLE recovery_rehearsal.records
    ADD COLUMN deployment_generation text NOT NULL DEFAULT 'stable'
    CHECK (deployment_generation IN ('stable', 'candidate'));

CREATE INDEX records_generation_idx
    ON recovery_rehearsal.records (deployment_generation, committed_at);

INSERT INTO recovery_rehearsal.records (
    id,
    business_key,
    amount,
    deployment_generation
) VALUES (
    '00000000-0000-4000-8000-000000000004',
    'invoice-candidate',
    400,
    'candidate'
);

INSERT INTO recovery_rehearsal.audit_events (sequence, record_id, payload)
VALUES (
    4,
    '00000000-0000-4000-8000-000000000004',
    '{"event":"created","version":2,"writer":"candidate"}'
);

COMMIT;
