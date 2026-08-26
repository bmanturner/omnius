\set ON_ERROR_STOP on

BEGIN;

PREPARE stable_record_write (uuid, text, bigint) AS
    INSERT INTO recovery_rehearsal.records (id, business_key, amount)
    VALUES ($1, $2, $3);

EXECUTE stable_record_write(
    '00000000-0000-4000-8000-000000000005',
    'invoice-after-rollback',
    500
);

INSERT INTO recovery_rehearsal.audit_events (sequence, record_id, payload)
VALUES (
    5,
    '00000000-0000-4000-8000-000000000005',
    '{"event":"created","version":1,"writer":"stable"}'
);

SELECT id, business_key, amount, committed_at
FROM recovery_rehearsal.records
ORDER BY id;

COMMIT;
