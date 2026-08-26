\set ON_ERROR_STOP on

DO $$
DECLARE
    record_count bigint;
    amount_total numeric;
    audit_count bigint;
    stable_count bigint;
    candidate_count bigint;
BEGIN
    SELECT
        count(*),
        sum(amount),
        count(*) FILTER (WHERE deployment_generation = 'stable'),
        count(*) FILTER (WHERE deployment_generation = 'candidate')
    INTO record_count, amount_total, stable_count, candidate_count
    FROM recovery_rehearsal.records;

    IF record_count <> 5 OR amount_total <> 1500 THEN
        RAISE EXCEPTION 'rollback record invariant failed: count=%, total=%',
            record_count, amount_total;
    END IF;

    IF stable_count <> 4 OR candidate_count <> 1 THEN
        RAISE EXCEPTION 'rollback compatibility failed: stable=%, candidate=%',
            stable_count, candidate_count;
    END IF;

    SELECT count(*) INTO audit_count
    FROM recovery_rehearsal.audit_events;

    IF audit_count <> 5 THEN
        RAISE EXCEPTION 'rollback audit invariant failed: count=%', audit_count;
    END IF;

    IF (SELECT deployment_generation <> 'stable'
        FROM recovery_rehearsal.records
        WHERE business_key = 'invoice-after-rollback') THEN
        RAISE EXCEPTION 'stable writer default is not rollback compatible';
    END IF;

    IF to_regclass('recovery_rehearsal.records_generation_idx') IS NULL THEN
        RAISE EXCEPTION 'candidate expand migration was destructively reverted';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM recovery_rehearsal.audit_events AS event
        LEFT JOIN recovery_rehearsal.records AS record
            ON record.id = event.record_id
        WHERE record.id IS NULL
    ) THEN
        RAISE EXCEPTION 'rollback produced orphan audit events';
    END IF;
END
$$;
