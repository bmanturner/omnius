\set ON_ERROR_STOP on

DO $$
DECLARE
    record_count bigint;
    amount_total numeric;
    audit_count bigint;
    orphan_count bigint;
    required_constraint_count bigint;
BEGIN
    SELECT count(*), sum(amount)
    INTO record_count, amount_total
    FROM recovery_rehearsal.records;

    IF record_count <> 3 OR amount_total <> 600 THEN
        RAISE EXCEPTION 'restored record invariant failed: count=%, total=%',
            record_count, amount_total;
    END IF;

    SELECT count(*) INTO audit_count
    FROM recovery_rehearsal.audit_events;

    SELECT count(*) INTO orphan_count
    FROM recovery_rehearsal.audit_events AS event
    LEFT JOIN recovery_rehearsal.records AS record
        ON record.id = event.record_id
    WHERE record.id IS NULL;

    IF audit_count <> 3 OR orphan_count <> 0 THEN
        RAISE EXCEPTION 'restored audit invariant failed: count=%, orphans=%',
            audit_count, orphan_count;
    END IF;

    IF (SELECT backup_started_at IS NULL FROM recovery_rehearsal.metadata) THEN
        RAISE EXCEPTION 'backup marker was not captured';
    END IF;

    SELECT count(*) INTO required_constraint_count
    FROM pg_constraint
    WHERE conname IN (
        'records_pkey',
        'records_business_key_key',
        'records_amount_check',
        'audit_events_pkey',
        'audit_events_record_id_fkey'
    )
      AND connamespace = 'recovery_rehearsal'::regnamespace;

    IF required_constraint_count <> 5 THEN
        RAISE EXCEPTION 'restored constraints missing: found % of 5',
            required_constraint_count;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'recovery_rehearsal'
          AND table_name = 'records'
          AND column_name = 'deployment_generation'
    ) THEN
        RAISE EXCEPTION 'fresh restore unexpectedly contains candidate deployment state';
    END IF;
END
$$;
