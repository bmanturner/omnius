CREATE TABLE public.billing_plans (
    plan_key varchar(128) PRIMARY KEY,
    enabled boolean NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT billing_plans_key_identifier CHECK (
        octet_length(plan_key) BETWEEN 1 AND 128
        AND plan_key ~ '^[a-z][a-z0-9._:/-]*$'
    ),
    CONSTRAINT billing_plans_timestamp_order CHECK (updated_at >= created_at)
);

CREATE TABLE public.billing_entitlement_definitions (
    entitlement_key varchar(128) PRIMARY KEY,
    value_kind varchar(16) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT billing_entitlement_definitions_key_identifier CHECK (
        octet_length(entitlement_key) BETWEEN 1 AND 128
        AND entitlement_key ~ '^[a-z][a-z0-9._:/-]*$'
    ),
    CONSTRAINT billing_entitlement_definitions_kind_known CHECK (
        value_kind IN ('boolean', 'limit')
    ),
    CONSTRAINT billing_entitlement_definitions_key_kind UNIQUE (
        entitlement_key, value_kind
    )
);

CREATE TABLE public.billing_plan_entitlements (
    plan_key varchar(128) NOT NULL,
    entitlement_key varchar(128) NOT NULL,
    value_kind varchar(16) NOT NULL,
    boolean_value boolean,
    limit_value bigint,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT billing_plan_entitlements_pkey PRIMARY KEY (plan_key, entitlement_key),
    CONSTRAINT billing_plan_entitlements_plan_fkey
        FOREIGN KEY (plan_key) REFERENCES public.billing_plans (plan_key) ON DELETE CASCADE,
    CONSTRAINT billing_plan_entitlements_definition_fkey
        FOREIGN KEY (entitlement_key, value_kind)
        REFERENCES public.billing_entitlement_definitions (entitlement_key, value_kind)
        ON DELETE RESTRICT,
    CONSTRAINT billing_plan_entitlements_value_coherent CHECK (
        (value_kind = 'boolean' AND boolean_value IS NOT NULL AND limit_value IS NULL)
        OR (value_kind = 'limit' AND boolean_value IS NULL AND limit_value > 0)
    ),
    CONSTRAINT billing_plan_entitlements_timestamp_order CHECK (updated_at >= created_at)
);

CREATE TABLE public.billing_provider_prices (
    provider varchar(64) NOT NULL,
    provider_price_id varchar(255) NOT NULL,
    plan_key varchar(128) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT billing_provider_prices_pkey PRIMARY KEY (provider, provider_price_id),
    CONSTRAINT billing_provider_prices_plan_fkey
        FOREIGN KEY (plan_key) REFERENCES public.billing_plans (plan_key) ON DELETE RESTRICT,
    CONSTRAINT billing_provider_prices_provider_identifier CHECK (
        octet_length(provider) BETWEEN 1 AND 64
        AND provider ~ '^[a-z][a-z0-9._:/-]*$'
    ),
    CONSTRAINT billing_provider_prices_price_identifier CHECK (
        octet_length(provider_price_id) BETWEEN 1 AND 255
        AND provider_price_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    CONSTRAINT billing_provider_prices_timestamp_order CHECK (updated_at >= created_at)
);

CREATE TABLE public.billing_customers (
    tenant_id uuid PRIMARY KEY,
    provider varchar(64) NOT NULL,
    provider_customer_id varchar(255) NOT NULL,
    provider_revision bigint NOT NULL,
    state_facts jsonb NOT NULL,
    reconciled_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT billing_customers_tenant_fkey
        FOREIGN KEY (tenant_id) REFERENCES public.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT billing_customers_tenant_provider_key UNIQUE (tenant_id, provider),
    CONSTRAINT billing_customers_provider_customer_key UNIQUE (provider, provider_customer_id),
    CONSTRAINT billing_customers_provider_identifier CHECK (
        octet_length(provider) BETWEEN 1 AND 64
        AND provider ~ '^[a-z][a-z0-9._:/-]*$'
    ),
    CONSTRAINT billing_customers_customer_identifier CHECK (
        octet_length(provider_customer_id) BETWEEN 1 AND 255
        AND provider_customer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    CONSTRAINT billing_customers_revision_nonnegative CHECK (provider_revision >= 0),
    CONSTRAINT billing_customers_facts_bounded CHECK (
        jsonb_typeof(state_facts) = 'object'
        AND octet_length(state_facts::text) <= 32768
    ),
    CONSTRAINT billing_customers_timestamp_order CHECK (
        updated_at >= created_at AND reconciled_at <= updated_at
    )
);

CREATE TABLE public.billing_subscriptions (
    tenant_id uuid NOT NULL,
    provider varchar(64) NOT NULL,
    provider_subscription_id varchar(255) NOT NULL,
    provider_customer_id varchar(255) NOT NULL,
    provider_price_id varchar(255) NOT NULL,
    standing varchar(24) NOT NULL,
    access_state varchar(16) NOT NULL,
    current_period_end timestamptz,
    grace_until timestamptz,
    dunning_started_at timestamptz,
    dunning_attempt_count integer,
    dunning_next_attempt_at timestamptz,
    state_facts jsonb NOT NULL,
    provider_revision bigint NOT NULL,
    reconciled_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT billing_subscriptions_pkey
        PRIMARY KEY (tenant_id, provider, provider_subscription_id),
    CONSTRAINT billing_subscriptions_customer_fkey
        FOREIGN KEY (tenant_id, provider)
        REFERENCES public.billing_customers (tenant_id, provider) ON DELETE CASCADE,
    CONSTRAINT billing_subscriptions_provider_identifier CHECK (
        octet_length(provider) BETWEEN 1 AND 64
        AND provider ~ '^[a-z][a-z0-9._:/-]*$'
    ),
    CONSTRAINT billing_subscriptions_object_identifiers CHECK (
        octet_length(provider_subscription_id) BETWEEN 1 AND 255
        AND provider_subscription_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        AND octet_length(provider_customer_id) BETWEEN 1 AND 255
        AND provider_customer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        AND octet_length(provider_price_id) BETWEEN 1 AND 255
        AND provider_price_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    CONSTRAINT billing_subscriptions_standing_known CHECK (
        standing IN ('in_good_standing', 'delinquent', 'pending', 'ended')
    ),
    CONSTRAINT billing_subscriptions_access_known CHECK (
        access_state IN ('active', 'grace', 'denied')
    ),
    CONSTRAINT billing_subscriptions_access_coherent CHECK (
        (standing = 'in_good_standing' AND access_state = 'active' AND grace_until IS NULL)
        OR (standing = 'delinquent' AND access_state IN ('grace', 'denied'))
        OR (standing IN ('pending', 'ended') AND access_state = 'denied' AND grace_until IS NULL)
    ),
    CONSTRAINT billing_subscriptions_dunning_coherent CHECK (
        (standing = 'delinquent' AND dunning_started_at IS NOT NULL
            AND dunning_attempt_count BETWEEN 0 AND 100)
        OR (standing <> 'delinquent' AND dunning_started_at IS NULL
            AND dunning_attempt_count IS NULL AND dunning_next_attempt_at IS NULL)
    ),
    CONSTRAINT billing_subscriptions_grace_coherent CHECK (
        (access_state = 'grace' AND grace_until IS NOT NULL AND grace_until > reconciled_at)
        OR (access_state <> 'grace' AND grace_until IS NULL)
    ),
    CONSTRAINT billing_subscriptions_dunning_order CHECK (
        dunning_next_attempt_at IS NULL OR dunning_next_attempt_at >= dunning_started_at
    ),
    CONSTRAINT billing_subscriptions_revision_nonnegative CHECK (provider_revision >= 0),
    CONSTRAINT billing_subscriptions_facts_bounded CHECK (
        jsonb_typeof(state_facts) = 'object'
        AND octet_length(state_facts::text) <= 32768
    ),
    CONSTRAINT billing_subscriptions_timestamp_order CHECK (
        updated_at >= created_at AND reconciled_at <= updated_at
    )
);

CREATE TABLE public.billing_invoices (
    tenant_id uuid NOT NULL,
    provider varchar(64) NOT NULL,
    provider_invoice_id varchar(255) NOT NULL,
    provider_customer_id varchar(255) NOT NULL,
    amount_due_minor bigint NOT NULL,
    currency char(3) NOT NULL,
    due_at timestamptz,
    paid_at timestamptz,
    state_facts jsonb NOT NULL,
    provider_revision bigint NOT NULL,
    reconciled_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT billing_invoices_pkey PRIMARY KEY (tenant_id, provider, provider_invoice_id),
    CONSTRAINT billing_invoices_customer_fkey
        FOREIGN KEY (tenant_id, provider)
        REFERENCES public.billing_customers (tenant_id, provider) ON DELETE CASCADE,
    CONSTRAINT billing_invoices_object_identifiers CHECK (
        octet_length(provider_invoice_id) BETWEEN 1 AND 255
        AND provider_invoice_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        AND octet_length(provider_customer_id) BETWEEN 1 AND 255
        AND provider_customer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    CONSTRAINT billing_invoices_amount_nonnegative CHECK (amount_due_minor >= 0),
    CONSTRAINT billing_invoices_currency_uppercase CHECK (currency ~ '^[A-Z]{3}$'),
    CONSTRAINT billing_invoices_revision_nonnegative CHECK (provider_revision >= 0),
    CONSTRAINT billing_invoices_facts_bounded CHECK (
        jsonb_typeof(state_facts) = 'object'
        AND octet_length(state_facts::text) <= 32768
    ),
    CONSTRAINT billing_invoices_timestamp_order CHECK (
        updated_at >= created_at AND reconciled_at <= updated_at
    )
);

CREATE TABLE public.billing_entitlements (
    tenant_id uuid NOT NULL,
    entitlement_key varchar(128) NOT NULL,
    provider varchar(64) NOT NULL,
    value_kind varchar(16) NOT NULL,
    boolean_value boolean,
    limit_value bigint,
    provider_revision bigint NOT NULL,
    valid_until timestamptz,
    in_grace boolean NOT NULL,
    reconciled_at timestamptz NOT NULL,
    CONSTRAINT billing_entitlements_pkey PRIMARY KEY (tenant_id, entitlement_key),
    CONSTRAINT billing_entitlements_customer_fkey
        FOREIGN KEY (tenant_id, provider)
        REFERENCES public.billing_customers (tenant_id, provider) ON DELETE CASCADE,
    CONSTRAINT billing_entitlements_definition_fkey
        FOREIGN KEY (entitlement_key, value_kind)
        REFERENCES public.billing_entitlement_definitions (entitlement_key, value_kind)
        ON DELETE RESTRICT,
    CONSTRAINT billing_entitlements_value_coherent CHECK (
        (value_kind = 'boolean' AND boolean_value IS NOT NULL AND limit_value IS NULL)
        OR (value_kind = 'limit' AND boolean_value IS NULL AND limit_value > 0)
    ),
    CONSTRAINT billing_entitlements_revision_nonnegative CHECK (provider_revision >= 0),
    CONSTRAINT billing_entitlements_grace_coherent CHECK (
        NOT in_grace OR (valid_until IS NOT NULL AND valid_until > reconciled_at)
    )
);

CREATE TABLE public.billing_usage (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    provider varchar(64) NOT NULL,
    meter_key varchar(128) NOT NULL,
    idempotency_key varchar(255) NOT NULL,
    request_fingerprint bytea NOT NULL,
    quantity bigint NOT NULL,
    occurred_at timestamptz NOT NULL,
    status varchar(16) NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_token uuid,
    lease_expires_at timestamptz,
    last_error_class varchar(64),
    provider_usage_id varchar(255),
    provider_accepted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT billing_usage_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT billing_usage_customer_fkey
        FOREIGN KEY (tenant_id, provider)
        REFERENCES public.billing_customers (tenant_id, provider) ON DELETE RESTRICT,
    CONSTRAINT billing_usage_identity_key UNIQUE (tenant_id, meter_key, idempotency_key),
    CONSTRAINT billing_usage_meter_identifier CHECK (
        octet_length(meter_key) BETWEEN 1 AND 128
        AND meter_key ~ '^[a-z][a-z0-9._:/-]*$'
    ),
    CONSTRAINT billing_usage_idempotency_identifier CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 255
        AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    CONSTRAINT billing_usage_fingerprint_size CHECK (octet_length(request_fingerprint) = 32),
    CONSTRAINT billing_usage_quantity_positive CHECK (quantity > 0),
    CONSTRAINT billing_usage_status_known CHECK (
        status IN ('pending', 'processing', 'accepted', 'rejected')
    ),
    CONSTRAINT billing_usage_attempts_bounded CHECK (attempt_count BETWEEN 0 AND 20),
    CONSTRAINT billing_usage_lease_uuid_v7 CHECK (
        lease_token IS NULL OR (
            (get_byte(uuid_send(lease_token), 6) >> 4) = 7
            AND (get_byte(uuid_send(lease_token), 8) & 192) = 128
        )
    ),
    CONSTRAINT billing_usage_lease_pair CHECK (
        (lease_token IS NULL) = (lease_expires_at IS NULL)
    ),
    CONSTRAINT billing_usage_provider_result_coherent CHECK (
        (status = 'pending' AND lease_token IS NULL
            AND provider_usage_id IS NULL AND provider_accepted_at IS NULL)
        OR (status = 'processing' AND lease_token IS NOT NULL AND attempt_count > 0
            AND provider_usage_id IS NULL AND provider_accepted_at IS NULL)
        OR (status = 'accepted' AND lease_token IS NULL
            AND provider_usage_id IS NOT NULL AND provider_accepted_at IS NOT NULL)
        OR (status = 'rejected' AND lease_token IS NULL AND attempt_count > 0
            AND provider_usage_id IS NULL AND provider_accepted_at IS NULL)
    ),
    CONSTRAINT billing_usage_failure_identifier CHECK (
        last_error_class IS NULL OR (
            octet_length(last_error_class) BETWEEN 1 AND 64
            AND last_error_class ~ '^[a-z][a-z0-9._-]*$'
        )
    ),
    CONSTRAINT billing_usage_provider_usage_identifier CHECK (
        provider_usage_id IS NULL OR (
            octet_length(provider_usage_id) BETWEEN 1 AND 255
            AND provider_usage_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        )
    ),
    CONSTRAINT billing_usage_timestamp_order CHECK (
        updated_at >= created_at
        AND (lease_expires_at IS NULL OR lease_expires_at > updated_at)
    )
);

CREATE TABLE public.billing_provider_events (
    tenant_id uuid NOT NULL,
    provider varchar(64) NOT NULL,
    provider_event_id varchar(255) NOT NULL,
    provider_event_sequence bigint NOT NULL,
    receipt_id uuid NOT NULL,
    event_fingerprint bytea NOT NULL,
    disposition varchar(24) NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT billing_provider_events_pkey
        PRIMARY KEY (tenant_id, provider, provider_event_id),
    CONSTRAINT billing_provider_events_tenant_fkey
        FOREIGN KEY (tenant_id) REFERENCES public.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT billing_provider_events_receipt_fkey
        FOREIGN KEY (receipt_id) REFERENCES public.webhook_receipts (id) ON DELETE RESTRICT,
    CONSTRAINT billing_provider_events_sequence_key
        UNIQUE (tenant_id, provider, provider_event_sequence),
    CONSTRAINT billing_provider_events_event_identifier CHECK (
        octet_length(provider_event_id) BETWEEN 1 AND 255
        AND provider_event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    CONSTRAINT billing_provider_events_sequence_nonnegative CHECK (provider_event_sequence >= 0),
    CONSTRAINT billing_provider_events_fingerprint_size CHECK (octet_length(event_fingerprint) = 32),
    CONSTRAINT billing_provider_events_disposition_known CHECK (
        disposition IN ('accepted', 'out_of_order')
    )
);

CREATE TABLE public.billing_reconciliation_state (
    tenant_id uuid PRIMARY KEY,
    provider varchar(64) NOT NULL,
    last_event_sequence bigint,
    last_reconciliation_revision bigint,
    last_snapshot_fingerprint bytea,
    reconciled_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT billing_reconciliation_state_tenant_fkey
        FOREIGN KEY (tenant_id) REFERENCES public.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT billing_reconciliation_state_tenant_provider_key UNIQUE (tenant_id, provider),
    CONSTRAINT billing_reconciliation_state_event_nonnegative CHECK (
        last_event_sequence IS NULL OR last_event_sequence >= 0
    ),
    CONSTRAINT billing_reconciliation_state_revision_nonnegative CHECK (
        last_reconciliation_revision IS NULL OR last_reconciliation_revision >= 0
    ),
    CONSTRAINT billing_reconciliation_state_snapshot_pair CHECK (
        (last_reconciliation_revision IS NULL) = (last_snapshot_fingerprint IS NULL)
        AND (last_reconciliation_revision IS NULL) = (reconciled_at IS NULL)
        AND (last_snapshot_fingerprint IS NULL OR octet_length(last_snapshot_fingerprint) = 32)
    )
);

CREATE TABLE public.billing_reconciliation_tasks (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    provider varchar(64) NOT NULL,
    reason varchar(16) NOT NULL,
    source_event_id varchar(255),
    repair_idempotency_key varchar(255),
    status varchar(24) NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_token uuid,
    lease_expires_at timestamptz,
    last_error_class varchar(64),
    completed_at timestamptz,
    dead_lettered_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT billing_reconciliation_tasks_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT billing_reconciliation_tasks_state_fkey
        FOREIGN KEY (tenant_id, provider)
        REFERENCES public.billing_reconciliation_state (tenant_id, provider) ON DELETE CASCADE,
    CONSTRAINT billing_reconciliation_tasks_event_fkey
        FOREIGN KEY (tenant_id, provider, source_event_id)
        REFERENCES public.billing_provider_events (tenant_id, provider, provider_event_id)
        ON DELETE RESTRICT,
    CONSTRAINT billing_reconciliation_tasks_event_key
        UNIQUE (tenant_id, provider, source_event_id),
    CONSTRAINT billing_reconciliation_tasks_reason_known CHECK (
        reason IN ('webhook', 'repair', 'scheduled')
    ),
    CONSTRAINT billing_reconciliation_tasks_source_coherent CHECK (
        (reason = 'webhook' AND source_event_id IS NOT NULL AND repair_idempotency_key IS NULL)
        OR (reason = 'repair' AND source_event_id IS NULL AND repair_idempotency_key IS NOT NULL)
        OR (reason = 'scheduled' AND source_event_id IS NULL AND repair_idempotency_key IS NULL)
    ),
    CONSTRAINT billing_reconciliation_tasks_repair_identifier CHECK (
        repair_idempotency_key IS NULL OR (
            octet_length(repair_idempotency_key) BETWEEN 1 AND 255
            AND repair_idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        )
    ),
    CONSTRAINT billing_reconciliation_tasks_status_known CHECK (
        status IN ('pending', 'processing', 'completed', 'dead_letter')
    ),
    CONSTRAINT billing_reconciliation_tasks_attempts_bounded CHECK (
        attempt_count BETWEEN 0 AND 20
    ),
    CONSTRAINT billing_reconciliation_tasks_lease_uuid_v7 CHECK (
        lease_token IS NULL OR (
            (get_byte(uuid_send(lease_token), 6) >> 4) = 7
            AND (get_byte(uuid_send(lease_token), 8) & 192) = 128
        )
    ),
    CONSTRAINT billing_reconciliation_tasks_lease_pair CHECK (
        (lease_token IS NULL) = (lease_expires_at IS NULL)
    ),
    CONSTRAINT billing_reconciliation_tasks_state_coherent CHECK (
        (status = 'pending' AND lease_token IS NULL AND completed_at IS NULL
            AND dead_lettered_at IS NULL)
        OR (status = 'processing' AND lease_token IS NOT NULL AND attempt_count > 0
            AND completed_at IS NULL AND dead_lettered_at IS NULL)
        OR (status = 'completed' AND lease_token IS NULL AND completed_at IS NOT NULL
            AND dead_lettered_at IS NULL)
        OR (status = 'dead_letter' AND lease_token IS NULL AND completed_at IS NULL
            AND dead_lettered_at IS NOT NULL AND attempt_count > 0)
    ),
    CONSTRAINT billing_reconciliation_tasks_failure_identifier CHECK (
        last_error_class IS NULL OR (
            octet_length(last_error_class) BETWEEN 1 AND 64
            AND last_error_class ~ '^[a-z][a-z0-9._-]*$'
        )
    ),
    CONSTRAINT billing_reconciliation_tasks_timestamp_order CHECK (
        updated_at >= created_at
        AND (lease_expires_at IS NULL OR lease_expires_at > updated_at)
        AND (completed_at IS NULL OR completed_at >= created_at)
        AND (dead_lettered_at IS NULL OR dead_lettered_at >= created_at)
    )
);

CREATE UNIQUE INDEX billing_reconciliation_tasks_repair_key
    ON public.billing_reconciliation_tasks (tenant_id, provider, repair_idempotency_key)
    WHERE repair_idempotency_key IS NOT NULL;

CREATE INDEX billing_reconciliation_tasks_ready_idx
    ON public.billing_reconciliation_tasks (available_at, id)
    WHERE status = 'pending';

CREATE INDEX billing_reconciliation_tasks_recovery_idx
    ON public.billing_reconciliation_tasks (lease_expires_at, id)
    WHERE status = 'processing';

CREATE INDEX billing_subscriptions_tenant_access_idx
    ON public.billing_subscriptions (tenant_id, access_state, provider_subscription_id);

CREATE INDEX billing_invoices_tenant_time_idx
    ON public.billing_invoices (tenant_id, due_at DESC, provider_invoice_id DESC);

CREATE INDEX billing_entitlements_tenant_idx
    ON public.billing_entitlements (tenant_id, entitlement_key);

CREATE INDEX billing_usage_pending_idx
    ON public.billing_usage (available_at, id)
    WHERE status = 'pending';

CREATE INDEX billing_usage_recovery_idx
    ON public.billing_usage (lease_expires_at, id)
    WHERE status = 'processing';

CREATE UNIQUE INDEX billing_usage_provider_result_key
    ON public.billing_usage (provider, provider_usage_id)
    WHERE provider_usage_id IS NOT NULL;

CREATE FUNCTION public.billing_preserve_immutable_fence()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'billing_provider_events' THEN
        IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
            OR NEW.provider IS DISTINCT FROM OLD.provider
            OR NEW.provider_event_id IS DISTINCT FROM OLD.provider_event_id
            OR NEW.provider_event_sequence IS DISTINCT FROM OLD.provider_event_sequence
            OR NEW.receipt_id IS DISTINCT FROM OLD.receipt_id
            OR NEW.event_fingerprint IS DISTINCT FROM OLD.event_fingerprint
            OR NEW.received_at IS DISTINCT FROM OLD.received_at
        THEN
            RAISE EXCEPTION 'billing provider event fence cannot be changed'
                USING ERRCODE = 'check_violation';
        END IF;
    ELSIF TG_TABLE_NAME = 'billing_usage' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
            OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
            OR NEW.provider IS DISTINCT FROM OLD.provider
            OR NEW.meter_key IS DISTINCT FROM OLD.meter_key
            OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
            OR NEW.request_fingerprint IS DISTINCT FROM OLD.request_fingerprint
            OR NEW.quantity IS DISTINCT FROM OLD.quantity
            OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at
            OR NEW.created_at IS DISTINCT FROM OLD.created_at
        THEN
            RAISE EXCEPTION 'billing usage idempotency fence cannot be changed'
                USING ERRCODE = 'check_violation';
        END IF;
    ELSIF TG_TABLE_NAME = 'billing_reconciliation_tasks' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
            OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
            OR NEW.provider IS DISTINCT FROM OLD.provider
            OR NEW.reason IS DISTINCT FROM OLD.reason
            OR NEW.source_event_id IS DISTINCT FROM OLD.source_event_id
            OR NEW.repair_idempotency_key IS DISTINCT FROM OLD.repair_idempotency_key
            OR NEW.created_at IS DISTINCT FROM OLD.created_at
        THEN
            RAISE EXCEPTION 'billing reconciliation source fence cannot be changed'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER billing_provider_events_preserve_fence
BEFORE UPDATE ON public.billing_provider_events
FOR EACH ROW EXECUTE FUNCTION public.billing_preserve_immutable_fence();

CREATE TRIGGER billing_usage_preserve_fence
BEFORE UPDATE ON public.billing_usage
FOR EACH ROW EXECUTE FUNCTION public.billing_preserve_immutable_fence();

CREATE TRIGGER billing_reconciliation_tasks_preserve_fence
BEFORE UPDATE ON public.billing_reconciliation_tasks
FOR EACH ROW EXECUTE FUNCTION public.billing_preserve_immutable_fence();
