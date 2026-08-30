CREATE FUNCTION llm_prompt_text_array_is_canonical(
    candidate text[],
    maximum_count integer,
    maximum_octets integer
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
    SELECT cardinality(candidate) <= maximum_count
        AND array_position(candidate, NULL) IS NULL
        AND NOT EXISTS (
            SELECT 1
            FROM unnest(candidate) AS value(item)
            WHERE octet_length(item) NOT BETWEEN 1 AND maximum_octets
                OR item COLLATE "C" !~ '^[A-Za-z0-9._:/@-]+$'
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

CREATE FUNCTION llm_prompt_rollout_metadata_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
DECLARE
    metadata_key text;
    metadata_value jsonb;
BEGIN
    IF jsonb_typeof(candidate) <> 'object' THEN
        RETURN false;
    END IF;
    IF (SELECT count(*) FROM jsonb_object_keys(candidate)) > 256 THEN
        RETURN false;
    END IF;

    FOR metadata_key, metadata_value IN SELECT key, value FROM jsonb_each(candidate) LOOP
        IF octet_length(metadata_key) NOT BETWEEN 1 AND 128
            OR metadata_key COLLATE "C" !~ '^[A-Za-z0-9._-]+$'
            OR jsonb_typeof(metadata_value) <> 'string'
            OR octet_length(metadata_value #>> '{}') > 2048 THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE FUNCTION llm_prompt_json_compact_octets(candidate jsonb, depth integer DEFAULT 0)
RETURNS bigint
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
DECLARE
    child jsonb;
    object_key text;
    total bigint := 0;
    item_count bigint := 0;
BEGIN
    IF depth > 32 OR (depth = 0 AND pg_column_size(candidate) > 131072) THEN
        RETURN 65537;
    END IF;

    CASE jsonb_typeof(candidate)
        WHEN 'array' THEN
            total := 2;
            FOR child IN SELECT value FROM jsonb_array_elements(candidate) LOOP
                item_count := item_count + 1;
                total := total + llm_prompt_json_compact_octets(child, depth + 1);
            END LOOP;
            RETURN total + greatest(item_count - 1, 0);
        WHEN 'object' THEN
            total := 2;
            FOR object_key, child IN SELECT key, value FROM jsonb_each(candidate) LOOP
                item_count := item_count + 1;
                total := total
                    + octet_length(to_jsonb(object_key)::text)
                    + 1
                    + llm_prompt_json_compact_octets(child, depth + 1);
            END LOOP;
            RETURN total + greatest(item_count - 1, 0);
        ELSE
            RETURN octet_length(candidate::text);
    END CASE;
END;
$$;

CREATE FUNCTION llm_prompt_schema_keywords_are_valid(
    candidate jsonb,
    depth integer DEFAULT 0
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
DECLARE
    child jsonb;
    schema_keyword text;
BEGIN
    IF depth > 32 THEN
        RETURN false;
    END IF;
    IF jsonb_typeof(candidate) = 'boolean' THEN
        RETURN true;
    END IF;
    IF jsonb_typeof(candidate) <> 'object' THEN
        RETURN false;
    END IF;

    IF candidate ? 'required' THEN
        IF jsonb_typeof(candidate -> 'required') <> 'array' THEN
            RETURN false;
        END IF;
        IF EXISTS (
            SELECT 1
            FROM jsonb_array_elements(candidate -> 'required') AS required_name(value)
            WHERE jsonb_typeof(value) <> 'string'
        ) OR (
            SELECT count(*)
            FROM jsonb_array_elements(candidate -> 'required')
        ) <> (
            SELECT count(DISTINCT value #>> '{}')
            FROM jsonb_array_elements(candidate -> 'required') AS required_name(value)
        ) THEN
            RETURN false;
        END IF;
    END IF;

    IF candidate ? 'type' THEN
        IF jsonb_typeof(candidate -> 'type') = 'string' THEN
            IF candidate ->> 'type' NOT IN (
                'null', 'boolean', 'object', 'array', 'number', 'string', 'integer'
            ) THEN
                RETURN false;
            END IF;
        ELSIF jsonb_typeof(candidate -> 'type') = 'array' THEN
            IF jsonb_array_length(candidate -> 'type') = 0
                OR EXISTS (
                    SELECT 1
                    FROM jsonb_array_elements(candidate -> 'type') AS type_name(value)
                    WHERE jsonb_typeof(value) <> 'string'
                        OR value #>> '{}' NOT IN (
                            'null', 'boolean', 'object', 'array', 'number', 'string', 'integer'
                        )
                ) OR (
                    SELECT count(*)
                    FROM jsonb_array_elements(candidate -> 'type')
                ) <> (
                    SELECT count(DISTINCT value #>> '{}')
                    FROM jsonb_array_elements(candidate -> 'type') AS type_name(value)
                ) THEN
                RETURN false;
            END IF;
        ELSE
            RETURN false;
        END IF;
    END IF;

    IF candidate ? 'dependentRequired' THEN
        IF jsonb_typeof(candidate -> 'dependentRequired') <> 'object' THEN
            RETURN false;
        END IF;
        FOR child IN SELECT value FROM jsonb_each(candidate -> 'dependentRequired') LOOP
            IF jsonb_typeof(child) <> 'array' THEN
                RETURN false;
            END IF;
            IF EXISTS (
                SELECT 1
                FROM jsonb_array_elements(child) AS dependent_name(value)
                WHERE jsonb_typeof(value) <> 'string'
            ) OR (
                SELECT count(*)
                FROM jsonb_array_elements(child)
            ) <> (
                SELECT count(DISTINCT value #>> '{}')
                FROM jsonb_array_elements(child) AS dependent_name(value)
            ) THEN
                RETURN false;
            END IF;
        END LOOP;
    END IF;

    IF candidate ? 'multipleOf' THEN
        IF jsonb_typeof(candidate -> 'multipleOf') <> 'number' THEN
            RETURN false;
        END IF;
        IF (candidate ->> 'multipleOf')::numeric <= 0 THEN
            RETURN false;
        END IF;
    END IF;

    FOR schema_keyword IN
        SELECT unnest(ARRAY[
            'maximum',
            'exclusiveMaximum',
            'minimum',
            'exclusiveMinimum'
        ]::text[])
    LOOP
        IF candidate ? schema_keyword
            AND jsonb_typeof(candidate -> schema_keyword) <> 'number' THEN
            RETURN false;
        END IF;
    END LOOP;

    FOR schema_keyword IN
        SELECT unnest(ARRAY[
            'maxLength',
            'minLength',
            'maxItems',
            'minItems',
            'maxContains',
            'minContains',
            'maxProperties',
            'minProperties'
        ]::text[])
    LOOP
        IF candidate ? schema_keyword THEN
            IF jsonb_typeof(candidate -> schema_keyword) <> 'number' THEN
                RETURN false;
            END IF;
            IF (candidate ->> schema_keyword)::numeric < 0
                OR trunc((candidate ->> schema_keyword)::numeric)
                    <> (candidate ->> schema_keyword)::numeric THEN
                RETURN false;
            END IF;
        END IF;
    END LOOP;

    FOR schema_keyword IN
        SELECT unnest(ARRAY[
            '$id',
            '$schema',
            '$anchor',
            '$dynamicRef',
            '$dynamicAnchor',
            '$comment',
            'title',
            'description',
            'pattern',
            'format',
            'contentEncoding',
            'contentMediaType'
        ]::text[])
    LOOP
        IF candidate ? schema_keyword
            AND jsonb_typeof(candidate -> schema_keyword) <> 'string' THEN
            RETURN false;
        END IF;
    END LOOP;

    FOR schema_keyword IN
        SELECT unnest(ARRAY[
            'uniqueItems',
            'deprecated',
            'readOnly',
            'writeOnly'
        ]::text[])
    LOOP
        IF candidate ? schema_keyword
            AND jsonb_typeof(candidate -> schema_keyword) <> 'boolean' THEN
            RETURN false;
        END IF;
    END LOOP;

    IF candidate ? 'examples'
        AND jsonb_typeof(candidate -> 'examples') <> 'array' THEN
        RETURN false;
    END IF;
    IF candidate ? '$vocabulary' THEN
        IF jsonb_typeof(candidate -> '$vocabulary') <> 'object' THEN
            RETURN false;
        END IF;
        IF EXISTS (
            SELECT 1
            FROM jsonb_each(candidate -> '$vocabulary') AS vocabulary_entry(key, value)
            WHERE jsonb_typeof(value) <> 'boolean'
        ) THEN
            RETURN false;
        END IF;
    END IF;

    FOR schema_keyword IN
        SELECT unnest(ARRAY[
            'properties',
            'patternProperties',
            '$defs',
            'dependentSchemas'
        ]::text[])
    LOOP
        IF candidate ? schema_keyword THEN
            IF jsonb_typeof(candidate -> schema_keyword) <> 'object' THEN
                RETURN false;
            END IF;
            FOR child IN SELECT value FROM jsonb_each(candidate -> schema_keyword) LOOP
                IF NOT llm_prompt_schema_keywords_are_valid(child, depth + 1) THEN
                    RETURN false;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    FOR schema_keyword IN
        SELECT unnest(ARRAY[
            'additionalProperties',
            'unevaluatedProperties',
            'unevaluatedItems',
            'propertyNames',
            'contains',
            'not',
            'if',
            'then',
            'else',
            'items',
            'contentSchema'
        ]::text[])
    LOOP
        IF candidate ? schema_keyword
            AND NOT llm_prompt_schema_keywords_are_valid(
                candidate -> schema_keyword,
                depth + 1
            ) THEN
            RETURN false;
        END IF;
    END LOOP;

    FOR schema_keyword IN
        SELECT unnest(ARRAY['prefixItems', 'allOf', 'anyOf', 'oneOf']::text[])
    LOOP
        IF candidate ? schema_keyword THEN
            IF jsonb_typeof(candidate -> schema_keyword) <> 'array' THEN
                RETURN false;
            END IF;
            IF jsonb_array_length(candidate -> schema_keyword) = 0 THEN
                RETURN false;
            END IF;
            FOR child IN SELECT value FROM jsonb_array_elements(candidate -> schema_keyword) LOOP
                IF NOT llm_prompt_schema_keywords_are_valid(child, depth + 1) THEN
                    RETURN false;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    IF candidate ? 'enum'
        AND jsonb_typeof(candidate -> 'enum') <> 'array' THEN
        RETURN false;
    END IF;
    RETURN true;
END;
$$;

CREATE FUNCTION llm_prompt_schema_node_count(candidate jsonb, depth integer)
RETURNS integer
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
DECLARE
    child jsonb;
    child_count integer;
    total integer := 1;
BEGIN
    IF depth > 32 THEN
        RETURN -1;
    END IF;

    IF jsonb_typeof(candidate) = 'object' THEN
        IF candidate ? '$ref'
            AND (
                jsonb_typeof(candidate -> '$ref') <> 'string'
                OR candidate ->> '$ref' NOT LIKE '#/%'
            ) THEN
            RETURN -1;
        END IF;
        FOR child IN SELECT value FROM jsonb_each(candidate) LOOP
            child_count := llm_prompt_schema_node_count(child, depth + 1);
            IF child_count < 0 OR total > 4096 - child_count THEN
                RETURN -1;
            END IF;
            total := total + child_count;
        END LOOP;
    ELSIF jsonb_typeof(candidate) = 'array' THEN
        FOR child IN SELECT value FROM jsonb_array_elements(candidate) LOOP
            child_count := llm_prompt_schema_node_count(child, depth + 1);
            IF child_count < 0 OR total > 4096 - child_count THEN
                RETURN -1;
            END IF;
            total := total + child_count;
        END LOOP;
    END IF;
    RETURN total;
END;
$$;

CREATE FUNCTION llm_prompt_schema_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
    SELECT jsonb_typeof(candidate) = 'object'
        AND candidate ->> 'type' = 'object'
        AND (
            NOT candidate ? 'properties'
            OR jsonb_typeof(candidate -> 'properties') = 'object'
        )
        AND llm_prompt_schema_keywords_are_valid(candidate)
        AND llm_prompt_json_compact_octets(candidate) <= 65536
        AND llm_prompt_schema_node_count(candidate, 0) BETWEEN 1 AND 4096;
$$;

CREATE TABLE llm_prompts (
    prompt_id text PRIMARY KEY,
    latest_revision bigint NOT NULL,
    row_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT llm_prompts_prompt_id_canonical CHECK (
        octet_length(prompt_id) BETWEEN 1 AND 128
        AND prompt_id COLLATE "C" ~ '^[a-z][a-z0-9.-]*$'
    ),
    CONSTRAINT llm_prompts_latest_revision_positive CHECK (latest_revision > 0),
    CONSTRAINT llm_prompts_row_version_positive CHECK (row_version > 0),
    CONSTRAINT llm_prompts_timeline_valid CHECK (updated_at >= created_at)
);

CREATE TABLE llm_prompt_revisions (
    prompt_id text NOT NULL,
    revision bigint NOT NULL,
    status text NOT NULL,
    content_digest bytea NOT NULL,
    input_schema jsonb NOT NULL,
    system_template text,
    developer_template text,
    user_template text NOT NULL,
    owner_id text NOT NULL,
    allowed_routes text[] NOT NULL,
    allowed_tools text[] NOT NULL,
    data_classification text NOT NULL,
    evaluation_sets text[] NOT NULL,
    rollout_metadata jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    published_at timestamptz,
    deprecated_at timestamptz,
    CONSTRAINT llm_prompt_revisions_pkey PRIMARY KEY (prompt_id, revision),
    CONSTRAINT llm_prompt_revisions_prompt_id_fkey FOREIGN KEY (prompt_id)
        REFERENCES llm_prompts (prompt_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT llm_prompt_revisions_revision_positive CHECK (revision > 0),
    CONSTRAINT llm_prompt_revisions_status_known CHECK (
        status IN ('draft', 'published', 'deprecated')
    ),
    CONSTRAINT llm_prompt_revisions_digest_length CHECK (
        octet_length(content_digest) = 32
    ),
    CONSTRAINT llm_prompt_revisions_input_schema_valid CHECK (
        llm_prompt_schema_is_valid(input_schema)
    ),
    CONSTRAINT llm_prompt_revisions_templates_bounded CHECK (
        (system_template IS NULL OR octet_length(system_template) <= 65536)
        AND (developer_template IS NULL OR octet_length(developer_template) <= 65536)
        AND octet_length(user_template) <= 65536
        AND (
            coalesce(system_template, '') <> ''
            OR coalesce(developer_template, '') <> ''
            OR user_template <> ''
        )
    ),
    CONSTRAINT llm_prompt_revisions_owner_id_canonical CHECK (
        octet_length(owner_id) BETWEEN 1 AND 256
        AND owner_id COLLATE "C" ~ '^[A-Za-z0-9._:/@-]+$'
    ),
    CONSTRAINT llm_prompt_revisions_allowed_routes_canonical CHECK (
        llm_prompt_text_array_is_canonical(allowed_routes, 256, 256)
    ),
    CONSTRAINT llm_prompt_revisions_allowed_tools_canonical CHECK (
        llm_prompt_text_array_is_canonical(allowed_tools, 256, 256)
    ),
    CONSTRAINT llm_prompt_revisions_classification_known CHECK (
        data_classification IN ('public', 'internal', 'confidential', 'restricted')
    ),
    CONSTRAINT llm_prompt_revisions_evaluation_sets_canonical CHECK (
        llm_prompt_text_array_is_canonical(evaluation_sets, 256, 256)
    ),
    CONSTRAINT llm_prompt_revisions_rollout_metadata_valid CHECK (
        llm_prompt_rollout_metadata_is_valid(rollout_metadata)
    ),
    CONSTRAINT llm_prompt_revisions_timeline_valid CHECK (
        updated_at >= created_at
        AND (
            (status = 'draft' AND published_at IS NULL AND deprecated_at IS NULL)
            OR (
                status = 'published'
                AND published_at IS NOT NULL
                AND published_at >= created_at
                AND deprecated_at IS NULL
            )
            OR (
                status = 'deprecated'
                AND published_at IS NOT NULL
                AND deprecated_at IS NOT NULL
                AND published_at >= created_at
                AND deprecated_at >= published_at
            )
        )
    )
);

CREATE FUNCTION enforce_llm_prompt_head_progression()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.latest_revision <> 1 OR NEW.row_version <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'llm_prompts_initial_version',
                MESSAGE = 'prompt head must begin at revision one';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'llm_prompts_delete_forbidden',
            MESSAGE = 'prompt heads are retained';
    END IF;

    IF NEW.prompt_id IS DISTINCT FROM OLD.prompt_id
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.latest_revision <> OLD.latest_revision + 1
        OR NEW.row_version <> OLD.row_version + 1
        OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'llm_prompts_revision_progression',
            MESSAGE = 'prompt revisions must advance atomically by one';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER llm_prompts_head_progression
BEFORE INSERT OR UPDATE OR DELETE ON llm_prompts
FOR EACH ROW EXECUTE FUNCTION enforce_llm_prompt_head_progression();

CREATE FUNCTION enforce_llm_prompt_revision_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    parent_latest bigint;
    definition_changed boolean;
    digest_changed boolean;
    content_changed boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'draft' THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'llm_prompt_revisions_insert_draft_only',
                MESSAGE = 'prompt revisions must begin as drafts';
        END IF;
        SELECT latest_revision INTO parent_latest
        FROM public.llm_prompts
        WHERE prompt_id = NEW.prompt_id
        FOR KEY SHARE;
        IF parent_latest IS NULL OR NEW.revision <> parent_latest THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'llm_prompt_revisions_matches_head',
                MESSAGE = 'prompt revision must match the allocated head';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'llm_prompt_revisions_delete_forbidden',
            MESSAGE = 'prompt revisions are retained';
    END IF;

    IF NEW.prompt_id IS DISTINCT FROM OLD.prompt_id
        OR NEW.revision IS DISTINCT FROM OLD.revision
        OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'llm_prompt_revisions_identity_immutable',
            MESSAGE = 'prompt revision identity is immutable';
    END IF;

    digest_changed := NEW.content_digest IS DISTINCT FROM OLD.content_digest;
    definition_changed := NEW.input_schema IS DISTINCT FROM OLD.input_schema
        OR NEW.system_template IS DISTINCT FROM OLD.system_template
        OR NEW.developer_template IS DISTINCT FROM OLD.developer_template
        OR NEW.user_template IS DISTINCT FROM OLD.user_template
        OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
        OR NEW.allowed_routes IS DISTINCT FROM OLD.allowed_routes
        OR NEW.allowed_tools IS DISTINCT FROM OLD.allowed_tools
        OR NEW.data_classification IS DISTINCT FROM OLD.data_classification
        OR NEW.evaluation_sets IS DISTINCT FROM OLD.evaluation_sets
        OR NEW.rollout_metadata IS DISTINCT FROM OLD.rollout_metadata;
    content_changed := digest_changed OR definition_changed;

    IF OLD.status = 'draft' AND NEW.status = 'draft'
        AND definition_changed IS DISTINCT FROM digest_changed THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'llm_prompt_revisions_draft_digest_binding',
            MESSAGE = 'draft content and its digest must change together';
    END IF;

    IF OLD.status = 'deprecated' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'llm_prompt_revisions_published_immutable',
            MESSAGE = 'deprecated prompt revisions are immutable';
    END IF;

    IF OLD.status = 'published' THEN
        IF NEW.status = 'published' AND NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'llm_prompt_revisions_published_immutable',
                MESSAGE = 'published prompt revisions are immutable';
        END IF;
        IF NEW.status = 'deprecated' AND (
            content_changed
            OR NEW.published_at IS DISTINCT FROM OLD.published_at
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'llm_prompt_revisions_published_immutable',
                MESSAGE = 'published prompt content is immutable';
        END IF;
    END IF;

    IF OLD.status = 'draft' AND NEW.status = 'published' AND content_changed THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'llm_prompt_revisions_publish_content_immutable',
            MESSAGE = 'publishing cannot change prompt content';
    END IF;

    IF NEW.status IS DISTINCT FROM OLD.status
        AND NOT (
            (OLD.status = 'draft' AND NEW.status = 'published')
            OR (OLD.status = 'published' AND NEW.status = 'deprecated')
        ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'llm_prompt_revisions_status_transition',
            MESSAGE = 'prompt lifecycle transition is invalid';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER llm_prompt_revisions_lifecycle
BEFORE INSERT OR UPDATE OR DELETE ON llm_prompt_revisions
FOR EACH ROW EXECUTE FUNCTION enforce_llm_prompt_revision_lifecycle();

CREATE FUNCTION enforce_llm_prompt_head_materialized()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM public.llm_prompt_revisions
        WHERE prompt_id = NEW.prompt_id AND revision = NEW.latest_revision
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'llm_prompts_latest_revision_materialized',
            MESSAGE = 'allocated prompt head must have a retained revision';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER llm_prompts_head_materialized
AFTER INSERT OR UPDATE OF latest_revision ON llm_prompts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION enforce_llm_prompt_head_materialized();

CREATE INDEX llm_prompt_revisions_published_idx
    ON llm_prompt_revisions (prompt_id, revision DESC)
    WHERE status = 'published';
CREATE INDEX llm_prompt_revisions_owner_idx
    ON llm_prompt_revisions (owner_id, prompt_id, revision DESC);
CREATE INDEX llm_prompt_revisions_routes_idx
    ON llm_prompt_revisions USING gin (allowed_routes);
CREATE INDEX llm_prompt_revisions_tools_idx
    ON llm_prompt_revisions USING gin (allowed_tools);
