CREATE TABLE short_links (
    code TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expired_at TIMESTAMPTZ NULL,
    CONSTRAINT short_links_code_format CHECK (code ~ '^[0-9a-f]{12}$'),
    CONSTRAINT short_links_target_url_length CHECK (
        btrim(target_url) <> ''
        AND octet_length(target_url) <= 2048
    ),
    CONSTRAINT short_links_expiry_order CHECK (
        expired_at IS NULL OR expired_at >= created_at
    )
);

CREATE INDEX short_links_created_at_idx
    ON short_links (created_at DESC, code DESC);
