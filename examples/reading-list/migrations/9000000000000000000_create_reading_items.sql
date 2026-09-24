CREATE TABLE reading_items (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    url TEXT NOT NULL,
    finished BOOLEAN NOT NULL DEFAULT FALSE,
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT reading_items_title_valid CHECK (
        title = btrim(title)
        AND title <> ''
        AND octet_length(title) <= 200
    ),
    CONSTRAINT reading_items_url_valid CHECK (
        url = btrim(url)
        AND octet_length(url) <= 2048
        AND url ~ '^https?://'
    ),
    CONSTRAINT reading_items_version_positive CHECK (version > 0),
    CONSTRAINT reading_items_owner_url_unique UNIQUE (owner_id, url)
);

CREATE INDEX reading_items_owner_list_idx
    ON reading_items (owner_id, finished, created_at DESC, id DESC);
