CREATE TABLE reference_records (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT reference_records_name_nonblank CHECK (name ~ '[^[:space:]]'),
    CONSTRAINT reference_records_id_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7
        AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT reference_records_name_length CHECK (char_length(name) <= 100),
    CONSTRAINT reference_records_timeline CHECK (updated_at >= created_at)
);
