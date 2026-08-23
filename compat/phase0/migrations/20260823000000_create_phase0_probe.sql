CREATE TABLE phase0_probe (
    id bigint PRIMARY KEY,
    value text NOT NULL
);

INSERT INTO phase0_probe (id, value) VALUES (1, 'offline-ready');
