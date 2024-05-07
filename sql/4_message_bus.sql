-- FIFO message bus
CREATE SCHEMA IF NOT EXISTS message_bus;

CREATE TABLE IF NOT EXISTS message_bus.events (
    id UUID PRIMARY KEY,
    inserted_at TIMESTAMP NOT NULL DEFAULT NOW(),
    payload BLOB
);

INSERT INTO message_bus.events (id, inserted_at, payload)
VALUES (gen_random_uuid(), NOW(), RAWTOHEX('hello'));

-- DELETE
-- FROM message_bus.events e
-- WHERE e.id =
--       (
--           SELECT e_inner.id,
--                  FROM message_bus.events e_inner
--                  ORDER BY e_inner.inserted_at ASC
--                  LIMIT 1
--           )
-- RETURNING e.id, e.inserted_at, e.payload;



