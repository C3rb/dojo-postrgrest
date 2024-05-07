BEGIN;
CREATE SCHEMA api;

GRANT USAGE ON SCHEMA api TO web_anon;

CREATE TABLE api.todos
(
    id   SERIAL PRIMARY KEY,
    done BOOLEAN NOT NULL DEFAULT FALSE,
    task TEXT    NOT NULL,
    due  timestamptz
);
GRANT SELECT ON api.todos TO web_anon;

INSERT INTO api.todos (task)
VALUES ('finish tutorial 0'),
       ('pat self on back');

CREATE ROLE todo_user nologin;
grant todo_user to authenticator;

GRANT USAGE ON SCHEMA api TO todo_user;
GRANT ALL ON api.todos TO todo_user;
GRANT USAGE, SELECT ON SEQUENCE api.todos_id_seq TO todo_user;

COMMIT;
