CREATE ROLE web_anon nologin;

CREATE ROLE authenticator NOINHERIT LOGIN PASSWORD 'mysecretpassword';
GRANT web_anon TO authenticator;
