-- v1_schema.sql
-- Initial schema: users table with a single 'name' field.
-- Legacy application queries SELECT id, name, email FROM users.

CREATE TABLE IF NOT EXISTS users (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT    NOT NULL,
    email TEXT    NOT NULL UNIQUE
);

INSERT INTO users (name, email) VALUES ('Alice Smith',   'alice@example.com');
INSERT INTO users (name, email) VALUES ('Bob Jones',     'bob@example.com');
INSERT INTO users (name, email) VALUES ('Carol White',   'carol@example.com');
