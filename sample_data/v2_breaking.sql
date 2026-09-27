-- v2_breaking.sql
-- Destructive migration: removes 'name', introduces 'first_name' and 'last_name'.
-- Any legacy query referencing the 'name' column will break after this migration.

ALTER TABLE users RENAME TO users_old;

CREATE TABLE users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT    NOT NULL,
    last_name  TEXT    NOT NULL,
    email      TEXT    NOT NULL UNIQUE
);

INSERT INTO users (id, first_name, last_name, email)
SELECT
    id,
    TRIM(SUBSTR(name, 1, INSTR(name || ' ', ' ') - 1)),
    TRIM(SUBSTR(name, INSTR(name || ' ', ' ') + 1)),
    email
FROM users_old;

DROP TABLE users_old;
