"""
sample_data/app.py — Mock legacy application.

Represents a real-world application that queries the 'users' table using the
original v1 schema (id, name, email).  Used by the Bifrost harvester to
discover which application queries will break when the v2 migration is applied.

Queries present:
    Q1  SELECT id, name, email FROM users WHERE id = 1           — uses 'name' → BREAKS
    Q2  SELECT name FROM users ORDER BY id                       — uses 'name' → BREAKS
    Q3  SELECT id, email FROM users                              — no 'name'   → safe
    Q4  SELECT id, name, email FROM users WHERE email LIKE '%@example.com'
                                                                 — uses 'name' → BREAKS
"""

import sqlite3
from typing import List


# ---------------------------------------------------------------------------
# Simulated data-access layer
# ---------------------------------------------------------------------------

def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> dict:
    """Fetch a single user by primary key — legacy schema query."""
    # Q1
    row = conn.execute(
        "SELECT id, name, email FROM users WHERE id = 1"
    ).fetchone()
    if row is None:
        return {}
    return {"id": row[0], "name": row[1], "email": row[2]}


def list_user_names(conn: sqlite3.Connection) -> List[str]:
    """Return all user names ordered by id — legacy schema query."""
    # Q2
    rows = conn.execute(
        "SELECT name FROM users ORDER BY id"
    ).fetchall()
    return [r[0] for r in rows]


def list_user_emails(conn: sqlite3.Connection) -> List[str]:
    """Return all user ids and emails — does NOT reference 'name', so it is safe."""
    # Q3 — this query is NOT affected by the v2 migration
    rows = conn.execute(
        "SELECT id, email FROM users"
    ).fetchall()
    return [r[1] for r in rows]


def search_users_by_domain(conn: sqlite3.Connection, domain: str) -> List[dict]:
    """Search users whose email matches a domain pattern — legacy schema query."""
    # Q4
    rows = conn.execute(
        "SELECT id, name, email FROM users WHERE email LIKE '%@example.com'"
    ).fetchall()
    return [{"id": r[0], "name": r[1], "email": r[2]} for r in rows]
