import sqlite3
from collections.abc import Iterable
from pathlib import Path

from .models import AuthEvent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS auth_events (
    id INTEGER PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    hostname TEXT NOT NULL,
    service TEXT NOT NULL,
    outcome TEXT NOT NULL,
    username TEXT,
    source_ip TEXT,
    raw_line TEXT NOT NULL,
    UNIQUE(raw_line)
);
CREATE INDEX IF NOT EXISTS idx_auth_events_ip_outcome
ON auth_events(source_ip, outcome);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.executescript(_SCHEMA)
    return connection


def save_events(connection: sqlite3.Connection, events: Iterable[AuthEvent]) -> int:
    before = connection.total_changes
    connection.executemany(
        """
        INSERT OR IGNORE INTO auth_events
        (occurred_at, hostname, service, outcome, username, source_ip, raw_line)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                event.occurred_at,
                event.hostname,
                event.service,
                event.outcome,
                event.username,
                event.source_ip,
                event.raw_line,
            )
            for event in events
        ],
    )
    connection.commit()
    return connection.total_changes - before
