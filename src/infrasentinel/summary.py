"""Aggregate persisted authentication events without exposing raw log lines."""

import sqlite3


def summarize(connection: sqlite3.Connection) -> dict:
    counts = {row["outcome"]: row["total"] for row in connection.execute(
        "SELECT outcome, COUNT(*) AS total FROM auth_events GROUP BY outcome"
    )}
    sources = [
        {"source_ip": row["source_ip"], "attempts": row["attempts"]}
        for row in connection.execute(
            """SELECT source_ip, COUNT(*) AS attempts FROM auth_events
               WHERE outcome IN ('failed', 'invalid_user') AND source_ip IS NOT NULL
               GROUP BY source_ip ORDER BY attempts DESC, source_ip LIMIT 5"""
        )
    ]
    return {
        "total_events": sum(counts.values()),
        "outcomes": {name: counts.get(name, 0) for name in
                     ("accepted", "failed", "invalid_user")},
        "distinct_sources": connection.execute(
            "SELECT COUNT(DISTINCT source_ip) FROM auth_events WHERE source_ip IS NOT NULL"
        ).fetchone()[0],
        "top_failed_sources": sources,
    }
