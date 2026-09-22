import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    source_ip: str
    count: int
    summary: str


def detect_brute_force(
    connection: sqlite3.Connection, threshold: int = 5
) -> list[Finding]:
    """Flag source IPs with at least threshold failed or invalid-user attempts."""
    rows = connection.execute(
        """
        SELECT source_ip, COUNT(*) AS attempts
        FROM auth_events
        WHERE outcome IN ('failed', 'invalid_user') AND source_ip IS NOT NULL
        GROUP BY source_ip
        HAVING COUNT(*) >= ?
        ORDER BY attempts DESC, source_ip
        """,
        (threshold,),
    ).fetchall()
    return [
        Finding(
            rule="AUTH-BRUTE-FORCE",
            severity="high" if row["attempts"] >= threshold * 2 else "medium",
            source_ip=row["source_ip"],
            count=row["attempts"],
            summary=f"{row['attempts']} unsuccessful authentication attempts",
        )
        for row in rows
    ]
