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


def detect_success_after_failures(
    connection: sqlite3.Connection, threshold: int = 5
) -> list[Finding]:
    """Flag a successful login from an IP right after repeated failures from that IP.

    Syslog timestamps have no year, so events are compared in ingestion order
    (row id). The failure count resets after each successful login, so a user
    who mistypes a password a few times on different days is not stacked up
    into one alert.
    """
    rows = connection.execute(
        """
        SELECT source_ip, outcome, username, occurred_at
        FROM auth_events
        WHERE source_ip IS NOT NULL
        ORDER BY id
        """
    ).fetchall()
    failures: dict[str, int] = {}
    findings: list[Finding] = []
    for row in rows:
        ip = row["source_ip"]
        if row["outcome"] in ("failed", "invalid_user"):
            failures[ip] = failures.get(ip, 0) + 1
            continue
        if row["outcome"] != "accepted":
            continue
        count = failures.pop(ip, 0)
        if count >= threshold:
            findings.append(
                Finding(
                    rule="AUTH-SUCCESS-AFTER-FAILURES",
                    severity="critical",
                    source_ip=ip,
                    count=count,
                    summary=(
                        f"login accepted for {row['username']} at {row['occurred_at']} "
                        f"after {count} unsuccessful attempts"
                    ),
                )
            )
    return findings
