import ipaddress
import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from .models import AuthEvent

_PREFIX = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>[\w-]+)(?:\[\d+\])?:\s+(?P<body>.*)$"
)
_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)"
)
_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")


def _with_year(timestamp: str, year: int) -> str | None:
    """Turn 'Sep 20 10:15:01' into '2026-09-20T10:15:01', or None if the date cannot exist."""
    try:
        # The year goes in the parsed string so Feb 29 is checked against the real year.
        parsed = datetime.strptime(f"{year} {' '.join(timestamp.split())}", "%Y %b %d %H:%M:%S")  # noqa: DTZ007 - syslog has no zone
    except ValueError:
        return None
    return parsed.isoformat()


def parse_line(line: str, year: int | None = None) -> AuthEvent | None:
    """Parse a supported syslog authentication line without raising on unknown input.

    Syslog timestamps have no year. With *year*, occurred_at becomes an ISO
    timestamp; lines whose date does not exist in that year are skipped.
    """
    line = line.rstrip("\n")
    prefix = _PREFIX.match(line)
    if not prefix or prefix.group("service") != "sshd":
        return None

    body = prefix.group("body")
    for outcome, pattern in (
        ("failed", _FAILED),
        ("accepted", _ACCEPTED),
        ("invalid_user", _INVALID),
    ):
        match = pattern.search(body)
        if match:
            try:
                ipaddress.ip_address(match.group("ip"))
            except ValueError:
                # Reject malformed source addresses instead of saving a partial match.
                return None
            occurred_at = prefix.group("timestamp")
            if year is not None:
                occurred_at = _with_year(occurred_at, year)
                if occurred_at is None:
                    return None
            return AuthEvent(
                occurred_at=occurred_at,
                hostname=prefix.group("host"),
                service=prefix.group("service"),
                outcome=outcome,
                username=match.group("user"),
                source_ip=match.group("ip"),
                raw_line=line,
            )
    return None


def parse_lines(lines: Iterable[str], year: int | None = None) -> Iterator[AuthEvent]:
    for line in lines:
        event = parse_line(line, year)
        if event is not None:
            yield event
