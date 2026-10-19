import ipaddress
import re
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

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


def parse_timezone(value: str) -> tzinfo:
    """Parse UTC, a fixed +HH:MM / -HH:MM offset, or an IANA zone name."""
    text = value.strip()
    if text.upper() in ("UTC", "Z"):
        return UTC
    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", text)
    if match:
        sign, hours, minutes = match.groups()
        if int(hours) > 23 or int(minutes) > 59:
            raise ValueError(f"invalid UTC offset {value!r}")
        offset = timedelta(hours=int(hours), minutes=int(minutes))
        return timezone(-offset if sign == "-" else offset)
    try:
        return ZoneInfo(text)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(
            f"unknown time zone {value!r}; use UTC, an offset like -05:00, "
            "or an IANA name like America/Chicago"
        ) from None


def _with_year(timestamp: str, year: int, tz: tzinfo | None = None) -> str | None:
    """Turn 'Sep 20 10:15:01' into '2026-09-20T10:15:01', or None if the date cannot exist.

    With *tz* the result records the log's time zone, for example
    '2026-09-20T10:15:01-05:00'. The logged local time is never converted.
    """
    try:
        # The year goes in the parsed string so Feb 29 is checked against the real year.
        parsed = datetime.strptime(f"{year} {' '.join(timestamp.split())}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    if tz is not None:
        parsed = parsed.replace(tzinfo=tz)
    return parsed.isoformat()


def parse_line(line: str, year: int | None = None, tz: tzinfo | None = None) -> AuthEvent | None:
    """Parse a supported syslog authentication line without raising on unknown input.

    Syslog timestamps have no year and no time zone. With *year*, occurred_at
    becomes an ISO timestamp; lines whose date does not exist in that year are
    skipped. With *tz*, the ISO timestamp records the log's time zone as a UTC
    offset. Without *tz*, no zone is guessed.
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
                occurred_at = _with_year(occurred_at, year, tz)
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


def parse_lines(lines: Iterable[str], year: int | None = None, tz: tzinfo | None = None) -> Iterator[AuthEvent]:
    for line in lines:
        event = parse_line(line, year, tz)
        if event is not None:
            yield event
