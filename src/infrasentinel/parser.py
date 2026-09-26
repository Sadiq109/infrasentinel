import ipaddress
import re
from collections.abc import Iterable, Iterator

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


def parse_line(line: str) -> AuthEvent | None:
    """Parse a supported syslog authentication line without raising on unknown input."""
    line = line.rstrip("\n")
    prefix = _PREFIX.match(line)
    if not prefix:
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
            return AuthEvent(
                occurred_at=prefix.group("timestamp"),
                hostname=prefix.group("host"),
                service=prefix.group("service"),
                outcome=outcome,
                username=match.group("user"),
                source_ip=match.group("ip"),
                raw_line=line,
            )
    return None


def parse_lines(lines: Iterable[str]) -> Iterator[AuthEvent]:
    for line in lines:
        event = parse_line(line)
        if event is not None:
            yield event
