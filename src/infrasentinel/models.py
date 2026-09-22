from dataclasses import dataclass


@dataclass(frozen=True)
class AuthEvent:
    occurred_at: str
    hostname: str
    service: str
    outcome: str
    username: str | None
    source_ip: str | None
    raw_line: str
