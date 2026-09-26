import pytest

from infrasentinel.parser import parse_line


def test_parses_failed_password_for_invalid_user():
    event = parse_line(
        "Sep 20 10:15:01 web01 sshd[921]: Failed password for invalid user admin "
        "from 203.0.113.7 port 51122 ssh2"
    )
    assert event is not None
    assert event.outcome == "failed"
    assert event.username == "admin"
    assert event.source_ip == "203.0.113.7"


def test_parses_ipv6_accepted_login():
    event = parse_line(
        "Sep 20 10:16:01 web01 sshd[922]: Accepted publickey for deploy "
        "from 2001:db8::5 port 51123 ssh2"
    )
    assert event is not None
    assert event.outcome == "accepted"
    assert event.source_ip == "2001:db8::5"


def test_ignores_unsupported_line():
    assert parse_line("not a syslog line") is None


@pytest.mark.parametrize("source", ["203.0.113.999", "192.0.2.4x", "2001:db8::zz", "192.0.2.4,"])
@pytest.mark.parametrize("message", [
    "Failed password for root from {source} port 42 ssh2",
    "Accepted password for root from {source} port 42 ssh2",
    "Invalid user root from {source} port 42 ssh2",
])
def test_rejects_malformed_source_address(source, message):
    line = "Sep 20 10:15:01 web01 sshd[921]: " + message.format(source=source)
    assert parse_line(line) is None
