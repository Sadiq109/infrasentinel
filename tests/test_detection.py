from infrasentinel.detectors import detect_brute_force
from infrasentinel.models import AuthEvent
from infrasentinel.storage import connect, save_events


def event(number: int, ip: str = "203.0.113.7") -> AuthEvent:
    raw = f"Sep 20 10:15:{number:02d} web01 sshd: Failed password from {ip}"
    return AuthEvent("Sep 20", "web01", "sshd", "failed", "admin", ip, raw)


def test_detects_threshold_and_deduplicates_raw_lines():
    connection = connect(":memory:")
    events = [event(number) for number in range(5)]
    assert save_events(connection, events + [events[0]]) == 5
    findings = detect_brute_force(connection, threshold=5)
    assert len(findings) == 1
    assert findings[0].count == 5
    assert findings[0].severity == "medium"


def test_does_not_flag_below_threshold():
    connection = connect(":memory:")
    save_events(connection, [event(1), event(2)])
    assert detect_brute_force(connection, threshold=3) == []
