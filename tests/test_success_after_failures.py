from infrasentinel.detectors import detect_success_after_failures
from infrasentinel.models import AuthEvent
from infrasentinel.storage import connect, save_events


def ev(second: int, outcome: str, ip: str = "192.0.2.44", user: str = "ubuntu") -> AuthEvent:
    raw = f"Sep 20 10:20:{second:02d} web01 sshd: {outcome} {user} from {ip}"
    return AuthEvent(f"Sep 20 10:20:{second:02d}", "web01", "sshd", outcome, user, ip, raw)


def test_flags_login_after_threshold_failures():
    connection = connect(":memory:")
    save_events(connection, [ev(s, "failed") for s in range(5)] + [ev(10, "accepted")])
    findings = detect_success_after_failures(connection, threshold=5)
    assert len(findings) == 1
    assert findings[0].rule == "AUTH-SUCCESS-AFTER-FAILURES"
    assert findings[0].severity == "critical"
    assert findings[0].count == 5
    assert "ubuntu" in findings[0].summary


def test_ignores_login_below_threshold():
    connection = connect(":memory:")
    save_events(connection, [ev(1, "failed"), ev(2, "failed"), ev(3, "accepted")])
    assert detect_success_after_failures(connection, threshold=3) == []


def test_failures_from_other_ip_do_not_count():
    connection = connect(":memory:")
    events = [ev(s, "failed", ip="203.0.113.7") for s in range(5)]
    save_events(connection, events + [ev(10, "accepted")])
    assert detect_success_after_failures(connection, threshold=5) == []


def test_count_resets_after_each_success():
    connection = connect(":memory:")
    events = [ev(1, "failed"), ev(2, "failed"), ev(3, "accepted"),
              ev(4, "failed"), ev(5, "failed"), ev(6, "accepted")]
    save_events(connection, events)
    assert detect_success_after_failures(connection, threshold=3) == []


def test_invalid_user_attempts_count_as_failures():
    connection = connect(":memory:")
    events = [ev(s, "invalid_user") for s in range(3)] + [ev(10, "accepted")]
    save_events(connection, events)
    assert len(detect_success_after_failures(connection, threshold=3)) == 1
