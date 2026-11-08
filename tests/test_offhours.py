from infrasentinel.cli import main as cli_main
from infrasentinel.detectors import _log_hour, detect_off_hours_success
from infrasentinel.models import AuthEvent
from infrasentinel.storage import connect, save_events


def event(hour: int, outcome: str = "accepted", ip: str = "203.0.113.50", user: str = "alex") -> AuthEvent:
    return AuthEvent(
        f"Sep 20 {hour:02d}:12:44",
        "web01",
        "sshd",
        outcome,
        user,
        ip,
        f"raw {hour}",
    )


def test_log_hour_handles_syslog_and_iso_timestamps():
    assert _log_hour("Sep 20 03:12:44") == 3
    assert _log_hour("2026-09-20T03:12:44") == 3
    assert _log_hour("2026-09-20T03:12:44-05:00") == 3
    assert _log_hour("2026-09-20T03:12:44.483215-06:00") == 3
    assert _log_hour("not a timestamp") is None


def test_flags_login_accepted_at_night():
    connection = connect(":memory:")
    save_events(connection, [event(3)])
    findings = detect_off_hours_success(connection)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == "AUTH-OFF-HOURS-SUCCESS"
    assert finding.severity == "low"
    assert finding.source_ip == "203.0.113.50"
    assert finding.count == 1
    assert "00:00 and 06:00" in finding.summary
    assert "misuse" not in finding.summary


def test_window_boundaries():
    connection = connect(":memory:")
    save_events(connection, [event(0), event(5), event(6), event(23)])
    findings = detect_off_hours_success(connection)
    assert len(findings) == 1
    assert findings[0].count == 2  # 00:xx and 05:xx only


def test_failures_at_night_are_not_flagged():
    connection = connect(":memory:")
    save_events(connection, [event(2, outcome="failed"), event(3, outcome="invalid_user")])
    assert detect_off_hours_success(connection) == []


def test_night_logins_group_by_ip():
    connection = connect(":memory:")
    save_events(connection, [event(1), event(2), event(3, ip="198.51.100.9")])
    findings = detect_off_hours_success(connection)
    assert {f.source_ip: f.count for f in findings} == {"203.0.113.50": 2, "198.51.100.9": 1}


def test_cli_import_reports_off_hours_finding(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        ["infrasentinel", "sample_data/auth-offhours.log", "--database", str(tmp_path / "t.db"), "--threshold", "5"],
    )
    assert cli_main() == 0
    out = capsys.readouterr().out
    assert "AUTH-OFF-HOURS-SUCCESS" in out
    assert "[LOW]" in out
