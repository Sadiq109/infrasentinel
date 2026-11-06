from infrasentinel.cli import main as cli_main
from infrasentinel.detectors import detect_brute_force, detect_sudo_repeated_failures
from infrasentinel.models import AuthEvent
from infrasentinel.parser import parse_line
from infrasentinel.storage import connect, save_events

SUDO_FAILURE = (
    "Nov  6 14:23:{sec:02d} web01 sudo: pam_unix(sudo:auth): authentication failure; "
    "logname=alex uid=1000 euid=0 tty=/dev/pts/0 ruser=alex rhost=  user=alex"
)


def sudo_event(number: int, user: str = "alex") -> AuthEvent:
    raw = SUDO_FAILURE.format(sec=number)
    return AuthEvent(f"Nov  6 14:23:{number:02d}", "web01", "sudo", "sudo_failed", user, None, raw)


def test_parses_sudo_auth_failure():
    event = parse_line(SUDO_FAILURE.format(sec=1))
    assert event is not None
    assert event.outcome == "sudo_failed"
    assert event.service == "sudo"
    assert event.username == "alex"
    assert event.source_ip is None


def test_sudo_username_falls_back_to_ruser():
    event = parse_line(
        "Nov  6 14:23:01 web01 sudo: pam_unix(sudo:auth): authentication failure; "
        "logname=alex uid=1000 euid=0 tty=/dev/pts/0 ruser=alex rhost="
    )
    assert event is not None
    assert event.username == "alex"


def test_sudo_failure_records_year_and_timezone():
    event = parse_line(SUDO_FAILURE.format(sec=1), year=2026)
    assert event is not None
    assert event.occurred_at == "2026-11-06T14:23:01"


def test_other_sudo_lines_are_ignored():
    assert parse_line(
        "Nov  6 14:23:10 web01 sudo: pam_unix(sudo:session): session opened for user root by alex(uid=1000)"
    ) is None
    assert parse_line(
        "Nov  6 14:23:10 web01 sudo:     alex : TTY=pts/0 ; PWD=/home/alex ; USER=root ; COMMAND=/usr/bin/apt update"
    ) is None
    # A sudo line quoting SSH text is still not an SSH event.
    assert parse_line(
        "Nov  6 14:23:11 web01 sudo: Failed password for root from 203.0.113.7 port 42 ssh2"
    ) is None


def test_detects_repeated_sudo_failures():
    connection = connect(":memory:")
    save_events(connection, [sudo_event(n) for n in range(5)])
    findings = detect_sudo_repeated_failures(connection, threshold=5)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == "SUDO-REPEATED-FAILURES"
    assert finding.severity == "medium"
    assert finding.source_ip == "local"
    assert finding.count == 5
    assert "alex" in finding.summary
    assert "misuse" not in finding.summary


def test_sudo_failures_below_threshold_not_flagged():
    connection = connect(":memory:")
    save_events(connection, [sudo_event(n) for n in range(4)])
    assert detect_sudo_repeated_failures(connection, threshold=5) == []


def test_sudo_failures_do_not_feed_ip_rules():
    connection = connect(":memory:")
    save_events(connection, [sudo_event(n) for n in range(9)])
    assert detect_brute_force(connection, threshold=5) == []


def test_cli_import_reports_sudo_findings(tmp_path, capsys, monkeypatch):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(SUDO_FAILURE.format(sec=n) for n in range(5)) + "\n")
    monkeypatch.setattr(
        "sys.argv",
        ["infrasentinel", str(log), "--database", str(tmp_path / "test.db"), "--threshold", "5"],
    )
    code = cli_main()
    out = capsys.readouterr().out
    assert code == 0
    assert "SUDO-REPEATED-FAILURES" in out
    assert "5 failed sudo authentication attempts for user alex" in out
