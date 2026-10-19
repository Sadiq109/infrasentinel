import subprocess
import sys

import pytest

from infrasentinel.detectors import detect_brute_force_window
from infrasentinel.models import AuthEvent
from infrasentinel.parser import parse_line, parse_timezone
from infrasentinel.storage import connect, save_events

LINE = "Sep 20 10:15:01 web01 sshd[99]: Failed password for root from 203.0.113.7 port 22 ssh2"


def run(*args):
    return subprocess.run([sys.executable, "-m", "infrasentinel.cli", *args], capture_output=True, text=True, check=False)


def test_fixed_offset_is_recorded():
    event = parse_line(LINE, 2026, parse_timezone("-05:00"))
    assert event.occurred_at == "2026-09-20T10:15:01-05:00"


def test_utc_is_recorded():
    event = parse_line(LINE, 2026, parse_timezone("UTC"))
    assert event.occurred_at == "2026-09-20T10:15:01+00:00"


def test_iana_zone_uses_the_right_offset_for_the_date():
    zone = parse_timezone("America/Chicago")
    summer = parse_line(LINE, 2026, zone)
    winter = parse_line(LINE.replace("Sep 20", "Nov 20"), 2026, zone)
    assert summer.occurred_at == "2026-09-20T10:15:01-05:00"  # CDT
    assert winter.occurred_at == "2026-11-20T10:15:01-06:00"  # CST


def test_logged_local_time_is_never_converted():
    # 10:15:01 stays 10:15:01; only the offset is attached.
    for value in ("+02:00", "-09:30", "UTC"):
        event = parse_line(LINE, 2026, parse_timezone(value))
        assert "T10:15:01" in event.occurred_at


def test_bad_timezones_are_rejected():
    for value in ("Mars/Olympus", "+25:00", "-05:99", "soon", ""):
        with pytest.raises(ValueError):
            parse_timezone(value)


def test_cli_timezone_needs_year(tmp_path):
    result = run("sample_data/auth.log", "--timezone", "UTC")
    assert result.returncode != 0
    assert "--timezone needs --year" in result.stderr


def test_cli_rejects_unknown_timezone(tmp_path):
    result = run("sample_data/auth.log", "--year", "2026", "--timezone", "Mars/Olympus")
    assert result.returncode != 0
    assert "unknown time zone" in result.stderr


def test_cli_stores_zoned_timestamps(tmp_path):
    db = tmp_path / "events.db"
    result = run("sample_data/auth.log", "--database", str(db), "--year", "2026", "--timezone", "UTC", "--json")
    assert result.returncode == 0, result.stderr
    rows = connect(db).execute("SELECT occurred_at FROM auth_events LIMIT 1").fetchone()
    assert rows["occurred_at"].endswith("+00:00")


def fail(ts, ip="203.0.113.7"):
    return AuthEvent(ts, "web01", "sshd", "failed", "root", ip, f"{ts} web01 sshd: Failed password from {ip}")


def test_window_compares_zoned_events_in_absolute_time():
    # 10:00:00 UTC and 05:00:30 at -05:00 are 30 seconds apart.
    db = connect(":memory:")
    save_events(db, [fail("2026-09-20T10:00:00+00:00"), fail("2026-09-20T05:00:30-05:00")])
    found = detect_brute_force_window(db, 2, 60)
    assert [(f.source_ip, f.count) for f in found] == [("203.0.113.7", 2)]


def test_window_never_mixes_naive_and_zoned_timestamps():
    # One naive and one zoned burst from the same IP stay in separate windows:
    # neither bucket reaches the threshold on its own.
    db = connect(":memory:")
    events = [fail(f"2026-09-20T10:00:0{s}") for s in range(2)]
    events += [fail(f"2026-09-20T10:00:0{s}+00:00") for s in range(2)]
    save_events(db, events)
    assert detect_brute_force_window(db, 3, 60) == []
