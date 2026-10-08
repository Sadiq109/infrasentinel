import subprocess
import sys

from infrasentinel.detectors import detect_brute_force_window
from infrasentinel.models import AuthEvent
from infrasentinel.storage import connect, save_events


def fail(ts, ip="203.0.113.7"):
    return AuthEvent(ts, "web01", "sshd", "failed", "root", ip, f"{ts} web01 sshd: Failed password from {ip}")


def test_burst_is_flagged_and_boundary_is_inclusive():
    db = connect(":memory:")
    save_events(db, [fail(f"2026-09-20T10:00:{s:02d}") for s in (0, 20, 40, 59)])
    assert detect_brute_force_window(db, 4, 59)[0].count == 4
    assert detect_brute_force_window(db, 4, 58) == []


def test_slow_failures_across_days_are_not_flagged():
    db = connect(":memory:")
    save_events(db, [fail(f"2026-09-{d:02d}T10:00:00") for d in range(10, 16)])
    assert detect_brute_force_window(db, 3, 3600) == []


def test_best_window_is_used_and_ips_are_separate():
    db = connect(":memory:")
    events = [fail("2026-09-20T01:00:00"), fail("2026-09-20T09:00:00")]
    events += [fail(f"2026-09-20T10:00:0{s}") for s in range(3)]
    events += [fail("2026-09-20T10:00:00", "192.0.2.9")]
    save_events(db, events)
    found = detect_brute_force_window(db, 3, 10)
    assert [(f.source_ip, f.count) for f in found] == [("203.0.113.7", 3)]


def test_events_without_year_are_ignored():
    db = connect(":memory:")
    save_events(db, [fail(f"Sep 20 10:00:0{s}") for s in range(5)])
    assert detect_brute_force_window(db, 2, 60) == []


def run(*args):
    return subprocess.run([sys.executable, "-m", "infrasentinel.cli", *args], capture_output=True, text=True, check=False)


def test_cli_window_requires_year_and_reports_rule(tmp_path):
    no_year = run("sample_data/auth.log", "--database", str(tmp_path / "a.db"), "--window-seconds", "60")
    assert no_year.returncode != 0 and "--year" in no_year.stderr
    ok = run("sample_data/auth.log", "--database", str(tmp_path / "b.db"), "--year", "2026", "--window-seconds", "60")
    assert ok.returncode == 0, ok.stderr
    assert "AUTH-BRUTE-FORCE-WINDOW" in ok.stdout
