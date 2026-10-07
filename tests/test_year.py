import subprocess
import sys

from infrasentinel.parser import parse_line

LINE = "Sep 20 10:15:01 web01 sshd[921]: Failed password for invalid user admin from 203.0.113.7 port 51122 ssh2"
LEAP = LINE.replace("Sep 20", "Feb 29")


def test_year_makes_iso_timestamp_and_default_is_unchanged():
    assert parse_line(LINE, 2026).occurred_at == "2026-09-20T10:15:01"
    assert parse_line(LINE).occurred_at == "Sep 20 10:15:01"


def test_padded_single_digit_day():
    assert parse_line(LINE.replace("Sep 20", "Sep  5"), 2026).occurred_at == "2026-09-05T10:15:01"


def test_feb_29_only_exists_in_leap_years():
    assert parse_line(LEAP, 2024).occurred_at == "2024-02-29T10:15:01"
    assert parse_line(LEAP, 2026) is None


def run(*args):
    return subprocess.run([sys.executable, "-m", "infrasentinel.cli", *args], capture_output=True, text=True, check=False)


def test_cli_year_flows_into_findings_and_rejects_bad_year(tmp_path):
    ok = run("sample_data/auth.log", "--database", str(tmp_path / "t.db"), "--year", "2026")
    assert ok.returncode == 0, ok.stderr
    assert "at 2026-09-20T10:20:22" in ok.stdout
    bad = run("sample_data/auth.log", "--database", str(tmp_path / "u.db"), "--year", "26")
    assert bad.returncode != 0 and "--year" in bad.stderr
