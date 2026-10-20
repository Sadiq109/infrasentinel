import subprocess
import sys
from datetime import UTC, datetime

from infrasentinel.detectors import Finding
from infrasentinel.report import render_report

REPORT = {
    "total_events": 12,
    "distinct_sources": 3,
    "outcomes": {"accepted": 2, "failed": 7, "invalid_user": 3},
    "top_failed_sources": [{"source_ip": "203.0.113.7", "attempts": 5}],
}
FINDINGS = [
    Finding("AUTH-BRUTE-FORCE", "medium", "203.0.113.7", 5, "5 unsuccessful authentication attempts"),
    Finding("AUTH-SUCCESS-AFTER-FAILURES", "critical", "192.0.2.44", 5,
            "login accepted for ubuntu at Sep 20 10:20:22 after 5 unsuccessful attempts"),
]
STAMP = datetime(2026, 10, 20, 12, 0, 0, tzinfo=UTC)


def run(*args):
    return subprocess.run([sys.executable, "-m", "infrasentinel.cli", *args], capture_output=True, text=True, check=False)


def test_render_contains_summary_and_findings():
    page = render_report(REPORT, FINDINGS, STAMP)
    assert "12 events from 3 distinct source IPs" in page
    assert "<td>failed</td><td>7</td>" in page
    assert "203.0.113.7" in page and "AUTH-BRUTE-FORCE" in page
    assert "sev-critical" in page
    assert "2026-10-20T12:00:00+00:00" in page


def test_render_escapes_attacker_controlled_text():
    evil = dict(REPORT, top_failed_sources=[{"source_ip": "<script>alert(1)</script>", "attempts": 9}])
    findings = [Finding("R", "high", "203.0.113.7", 1, "login accepted for <b>root</b> at x after 1 attempts")]
    page = render_report(evil, findings, STAMP)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page and "&lt;b&gt;root&lt;/b&gt;" in page


def test_render_empty_states():
    empty = {"total_events": 0, "distinct_sources": 0,
             "outcomes": {"accepted": 0, "failed": 0, "invalid_user": 0}, "top_failed_sources": []}
    page = render_report(empty, [], STAMP)
    assert "No failed or invalid-user attempts stored." in page
    assert "No findings at the selected threshold." in page


def test_cli_writes_report(tmp_path):
    db = tmp_path / "t.db"
    out = tmp_path / "report.html"
    assert run("sample_data/auth.log", "--database", str(db)).returncode == 0
    result = run("--report", str(out), "--database", str(db))
    assert result.returncode == 0, result.stderr
    assert "Wrote HTML report" in result.stdout
    page = out.read_text()
    assert "InfraSentinel report" in page and "AUTH-SUCCESS-AFTER-FAILURES" in page
    assert "http" not in page.split("<body>")[0].replace("<!doctype html>", "")


def test_cli_report_refuses_overwrite_and_missing_db(tmp_path):
    db = tmp_path / "t.db"
    assert run("sample_data/auth.log", "--database", str(db)).returncode == 0
    out = tmp_path / "report.html"
    assert run("--report", str(out), "--database", str(db)).returncode == 0
    again = run("--report", str(out), "--database", str(db))
    assert again.returncode != 0 and "already exists" in again.stderr
    missing = run("--report", str(tmp_path / "r2.html"), "--database", str(tmp_path / "no.db"))
    assert missing.returncode != 0 and "does not exist" in missing.stderr


def test_cli_report_rejects_combinations(tmp_path):
    db = tmp_path / "t.db"
    for extra in (["sample_data/auth.log"], ["--summary"], ["--search"], ["--export", str(tmp_path / "x.csv")], ["--purge"]):
        result = run("--report", str(tmp_path / "r.html"), "--database", str(db), *extra)
        assert result.returncode != 0, extra
        assert "--report cannot be combined" in result.stderr


def test_cli_report_anonymizes_ips(tmp_path):
    db = tmp_path / "t.db"
    assert run("sample_data/auth.log", "--database", str(db)).returncode == 0
    out = tmp_path / "report.html"
    assert run("--report", str(out), "--database", str(db), "--anonymize").returncode == 0
    page = out.read_text()
    assert "203.0.113.7" not in page and "192.0.2.44" not in page
    assert "ip-001" in page
