import csv
import json
import subprocess
import sys

import pytest

from infrasentinel.detectors import Finding
from infrasentinel.export import write_findings

FINDING = Finding("AUTH-BRUTE-FORCE", "medium", "203.0.113.7", 5, "5 unsuccessful authentication attempts")


def test_csv_export_has_header_and_neutralizes_formulas(tmp_path):
    hostile = Finding("AUTH-SUCCESS-AFTER-FAILURES", "critical", "192.0.2.44", 5, "=HYPERLINK(\"http://x\")")
    path = tmp_path / "findings.csv"
    assert write_findings(path, [FINDING, hostile], "csv") == 2
    rows = list(csv.DictReader(path.open(newline="", encoding="utf-8")))
    assert rows[0]["source_ip"] == "203.0.113.7"
    assert rows[0]["count"] == "5"
    assert rows[1]["summary"].startswith("'=")


def test_jsonl_export_is_one_object_per_line_and_unmodified(tmp_path):
    path = tmp_path / "findings.jsonl"
    hostile = Finding("R", "high", "192.0.2.1", 1, "=raw")
    write_findings(path, [FINDING, hostile], "jsonl")
    lines = path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["source_ip"] for line in lines] == ["203.0.113.7", "192.0.2.1"]
    assert json.loads(lines[1])["summary"] == "=raw"


def test_empty_findings_still_write_a_valid_csv_header(tmp_path):
    path = tmp_path / "none.csv"
    assert write_findings(path, [], "csv") == 0
    assert path.read_text(encoding="utf-8").strip() == "rule,severity,source_ip,count,summary"


def test_unknown_format_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        write_findings(tmp_path / "x", [FINDING], "xml")


def run(*args):
    return subprocess.run([sys.executable, "-m", "infrasentinel.cli", *args], capture_output=True, text=True, check=False)


def test_cli_exports_and_refuses_to_overwrite(tmp_path):
    out = tmp_path / "findings.csv"
    base = ["sample_data/auth.log", "--database", str(tmp_path / "t.db"), "--export", str(out)]
    first = run(*base)
    assert first.returncode == 0, first.stderr
    assert len(list(csv.DictReader(out.open(newline="")))) == 3
    before = out.read_text()
    second = run(*base)
    assert second.returncode != 0
    assert "already exists" in second.stderr
    assert out.read_text() == before
