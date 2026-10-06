import subprocess
import sys

from infrasentinel.anonymize import IpAnonymizer
from infrasentinel.detectors import Finding


def test_same_ip_same_label_and_no_address_kept():
    anon = IpAnonymizer()
    a = Finding("R", "high", "192.0.2.44", 5, "x")
    b = Finding("R", "high", "203.0.113.7", 5, "x")
    out = [anon.finding(a), anon.finding(b), anon.finding(a)]
    assert [f.source_ip for f in out] == ["ip-001", "ip-002", "ip-001"]
    assert out[0].count == 5 and a.source_ip == "192.0.2.44"


def run(*args):
    return subprocess.run([sys.executable, "-m", "infrasentinel.cli", *args], capture_output=True, text=True, check=False)


def test_cli_anonymize_hides_ips_in_console_and_export(tmp_path):
    out = tmp_path / "f.csv"
    result = run("sample_data/auth.log", "--database", str(tmp_path / "t.db"), "--anonymize", "--export", str(out))
    assert result.returncode == 0, result.stderr
    for ip in ("192.0.2.44", "203.0.113.7"):
        assert ip not in result.stdout
        assert ip not in out.read_text()
    assert "ip-001" in result.stdout
    json_result = run("sample_data/auth.log", "--database", str(tmp_path / "t2.db"), "--anonymize", "--json")
    assert "192.0.2" not in json_result.stdout
