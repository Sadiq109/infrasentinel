"""Self-contained HTML report over stored events. No scripts, fonts or network calls."""

import html
from datetime import UTC, datetime
from pathlib import Path

from .detectors import Finding

_STYLE = """
body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 52rem; color: #1a1a1a; }
h1 { font-size: 1.4rem; } h2 { font-size: 1.1rem; border-bottom: 1px solid #ccc; padding-bottom: .2rem; }
table { border-collapse: collapse; margin: .5rem 0 1rem; }
th, td { border: 1px solid #ccc; padding: .3rem .7rem; text-align: left; }
th { background: #f0f0f0; }
.meta, .note { color: #555; font-size: .85rem; }
.sev-critical { color: #b00020; font-weight: 600; }
.sev-high { color: #b06000; font-weight: 600; }
.sev-medium { color: #7a7000; }
"""


def _esc(value: object) -> str:
    return html.escape(str(value))


def render_report(report: dict, findings: list[Finding], generated_at: datetime | None = None) -> str:
    """Render the summary and findings as one self-contained HTML page.

    Every value is HTML-escaped: usernames and IPs come from logs, so they
    are attacker-controlled text, never markup.
    """
    stamp = (generated_at or datetime.now(UTC)).isoformat(timespec="seconds")
    outcome_rows = "".join(
        f"<tr><td>{_esc(name)}</td><td>{count}</td></tr>"
        for name, count in report["outcomes"].items()
    )
    sources = report["top_failed_sources"]
    if sources:
        source_rows = "".join(
            f"<tr><td>{_esc(row['source_ip'])}</td><td>{row['attempts']}</td></tr>" for row in sources
        )
        sources_table = f"<table><tr><th>Source IP</th><th>Unsuccessful attempts</th></tr>{source_rows}</table>"
    else:
        sources_table = "<p>No failed or invalid-user attempts stored.</p>"
    if findings:
        finding_rows = "".join(
            f"<tr><td class=\"sev-{_esc(f.severity)}\">{_esc(f.severity.upper())}</td>"
            f"<td>{_esc(f.rule)}</td><td>{_esc(f.source_ip)}</td><td>{_esc(f.summary)}</td></tr>"
            for f in findings
        )
        findings_table = (
            "<table><tr><th>Severity</th><th>Rule</th><th>Source IP</th><th>Finding</th></tr>"
            f"{finding_rows}</table>"
        )
    else:
        findings_table = "<p>No findings at the selected threshold.</p>"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>InfraSentinel report</title>
<style>{_STYLE}</style>
</head>
<body>
<h1>InfraSentinel report</h1>
<p class="meta">Generated {stamp}. Parsed fields only - no raw log lines.</p>
<h2>Stored events</h2>
<p>{report['total_events']} events from {report['distinct_sources']} distinct source IPs.</p>
<table><tr><th>Outcome</th><th>Events</th></tr>{outcome_rows}</table>
<h2>Top sources of unsuccessful attempts</h2>
{sources_table}
<h2>Findings</h2>
{findings_table}
<p class="note">This file can contain sensitive IPs and usernames. Share it as carefully as the logs themselves.</p>
</body>
</html>
"""


def write_report(path: Path, report: dict, findings: list[Finding]) -> None:
    """Write the HTML report. The caller checks that the file does not exist yet."""
    Path(path).write_text(render_report(report, findings), encoding="utf-8")
