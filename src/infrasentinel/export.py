import csv
import json
from collections.abc import Iterable
from dataclasses import asdict, fields
from pathlib import Path

from .detectors import Finding

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _safe_cell(value: object) -> object:
    """Stop spreadsheet apps from running a cell as a formula.

    Finding text can include attacker-controlled log fields such as usernames.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def write_findings(path: Path, findings: Iterable[Finding], export_format: str) -> int:
    """Write findings to *path* as CSV or JSON Lines and return the row count."""
    rows = [asdict(finding) for finding in findings]
    with path.open("w", newline="", encoding="utf-8") as handle:
        if export_format == "csv":
            writer = csv.DictWriter(handle, fieldnames=[f.name for f in fields(Finding)])
            writer.writeheader()
            writer.writerows({key: _safe_cell(value) for key, value in row.items()} for row in rows)
        elif export_format == "jsonl":
            for row in rows:
                handle.write(json.dumps(row) + "\n")
        else:
            raise ValueError(f"unsupported export format: {export_format}")
    return len(rows)
