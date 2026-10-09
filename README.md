# InfraSentinel

InfraSentinel is a privacy-first Python CLI that converts Linux authentication logs into structured SQLite records and security findings. It is designed as a practical IT operations and defensive-security project: ingest real system data locally, preserve evidence, run explainable detection rules, and make the results easy to query.

> Status: early build. The parser and two detection rules work end to end; more log sources and reporting are on the roadmap.

## What works

- Parses common OpenSSH accepted, failed-password, and invalid-user events from `sshd` syslog entries only; similar text quoted by other services is ignored
- Supports IPv4 and IPv6 source addresses, rejecting malformed source addresses rather than silently storing a partial match
- Stores normalized events in SQLite with duplicate protection and an index for investigations
- Detects repeated unsuccessful authentication attempts with a configurable threshold
- Flags a successful login that comes right after repeated failures from the same IP (a likely guessed password)
- Emits human-readable or JSON output, and can export findings to CSV or JSON Lines
- Includes unit tests and safe synthetic sample data

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
infrasentinel sample_data/auth.log --threshold 5
```

Expected finding from the synthetic sample:

```text
Imported 12 new events into infrasentinel.db
[MEDIUM] AUTH-BRUTE-FORCE 192.0.2.44: 5 unsuccessful authentication attempts
[MEDIUM] AUTH-BRUTE-FORCE 203.0.113.7: 5 unsuccessful authentication attempts
[CRITICAL] AUTH-SUCCESS-AFTER-FAILURES 192.0.2.44: login accepted for ubuntu at Sep 20 10:20:22 after 5 unsuccessful attempts
```

To inspect the stored database without importing another log, run:

```bash
infrasentinel --summary --database infrasentinel.db
infrasentinel --summary --database infrasentinel.db --json
```

This reports outcome counts, distinct source IPs, and the top five sources of failed or invalid-user attempts. It never prints raw log lines. The database stays local and may contain sensitive IPs and usernames; use only synthetic data for public demos.

For machine-readable output:

```bash
infrasentinel sample_data/auth.log --threshold 5 --json
```

To save findings for a spreadsheet or another tool:

```bash
infrasentinel sample_data/auth.log --export findings.csv
infrasentinel sample_data/auth.log --export findings.jsonl --export-format jsonl
```

The command refuses to overwrite an existing export file. CSV cells that start with `=`, `+`, `-` or `@` get a leading apostrophe, because usernames in a log are attacker-controlled and could otherwise run as spreadsheet formulas.

To catch fast bursts, add `--window-seconds 60` (it needs `--year`). An IP is flagged as `AUTH-BRUTE-FORCE-WINDOW` when it has at least `--threshold` unsuccessful attempts inside any 60-second span, so slow failures spread over days no longer look like an attack. Events stored without a year are ignored by this rule.

Syslog lines carry no year. Pass `--year 2026` to store full ISO timestamps such as `2026-09-20T10:15:01` instead of `Sep 20 10:15:01`. Lines with a date that does not exist in that year (for example Feb 29 in 2026) are skipped. Without `--year`, behavior is unchanged. Time zones are not guessed: timestamps stay in the host's local time as logged.

For demos or screenshots, add `--anonymize` to replace source IPs with labels such as `ip-001` in console output, JSON and exports. The same IP gets the same label within one run, and the mapping is never saved. It does not change the stored database, which still holds the real addresses, and usernames are not masked.

Damaged logs do not abort an import: invalid bytes are replaced and unparseable lines are skipped. A missing or unreadable log file exits with a short error instead of a traceback.

All sample IPs use documentation-only ranges. Do not commit production logs, credentials, personal data, or generated `.db` files.

## Architecture

```text
auth.log -> parser -> AuthEvent -> SQLite -> detection rules -> CLI/JSON
```

The code uses only the Python standard library at runtime. This keeps the first version easy to audit and deploy on a small Linux host.

## Roadmap

See [ROADMAP.md](ROADMAP.md). Near-term work includes time-windowed detections, a summary command, anonymization and CSV export.

## Why this project exists

Many security demos stop at a notebook or copied dashboard. InfraSentinel focuses on the work an entry-level infrastructure or security engineer can explain in an interview: parsing imperfect operational data, choosing a schema, preventing duplicate ingestion, writing deterministic rules, testing edge cases, and documenting safe handling of logs.
