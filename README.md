# InfraSentinel

InfraSentinel is a privacy-first Python CLI that converts Linux authentication logs into structured SQLite records and security findings. It is designed as a practical IT operations and defensive-security project: ingest real system data locally, preserve evidence, run explainable detection rules, and make the results easy to query.

> Status: early private build. The parser and first brute-force rule work end to end; more log sources and reporting are on the roadmap.

## What works

- Parses common OpenSSH accepted, failed-password, and invalid-user events
- Supports IPv4 and IPv6 source addresses
- Stores normalized events in SQLite with duplicate protection and an index for investigations
- Detects repeated unsuccessful authentication attempts with a configurable threshold
- Emits human-readable or JSON output
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
Imported 6 new events into infrasentinel.db
[MEDIUM] AUTH-BRUTE-FORCE 203.0.113.7: 5 unsuccessful authentication attempts
```

For machine-readable output:

```bash
infrasentinel sample_data/auth.log --threshold 5 --json
```

All sample IPs use documentation-only ranges. Do not commit production logs, credentials, personal data, or generated `.db` files.

## Architecture

```text
auth.log -> parser -> AuthEvent -> SQLite -> detection rules -> CLI/JSON
```

The code uses only the Python standard library at runtime. This keeps the first version easy to audit and deploy on a small Linux host.

## Roadmap

See [ROADMAP.md](ROADMAP.md). Near-term work includes time-windowed detections, a summary command, anonymization, CSV export, and GitHub Actions checks.

## Why this project exists

Many security demos stop at a notebook or copied dashboard. InfraSentinel focuses on the work an entry-level infrastructure or security engineer can explain in an interview: parsing imperfect operational data, choosing a schema, preventing duplicate ingestion, writing deterministic rules, testing edge cases, and documenting safe handling of logs.
