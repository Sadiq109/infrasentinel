# Roadmap

## Milestone 1: trustworthy ingestion

- [x] Parse accepted, failed-password, and invalid-user OpenSSH events
- [x] Normalize events into SQLite
- [x] Prevent duplicate ingestion
- [x] Add parser and detection unit tests
- [x] Add year handling for traditional syslog timestamps (`--year`)
- [ ] Record the log's time zone
- [x] Add fixture-based tests for malformed and damaged logs (invalid bytes, missing file)

## Milestone 2: useful detection and investigation

- [x] Configurable repeated-failure threshold
- [x] Count attempts inside a configurable time window (`--window-seconds`)
- [x] Detect a successful login following repeated failures
- [x] Add a summary mode for stored events
- [ ] Add a search subcommand
- [x] Export findings to CSV and JSON Lines

## Milestone 3: safe operations

- [x] Optional IP anonymization for demos
- [ ] Document retention and deletion controls
- [ ] Add a Docker image and read-only log mount example
- [ ] Run tests and lint checks in GitHub Actions
- [ ] Add a small dashboard only after the CLI and data model are stable
