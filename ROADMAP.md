# Roadmap

## Milestone 1: trustworthy ingestion

- [x] Parse accepted, failed-password, and invalid-user OpenSSH events
- [x] Normalize events into SQLite
- [x] Prevent duplicate ingestion
- [x] Add parser and detection unit tests
- [ ] Add year/timezone handling for traditional syslog timestamps
- [ ] Add fixture-based tests for malformed and rotated logs

## Milestone 2: useful detection and investigation

- [x] Configurable repeated-failure threshold
- [ ] Count attempts inside a configurable time window
- [x] Detect a successful login following repeated failures
- [ ] Add `summary` and `search` subcommands
- [ ] Export findings to CSV and JSON Lines

## Milestone 3: safe operations

- [ ] Optional IP anonymization for demos
- [ ] Document retention and deletion controls
- [ ] Add a Docker image and read-only log mount example
- [ ] Run tests and lint checks in GitHub Actions
- [ ] Add a small dashboard only after the CLI and data model are stable
