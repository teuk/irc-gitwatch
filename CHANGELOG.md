# Changelog

All notable changes are documented here. The project follows semantic intent while the original production version number is retained for the first public release.

## 0.31 — 2026-09-02

### Added

- Named deterministic self-test registry with `--selftest-list` and a cardinality guard against silently omitted assertions.
- Explicit targeted, fast and full validation profiles with visible progress and fail-fast named checks.
- Synthetic v0.29 and v0.30 persistent-state fixtures with 28 compatibility assertions.
- Public CI coverage for Ubuntu 24.04, Debian 12 and Debian 13.
- CI contract validation for platform coverage, immutable action references and disabled checkout credential persistence.
- Signed webhook HTTP black-box coverage for valid, malformed, private, unsupported, missing-scope and wrong-repository deliveries (31 assertions).
- Webhook/polling reconciliation fixtures proving overlap suppression and catch-up of genuinely new events across process restarts (30 assertions).
- Persistent multi-target IRC fan-out coverage proving delayed acknowledgement, partial write failure, IRC rejection truth, exact missing-target resume, formatted-to-plain fallback, optional-target retirement and duplicate-free restart (57 assertions).
- Persistent-state disaster-recovery coverage for corrupt and missing primary files, validated backup preservation, atomic mode-0600 repair and retained queue acknowledgements (25 assertions).
- Optional `UNDERNET_CHANNEL_SECONDARY`; an explicit empty value disables the secondary target while preserving the channel-qualified primary delivery identity.
- `IRC_REQUIRED_TARGETS`, `IRC_DELIVERY_SETTLE_MS` and `IRC_DELIVERY_RETRY_SECONDS` operational contracts.
- Additive per-target delivery error, retry, pending-acknowledgement and learned plain-text fields in status, dashboard and broadcast JSON.

### Security

- Pin `actions/checkout` v7.0.1 to its full immutable commit SHA and disable persisted Git credentials.

### Fixed

- Avoid an uninitialized-value warning when loading a legacy scalar pending-delivery entry without an explicit id; generated identifiers and runtime behavior are unchanged.
- Do not count a successful socket write as delivered until the IRC rejection window has elapsed.
- Observe IRC numerics 404/442, retain rejected queue items and retry a formatted rejection once as plain UTF-8 text without affecting other targets.
- Complete a persisted four-target queue record when an intentionally retired optional target was its only missing acknowledgement; no successful target is replayed.

### Compatibility

- State schema 11, existing environment variables, routes, IRC commands and Prometheus metrics remain compatible; new configuration and JSON fields are additive.
- The v0.29 and v0.30 fixture contracts now make that promise executable in local and public CI.
- All new scenario entry points are test-only, require explicit `IRC_GITWATCH_TEST_MODE=1`, use synthetic local files and perform no GitHub or IRC network operation.

## 0.30 — 2026-08-30

### Added

- Bounded 30-day, 500-run GitHub Actions history using the existing Actions responses.
- CI pass rate, decisive outcomes, active/resolved incident analysis, MTTR, longest recovery, p50/p95 runtime and green streak.
- Live dashboard reliability panel and additive `ci_reliability` dashboard/status payload.
- Read-only `/ci.json` and `/?api=ci` endpoints.
- `!github reliability`, `!github slo` and `!github incidents` IRC commands.
- Prometheus reliability, incident, recovery, duration and streak gauges.
- Eleven deterministic regressions covering storage, deduplication, inference, IRC, JSON, metrics and dashboard rendering.

### Compatibility

- No additional GitHub request or token permission is required.
- State schema 11, all v0.29 fields, routes, commands, metrics and inert public defaults are preserved.
- Existing v0.29 state loads unchanged; CI reliability coverage begins populating on the next successful Actions scan.

## 0.29 — 2026-08-29

Initial public release of IRC GitWatch.

### Added

- Configurable GitHub repository and public owner account.
- Public-account inventory, hygiene, trends, stale-project detection and change audit.
- Live dashboard account panel, `/account.json`, Prometheus account metrics and IRC portfolio commands.
- Latest GitHub Traffic clone/unique snapshot in the dashboard toolbar and pulse strip.
- Long-term daily traffic history alongside exact rolling 14-day aggregates.
- Built-in cross-account self-test coverage and failure indices.

### Preserved

- HMAC-SHA256 webhook validation and event reconciliation.
- Per-target persistent IRC fan-out queue.
- GitHub Actions monitoring and diagnostic commands.
- UTF-8 normalization and legacy activity repair.
- State schema 11 and the `githubwatch_` metrics namespace.

### Public packaging

- Safe inert defaults, environment template, hardened systemd unit, installer, CI and project documentation.
