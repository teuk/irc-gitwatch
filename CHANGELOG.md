# Changelog

All notable changes are documented here. The project follows semantic intent while the original production version number is retained for the first public release.

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
