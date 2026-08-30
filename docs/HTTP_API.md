# HTTP API

The embedded HTTP listener is intended for loopback use behind a trusted proxy. It supports GET and HEAD diagnostics plus one signed GitHub webhook POST route.

## Security model

- GET/HEAD routes have no built-in authentication.
- Webhook POST requires `GITHUB_WEBHOOK_SECRET` and a valid `X-Hub-Signature-256` HMAC.
- The payload repository must exactly match `GITHUB_REPO`.
- Unsupported, malformed, oversized, duplicate and out-of-scope requests are rejected or suppressed and counted.
- Secrets are not serialized into dashboard, status, CI, traffic, account, broadcast or metrics responses.

Do not expose the listener directly to the Internet.

## Routes

| Method | Route | Content |
| --- | --- | --- |
| `GET`, `HEAD` | `/` | Live HTML dashboard. |
| `GET`, `HEAD` | `/?asset=dashboard-js` | Dashboard JavaScript. |
| `GET`, `HEAD` | `/?api=dashboard` | Full live dashboard JSON. |
| `GET`, `HEAD` | `/?api=ci` | CI reliability JSON alias. |
| `GET`, `HEAD` | `/?api=traffic` | Traffic JSON alias. |
| `GET`, `HEAD` | `/?api=account` | Account JSON alias. |
| `GET`, `HEAD` | `/?api=broadcast` | Broadcast JSON alias. |
| `GET`, `HEAD` | `/status.json` | Compact service/runtime JSON. |
| `GET`, `HEAD` | `/ci.json` | Bounded CI reliability, incident and runtime analysis. |
| `GET`, `HEAD` | `/traffic.json` | Exact 14-day traffic, daily history and semantics. |
| `GET`, `HEAD` | `/account.json` | Public owner portfolio, history and changes. |
| `GET`, `HEAD` | `/broadcast.json` | Queue and per-target delivery audit. |
| `GET`, `HEAD` | `/healthz` | Aggregate health report. |
| `GET`, `HEAD` | `/livez` | Listener/process liveness. |
| `GET`, `HEAD` | `/readyz` | Readiness for useful operation. |
| `GET`, `HEAD` | `/metrics` | Prometheus text format when enabled. |
| `POST` | configured webhook path | Signed GitHub delivery. |

The configured webhook path defaults to `/githubhook`. With `GITHUB_WEBHOOK_ROOT_ALIAS=1`, signed POSTs to `/` are also accepted for compatibility; ordinary GET `/` remains the dashboard.

## Response stability

Fields remain additive in 0.30. Consumers should ignore unknown JSON keys. Existing field removal or semantic changes require a changelog entry and migration note.

`ci_reliability` is additive in dashboard/status JSON. The dedicated CI payload reports retention bounds, coverage, outcomes, pass rate, incidents, recovery time, duration percentiles, green streak and a short recent-run list. Empty history returns a `waiting` state rather than inventing a reliability result.

Prometheus metrics retain the historical `githubwatch_` prefix. Labels include configured repository/account and IRC target metadata but never credentials.

## Health semantics

- `/livez` answers whether the process and local listener are alive.
- `/readyz` accounts for configuration and operational dependencies.
- `/healthz` includes current issues and can be degraded while the dashboard remains reachable.

Use `/livez` for process restart policy, `/readyz` for traffic admission, and `/healthz` for alerts.
