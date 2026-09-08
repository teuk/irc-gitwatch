# HTTP API

The embedded HTTP listener is intended for loopback use behind a trusted proxy. It supports GET and HEAD diagnostics plus one signed GitHub webhook POST route.

## Security model

- GET/HEAD routes have no built-in authentication.
- Webhook POST requires `GITHUB_WEBHOOK_SECRET` and a valid `X-Hub-Signature-256` HMAC.
- The payload repository must exactly match `GITHUB_REPO` or one entry in `GITHUB_REPOS`.
- Unsupported, malformed, oversized, duplicate and out-of-scope requests are rejected or suppressed and counted.
- Secrets are not serialized into dashboard, status, CI, traffic, account, broadcast or metrics responses.

Do not expose the listener directly to the Internet.

## Routes

| Method | Route | Content |
| --- | --- | --- |
| `GET`, `HEAD` | `/` | Live HTML dashboard. |
| `GET`, `HEAD` | `/repo/<owner>/<repository>` | Repository-selected live HTML dashboard and deep link. |
| `GET`, `HEAD` | `/?asset=dashboard-js` | Dashboard JavaScript. |
| `GET`, `HEAD` | `/?api=dashboard` | Full live dashboard JSON; optional `&repo=owner/name`. |
| `GET`, `HEAD` | `/?api=ci` | CI reliability JSON alias; optional `&repo=owner/name`. |
| `GET`, `HEAD` | `/?api=traffic` | Traffic JSON alias; optional `&repo=owner/name`. |
| `GET`, `HEAD` | `/?api=account` | Account JSON alias. |
| `GET`, `HEAD` | `/?api=broadcast` | Broadcast JSON alias. |
| `GET`, `HEAD` | `/status.json` | Compact service/runtime JSON. |
| `GET`, `HEAD` | `/ci.json` | Bounded CI reliability, incident and runtime analysis; optional `?repo=owner/name`. |
| `GET`, `HEAD` | `/traffic.json` | Exact 14-day traffic, daily history and semantics; optional `?repo=owner/name`. |
| `GET`, `HEAD` | `/account.json` | Public owner portfolio, history and changes. |
| `GET`, `HEAD` | `/broadcast.json` | Queue and per-target delivery audit. |
| `GET`, `HEAD` | `/healthz` | Aggregate health report. |
| `GET`, `HEAD` | `/livez` | Listener/process liveness. |
| `GET`, `HEAD` | `/readyz` | Readiness for useful operation. |
| `GET`, `HEAD` | `/metrics` | Prometheus text format when enabled. |
| `POST` | configured webhook path | Signed GitHub delivery. |

The configured webhook path defaults to `/githubhook`. With `GITHUB_WEBHOOK_ROOT_ALIAS=1`, signed POSTs to `/` are also accepted for compatibility; ordinary GET `/` remains the dashboard.

Dashboard deep links serve the same HTML shell, JavaScript asset and JSON aliases beneath `/repo/<owner>/<repository>`. The header selector and watched-project rail use `history.pushState`; browser Back/Forward restores the URL-selected repository without a full page reload. The rail derives its per-project Events, CI and Traffic indicators from the additive `repositories` rows already carried by dashboard JSON. Unknown or unconfigured repository paths return `404`. A reverse proxy exposing the dashboard must forward `/repo/` in addition to `/`.

## Response stability

Fields remain additive in 0.34. Consumers should ignore unknown JSON keys. Existing field removal or semantic changes require a changelog entry and migration note. `/status.json` exposes the ordered `repos` list and a `repositories` status row for each scope while keeping `repo` as the primary scope. Dashboard JSON adds `selected_repo`, `primary_repo` and `dashboard.repository_path`; `github_traffic.repo` and `ci_reliability.repo` explicitly identify the repository-scoped Traffic and CI fields and match `selected_repo`.

`github_traffic.latest` retains the newest GitHub daily row and can therefore describe the current partial UTC day. The additive `github_traffic.last_closed` object excludes today, prefers yesterday, and otherwise selects the newest earlier row. It includes `available`, `date`, `target_date`, `lag_days`, `fallback`, clone/view totals and GitHub aggregate unique counts. This makes a delayed J-2 value explicit instead of silently presenting it as J-1.

`ci_reliability` is additive in dashboard/status JSON. The dedicated CI payload reports retention bounds, coverage, outcomes, pass rate, incidents, recovery time, duration percentiles, green streak and a short recent-run list. Empty history returns a `waiting` state rather than inventing a reliability result.

Prometheus metrics retain the historical `githubwatch_` prefix. The additive `githubwatch_repository_*` gauges use a `repo` label for per-repository Events, Actions, CI and freshness. Last-closed traffic is exposed through `githubwatch_github_last_closed_daily_{available,lag_days,clones,clone_uniques}`. Labels include configured repository/account and IRC target metadata but never credentials.

## IRC delivery truth

`status.json` and the dashboard payload expose each configured `irc.targets[]` entry with `awaiting`, `delivery_error`, `delivery_retry_at` and `plain_only`. The IRC object also includes the effective `required_targets` contract.

The broadcast payload exposes the same state per target; its retry timestamp is named `retry_at`. `awaiting: 1` means bytes were written but are still inside the short IRC rejection window, not that delivery has already been acknowledged. A numeric 404/442 clears that pending acknowledgement, retains the queue record and records the error. A formatted rejection is retried once as plain UTF-8 for that channel only.

## Health semantics

- `/livez` answers whether the process and local listener are alive.
- `/readyz` accounts for configuration and operational dependencies.
- `/healthz` includes current issues and can be degraded while the dashboard remains reachable.

Use `/livez` for process restart policy, `/readyz` for traffic admission, and `/healthz` for alerts.
