# Configuration reference

IRC GitWatch reads configuration exclusively from environment variables. Values are trimmed; boolean values treat `0`, `no`, `false` and `off` as false. Integer values are clamped to safe ranges.

`--config-check` prints an effective non-secret summary and validates cross-field constraints.

## GitHub and persistence

| Variable | Default | Meaning |
| --- | --- | --- |
| `GITHUB_REPO` | `teuk/irc-gitwatch` | Exact `owner/repository` scope. |
| `GITHUB_ACCOUNT` | repository owner | Public owner portfolio account. |
| `GITHUB_TOKEN` | empty | GitHub API bearer token. |
| `GITHUB_STATE_FILE` | `/var/lib/irc-gitwatch/state.json` | Absolute persistent state path. |
| `STATE_BACKUP_ENABLED` | `1` | Maintain an atomic `.bak` copy. |
| `GITHUB_HTTP_PROXY` | empty | Optional HTTP(S) proxy for GitHub requests. |
| `GITHUB_RATE_SAFETY_SECONDS` | `2` | Safety delay around primary rate reset. |
| `GITHUB_SECONDARY_BACKOFF_MAX_SECONDS` | `900` | Maximum secondary-limit backoff. |

When `GITHUB_ACCOUNT` is empty, the owner portion of `GITHUB_REPO` is used. Portfolio responses are filtered to public, non-private repository records whose owner and full name match this account.

## Webhook and dashboard

| Variable | Default | Meaning |
| --- | --- | --- |
| `GITHUB_WEBHOOK_SECRET` | empty | HMAC-SHA256 secret; POST disabled when empty. |
| `GITHUB_WEBHOOK_BIND` | `127.0.0.1` | Listener address. |
| `GITHUB_WEBHOOK_PORT` | `9510` | Listener port. |
| `GITHUB_WEBHOOK_PATH` | `/githubhook` | Webhook POST path. |
| `GITHUB_WEBHOOK_ROOT_ALIAS` | `1` | Accept signed webhook POSTs on `/` too. |
| `GITHUB_WEBHOOK_MAX_BODY` | `2000000` | Maximum request body bytes. |
| `HTTP_READ_TIMEOUT_SECONDS` | `5` | Client read deadline. |
| `DASHBOARD_PUBLIC_URL` | empty | URL advertised by the IRC `dashboard` command. It does not add access control. |
| `DASHBOARD_POLL_SECONDS` | `3` | Visible-browser refresh period. |
| `DASHBOARD_HIDDEN_POLL_SECONDS` | `20` | Background-tab refresh period. |
| `DASHBOARD_FETCH_TIMEOUT_SECONDS` | `4` | Browser request timeout. |
| `METRICS_ENABLED` | `1` | Serve `/metrics`. |

GET/HEAD routes do not implement authentication. Keep the listener private or add protection at the reverse proxy.

## Repository event polling

| Variable | Default | Meaning |
| --- | --- | --- |
| `GITHUB_POLL_ENABLED` | `1` | Reconcile the public repository event feed. |
| `GITHUB_RECONCILE_SECONDS` | `300` | Base reconciliation interval. |
| `GITHUB_EVENTS_MAX_PAGES` | `3` | Maximum event pages per catch-up scan. |

Webhook and poll events share fingerprints so the same public activity is announced once.

## GitHub Actions

| Variable | Default | Meaning |
| --- | --- | --- |
| `GITHUB_ACTIONS_ENABLED` | `1` | Enable Actions monitoring. |
| `GITHUB_ACTIONS_IDLE_SECONDS` | `120` | Normal polling interval. |
| `GITHUB_ACTIONS_FAST_SECONDS` | `30` | Fast interval after activity. |
| `GITHUB_ACTIONS_FAST_WINDOW_SECONDS` | `900` | Duration of fast mode. |
| `GITHUB_ACTIONS_PER_PAGE` | `20` | Runs requested per API page. |
| `GITHUB_ACTIONS_MAX_PAGES` | `3` | Maximum catch-up pages. |
| `GITHUB_ACTIONS_FAILURES_ONLY` | `1` | Announce failures rather than every completion. |
| `GITHUB_ACTIONS_RECOVERY` | `1` | Announce recovery after a failing workflow/ref. |
| `GITHUB_ACTIONS_ENRICH_FAILURES` | `1` | Fetch failed job names when possible. |
| `GITHUB_ACTIONS_FAILED_JOBS_MAX` | `3` | Job names retained per failure. |
| `GITHUB_ACTIONS_SHOW_JOBS` | `0` | Include job details more broadly. |
| `GITHUB_ACTIONS_SLOW_SECONDS` | `0` | Alert threshold for a running workflow; `0` disables. |
| `GITHUB_ACTIONS_RUNNING_MAX` | `5` | Running workflows shown in status. |
| `GITHUB_ACTIONS_EXPECT_AFTER_PUSH_SECONDS` | `0` | Alert if no workflow appears after a push; `0` disables. |
| `GITHUB_ACTIONS_EXPECT_BRANCHES` | empty | Optional comma-separated expected branches. |
| `GITHUB_ACTIONS_EXPECT_MAX` | `20` | Maximum retained expectations. |
| `GITHUB_ACTIONS_FLAKY_WINDOW_SECONDS` | `0` | Failure/success transition window; `0` disables. |
| `GITHUB_ACTIONS_FLAKY_TRANSITIONS` | `3` | Transitions required for a flaky alert. |

## Traffic and account portfolio

| Variable | Default | Meaning |
| --- | --- | --- |
| `GITHUB_TRAFFIC_ENABLED` | `1` | Fetch clone, view, referrer and path traffic. |
| `GITHUB_TRAFFIC_SECONDS` | `3600` | Traffic refresh interval. |
| `GITHUB_TRAFFIC_TOP` | `5` | Top referrers/paths retained. |
| `GITHUB_ACCOUNT_ENABLED` | `1` | Monitor public owner repositories. |
| `GITHUB_ACCOUNT_SECONDS` | `900` | Portfolio refresh interval. |
| `GITHUB_ACCOUNT_MAX_PAGES` | `3` | Maximum repository inventory pages. |
| `GITHUB_ACCOUNT_TOP` | `6` | Repositories/changes shown per list. |
| `GITHUB_ACCOUNT_STALE_DAYS` | `180` | Stale-project threshold. |
| `GITHUB_ACCOUNT_CHANGES_MAX` | `100` | Retained portfolio changes. |

Exact rolling 14-day totals come from GitHub's traffic API. Daily rows are retained for up to 400 days for longer trends. Unique figures are GitHub aggregates, not IP-address observations.

## IRC presentation and queue

| Variable | Default | Meaning |
| --- | --- | --- |
| `IRC_COLORS` | `1` | Enable IRC formatting/colors. |
| `IRC_ICON_MODE` | `compat` | `compat`, `emoji` or `ascii`. |
| `IRC_STARTUP_ANNOUNCE` | `1` | Send a startup status line after join. |
| `IRC_SEND_INTERVAL_MS` | `800` | Minimum send spacing. |
| `IRC_COMMAND_COOLDOWN_MS` | `750` | Per-user/channel command cooldown. |
| `IRC_RECONNECT_MAX_SECONDS` | `300` | Maximum reconnect delay. |
| `IRC_IDLE_PING_SECONDS` | `300` | Heartbeat idle threshold; `0` disables. |
| `IRC_PONG_TIMEOUT_SECONDS` | `60` | Heartbeat timeout. |
| `HEALTH_QUEUE_WARN` | `150` | Queue size that degrades health. |
| `ACTIVITY_HISTORY_MAX` | `20` | Persistent activity entries. |
| `ACTIVITY_HISTORY_SHOW` | `5` | Entries displayed by default. |
| `BROADCAST_AUDIT_MAX` | `30` | Retained fan-out audit records. |
| `OPS_ALERTS_ENABLED` | `0` | Broadcast health degradation/recovery. |
| `OPS_ALERTS_DEBOUNCE_SECONDS` | `60` | Health alert debounce. |

## EpiKnet-compatible connection

| Variable | Default |
| --- | --- |
| `EPIKNET_ENABLED` | `0` |
| `IRC_HOST` | `irc.epiknet.org` |
| `IRC_PORT` | `6697` |
| `IRC_CHANNEL` | `#irc-gitwatch` |
| `IRC_NICK` / `IRC_USER` | `gitwatch` |
| `IRC_REALNAME` | `IRC GitWatch` |

This connection uses TLS with peer verification.

## Libera Chat

| Variable | Default |
| --- | --- |
| `LIBERA_ENABLED` | `0` |
| `LIBERA_HOST` / `LIBERA_PORT` | `irc.libera.chat` / `6697` |
| `LIBERA_CHANNEL` | `IRC_CHANNEL` |
| `LIBERA_NICK` / `LIBERA_USER` | common IRC identity |
| `LIBERA_REALNAME` | `IRC GitWatch` |
| `LIBERA_SASL_ACCOUNT` / `LIBERA_SASL_PASSWORD` | empty |
| `LIBERA_REQUIRE_SASL` | `1` |

Set SASL account and password together. If SASL is required, registration fails closed when authentication does not succeed.

## Undernet

| Variable | Default |
| --- | --- |
| `UNDERNET_ENABLED` | `0` |
| `UNDERNET_HOST` / `UNDERNET_PORT` | `irc.undernet.org` / `6667` |
| `UNDERNET_TLS` | `0` |
| `UNDERNET_NICK` / `UNDERNET_USER` | common IRC identity |
| `UNDERNET_REALNAME` | `IRC GitWatch` |
| `UNDERNET_CHANNEL_PRIMARY` | `#irc-gitwatch` |
| `UNDERNET_CHANNEL_PRIMARY_KEY` | empty |
| `UNDERNET_CHANNEL_SECONDARY` | `#irc-gitwatch-ops` |
| `UNDERNET_JOIN_RETRY_SECONDS` | `60` |
| `UNDERNET_CONNECT_TIMEOUT_SECONDS` | `5` |
| `UNDERNET_REGISTER_TIMEOUT_SECONDS` | `12` |

Both channels share one TCP connection but remain independent delivery targets. Legacy `UNDERNET_CHANNEL_TEUK`, `UNDERNET_CHANNEL_TEUK_KEY` and `UNDERNET_CHANNEL_MIAW` environment names remain accepted as fallbacks for v0.29 migration.

## RSS/Atom

| Variable | Default | Meaning |
| --- | --- | --- |
| `RSS_ENABLED` | `0` | Enable feed polling. |
| `RSS_URL` | empty | HTTP(S) RSS/Atom URL. |
| `RSS_POLL_SECONDS` | `120` | Poll interval. |
| `RSS_MAX_ITEMS` | `50` | Maximum parsed items per response. |
