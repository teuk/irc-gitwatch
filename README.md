# IRC GitWatch

[![CI](https://github.com/teuk/irc-gitwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/teuk/irc-gitwatch/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Perl](https://img.shields.io/badge/Perl-5.36%2B-39457E.svg)](https://www.perl.org/)

IRC GitWatch is a single-process Perl daemon that turns GitHub activity into reliable IRC notifications and a live operational dashboard. It combines signed webhooks with polling reconciliation, watches GitHub Actions, preserves a per-target delivery queue, and exposes traffic and public-account analytics without pretending GitHub's aggregate “unique” figures are raw IP counts.

The project began as the production bot behind `teuk/mediabot_v3`. Release 0.32 lets one daemon watch several repositories while keeping every repository's Events, Actions/CI and Traffic state independent and preserving the battle-tested shared IRC delivery queue. Release 0.33 adds a dashboard repository selector and shareable deep links for those independent statistics. Release 0.34 makes the latest complete traffic day explicit: J-1 when GitHub has published it, otherwise an honestly labelled J-2-or-older fallback.

## Why it is different

- Signed `X-Hub-Signature-256` webhook verification with repository scope checks and replay suppression.
- Multi-repository polling reconciliation for events a webhook may miss, with independent ETags, baselines, pagination and CI/Traffic state.
- GitHub Actions failure, recovery, slow-run, missing-run and flaky-run detection.
- Bounded 30-day CI reliability analytics: pass rate, active/resolved incidents, MTTR, p50/p95 runtime and current green streak, derived from the existing Actions feed without extra API calls.
- Persistent fan-out delivery: each IRC network/channel is acknowledged independently after a short rejection window, with durable retry and honest IRC numeric errors.
- GitHub Traffic dashboard with a watched-repository selector, last-closed daily clones/unique cloners, views, trends and retained daily history.
- Public owner portfolio: activity, stars, forks, hygiene, stale projects and change history for one configurable GitHub account.
- Read-only JSON, health and Prometheus endpoints.
- Optional RSS/Atom announcements.
- Defensive UTF-8 and legacy mojibake repair across IRC, state, JSON and HTML.
- One executable, one state file, built-in diagnostics, 167 named deterministic self-tests, versioned state fixtures and restart-aware black-box harnesses. No framework required — a pleasantly small bit of machinery with rather a lot under the cloak. 🪄

## Requirements

- Perl 5.36 or newer.
- Core modules shipped with Perl, plus `IO::Socket::SSL`.
- `make` and Node.js for the complete contributor validation profile; neither is required by the running daemon.
- A GitHub token is strongly recommended and is required for repository traffic statistics.
- At least one IRC target enabled when notifications are wanted.

On Debian or Ubuntu:

```bash
sudo apt-get install perl libio-socket-ssl-perl ca-certificates
```

## Quick start

```bash
git clone https://github.com/teuk/irc-gitwatch.git
cd irc-gitwatch
cp .env.example .env
chmod 600 .env
${EDITOR:-vi} .env

set -a
. ./.env
set +a

./irc-gitwatch.pl --config-check
./irc-gitwatch.pl --selftest
./irc-gitwatch.pl --doctor
./irc-gitwatch.pl
```

The public defaults are deliberately inert: IRC networks and RSS are off, webhook POSTs are disabled until a secret is configured, and the HTTP listener binds to `127.0.0.1`.

For a system service, follow [docs/INSTALL.md](docs/INSTALL.md). Full environment documentation is in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Minimal configuration

```bash
GITHUB_REPO=your-account/your-repository
GITHUB_REPOS=your-account/another-repository
GITHUB_ACCOUNT=
GITHUB_TOKEN=github_pat_replace_me
GITHUB_WEBHOOK_SECRET=replace_with_a_long_random_secret

LIBERA_ENABLED=1
LIBERA_CHANNEL='#your-channel'
LIBERA_NICK=gitwatch
LIBERA_REQUIRE_SASL=0
```

An empty `GITHUB_ACCOUNT` follows the owner from `GITHUB_REPO`. Account monitoring is strictly limited to public repositories whose `owner.login` matches that value; private or foreign records are discarded even if an API response contains them.

`GITHUB_REPO` is always the primary repository. `GITHUB_REPOS` is an optional comma-separated list of additional repositories watched by the same process and announced through the same IRC fan-out. Repeating the primary repository is harmless and is deduplicated case-insensitively.

## GitHub webhook

Create the same repository webhook on every watched repository with:

- Payload URL: `https://your-host.example/githubhook`
- Content type: `application/json`
- Secret: the exact value of `GITHUB_WEBHOOK_SECRET`
- Events: individual repository events, or “Send me everything”

Keep the daemon on localhost and place a TLS reverse proxy in front of it. Webhook POST is rejected when the secret is empty. The dashboard GET routes remain available for local diagnostics.

## Dashboard and observability

The default local URL is `http://127.0.0.1:9510/`. Useful endpoints:

| Endpoint | Purpose |
| --- | --- |
| `/` | Live dashboard |
| `/repo/<owner>/<repository>` | Live dashboard deep link for one watched repository |
| `/status.json` | Compact runtime state |
| `/?api=dashboard` | Full primary-repository dashboard payload; accepts `&repo=owner/name` |
| `/ci.json` | Primary repository CI reliability; add `?repo=owner/name` for another watched repository |
| `/traffic.json` | Primary repository traffic; add `?repo=owner/name` for another watched repository |
| `/account.json` | Public owner portfolio |
| `/broadcast.json` | Per-target fan-out audit |
| `/healthz` | Aggregate health |
| `/livez` | Process/listener liveness |
| `/readyz` | Operational readiness |
| `/metrics` | Prometheus exposition |
| `/githubhook` | Signed GitHub webhook POST |

The sticky header combines the full-name selector with a one-click rail of every watched project. Each project carries its own Events, CI and Traffic signal; the primary scope, current position and permalink remain visible while Traffic, unique-audience and CI reliability switch as one guarded repository context. Selection updates the address bar to `/repo/<owner>/<repository>` without reloading the page, and browser Back/Forward restores the matching project. The public reverse proxy must forward `/repo/` as well as the dashboard root if these deep links are exposed outside loopback.

The dashboard's compact daily signal never mistakes the current partial UTC day for a finished result. It displays J-1 when present, otherwise the newest earlier row with its actual `J-N` lag and date. Exact rolling 14-day totals and the full daily curve remain available alongside it.

GitHub returns aggregate unique cloners and visitors, not visitor IP addresses. IRC GitWatch preserves and labels that distinction everywhere.

## IRC commands

Messages are read-only and begin with `!github`. Start with:

```text
!github help
!github status
!github watch
!github reliability
!github incidents
!github failures
!github traffic
!github portfolio
!github queue
!github endpoints
```

See [docs/IRC_COMMANDS.md](docs/IRC_COMMANDS.md) for the command families.

## Operations

```bash
./irc-gitwatch.pl --version
./irc-gitwatch.pl --config-check
./irc-gitwatch.pl --selftest
./irc-gitwatch.pl --selftest-list
./irc-gitwatch.pl --doctor
./irc-gitwatch.pl --state-check
./irc-gitwatch.pl --auth-check
./irc-gitwatch.pl --actions-check
./irc-gitwatch.pl --traffic-check
./irc-gitwatch.pl --account-check
./irc-gitwatch.pl --http-check
```

State writes are atomic, mode `0600`, and can keep a `.bak` recovery copy. SIGTERM and SIGINT trigger a clean state save and IRC quit.

## Validation profiles

The public test runner makes the cost and intent of every validation round explicit:

```bash
make test-targeted  # core contracts plus webhook, reconciliation, delivery and recovery black boxes
make test-fast      # targeted plus configuration, CI-contract and dashboard JS checks
make test-full      # fast plus credentials, public-tree and repository-hygiene gates
make check          # alias for the full release gate
```

All profiles display progress and stop on the first failing named check. The targeted profile proves signed HTTP admission, webhook/polling overlap, partial multi-target IRC delivery across process restarts, formatted-to-plain fallback, optional-target retirement without replay, and recovery from a corrupt or missing primary state. Its fixtures are deliberately credential-free and synthetic: no test opens an IRC or GitHub connection, and no production state is copied. Public CI runs the full gate independently on Ubuntu 24.04, Debian 12 and Debian 13.

## Compatibility contract

Release 0.34 retains the v0.29 state schema (`state_version: 11`), `githubwatch_` Prometheus metric prefix, webhook behavior and every existing IRC command. Existing v0.29/v0.30/v0.31/v0.32/v0.33 state can be reused directly. The historical top-level state remains the `GITHUB_REPO` view for rollback compatibility; repository-local state is stored additively under `repo_state`. A newly added repository establishes Events and Actions baselines without replay before it starts announcing new activity.

Run `make check` before every upgrade. The suite exercises project defaults and unrelated public-account configurations to guard against accidental `teuk` coupling. Versioned fixtures prove that v0.29 and v0.30 state remain loadable; black-box restart tests prove that reconciliation, per-target acknowledgements and validated backup recovery remain durable without changing the schema.

## Documentation

- [Installation and systemd](docs/INSTALL.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [IRC commands](docs/IRC_COMMANDS.md)
- [HTTP API](docs/HTTP_API.md)
- [Architecture and guarantees](docs/ARCHITECTURE.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## License

MIT © 2026 Teuk. See [LICENSE](LICENSE).
