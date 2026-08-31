# Installation

## Package requirements

Debian and Ubuntu:

```bash
sudo apt-get update
sudo apt-get install perl libio-socket-ssl-perl ca-certificates
```

For source validation or contribution work, also install the developer-only tools:

```bash
sudo apt-get install make nodejs git
```

Verify the source before installing:

```bash
make check
```

That command runs the full public release gate. During development, `make test-targeted` and `make test-fast` provide shorter feedback loops; see the main README for the exact coverage of each profile.

## Automated systemd installation

The installer creates an unprivileged `irc-gitwatch` service account, installs the executable under `/opt/irc-gitwatch`, installs the hardened unit, and creates `/etc/irc-gitwatch.env` only when it does not already exist. It does not enable or start the service.

```bash
sudo ./scripts/install.sh
sudoedit /etc/irc-gitwatch.env
sudo systemctl enable --now irc-gitwatch.service
```

The unit runs `--config-check` as `ExecStartPre`; a configuration error prevents the daemon from starting and is recorded in the journal:

```bash
sudo systemctl status irc-gitwatch.service
sudo journalctl -u irc-gitwatch.service -n 50 --no-pager
```

## Manual systemd installation

```bash
sudo useradd --system --home-dir /var/lib/irc-gitwatch \
  --create-home --shell /usr/sbin/nologin irc-gitwatch
sudo install -d -m 0755 /opt/irc-gitwatch
sudo install -m 0755 irc-gitwatch.pl /opt/irc-gitwatch/irc-gitwatch.pl
sudo install -m 0644 systemd/irc-gitwatch.service /etc/systemd/system/
sudo install -m 0600 .env.example /etc/irc-gitwatch.env
sudo chown root:root /etc/irc-gitwatch.env
sudoedit /etc/irc-gitwatch.env
sudo systemctl daemon-reload
sudo systemctl enable --now irc-gitwatch.service
```

The unit's `StateDirectory=irc-gitwatch` creates `/var/lib/irc-gitwatch` with the correct service ownership.

## GitHub token

Create a token for the account that can read the monitored repository. Use the narrowest repository selection and permissions compatible with the features you enable:

- repository metadata/events for polling;
- Actions read access for workflow monitoring and job enrichment;
- repository traffic access for clone/view statistics.

GitHub's traffic endpoints require the token owner to have suitable access to the repository. IRC GitWatch degrades visibly when an optional endpoint returns `403`; it does not silently relabel missing data.

Place the token only in `/etc/irc-gitwatch.env`, then enforce:

```bash
sudo chown root:root /etc/irc-gitwatch.env
sudo chmod 0600 /etc/irc-gitwatch.env
```

## Webhook and TLS proxy

The daemon listens on loopback by default. Configure your reverse proxy to forward only the chosen webhook path and, if desired, separately protect dashboard routes with an ACL or authentication layer.

GitHub webhook settings:

- URL: `https://your-host.example/githubhook`
- Content type: `application/json`
- Secret: same value as `GITHUB_WEBHOOK_SECRET`

Never terminate public TLS directly in the Perl daemon. Its HTTP server is intentionally compact and designed for a trusted local boundary.

## First diagnostics

```bash
sudo systemctl status irc-gitwatch.service
sudo journalctl -u irc-gitwatch.service -n 100 --no-pager
curl --fail http://127.0.0.1:9510/livez
curl --fail http://127.0.0.1:9510/readyz
curl --fail http://127.0.0.1:9510/status.json
```

Useful one-shot checks are listed in the main README. `--doctor` performs network calls; `--selftest` is deterministic and does not require credentials.

## Migrating or upgrading an existing GitHubWatch v0.29 instance

1. Stop the old service cleanly so its latest state is saved.
2. Back up its state and environment files.
3. Install IRC GitWatch without starting it.
4. Set `GITHUB_REPO`, `GITHUB_ACCOUNT` and `GITHUB_STATE_FILE` explicitly.
5. Copy the state file to `/var/lib/irc-gitwatch/state.json`, owner `irc-gitwatch`, mode `0600`.
6. Run `--state-check`, `--config-check` and `--selftest`.
7. Start only the new service.

Do not run two instances against the same state file or IRC targets. Version 0.30 retains the v0.29 state schema and metrics prefix specifically to make this migration uneventful. Its additive CI reliability history starts filling on the first successful Actions scan; no manual state migration is needed.
