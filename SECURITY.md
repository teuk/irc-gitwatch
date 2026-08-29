# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for `teuk/irc-gitwatch`. Do not open a public issue for a suspected secret leak, authentication bypass, signature-validation flaw or remote crash.

Include the affected version, configuration shape with all secrets removed, reproduction steps and expected impact. You should receive an acknowledgement within seven days.

## Deployment boundaries

- Bind the HTTP listener to loopback unless a trusted reverse proxy and access policy are in place.
- Configure a long random `GITHUB_WEBHOOK_SECRET`; webhook POSTs are disabled when it is empty.
- Store the environment file and state file as mode `0600`.
- Give `GITHUB_TOKEN` only the repository access needed for the enabled features.
- Never paste tokens, webhook secrets, SASL passwords or private-channel keys into issues or logs.
- Treat dashboard JSON and Prometheus endpoints as operational metadata. They intentionally omit configured secrets, but can reveal repository names, IRC channels and service health.

GitHub Traffic “unique” values are aggregates supplied by GitHub. IRC GitWatch neither receives nor stores visitor IP addresses.

## Supported version

Security fixes target the latest release on the default branch. Older snapshots may receive a patch when the change can be backported safely.
