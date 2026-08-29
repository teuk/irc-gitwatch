# IRC commands

IRC GitWatch commands are read-only, rate-limited and available in joined channels. Use `!github help` for the live command map.

## Overview and health

| Command | Result |
| --- | --- |
| `!github pulse` | Compact current operating pulse. |
| `!github now` / `today` | Current activity and latest daily traffic. |
| `!github summary` / `status` | Service, GitHub, CI, traffic and delivery state. |
| `!github health` / `problems` | Health result and current issues. |
| `!github dashboard` | Configured public dashboard URL or local endpoint hint. |
| `!github recent` / `last` | Recent normalized activity. |
| `!github freshness` | Age of each data source. |

## GitHub Actions and delivery

| Command | Result |
| --- | --- |
| `!github ci` | Latest CI state. |
| `!github failures` | Current failing workflow/ref states. |
| `!github flaky` | Detected flaky workflow/ref states. |
| `!github running` | Running workflows. |
| `!github expected` | Pushes still awaiting an expected workflow. |
| `!github broadcast` | Fan-out audit by target. |
| `!github queue` | Persistent queue depth and target backlog. |
| `!github networks` | IRC connections, joins and heartbeat state. |
| `!github schedule` | Polling cadence and next maintenance work. |

## Traffic and audience

| Command | Result |
| --- | --- |
| `!github snapshot` | Latest daily clones/views and unique values. |
| `!github traffic` | Exact rolling 14-day totals, today and peaks. |
| `!github audience` / `uniques` | Unique-cloner/visitor semantics and ratios. |
| `!github trend` / `week` / `compare` | Recent period comparison. |
| `!github peaks` | Best traffic and unique days. |
| `!github history` | Retained traffic-history bounds. |
| `!github referrers` | Top traffic referrers. |
| `!github paths` | Most visited repository paths. |

GitHub supplies aggregate unique counts. These commands never claim to expose raw or distinct visitor IP addresses.

## Public account portfolio

| Command | Result |
| --- | --- |
| `!github portfolio` / `projects` | Account totals, activity, hygiene and trend. |
| `!github repos` | Most recently pushed public repositories. |
| `!github stars` | Most starred public repositories. |
| `!github stale` | Projects beyond the configured stale threshold. |
| `!github changes` | Recent public portfolio changes. |
| `!github project <name>` | Detail for one cached public repository. |

Portfolio data is restricted to `GITHUB_ACCOUNT` and public owner repositories.

## Diagnostics

| Command | Result |
| --- | --- |
| `!github stats` | Persistent counters. |
| `!github webhook` | Listener, signature and rejection audit. |
| `!github auth` / `rate` | GitHub authentication and quota state. |
| `!github state` | Primary/backup state validation. |
| `!github alerts` | Operational-alert configuration/counters. |
| `!github endpoints` | Local HTTP route map. |
| `!github icons` | Active icon compatibility mode. |
| `!github events` | Public event classes and deliberate exclusions. |
| `!github repo` | Monitored repository URL. |

Security-alert payloads are deliberately excluded from public IRC announcements.
