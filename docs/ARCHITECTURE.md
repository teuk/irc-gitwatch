# Architecture and guarantees

IRC GitWatch is deliberately one event loop and one persistent state document. This keeps event ordering explicit and makes recovery inspectable.

```mermaid
flowchart TD
    GH[GitHub webhooks and APIs] --> N[Normalize and deduplicate]
    RSS[Optional RSS or Atom] --> N
    N --> Q[Persistent per-target queue]
    Q --> IRC[IRC networks and channels]
    N --> S[Atomic state and history]
    S --> HTTP[Dashboard, JSON, health and metrics]
    Q --> HTTP
```

## Event acquisition

Signed webhooks provide low latency. Repository event polling provides reconciliation when delivery is delayed or missing. Both paths normalize into the same event model and fingerprint space.

The reconciliation contract is restart-safe: webhook and polling observations of the same push converge on one fingerprint and one announcement, while a genuinely new polling event remains eligible. Public fixtures exercise both the overlap and catch-up paths without a GitHub connection.

GitHub Actions, repository traffic, public account inventory and RSS each have independent adaptive schedules. Exactly one maintenance family advances per event-loop turn so an optional slow source does not monopolize local HTTP or IRC work.

Completed Actions runs are normalized into a separate bounded history (30 days, at most 500 runs) during the existing Actions scan. Reliability and incident summaries are computed from that local state, so dashboard, IRC, JSON and Prometheus consumers do not create additional GitHub traffic.

## Delivery invariant

One normalized announcement becomes one queue record with an explicit target set. Every network/channel acknowledges delivery independently. A successful socket write first becomes a short-lived receipt; only expiry of the IRC rejection window turns it into a durable acknowledgement. Numeric 404/442 rejection clears the receipt, retains the queue record and makes the target error visible.

Formatted rejection is retried once as plain UTF-8 for that channel only. If the plain retry is also rejected, health remains degraded and no success is invented. A record leaves the queue only after every active target has succeeded; partial progress survives state saves and restarts.

Configured target sets may intentionally shrink. On state load, inactive targets are retired from pending obligations while historical audit values remain intact. If all remaining targets were already acknowledged, the record completes immediately without replay. Undernet target ids remain channel-qualified so a primary target keeps the same identity when its optional secondary disappears.

The 57-assertion delivery black box forces socket failure, an unavailable channel, formatted and plain rejection, process restarts and a four-to-three target migration. Wire captures, queue audit and per-target counters must agree exactly, and already successful targets must never be served twice.

The queue is bounded. When space is exhausted, eviction and partial-delivery loss are separately counted and surfaced rather than hidden.

## State invariant

- JSON state schema version 11.
- Atomic temporary-file write and rename.
- Mode `0600`.
- Optional validated `.bak` recovery copy.
- Bounded histories, IDs, fingerprints, delivery audits, CI runs and account changes.
- Legacy activity text is repaired at display/serialization boundaries without rewriting unrelated strings.

Before replacing the primary file, backup rotation parses and validates the current primary. Invalid bytes are never promoted into `.bak`. If the primary is corrupt or missing, startup may load the validated backup; the next save atomically rebuilds the primary while retaining pending fan-out, acknowledgements, fingerprints, history and counters. The disaster-recovery black box proves both incidents in separate Perl processes and checks mode `0600` after repair. Target retirement remains an in-schema normalization and does not require a state-version bump.

## Scope and privacy invariant

- Webhook repository must equal `GITHUB_REPO`.
- GitHub REST URLs are constructed and checked against the configured repository/account scope.
- Portfolio inventory accepts only non-private owner repositories for `GITHUB_ACCOUNT`.
- Security-alert event classes are deliberately not announced.
- Configured credentials and private channel keys are excluded from every read-only surface.
- GitHub unique-cloner/visitor aggregates are never presented as raw IP data.

## Failure behavior

Network reconnects use bounded backoff. GitHub primary and secondary limits pause REST maintenance without blocking signed webhooks, dashboard requests or already-queued IRC delivery. Each optional subsystem reports `off`, `waiting`, `limited`, `online` or `error` as appropriate.

SIGTERM/SIGINT request a graceful state save and IRC quit. systemd restarts only on failure.

## Compatibility surfaces

Treat these as public interfaces:

- environment variable names and defaults;
- state schema and migration behavior;
- IRC command vocabulary;
- JSON response fields and route paths;
- Prometheus metric names and labels;
- webhook verification and deduplication behavior.

Every change to one of these surfaces needs a deterministic regression check and a changelog note.

## Validation invariant

Validation is layered so development feedback stays quick without weakening the release gate:

- `targeted` checks TLS availability, Perl syntax, the named built-in registry, both retained state contracts, signed webhook admission, webhook/polling reconciliation, persistent IRC fan-out and state disaster recovery;
- `fast` adds unrelated-account configurations, the public CI contract and dashboard JavaScript syntax;
- `full` adds credential discovery, the exact public-tree contract and Git repository hygiene.

The v0.29 and v0.30 fixtures are intentionally small synthetic documents. Scenario fixtures and wire files use public or invented identities. Together they exercise scalar and structured pending delivery, retained CI history, unknown additive fields, HTTP rejection paths, deduplication, fan-out resume and backup repair without containing a production token, channel or state dump or opening an external connection.

Public CI executes the full profile on Ubuntu 24.04 and in Debian 12/13 job containers. Every reusable GitHub Action is referenced by a full commit SHA, and checkout credentials are removed before the test steps run.
