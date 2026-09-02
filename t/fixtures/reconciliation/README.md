# Webhook and polling reconciliation fixtures

These synthetic public-repository payloads exercise the shared event
fingerprint contract without contacting GitHub.

- `baseline.json` seeds the first Events API view and must never enqueue it.
- `new_push.json` represents a new polling event that is later replayed by a
  signed webhook.
- `overlap.json` mirrors the push, issue, and release webhook fixtures so the
  reverse webhook-first order can be verified.

All identities and URLs refer to GitHub's public `octocat/Hello-World` example.
