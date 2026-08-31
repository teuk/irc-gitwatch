# Persistent-state compatibility fixtures

These deliberately small JSON documents model the public compatibility
boundary between IRC GitWatch 0.29 and 0.30.

- `state-v0.29.json` has schema version 11 without the additive CI run history.
  It also retains the older array representation of traffic history and
  `stats_version: 2` so the loader's compatibility migrations are exercised.
- `state-v0.30.json` has the same schema version with the additive bounded CI
  history introduced in 0.30. A duplicate run proves deterministic
  normalization and deduplication.

All identities, URLs and counters are synthetic public test data. The fixtures
contain no tokens, webhook secrets, IRC channel keys, private channels or raw
visitor addresses.
