# Contributing

Issues and focused pull requests are welcome.

## Development loop

1. Fork and create a narrowly scoped branch.
2. Keep the daemon single-process and avoid adding mandatory non-core dependencies without a clear operational benefit.
3. Preserve state migration, webhook verification, per-target delivery and UTF-8 behavior.
4. Add or update a named deterministic check for every behavior change.
5. Run the targeted and fast profiles while iterating, then the full gate once the proposed tree is final.

```bash
sudo apt-get install perl libio-socket-ssl-perl nodejs
make test-targeted
make test-fast
make check
```

`make check` is the full profile used by public CI. It adds the credential scan, public-tree contract and repository-hygiene checks. `scripts/test.sh --profile targeted|fast|full --progress` is the underlying interface for automation.

When state handling changes, update or add a synthetic fixture under `t/fixtures/` and keep older fixtures passing. Never derive a public fixture by redacting a production state file: build the smallest synthetic document that proves the contract instead.

Do not use real tokens, passwords, webhook payloads containing private data or production state files in tests. Fixtures should use public or synthetic identities.

## Compatibility

Changes to environment names, JSON response fields, IRC commands, state schema or the `githubwatch_` Prometheus namespace are public-interface changes. Document them in `CHANGELOG.md` and provide a migration path.

## Style

- Keep `use strict`, `use warnings` and `use utf8` clean.
- Keep outbound IRC lines within the byte limit.
- Encode/decode explicitly at protocol boundaries.
- Prefer a small, testable function over hidden global side effects.
- Preserve read-only behavior for IRC commands and dashboard APIs.

By contributing, you agree that your contribution is licensed under the MIT License.
