# Contributing

Issues and focused pull requests are welcome.

## Development loop

1. Fork and create a narrowly scoped branch.
2. Keep the daemon single-process and avoid adding mandatory non-core dependencies without a clear operational benefit.
3. Preserve state migration, webhook verification, per-target delivery and UTF-8 behavior.
4. Add or update a deterministic built-in check for every behavior change.
5. Run `make check` before opening the pull request.

```bash
sudo apt-get install perl libio-socket-ssl-perl nodejs
make check
```

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
