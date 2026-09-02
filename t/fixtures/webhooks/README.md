# Synthetic webhook fixtures

These payloads exercise the real loopback TCP/HTTP listener through
`t/webhook-blackbox.pl`. They use only the public GitHub example repository
`octocat/Hello-World`, deterministic identifiers and invented delivery data.

No fixture was copied from a production delivery. The directory must never
contain a real webhook secret, token, private repository name or user data.
