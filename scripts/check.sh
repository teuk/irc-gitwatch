#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

perl -MIO::Socket::SSL -e 'exit 0'
perl -c irc-gitwatch.pl
perl irc-gitwatch.pl --selftest
GITHUB_REPO=octocat/Hello-World GITHUB_ACCOUNT=octocat perl irc-gitwatch.pl --selftest
GITHUB_REPO=octocat/Hello-World GITHUB_ACCOUNT= perl irc-gitwatch.pl --selftest

if command -v node >/dev/null 2>&1; then
  temp_dir=$(mktemp -d)
  js_file=$temp_dir/dashboard.js
  trap 'rm -rf -- "$temp_dir"' EXIT HUP INT TERM
  awk '
    /^sub dashboard_js \{/ { in_function=1; next }
    in_function && /^ return <<'\''JS'\'';/ { in_js=1; next }
    in_js && /^JS$/ { exit }
    in_js { print }
  ' irc-gitwatch.pl >"$js_file"
  node --check "$js_file"
fi

if grep -RIE --exclude-dir='.git' --exclude='check.sh' \
  '(github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY)' .; then
  echo 'Potential credential material found.' >&2
  exit 1
fi

echo 'IRC GitWatch checks: OK'
