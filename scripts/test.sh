#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

profile=full
show_progress=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile)
      [ "$#" -ge 2 ] || {
        echo 'Missing value after --profile.' >&2
        exit 64
      }
      profile=$2
      shift 2
      ;;
    --progress)
      show_progress=1
      shift
      ;;
    --help|-h)
      echo 'usage: scripts/test.sh [--profile targeted|fast|full] [--progress]'
      exit 0
      ;;
    *)
      echo "Unknown test option: $1" >&2
      exit 64
      ;;
  esac
done

case "$profile" in
  targeted) total=9 ;;
  fast) total=13 ;;
  full) total=16 ;;
  *)
    echo "Unknown test profile: $profile" >&2
    exit 64
    ;;
esac

perl_bin=${PERL:-perl}
completed=0
temp_dir=

cleanup() {
  if [ -n "$temp_dir" ] && [ -d "$temp_dir" ]; then
    rm -rf -- "$temp_dir"
  fi
}
trap cleanup EXIT HUP INT TERM

progress_line() {
  state=$1
  label=$2
  if [ "$show_progress" -ne 1 ]; then
    printf '%s %s\n' "$state" "$label"
    return
  fi

  width=24
  filled=$((completed * width / total))
  empty=$((width - filled))
  left=
  right=
  i=0
  while [ "$i" -lt "$filled" ]; do
    left=$left#
    i=$((i + 1))
  done
  i=0
  while [ "$i" -lt "$empty" ]; do
    right=$right-
    i=$((i + 1))
  done
  percent=$((completed * 100 / total))
  printf '[%s%s] %3d%% %-4s %s\n' "$left" "$right" "$percent" "$state" "$label"
}

run_case() {
  label=$1
  shift
  progress_line RUN "$label"
  if "$@"; then
    completed=$((completed + 1))
    progress_line PASS "$label"
  else
    rc=$?
    progress_line FAIL "$label"
    echo "Test profile '$profile' stopped at: $label" >&2
    exit "$rc"
  fi
}

check_ssl_module() {
  "$perl_bin" -MIO::Socket::SSL -e 'exit 0'
}

check_syntax() {
  "$perl_bin" -c irc-gitwatch.pl
}

selftest_default() {
  "$perl_bin" irc-gitwatch.pl --selftest
}

selftest_public_account() {
  GITHUB_REPO=octocat/Hello-World \
  GITHUB_ACCOUNT=octocat \
    "$perl_bin" irc-gitwatch.pl --selftest
}

selftest_repository_only() {
  GITHUB_REPO=octocat/Hello-World \
  GITHUB_ACCOUNT= \
    "$perl_bin" irc-gitwatch.pl --selftest
}

check_state_v029() {
  "$perl_bin" irc-gitwatch.pl \
    --state-fixture-check t/fixtures/state-v0.29.json v0.29
}

check_state_v030() {
  "$perl_bin" irc-gitwatch.pl \
    --state-fixture-check t/fixtures/state-v0.30.json v0.30
}

check_webhook_blackbox() {
  "$perl_bin" t/webhook-blackbox.pl
}

check_reconciliation_blackbox() {
  "$perl_bin" t/reconciliation-blackbox.pl
}

check_delivery_blackbox() {
  "$perl_bin" t/delivery-blackbox.pl
}

check_state_recovery_blackbox() {
  "$perl_bin" t/state-recovery-blackbox.pl
}

check_dashboard_javascript() {
  if ! command -v node >/dev/null 2>&1; then
    echo '[SKIP] node is unavailable; dashboard JavaScript syntax was not checked.'
    return 0
  fi

  temp_dir=$(mktemp -d)
  js_file=$temp_dir/dashboard.js
  awk '
    /^sub dashboard_js \{/ { in_function=1; next }
    in_function && /^ return <<'\''JS'\'';/ { in_js=1; next }
    in_js && /^JS$/ { exit }
    in_js { print }
  ' irc-gitwatch.pl >"$js_file"
  node --check "$js_file"
  cleanup
  temp_dir=
}

check_ci_contract() {
  workflow=.github/workflows/ci.yml
  checkout_sha=3d3c42e5aac5ba805825da76410c181273ba90b1

  [ -f "$workflow" ] || {
    echo "Missing CI workflow: $workflow" >&2
    return 1
  }

  grep -Fq 'runs-on: ubuntu-24.04' "$workflow" &&
  grep -Fq 'image: debian:12-slim' "$workflow" &&
  grep -Fq 'image: debian:13-slim' "$workflow" &&
  grep -Fq 'fail-fast: false' "$workflow" || {
    echo 'CI must cover Ubuntu 24.04, Debian 12 and Debian 13 without fail-fast.' >&2
    return 1
  }

  refs=$(sed -n 's/^[[:space:]]*uses:[[:space:]]*[^@[:space:]]*@\([^[:space:]#]*\).*/\1/p' "$workflow")
  [ -n "$refs" ] || {
    echo 'CI workflow contains no reusable action reference.' >&2
    return 1
  }
  if printf '%s\n' "$refs" | grep -Ev '^[0-9a-f]{40}$' >/dev/null; then
    echo 'Every CI action must be pinned to a full immutable commit SHA.' >&2
    return 1
  fi

  checkout_count=$(grep -Fc "uses: actions/checkout@$checkout_sha" "$workflow")
  credential_count=$(grep -Fc 'persist-credentials: false' "$workflow")
  check_count=$(grep -Fc 'run: make check' "$workflow")
  [ "$checkout_count" -eq 2 ] &&
  [ "$credential_count" -eq 2 ] &&
  [ "$check_count" -eq 2 ] || {
    echo 'CI checkout pin, credential isolation or deterministic check contract changed.' >&2
    return 1
  }

  if grep -Eq 'uses:[[:space:]]+[^[:space:]]+@(main|master|v[0-9])' "$workflow"; then
    echo 'Mutable GitHub Action reference found in CI.' >&2
    return 1
  fi
}

check_credentials() {
  if grep -RIE \
    --exclude-dir='.git' \
    --exclude='check.sh' \
    --exclude='test.sh' \
    '(github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY)' .; then
    echo 'Potential credential material found.' >&2
    return 1
  fi
}

check_public_tree() {
  for path in \
    README.md \
    CHANGELOG.md \
    CONTRIBUTING.md \
    SECURITY.md \
    LICENSE \
    .env.example \
    .github/workflows/ci.yml \
    docs/ARCHITECTURE.md \
    docs/CONFIGURATION.md \
    docs/HTTP_API.md \
    docs/INSTALL.md \
    docs/IRC_COMMANDS.md \
    irc-gitwatch.pl \
    scripts/check.sh \
    scripts/install.sh \
    scripts/test.sh \
    t/fixtures/README.md \
    t/fixtures/state-v0.29.json \
    t/fixtures/state-v0.30.json \
    t/fixtures/webhooks/README.md \
    t/fixtures/webhooks/issues.json \
    t/fixtures/webhooks/missing_repository.json \
    t/fixtures/webhooks/ping.json \
    t/fixtures/webhooks/private_event.json \
    t/fixtures/webhooks/pull_request.json \
    t/fixtures/webhooks/push.json \
    t/fixtures/webhooks/release.json \
    t/fixtures/webhooks/unknown_event.json \
    t/fixtures/webhooks/workflow_run.json \
    t/fixtures/webhooks/wrong_repository.json \
    t/fixtures/reconciliation/README.md \
    t/fixtures/reconciliation/baseline.json \
    t/fixtures/reconciliation/new_push.json \
    t/fixtures/reconciliation/overlap.json \
    t/delivery-blackbox.pl \
    t/reconciliation-blackbox.pl \
    t/state-recovery-blackbox.pl \
    t/webhook-blackbox.pl \
    systemd/irc-gitwatch.service
  do
    [ -f "$path" ] || {
      echo "Missing public project file: $path" >&2
      return 1
    }
  done

  [ -x irc-gitwatch.pl ] &&
  [ -x scripts/check.sh ] &&
  [ -x scripts/install.sh ] &&
  [ -x scripts/test.sh ] &&
  [ -x t/delivery-blackbox.pl ] &&
  [ -x t/reconciliation-blackbox.pl ] &&
  [ -x t/state-recovery-blackbox.pl ] &&
  [ -x t/webhook-blackbox.pl ]
}

check_repository_hygiene() {
  [ ! -e .env ] || {
    echo 'Private .env file present in the public project tree.' >&2
    return 1
  }

  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git diff --check
    if git ls-files --error-unmatch .env >/dev/null 2>&1; then
      echo 'Private .env file is tracked by Git.' >&2
      return 1
    fi
    if git ls-files | grep -Eq '(^|/)commit\.sh$'; then
      echo 'A private commit.sh helper is tracked by Git.' >&2
      return 1
    fi
  fi
}

echo "IRC GitWatch test profile: $profile"
run_case 'Perl TLS dependency' check_ssl_module
run_case 'Perl syntax' check_syntax
run_case 'named deterministic selftest' selftest_default
run_case 'v0.29 persistent-state compatibility' check_state_v029
run_case 'v0.30 persistent-state compatibility' check_state_v030
run_case 'signed webhook HTTP black-box' check_webhook_blackbox
run_case 'webhook and polling reconciliation black-box' check_reconciliation_blackbox
run_case 'persistent IRC fan-out delivery black-box' check_delivery_blackbox
run_case 'persistent state disaster recovery black-box' check_state_recovery_blackbox

if [ "$profile" = fast ] || [ "$profile" = full ]; then
  run_case 'public-account configuration selftest' selftest_public_account
  run_case 'repository-only configuration selftest' selftest_repository_only
  run_case 'public CI platform and action-pin contract' check_ci_contract
  run_case 'dashboard JavaScript syntax' check_dashboard_javascript
fi

if [ "$profile" = full ]; then
  run_case 'credential scan' check_credentials
  run_case 'public project tree contract' check_public_tree
  run_case 'repository hygiene' check_repository_hygiene
fi

echo "IRC GitWatch $profile checks: OK ($completed/$total)"
