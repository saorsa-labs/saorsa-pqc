#!/usr/bin/env bash
# Regression tests for scripts/ct_capture.sh.
# An early exit that still prints a max t line must fail. A run that
# fills the requested window must pass.

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
capture=$root/scripts/ct_capture.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

write_stub() {
  local path=$1
  cat >"$path"
  chmod +x "$path"
}

expect_fail() {
  local name=$1
  shift
  local log=$tmp/${name}.log
  if bash "$capture" "$@" "$log"; then
    echo "FAIL: $name was accepted" >&2
    exit 1
  fi
  echo "PASS: $name rejected"
}

expect_pass() {
  local name=$1
  shift
  local log=$tmp/${name}.log
  if ! bash "$capture" "$@" "$log"; then
    echo "FAIL: $name was rejected" >&2
    exit 1
  fi
  echo "PASS: $name accepted"
}

write_stub "$tmp/early" <<'EOF'
#!/bin/sh
echo "bench early ... : n == +1.000M, max t = +1.00000, max tau = +0.00010, (5/tau)^2 = 1"
exit 0
EOF

write_stub "$tmp/killed" <<'EOF'
#!/bin/sh
echo "bench killed ... : n == +1.000M, max t = +1.00000, max tau = +0.00010, (5/tau)^2 = 1"
kill -9 $$
EOF

write_stub "$tmp/full" <<'EOF'
#!/bin/sh
trap 'exit 0' TERM INT
while true; do
  echo "bench full ... : n == +1.000M, max t = +0.25000, max tau = +0.00010, (5/tau)^2 = 1"
done
EOF

write_stub "$tmp/complete" <<'EOF'
#!/bin/sh
echo "bench complete ... : n == +1.000M, max t = +0.25000, max tau = +0.00010, (5/tau)^2 = 1"
echo "dudect benches complete"
exit 0
EOF

expect_fail early "$tmp/early" early 2
expect_fail killed "$tmp/killed" killed 3

expect_pass full "$tmp/full" full 1
if ! grep -q "max t =" "$tmp/full.log"; then
  echo "FAIL: full-window log has no max t line" >&2
  exit 1
fi
if ! grep -Eq '^ct_capture_status=(124|137)$' "$tmp/full.log"; then
  echo "FAIL: full-window run did not report timeout status 124 or 137" >&2
  cat "$tmp/full.log" >&2
  exit 1
fi
elapsed=$(grep '^ct_capture_elapsed_s=' "$tmp/full.log" | tail -1 | cut -d= -f2)
if ! awk -v elapsed="$elapsed" 'BEGIN { exit ((elapsed + 0) >= 1) ? 0 : 1 }'; then
  echo "FAIL: full-window elapsed ${elapsed}s is under 1s" >&2
  exit 1
fi
echo "PASS: full-window log records a completed sample window (${elapsed}s)"

expect_pass complete "$tmp/complete" complete 5
if ! grep -q '^dudect_complete=1$' "$tmp/complete.log"; then
  echo "FAIL: completion report was not recorded" >&2
  exit 1
fi
echo "PASS: bench that reports completion is accepted"

echo "ct_capture regression tests passed"
