#!/usr/bin/env bash
# Run one DudeCT benchmark for a fixed duration and keep only its final
# measurement.
#
# dudect-bencher prints one line per sample and flushes it. On the
# ubuntu-24.04 runner that is about 123 bytes and ~5.6 million lines in
# 30 seconds (~660 MiB). The extended job runs 17 benchmarks for 5
# minutes each, which is ~100 GiB of logs — more than the ~108 GiB free
# after the runner image cleanup — so the runner is killed mid-job and
# the log blob is never uploaded.
#
# The workflow only reads the last "max t =" line. Sampling duration is
# unchanged; the per-sample transcript is not stored.
#
# A line of output is not proof that the sample window finished. Success
# requires either:
#   * timeout stopping the bench (exit 124, or 137 after --kill-after)
#     at or after the requested duration, or
#   * the bench exiting 0 and reporting "dudect benches complete".
# Anything else (early exit, crash, or a kill before the window ends)
# fails the step, even if a max t line was already printed.

set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: ct_capture.sh <binary> <bench> <seconds> <outfile>" >&2
  exit 2
fi

binary=$1
bench=$2
seconds=$3
outfile=$4

if [[ ! $seconds =~ ^[1-9][0-9]*$ ]]; then
  echo "ct_capture: seconds must be a positive integer, got: $seconds" >&2
  exit 2
fi

if [[ ! -x $binary ]]; then
  echo "ct_capture: binary not executable: $binary" >&2
  exit 1
fi

mkdir -p "$(dirname "$outfile")"

# Wall-clock proof that the sample window elapsed. Do not export a locale
# change into the bench; only this script's own timestamps are forced
# through the C numeric format.
timestamp() {
  local raw=${EPOCHREALTIME:-}
  if [[ -z $raw ]]; then
    raw=$(LC_ALL=C date +%s.%N)
  fi
  printf '%s\n' "${raw/,/.}"
}

start=$(timestamp)

# `timeout` exits 124 when its own timer fires, even if the bench catches
# SIGTERM and exits 0. It exits 137 when the bench dies from SIGKILL,
# which is also what --kill-after does if SIGTERM is ignored. An early
# SIGKILL is 137 as well, so the elapsed time is what distinguishes a
# finished window from a kill that happened too soon.
# pipefail would turn 124/137 into a pipeline failure before awk records
# the last line, so it is off only for this pipeline.
set +o pipefail
timeout --kill-after=5s "${seconds}s" "$binary" --continuous "$bench" 2>&1 \
  | awk '
      /max t =/ { last = $0; n++ }
      /dudect benches complete/ { complete = 1 }
      END {
        if (last != "") print last
        printf "dudect_lines=%d\n", n + 0
        printf "dudect_complete=%d\n", complete + 0
      }
    ' >"$outfile"
status=${PIPESTATUS[0]}
set -o pipefail

end=$(timestamp)
elapsed=$(awk -v start="$start" -v end="$end" 'BEGIN { printf "%.3f", (end + 0) - (start + 0) }')

{
  printf 'ct_capture_start=%s\n' "$start"
  printf 'ct_capture_end=%s\n' "$end"
  printf 'ct_capture_elapsed_s=%s\n' "$elapsed"
  printf 'ct_capture_status=%s\n' "$status"
} >>"$outfile"

window_met() {
  awk -v elapsed="$elapsed" -v need="$seconds" 'BEGIN {
    exit ((elapsed + 0) >= (need + 0)) ? 0 : 1
  }'
}

if ! grep -q "max t =" "$outfile"; then
  echo "ct_capture: $bench produced no max_t measurement (status $status, elapsed ${elapsed}s)" >&2
  exit 1
fi

if [[ $status -eq 124 || $status -eq 137 ]]; then
  if ! window_met; then
    echo "ct_capture: $bench stopped after ${elapsed}s, before the ${seconds}s sample window (status $status)" >&2
    exit 1
  fi
elif [[ $status -eq 0 ]] && grep -q '^dudect_complete=1$' "$outfile"; then
  : # Bench exited normally and reported that its run finished.
else
  echo "ct_capture: $bench stopped early (status $status, elapsed ${elapsed}s, wanted ${seconds}s)" >&2
  exit 1
fi

echo "ct_capture: $bench status=$status elapsed=${elapsed}s window=${seconds}s"
