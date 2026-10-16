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

set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: ct_capture.sh <binary> <bench> <seconds> <outfile>" >&2
  exit 2
fi

binary=$1
bench=$2
seconds=$3
outfile=$4

if [[ ! -x $binary ]]; then
  echo "ct_capture: binary not executable: $binary" >&2
  exit 1
fi

mkdir -p "$(dirname "$outfile")"

# `timeout` exits 124 when it stops the bench at the end of the window,
# or 137 if the bench ignores SIGTERM and has to be SIGKILLed. Both mean
# the sample window completed. pipefail would turn those into a pipeline
# failure before awk records the last line, so it is off only here.
# --kill-after keeps a bench that swallows SIGTERM from running on
# until the job timeout.
set +o pipefail
timeout --kill-after=5s "${seconds}s" "$binary" --continuous "$bench" 2>&1 \
  | awk '
      /max t =/ { last = $0; n++ }
      END {
        if (last != "") print last
        printf "dudect_lines=%d\n", n + 0
      }
    ' >"$outfile"
status=${PIPESTATUS[0]}
set -o pipefail

# 0: the bench exited on its own (ctrlc handles SIGTERM and exits 0).
# 124: timeout stopped it with SIGTERM after the full sample window.
# 137: timeout followed up with SIGKILL.
if [[ $status -ne 0 && $status -ne 124 && $status -ne 137 ]]; then
  echo "ct_capture: $bench exited $status" >&2
  exit "$status"
fi

if ! grep -q "max t =" "$outfile"; then
  echo "ct_capture: $bench produced no max_t measurement" >&2
  exit 1
fi
