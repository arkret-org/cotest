#!/usr/bin/env sh
# Run clippy over every target and leave machine-readable evidence behind.
#
# This exists because nothing runs clippy for this repository: the GitHub
# Actions workflows are disabled across all eleven repositories, so the lint
# baseline went red and stayed red — eight findings accumulated in files no one
# had reason to re-read. A gate that only lives in a workflow is a gate that
# never runs; this one is local and takes seconds.
#
# `-D warnings` is the point: a warning nobody fails on is a warning nobody
# fixes.
#
# `--all-features` is deliberately *not* the default here. The only feature is
# `test-with-containers`, whose code is `cfg`-gated to non-Windows and whose
# dependency drags in a Docker runtime; nothing in this workspace is behind
# `required-features`, so the default target set already type-checks every
# file. Pass `--all-features` yourself on a Linux box that wants it.
#
# Output contract: the verdict goes to files, not to the terminal tail. Read
# `$COTEST_CLIPPY_GATE_DIR/summary.txt`.
#
# Usage:
#   scripts/clippy_gate.sh                    # whole workspace
#   scripts/clippy_gate.sh --all-features     # narrow or widened re-run

set -eu

gate_dir="${COTEST_CLIPPY_GATE_DIR:-target/clippy-gate}"
target_dir="${COTEST_CLIPPY_GATE_TARGET_DIR:-target/clippy}"

mkdir -p "$gate_dir"
log="$gate_dir/clippy.log"
summary="$gate_dir/summary.txt"
status="$gate_dir/status.txt"

echo "clippy gate: target=$target_dir log=$log"

set +e
CARGO_TARGET_DIR="$target_dir" cargo clippy --locked \
    --workspace --all-targets "$@" -- -D warnings > "$log" 2>&1
code=$?
set -e

echo "$code" > "$status"

# Keep the lines a reviewer acts on: every diagnostic header and the source
# location that follows it.
grep -E '^(error(\[E[0-9]+\])?:|warning:|\s+--> )' "$log" > "$summary" || true

echo "--- $summary ---"
cat "$summary"
echo "--- exit $code (full log: $log) ---"
exit "$code"
