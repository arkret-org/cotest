#!/usr/bin/env bash
# C.8 — CI compliance: every `#[ignore]` attribute in the cotest crate must
# be preceded by a `/// Issue:` or `/// Gating:` doc comment so reviewers can
# trace why the test is skipped and what unblocks it.
#
# Usage:
#   scripts/check_ignore_comments.sh
#
# Exits non-zero if any `#[ignore]` line in `tests/` or `src/` (excluding
# `target/`) is not preceded — within a small lookback window — by a
# `/// Issue:` or `/// Gating:` doc-comment line.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Lookback window: max number of lines between the doc comment and the
# `#[ignore]` attribute. Keeps room for other attribute lines like
# `#[tokio::test]`, `#[serial]`, etc. without being permissive enough to
# attribute an unrelated earlier comment.
WINDOW=12

# Files to scan: any `.rs` file under tests/ or src/ that mentions
# `#[ignore`. We use `git ls-files` when available so submodule / target
# directories never sneak in; otherwise fall back to a `find` filter.
if command -v git >/dev/null 2>&1 && [ -d ".git" ]; then
  FILES=$(git ls-files 'tests/*.rs' 'src/**/*.rs' 'src/*.rs' 2>/dev/null || true)
else
  FILES=$(find tests src -type f -name '*.rs' -not -path '*/target/*' 2>/dev/null || true)
fi

if [ -z "${FILES:-}" ]; then
  echo "check_ignore_comments: no Rust files found under tests/ or src/" >&2
  exit 0
fi

missing=0
total=0

for file in $FILES; do
  # Skip if no #[ignore at all
  if ! grep -q '#\[ignore' "$file" 2>/dev/null; then
    continue
  fi

  # Collect 1-based line numbers of each #[ignore attribute.
  mapfile -t lines < <(grep -nE '^\s*#\[ignore' "$file" | cut -d: -f1)

  for lineno in "${lines[@]}"; do
    total=$((total + 1))
    start=$((lineno - WINDOW))
    if [ "$start" -lt 1 ]; then start=1; fi

    # Window of preceding lines (exclusive of the #[ignore] line itself).
    snippet=$(sed -n "${start},$((lineno - 1))p" "$file")

    if echo "$snippet" | grep -qE '^\s*///\s*(Issue|Gating):'; then
      continue
    fi

    echo "missing /// Issue: or /// Gating: doc comment above #[ignore] at ${file}:${lineno}" >&2
    missing=$((missing + 1))
  done
done

if [ "$missing" -gt 0 ]; then
  echo >&2
  echo "FAIL: ${missing} of ${total} #[ignore] attribute(s) lack a tracking doc comment." >&2
  echo "Add `/// Issue: <ticket>` or `/// Gating: <reason>` immediately above each one." >&2
  exit 1
fi

echo "ok: ${total} #[ignore] attribute(s) all have /// Issue: or /// Gating: tracking comments"
