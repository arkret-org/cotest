#!/usr/bin/env bash
# C.8 — CI compliance: every `#[ignore]` attribute in the cotest crate must
# be preceded by a `/// Issue:` or `/// Gating:` doc comment so reviewers can
# trace why the test is skipped and what unblocks it.
#
# ARC-0002 (refactoring plan 2026-07-10): additionally, every `#[ignore]` must carry a
# machine-readable `/// Tier:` line declaring its test layer:
#   contract       — deterministic cross-project contract check (PR lane)
#   live           — needs real service binaries / Docker / live stack (nightly lane)
#   mls-data-plane — needs real MLS group state / epoch secrets / ciphertext
#                    (controlled-environment lane)
#
# Usage:
#   scripts/check_ignore_comments.sh
#
# Exits non-zero if any `#[ignore]` line in `tests/` or `src/` (excluding
# `target/`) is not preceded — within a small lookback window — by BOTH a
# `/// Issue:` or `/// Gating:` doc-comment line and a valid `/// Tier:` line.

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
if command -v git >/dev/null 2>&1 && FILES=$(git ls-files -- '*.rs'); then
  :
else
  FILES=$(find tests src crates -type f -name '*.rs' -not -path '*/target/*')
fi

if [ -z "${FILES:-}" ]; then
  echo "check_ignore_comments: no Rust files found under tests/ or src/" >&2
  exit 1
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

    ok=1
    if ! echo "$snippet" | grep -qE '^\s*///\s*(Issue|Gating):'; then
      echo "missing /// Issue: or /// Gating: doc comment above #[ignore] at ${file}:${lineno}" >&2
      ok=0
    fi
    if ! echo "$snippet" | grep -qE '^\s*///\s*Tier:\s*(contract|live|mls-data-plane)\s*$'; then
      echo "missing or invalid /// Tier: (contract|live|mls-data-plane) above #[ignore] at ${file}:${lineno}" >&2
      ok=0
    fi
    if [ "$ok" -eq 0 ]; then
      missing=$((missing + 1))
    fi
  done
done

if [ "$missing" -gt 0 ]; then
  echo >&2
  echo "FAIL: ${missing} of ${total} #[ignore] attribute(s) lack tracking doc comments." >&2
  printf '%s\n' 'Add `/// Issue: <ticket>` or `/// Gating: <reason>` plus' >&2
  printf '%s\n' '`/// Tier: contract|live|mls-data-plane` immediately above each one.' >&2
  exit 1
fi

echo "ok: ${total} #[ignore] attribute(s) all have /// Issue:|Gating: and /// Tier: comments"
