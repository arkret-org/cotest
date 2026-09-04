#!/usr/bin/env python3
"""Check that API-only Playwright ownership stays closed over Rust tests."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
COTEST_ROOT = WORKSPACE_ROOT / "cotest"
MANIFEST_PATH = COTEST_ROOT / "api-only-migration.json"
BROWSER_SIGNAL = re.compile(
    r"\b(?:page|browser|context)\b|"
    r"\.(?:locator|getByRole|getByText|getByTestId|getByLabel|getByPlaceholder|"
    r"getByTitle|getByAltText|goto|screenshot)\("
)


def _load_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("migration manifest must be an object")
    return value


def validation_errors(
    workspace_root: Path = WORKSPACE_ROOT,
    manifest_path: Path | None = None,
) -> list[str]:
    if manifest_path is None:
        manifest_path = workspace_root / "cotest" / "api-only-migration.json"
    manifest = _load_manifest(manifest_path)
    errors: list[str] = []
    if manifest.get("schema") != "arkret.api-only-rust-migration.v1":
        errors.append("unsupported migration manifest schema")

    candidates = manifest.get("candidates")
    expected = manifest.get("expected_candidate_count")
    if not isinstance(candidates, list):
        return errors + ["migration manifest candidates must be an array"]
    if expected != 30 or len(candidates) != expected:
        errors.append(f"expected exactly 30 migration candidates, found {len(candidates)}")

    seen_sources: set[str] = set()
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            errors.append(f"candidate[{index}] must be an object")
            continue
        source = candidate.get("source")
        if not isinstance(source, str) or not source.endswith(".spec.ts"):
            errors.append(f"candidate[{index}] has an invalid source")
            continue
        if source in seen_sources:
            errors.append(f"duplicate migration source: {source}")
        seen_sources.add(source)
        if (workspace_root / source).exists():
            errors.append(f"migrated API-only source still exists: {source}")
        if candidate.get("disposition") not in {"migrated", "duplicate_removed"}:
            errors.append(f"candidate {source} has an unfinished disposition")
        replacements = candidate.get("replacements")
        if not isinstance(replacements, list) or not replacements:
            errors.append(f"candidate {source} has no Rust replacement evidence")
            continue
        for replacement in replacements:
            if not isinstance(replacement, dict):
                errors.append(f"candidate {source} has an invalid replacement")
                continue
            file_name = replacement.get("file")
            symbol = replacement.get("symbol")
            if not isinstance(file_name, str) or not isinstance(symbol, str):
                errors.append(f"candidate {source} has incomplete replacement evidence")
                continue
            target = workspace_root / file_name
            if target.suffix != ".rs" or not target.is_file():
                errors.append(f"candidate {source} replacement is missing: {file_name}")
                continue
            if symbol not in target.read_text(encoding="utf-8", errors="replace"):
                errors.append(
                    f"candidate {source} replacement symbol {symbol!r} is missing from {file_name}"
                )

    specialized = manifest.get("specialized_api_lanes")
    if not isinstance(specialized, list) or not all(
        isinstance(item, str) for item in specialized
    ):
        return errors + ["specialized_api_lanes must be a string array"]
    specialized_set = set(specialized)
    for path_string in specialized_set:
        if not (workspace_root / path_string).is_file():
            errors.append(f"specialized API lane is missing: {path_string}")

    tests_root = workspace_root / "cotest" / "e2e" / "tests"
    for path in sorted(tests_root.rglob("*.spec.ts")):
        relative = path.relative_to(workspace_root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        if not BROWSER_SIGNAL.search(text) and relative not in specialized_set:
            errors.append(f"API-only Playwright spec is not classified: {relative}")

    return errors


def validate_repository(
    workspace_root: Path = WORKSPACE_ROOT,
    manifest_path: Path | None = None,
) -> None:
    errors = validation_errors(workspace_root, manifest_path)
    if errors:
        raise ValueError("; ".join(errors))


def main() -> int:
    try:
        validate_repository()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"API-only migration gate failed: {error}")
        return 1
    print(f"checked {MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
