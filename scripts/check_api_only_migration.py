#!/usr/bin/env python3
"""Check that API-only Playwright ownership stays closed over Rust tests.

Three lists partition every Playwright spec that never reaches a browser:

* ``candidates``          — migrated or deleted; the source must be gone and a
                            named Rust symbol must have taken it over.
* ``specialized_api_lanes`` — browserless mock/platform/client lanes that stay
                              in Playwright.
* ``pending_migration``   — not migrated yet; the source must still exist, must
                            still be API-only, and must say what it needs.

Any API-only spec outside all three fails the gate, so new browserless coverage
cannot be added to Playwright — it belongs in the Rust harness.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
COTEST_ROOT = WORKSPACE_ROOT / "cotest"
MANIFEST_PATH = COTEST_ROOT / "api-only-migration.json"
# A spec counts as browser coverage when it actually takes a Playwright page
# fixture or drives one. Matching the bare words `page` / `browser` / `context`
# classified thirteen API-only specs as browser coverage because those words
# occur in prose comments, in JSON-LD `"@context"`, and in
# `request.newContext()` — the API-only request fixture. The signals below are
# all syntactic uses of a page or a browser context.
# A spec also reaches a browser when it calls a helper that opens one for it.
# `users.ts` has exactly one `browser.newContext()`, inside `openUser`; these are
# the exported entry points whose call graph reaches it. A spec that only calls
# them is browser coverage even though its own text drives no page, and running
# it browserless fails where `inksonBaseUrl()` refuses to invent a URL. Keep
# this list in step with `e2e/helpers/users.ts`: a new page-opening export
# belongs here.
BROWSER_ENTRY_HELPERS = (
    "openUser",
    "openUserPage",
    "openDpopUserPage",
    "openDpopUserPageForAccount",
    "openDpopUserPageFromSession",
)
BROWSER_SIGNAL = re.compile(
    # Declaring the fixture is enough: Playwright resolves it before the test
    # body runs, even when a runtime branch never reads it.
    r"async\s*\(\s*\{[^}]*\bbrowser\b|"
    r"\bpage\s*[.,:})]|"
    r"\bpage\b\s*=>|"
    r"\.newPage\(|"
    r"browser\.newContext\(|"
    r"\btest\.use\(|"
    r"\.(?:locator|getByRole|getByText|getByTestId|getByLabel|getByPlaceholder|"
    r"getByTitle|getByAltText|screenshot)\(|"
    r"\b(?:" + "|".join(BROWSER_ENTRY_HELPERS) + r")\s*\("
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
    if not isinstance(expected, int) or expected < 1:
        errors.append("expected_candidate_count must be a positive integer")
    elif len(candidates) != expected:
        errors.append(
            f"expected exactly {expected} migration candidates, found {len(candidates)}"
        )

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
    for path_string in sorted(specialized_set):
        path = workspace_root / path_string
        if not path.is_file():
            errors.append(f"specialized API lane is missing: {path_string}")
            continue
        if BROWSER_SIGNAL.search(path.read_text(encoding="utf-8", errors="replace")):
            errors.append(
                f"specialized API lane drives a browser — it cannot run in joint-api: {path_string}"
            )

    pending = manifest.get("pending_migration", [])
    if not isinstance(pending, list):
        return errors + ["pending_migration must be an array"]
    pending_set: set[str] = set()
    for index, entry in enumerate(pending):
        if not isinstance(entry, dict):
            errors.append(f"pending_migration[{index}] must be an object")
            continue
        source = entry.get("source")
        if not isinstance(source, str) or not source.endswith(".spec.ts"):
            errors.append(f"pending_migration[{index}] has an invalid source")
            continue
        if source in pending_set:
            errors.append(f"duplicate pending migration source: {source}")
        if source in seen_sources:
            errors.append(f"pending migration source is already migrated: {source}")
        if source in specialized_set:
            errors.append(f"pending migration source is a specialized lane: {source}")
        pending_set.add(source)
        needs = entry.get("needs")
        if not isinstance(needs, str) or not needs.strip():
            errors.append(f"pending migration {source} does not say what it needs")
        path = workspace_root / source
        if not path.is_file():
            errors.append(
                f"pending migration source no longer exists — move it to candidates: {source}"
            )
            continue
        if BROWSER_SIGNAL.search(path.read_text(encoding="utf-8", errors="replace")):
            errors.append(
                f"pending migration source now drives a browser — drop it from the list: {source}"
            )

    # `pending_migration` and `specialized_api_lanes` together are the complete,
    # closed set of API-only Playwright specs. Anything else that reaches no
    # browser is unclassified drift: new API-only coverage belongs in the Rust
    # harness, not here.
    classified = specialized_set | pending_set
    tests_root = workspace_root / "cotest" / "e2e" / "tests"
    for path in sorted(tests_root.rglob("*.spec.ts")):
        relative = path.relative_to(workspace_root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        if not BROWSER_SIGNAL.search(text) and relative not in classified:
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
