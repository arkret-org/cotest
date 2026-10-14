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

    native = manifest.get("native_live_migrations", [])
    if not isinstance(native, list):
        return errors + ["native_live_migrations must be an array"]
    native_sources: set[str] = set()
    registry_path = workspace_root / "arkret-spec/spec/v1/artifacts/registry/operation-registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8")) if native and registry_path.is_file() else {}
    registered_operations = {row["operation_id"] for row in registry.get("operations", [])}
    if native and not registered_operations:
        errors.append("native migrations require the canonical operation registry")

    def validate_native_test(test: dict, source: str) -> None:
        target, symbol = test.get("target"), test.get("symbol")
        if not isinstance(target, str) or not isinstance(symbol, str) or not re.fullmatch(r"[a-z0-9_]+", target) or not re.fullmatch(r"[a-z0-9_]+", symbol):
            errors.append(f"invalid native live migration Cargo selector: {source}")
            return
        path = workspace_root / "cotest/tests" / f"{target}.rs"
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        if not re.search(r"\basync\s+fn\s+" + re.escape(symbol) + r"\s*\(", text):
            errors.append(f"native live migration test is missing: {target}::{symbol}")
        if test.get("environment", "canonical") not in {"canonical", "isolated_station"}:
            errors.append(f"native migration has an invalid environment: {source}")
        operations = test.get("operation_ids")
        if not isinstance(operations, list) or not operations or not all(isinstance(value, str) and value in registered_operations for value in operations):
            errors.append(f"native live migration has no registered operation evidence: {source}")

    for entry in native:
        required = {"source", "target", "symbol", "operation_ids", "legacy_case_count", "legacy_projects", "legacy_fully_implemented"}
        if not isinstance(entry, dict) or not required <= set(entry) or set(entry) - required - {"environment", "supporting_tests"}:
            errors.append("native live migration has unknown or missing fields")
            continue
        source, target, symbol = (entry[key] for key in ("source", "target", "symbol"))
        if not all(isinstance(value, str) for value in (source, target, symbol)):
            errors.append("native live migration selectors must be strings")
            continue
        if source not in seen_sources or source in native_sources:
            errors.append(f"native live migration has no unique migrated source: {source}")
        native_sources.add(source)
        validate_native_test(entry, source)
        supporting = entry.get("supporting_tests", [])
        if not isinstance(supporting, list):
            errors.append(f"native migration supporting_tests must be an array: {source}")
        else:
            for test in supporting:
                if not isinstance(test, dict) or set(test) - {"target", "symbol", "operation_ids", "environment"} or not {"target", "symbol", "operation_ids"} <= set(test):
                    errors.append(f"native migration has invalid supporting test: {source}")
                else:
                    validate_native_test(test, source)
        if type(entry["legacy_case_count"]) is not int or entry["legacy_case_count"] < 1:
            errors.append(f"native migration has no retained historical case count: {source}")
        projects = entry["legacy_projects"]
        if not isinstance(projects, list) or not projects or not all(
            isinstance(project, str) and project in {"chrome", "chromium", "joint-api", "joint-inkson"} for project in projects
        ) or len(set(projects)) != len(projects):
            errors.append(f"native migration has invalid prior Playwright selection: {source}")
        if type(entry["legacy_fully_implemented"]) is not bool:
            errors.append(f"native migration has no prior smoke selector: {source}")
    for candidate in candidates:
        if isinstance(candidate, dict) and candidate.get("coverage_status") == "live_native" and candidate.get("source") not in native_sources:
            errors.append(f"migrated live coverage has no mandatory joint executor: {candidate.get('source')}")

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
