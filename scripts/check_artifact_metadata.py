#!/usr/bin/env python3
"""Apply the canonical static metadata rules to SDK and test-owned JSON inputs."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
source = ROOT / "arkret-spec/tools/check_artifact_metadata.py"
spec = importlib.util.spec_from_file_location("canonical_artifact_metadata", source)
canonical = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canonical)


def writer_metadata_errors(source: str) -> list[str]:
    pattern = r"(?:schema|report_schema)\s*=\s*[\"'](?:cotest\.|arkret\.)[^\"']+[\"']"
    return [f"self-declared artifact format without a schema contract: {match[0]}"
            for match in re.finditer(pattern, source)]


def check(root: Path = ROOT, *, include_coordination: bool = False) -> list[str]:
    paths = sorted((root / "arkret-rust-sdk/tools").glob("*.json"))
    paths += sorted((root / "cotest/tests/fixtures").glob("*.json"))
    paths += sorted((root / "cotest/scripts/tests/fixtures").rglob("*.json"))
    if include_coordination:
        paths += sorted((root / "arkret-work/evidence").glob("*/index.json"))
        paths += [root / "arkret-work/tools" / name for name in (
            "authority-retirement-rules.json", "semantic-residue-rules.json", "review_reference_history.json",
        )]
    paths += [root / relative for relative in (
        "cotest/config/implementation-acceptance.json",
        "cotest/operation-test-coverage.json",
        "arkret-rust-sdk/compatibility/manifest.json",
        "coauth/conformance/configs/test-plans.json",
        "floria/floria.config.schema.json",
        "cotest/api-only-migration.json",
        "cotest/operation-product-private-paths.json",
        "cotest/e2e/scenarios/evidence-manifest.json",
        "inkson/tests/contract/mock-operation-review.json",
        "inkson/tests/e2e/mock-operation-inventory.json",
        "inkson/tests/contract/fixtures/native-read-evidence.json",
        "inkson/tests/contract/fixtures/native-read-evidence.manifest.json",
        "inkson/assets/vendor/manifest.json",
    )]
    errors = []
    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        fixture = path.parent == root / "cotest/tests/fixtures" or path.name == "evidence-manifest.json"
        errors += [f"{path.relative_to(root)}: {message}" for message in canonical.metadata_errors(document, fixture=fixture)]
    for path in sorted((root / "cotest/scripts").rglob("*.ps1")):
        errors += [f"{path.relative_to(root)}: {message}"
                   for message in writer_metadata_errors(path.read_text(encoding="utf-8"))]
    return errors


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--include-coordination", action="store_true",
                        help="also inspect Work indexes and tool configuration in the complete workspace")
    args = parser.parse_args()
    errors = check(include_coordination=args.include_coordination)
    for error in errors:
        print(error)
    if not errors:
        print("SDK and test artifacts: no redundant revisions or fixture labels")
    raise SystemExit(bool(errors))
