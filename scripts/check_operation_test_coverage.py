#!/usr/bin/env python3
"""Generate and check the cross-layer operation test responsibility inventory.

The current operation registry is the only operation-id source. Test sources
only contribute evidence: layer, responsibility, input, assertions and the
location of a retained oracle. Duplicate candidates require byte-equivalent
normalized test scopes as well as equal input and assertion fingerprints.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


COTEST_REPO = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = Path(
    os.environ.get("ARKRET_WORKSPACE_ROOT", COTEST_REPO.parent)
).resolve()
SPEC_ARTIFACTS = Path(
    os.environ.get(
        "ARKRET_SPEC_ARTIFACTS",
        WORKSPACE_ROOT / "arkret-spec" / "spec" / "v1" / "artifacts",
    )
).resolve()
REGISTRY_PATH = SPEC_ARTIFACTS / "registry" / "operation-registry.json"
OUTPUT_PATH = COTEST_REPO / "operation-test-coverage.json"

TEST_LAYERS = (
    "soland_unit",
    "soland_http",
    "cotest_rust",
    "cotest_e2e",
    "inkson_e2e",
)
RESPONSIBILITIES = (
    "protocol_kat",
    "storage_parity",
    "http_binding",
    "product_flow",
    "fault_recovery",
    "security_negative",
)
DEFAULT_RESPONSIBILITY = {
    "soland_unit": "protocol_kat",
    "soland_http": "http_binding",
    "cotest_rust": "protocol_kat",
    "cotest_e2e": "product_flow",
    "inkson_e2e": "product_flow",
}

OPERATION_TOKEN = re.compile(
    r"ak\.(?:server|self|peer|open|find|gate|root|edge)"
    r"(?:\.[a-z0-9_]+)+\.v\d+"
)
RUST_TEST_ATTRIBUTE = re.compile(r"#\[[^\]]*test[^\]]*\]", re.MULTILINE)
RUST_TEST_FUNCTION = re.compile(
    r"(?P<attrs>(?:\s*#\[[^\]]+\]\s*)+)"
    r"(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(?P<name>[A-Za-z0-9_]+)"
    r"[^\{;]*\{",
    re.MULTILINE,
)
TS_TEST_START = re.compile(
    r"\b(?:test|it)(?:\.(?:only|skip|fixme))?\s*\(\s*"
    r"(?P<quote>['\"`])(?P<name>.*?)(?P=quote)",
)
ASSERTION_PATTERN = re.compile(
    r"(?:assert(?:_eq|_ne|_matches)?!|matches!|expect_err|is_err\s*\(|"
    r"is_ok\s*\(|\bexpect\s*\(|\.to(?:Be|Equal|Match|Contain|Have|Throw)|"
    r"rejects\.|resolves\.|panic!)"
)
EXPLICIT_RESPONSIBILITY = re.compile(
    r"operation-coverage:\s*(" + "|".join(RESPONSIBILITIES) + r")"
)
FAULT_KEYWORDS = (
    "recovery",
    "recover_",
    "retry",
    "restart",
    "resume",
    "rollback",
    "response_loss",
    "lost_response",
    "crash",
    "failover",
    "interruption",
)
SECURITY_KEYWORDS = (
    "reject",
    "invalid",
    "unauthor",
    "forbid",
    "denied",
    "tamper",
    "replay",
    "mismatch",
    "spoof",
    "wrong_",
    "expired",
    "stale",
    "noncanonical",
    "cross_account",
    "cross_principal",
    "traversal",
    "unknown_",
)
IGNORED_DIRS = {".git", "node_modules", "target", "vendor"}


@dataclass(frozen=True)
class TestScope:
    name: str
    kind: str
    start: int
    end: int
    line: int


@dataclass(frozen=True)
class LayerSource:
    name: str
    files: tuple[Path, ...]


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def relative_path(path: Path) -> str:
    return path.resolve().relative_to(WORKSPACE_ROOT).as_posix()


def source_file(path: Path) -> bool:
    return path.is_file() and not any(part in IGNORED_DIRS for part in path.parts)


def rust_test_like(path: Path, text: str) -> bool:
    return (
        "tests" in path.parts
        or path.name in {"tests.rs", "contract_tests.rs"}
        or RUST_TEST_ATTRIBUTE.search(text) is not None
    )


def discover_layer_sources(workspace_root: Path = WORKSPACE_ROOT) -> tuple[LayerSource, ...]:
    soland = workspace_root / "soland"
    cotest = workspace_root / "cotest"
    inkson = workspace_root / "inkson"

    soland_http = {
        path
        for root in (
            soland / "crates" / "http" / "tests",
            soland / "crates" / "server" / "tests",
        )
        if root.is_dir()
        for path in root.rglob("*.rs")
        if source_file(path)
    }
    soland_unit: set[Path] = set()
    crates = soland / "crates"
    if crates.is_dir():
        for path in crates.rglob("*.rs"):
            if not source_file(path) or path in soland_http:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if rust_test_like(path, text):
                soland_unit.add(path)

    cotest_rust = {
        path
        for root in (
            cotest / "tests",
            cotest / "src" / "conformance",
            cotest / "src" / "scenarios",
        )
        if root.is_dir()
        for path in root.rglob("*.rs")
        if source_file(path)
    }
    cotest_crates = cotest / "crates"
    if cotest_crates.is_dir():
        cotest_rust.update(
            path for path in cotest_crates.rglob("*.rs")
            if source_file(path)
            and rust_test_like(path, path.read_text(encoding="utf-8", errors="replace"))
        )
    cotest_e2e = {
        path
        for path in (cotest / "e2e").rglob("*.ts")
        if source_file(path)
    } if (cotest / "e2e").is_dir() else set()
    inkson_e2e = {
        path
        for path in (inkson / "tests" / "e2e").rglob("*.ts")
        if source_file(path)
    } if (inkson / "tests" / "e2e").is_dir() else set()

    return (
        LayerSource("soland_unit", tuple(sorted(soland_unit))),
        LayerSource("soland_http", tuple(sorted(soland_http))),
        LayerSource("cotest_rust", tuple(sorted(cotest_rust))),
        LayerSource("cotest_e2e", tuple(sorted(cotest_e2e))),
        LayerSource("inkson_e2e", tuple(sorted(inkson_e2e))),
    )


def matching_brace(text: str, opening: int) -> int:
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = 0
    index = opening
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "/" and following == "*":
                block_comment += 1
                index += 2
                continue
            if char == "*" and following == "/":
                block_comment -= 1
                index += 2
                continue
            index += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char == "/" and following == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and following == "*":
            block_comment = 1
            index += 2
            continue
        if char == '"':
            quote = char
            index += 1
            continue
        # Rust lifetimes (`'a`) are not character literals. Only enter the
        # quote state for the two character-literal shapes needed here.
        if char == "'" and (
            (index + 2 < len(text) and text[index + 2] == "'")
            or (
                following == "\\"
                and index + 3 < len(text)
                and text[index + 3] == "'"
            )
        ):
            quote = char
            index += 1
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return len(text)


def rust_test_scopes(text: str) -> list[TestScope]:
    scopes: list[TestScope] = []
    for match in RUST_TEST_FUNCTION.finditer(text):
        attrs = match.group("attrs")
        if RUST_TEST_ATTRIBUTE.search(attrs) is None:
            continue
        opening = text.find("{", match.start(), match.end())
        if opening < 0:
            continue
        scopes.append(
            TestScope(
                name=match.group("name"),
                kind="rust_test",
                start=match.start(),
                end=matching_brace(text, opening),
                line=text.count("\n", 0, match.start()) + 1,
            )
        )
    return scopes


def typescript_test_scopes(text: str) -> list[TestScope]:
    starts = list(TS_TEST_START.finditer(text))
    scopes: list[TestScope] = []
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        scopes.append(
            TestScope(
                name=match.group("name"),
                kind="typescript_test",
                start=match.start(),
                end=end,
                line=text.count("\n", 0, match.start()) + 1,
            )
        )
    return scopes


def scope_for_position(scopes: list[TestScope], position: int, line: int) -> TestScope:
    candidates = [scope for scope in scopes if scope.start <= position < scope.end]
    if candidates:
        return min(candidates, key=lambda scope: scope.end - scope.start)
    return TestScope("<module_helper>", "module_helper", position, position, line)


def normalized_lines(text: str) -> list[str]:
    lines: list[str] = []
    for original in text.splitlines():
        stripped = re.sub(r"//.*$", "", original).strip()
        if not stripped or stripped in {"{", "}", "});", ");"}:
            continue
        lines.append(re.sub(r"\s+", " ", stripped))
    return lines


def evidence_fingerprints(scope_text: str, operation_id: str) -> dict[str, Any]:
    lines = normalized_lines(scope_text)
    assertion_lines = [line for line in lines if ASSERTION_PATTERN.search(line)]
    input_lines = [
        line
        for line in lines
        if line not in assertion_lines
        and not line.startswith("#[")
        and not re.match(r"(?:pub\s+)?(?:async\s+)?fn\s+", line)
    ]
    if not input_lines:
        input_lines = [operation_id]
    normalized_scope = "\n".join(lines)
    return {
        "scope_sha256": sha256_text(normalized_scope),
        "input_sha256": sha256_text("\n".join(input_lines)),
        "assertion_sha256": (
            sha256_text("\n".join(assertion_lines)) if assertion_lines else None
        ),
        "input_preview": input_lines[:4],
        "assertion_preview": assertion_lines[:4],
    }


def responsibility_for(layer: str, path: str, scope_name: str, scope_text: str) -> str:
    explicit = EXPLICIT_RESPONSIBILITY.search(scope_text)
    if explicit is not None:
        return explicit.group(1)
    lowered = f"{path} {scope_name}".lower()
    if path.endswith("/storage/src/contract_tests.rs") or "/storage-postgres/" in path:
        return "storage_parity"
    if any(token in lowered for token in FAULT_KEYWORDS):
        return "fault_recovery"
    if any(token in lowered for token in SECURITY_KEYWORDS):
        return "security_negative"
    return DEFAULT_RESPONSIBILITY[layer]


def aggregate_source_digest(files: Iterable[Path]) -> str:
    preimage = bytearray()
    for path in sorted(files):
        preimage.extend(relative_path(path).encode("utf-8"))
        preimage.append(0)
        preimage.extend(hashlib.sha256(path.read_bytes()).digest())
    return sha256_bytes(bytes(preimage))


def classify_non_registry_literal(path: str, scope: TestScope, context: str) -> str | None:
    lowered = f"{path} {scope.name} {context}".lower()
    if re.search(r"[\"']domain[\"']\s*:", context):
        return "non_operation_domain"
    if path.endswith("/tests/operation_registry_gate.rs"):
        return "synthetic_registry_fixture"
    if any(token in lowered for token in SECURITY_KEYWORDS):
        return "security_negative_selector"
    return None


def source_scopes(path: Path, text: str) -> list[TestScope]:
    return rust_test_scopes(text) if path.suffix == ".rs" else typescript_test_scopes(text)


def evidence_from_file(
    layer: str,
    path: Path,
    operation_ids: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    scopes = source_scopes(path, text)
    path_text = relative_path(path)
    grouped: dict[tuple[str, str, int], dict[str, Any]] = {}
    classified_non_registry: list[dict[str, Any]] = []
    unknown_literals: list[dict[str, Any]] = []

    for match in OPERATION_TOKEN.finditer(text):
        token = match.group(0)
        line = text.count("\n", 0, match.start()) + 1
        scope = scope_for_position(scopes, match.start(), line)
        if scope.kind == "module_helper":
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            line_end = len(text) if line_end < 0 else line_end
            scope_text = text[line_start:line_end]
        else:
            scope_text = text[scope.start : scope.end]

        if token not in operation_ids:
            context_start = max(0, match.start() - 160)
            context_end = min(len(text), match.end() + 160)
            context = text[context_start:context_end]
            classification = classify_non_registry_literal(path_text, scope, context)
            item = {
                "literal": token,
                "file": path_text,
                "line": line,
                "scope": scope.name,
            }
            if classification is None:
                unknown_literals.append(item)
            else:
                item["classification"] = classification
                classified_non_registry.append(item)
            continue

        key = (token, scope.name, scope.line)
        current = grouped.get(key)
        if current is not None:
            current["occurrence_lines"].append(line)
            continue
        fingerprints = evidence_fingerprints(scope_text, token)
        responsibility = responsibility_for(layer, path_text, scope.name, scope_text)
        grouped[key] = {
            "operation_id": token,
            "test_layer": layer,
            "responsibility": responsibility,
            "file": path_text,
            "line": scope.line,
            "scope": scope.name,
            "scope_kind": scope.kind,
            "occurrence_lines": [line],
            "protected_oracle": path_text.endswith(
                "/storage/src/contract_tests.rs"
            ),
            **fingerprints,
        }
    return list(grouped.values()), classified_non_registry, unknown_literals


def broader_test_sources(workspace_root: Path = WORKSPACE_ROOT) -> set[Path]:
    sources: set[Path] = set()
    for repo_name in ("soland", "cotest"):
        repo = workspace_root / repo_name
        if not repo.is_dir():
            continue
        for path in repo.rglob("*.rs"):
            if not source_file(path):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if rust_test_like(path, text):
                sources.add(path)
    for root in (
        workspace_root / "cotest" / "e2e",
        workspace_root / "inkson" / "tests" / "e2e",
    ):
        if root.is_dir():
            sources.update(path for path in root.rglob("*.ts") if source_file(path))
    return sources


def duplicate_candidates(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = {}
    for item in evidence:
        assertion = item["assertion_sha256"]
        if item["scope_kind"] == "module_helper" or assertion is None:
            continue
        key = (
            item["operation_id"],
            item["responsibility"],
            item["scope_sha256"],
            item["input_sha256"],
            assertion,
        )
        groups.setdefault(key, []).append(item)

    result: list[dict[str, Any]] = []
    for key, items in sorted(groups.items()):
        unique_locations = {(item["file"], item["scope"], item["line"]) for item in items}
        if len(unique_locations) < 2:
            continue
        ordered = sorted(
            items,
            key=lambda item: (
                not item["protected_oracle"],
                item["file"],
                item["line"],
            ),
        )
        retained = ordered[0]
        deletable = [item for item in ordered[1:] if not item["protected_oracle"]]
        if not deletable:
            continue
        result.append(
            {
                "operation_id": key[0],
                "responsibility": key[1],
                "equivalence": {
                    "scope_sha256": key[2],
                    "input_sha256": key[3],
                    "assertion_sha256": key[4],
                },
                "retained_oracle": {
                    "file": retained["file"],
                    "line": retained["line"],
                    "scope": retained["scope"],
                    "protected": retained["protected_oracle"],
                },
                "deletion_candidates": [
                    {
                        "file": item["file"],
                        "line": item["line"],
                        "scope": item["scope"],
                    }
                    for item in deletable
                ],
            }
        )
    return result


def generate(workspace_root: Path = WORKSPACE_ROOT) -> dict[str, Any]:
    global WORKSPACE_ROOT, SPEC_ARTIFACTS, REGISTRY_PATH
    original_root = WORKSPACE_ROOT
    original_artifacts = SPEC_ARTIFACTS
    original_registry = REGISTRY_PATH
    WORKSPACE_ROOT = workspace_root.resolve()
    SPEC_ARTIFACTS = WORKSPACE_ROOT / "arkret-spec" / "spec" / "v1" / "artifacts"
    REGISTRY_PATH = SPEC_ARTIFACTS / "registry" / "operation-registry.json"
    try:
        registry_bytes = REGISTRY_PATH.read_bytes()
        registry = json.loads(registry_bytes)
        operation_rows = registry.get("operations", [])
        if not operation_rows:
            raise ValueError("operation registry has no operations")
        operations = {
            row["operation_id"]: row
            for row in operation_rows
            if isinstance(row, dict) and isinstance(row.get("operation_id"), str)
        }
        if len(operations) != len(operation_rows):
            raise ValueError("operation registry contains invalid or duplicate rows")

        layer_sources = discover_layer_sources(WORKSPACE_ROOT)
        assigned_files = {
            path.resolve(): layer.name
            for layer in layer_sources
            for path in layer.files
        }
        all_evidence: list[dict[str, Any]] = []
        classified_non_registry: list[dict[str, Any]] = []
        unknown_literals: list[dict[str, Any]] = []
        layer_metadata: dict[str, Any] = {}
        for layer in layer_sources:
            layer_evidence: list[dict[str, Any]] = []
            for path in layer.files:
                evidence, classified, unknown = evidence_from_file(
                    layer.name, path, set(operations)
                )
                layer_evidence.extend(evidence)
                classified_non_registry.extend(classified)
                unknown_literals.extend(unknown)
            all_evidence.extend(layer_evidence)
            layer_metadata[layer.name] = {
                "source_file_count": len(layer.files),
                "source_sha256": aggregate_source_digest(layer.files),
                "evidence_count": len(layer_evidence),
                "covered_operation_count": len(
                    {item["operation_id"] for item in layer_evidence}
                ),
            }

        unknown_test_files: list[str] = []
        for path in broader_test_sources(WORKSPACE_ROOT):
            if path.resolve() in assigned_files:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if any(operation_id in text for operation_id in operations):
                unknown_test_files.append(relative_path(path))

        unassigned = [
            {
                "file": item["file"],
                "line": item["line"],
                "operation_id": item["operation_id"],
            }
            for item in all_evidence
            if item["responsibility"] not in RESPONSIBILITIES
        ]
        if unknown_test_files or unknown_literals or unassigned:
            details = {
                "unknown_test_files": sorted(unknown_test_files),
                "unknown_operation_literals": sorted(
                    unknown_literals,
                    key=lambda item: (item["file"], item["line"], item["literal"]),
                ),
                "unassigned_responsibilities": unassigned,
            }
            raise ValueError(
                "operation coverage inventory is not closed: "
                + json.dumps(details, ensure_ascii=False)
            )

        evidence_by_cell: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        for item in all_evidence:
            key = (item["operation_id"], item["test_layer"], item["responsibility"])
            public = {key: value for key, value in item.items() if key not in {
                "operation_id", "test_layer", "responsibility"
            }}
            evidence_by_cell.setdefault(key, []).append(public)

        matrix: list[dict[str, Any]] = []
        for operation_id in sorted(operations):
            operation = operations[operation_id]
            for layer in TEST_LAYERS:
                responsibilities = {
                    responsibility: sorted(
                        evidence_by_cell.get((operation_id, layer, responsibility), []),
                        key=lambda item: (item["file"], item["line"], item["scope"]),
                    )
                    for responsibility in RESPONSIBILITIES
                }
                matrix.append(
                    {
                        "operation_id": operation_id,
                        "http": operation.get("http"),
                        "test_layer": layer,
                        "responsibilities": responsibilities,
                    }
                )

        covered_operations = {item["operation_id"] for item in all_evidence}
        candidates = duplicate_candidates(all_evidence)
        return {
            "format_version": 1,
            "source_of_truth": False,
            "generated_from": {
                "operation_registry": relative_path(REGISTRY_PATH),
                "operation_registry_sha256": sha256_bytes(registry_bytes),
                "test_layers": layer_metadata,
            },
            "dimensions": {
                "operation_count": len(operations),
                "test_layers": list(TEST_LAYERS),
                "responsibilities": list(RESPONSIBILITIES),
                "matrix_cell_count": len(operations) * len(TEST_LAYERS),
            },
            "closure": {
                "covered_operation_count": len(covered_operations),
                "uncovered_operation_ids": sorted(set(operations) - covered_operations),
                "unknown_test_files": [],
                "unknown_operation_literals": [],
                "unassigned_responsibilities": [],
                "classified_non_registry_literals": sorted(
                    classified_non_registry,
                    key=lambda item: (item["file"], item["line"], item["literal"]),
                ),
            },
            "duplicate_policy": {
                "required_equal_fields": [
                    "operation_id",
                    "responsibility",
                    "scope_sha256",
                    "input_sha256",
                    "assertion_sha256",
                ],
                "protected_oracle": "soland/crates/storage/src/contract_tests.rs",
                "same_operation_id_alone_is_never_equivalent": True,
            },
            "duplicate_candidates": candidates,
            "matrix": matrix,
        }
    finally:
        WORKSPACE_ROOT = original_root
        SPEC_ARTIFACTS = original_artifacts
        REGISTRY_PATH = original_registry


def serialized(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def check_output(generated: str, output_path: Path = OUTPUT_PATH) -> bool:
    current = output_path.read_text(encoding="utf-8") if output_path.exists() else ""
    return current == generated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--workspace-root", type=Path, default=WORKSPACE_ROOT)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    args = parser.parse_args(argv)
    try:
        generated = serialized(generate(args.workspace_root))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"operation coverage inventory failed: {error}", file=sys.stderr)
        return 1
    if args.check:
        try:
            from check_api_only_migration import validate_repository

            validate_repository(args.workspace_root.resolve())
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print(f"API-only migration gate failed: {error}", file=sys.stderr)
            return 1
        if not check_output(generated, args.output):
            print(
                f"{args.output} is stale; regenerate with {Path(__file__).name}",
                file=sys.stderr,
            )
            return 1
        print(f"checked {args.output}")
        return 0
    # `serialized` already supplies a single final LF. Writing UTF-8 bytes
    # preserves that exact inventory on Python 3.9 as well as newer runtimes.
    args.output.write_bytes(generated.encode("utf-8"))
    print(f"generated {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
