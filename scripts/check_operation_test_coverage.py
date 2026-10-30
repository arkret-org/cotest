#!/usr/bin/env python3
"""Generate and check the cross-layer operation test responsibility inventory.

The current operation registry is the only operation-id source. Test sources
only contribute evidence: layer, responsibility, input, assertions and the
location of a retained oracle. Duplicate candidates require byte-equivalent
normalized test scopes as well as equal input and assertion fingerprints.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import stat
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
    "coland_unit",
    "coland_http",
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
    "coland_unit": "protocol_kat",
    "coland_http": "http_binding",
    "cotest_rust": "protocol_kat",
    "cotest_e2e": "product_flow",
    "inkson_e2e": "product_flow",
}

OPERATION_TOKEN = re.compile(
    r"ak\.(?:server|self|peer|open|find|gate|root|edge)"
    r"(?:\.[a-z0-9_]+)+\.v\d+"
)
RUST_OPERATION_CONSTANT_DEFINITION = re.compile(
    r"pub\s+const\s+([A-Z][A-Z0-9_]*)\s*:\s*&'static\s+str\s*=\s*\"([^\"]+)\"\s*;"
)
RUST_OPERATION_CONSTANT_REFERENCE = re.compile(
    r"\bServiceOperationId::([A-Z][A-Za-z0-9_]*)\b"
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
IGNORED_DIRS = {".git", "artifacts", "node_modules", "target", "vendor"}


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
    # Inventory identities use checkout-relative paths. Resolving a repository
    # junction here moves its sources outside this workspace and also replaces
    # file-symlink identities; source fingerprints still read the actual bytes.
    relative = path.absolute().relative_to(WORKSPACE_ROOT)
    if ".." in relative.parts:
        raise ValueError(f"source identity contains parent traversal: {path}")
    return relative.as_posix()


def read_source_bytes(path: Path) -> bytes:
    """Fingerprint the actual LF source bytes; never repair a checkout here."""
    content = path.read_bytes()
    if b"\r" in content:
        raise ValueError(f"source must use LF line endings (CRLF/CR forbidden): {path}")
    return content


def read_source_text(path: Path) -> str:
    # Keep the existing lexical treatment of non-UTF-8 bytes. Line endings are
    # checked before decoding, so universal-newline translation cannot hide CR.
    return read_source_bytes(path).decode("utf-8", errors="replace")


def ignored_source_path(path: Path) -> bool:
    try:
        parts = path.absolute().relative_to(WORKSPACE_ROOT).parts
    except ValueError:
        # Standalone walker callers retain their original lexical filtering.
        parts = path.parts
    return any(part in IGNORED_DIRS for part in parts)


def source_file(path: Path) -> bool:
    return path.is_file() and not ignored_source_path(path)


def directory_reparse_link(path: Path) -> bool:
    try:
        return path.is_symlink() or (
            os.name == "nt"
            and path.lstat().st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT
        )
    except FileNotFoundError:
        return True


def source_paths(root: Path, suffix: str) -> Iterable[Path]:
    """Walk source files while pruning the existing ignored directories."""
    if not root.is_dir() or ignored_source_path(root):
        return
    for directory, directories, files in os.walk(root, followlinks=False):
        parent = Path(directory)
        directories[:] = sorted(
            name for name in directories
            if name not in IGNORED_DIRS
            and not directory_reparse_link(parent / name)
        )
        for name in sorted(files):
            path = parent / name
            # is_file deliberately retains the original file-symlink behavior.
            if path.match("*" + suffix) and source_file(path):
                yield path


def rust_test_like(path: Path, text: str) -> bool:
    return (
        "tests" in path.parts
        or path.name in {"tests.rs", "contract_tests.rs"}
        or RUST_TEST_ATTRIBUTE.search(text) is not None
    )


def discover_layer_sources(workspace_root: Path = WORKSPACE_ROOT) -> tuple[LayerSource, ...]:
    coland = workspace_root / "coland"
    cotest = workspace_root / "cotest"
    inkson = workspace_root / "inkson"

    coland_http = {
        path
        for root in (
            coland / "crates" / "http" / "tests",
            coland / "crates" / "server" / "tests",
        )
        if root.is_dir()
        for path in source_paths(root, ".rs")
        if source_file(path)
    }
    coland_unit: set[Path] = set()
    crates = coland / "crates"
    if crates.is_dir():
        for path in source_paths(crates, ".rs"):
            if not source_file(path) or path in coland_http:
                continue
            text = read_source_text(path)
            if rust_test_like(path, text):
                coland_unit.add(path)

    cotest_rust = {
        path
        for root in (
            cotest / "tests",
            cotest / "src" / "conformance",
            cotest / "src" / "scenarios",
            cotest / "crates" / "inkson-client-tests" / "src",
            cotest / "crates" / "inkson-client-tests" / "tests",
        )
        if root.is_dir()
        for path in source_paths(root, ".rs")
        if source_file(path)
    }
    cotest_crates = cotest / "crates"
    if cotest_crates.is_dir():
        cotest_rust.update(
            path for path in source_paths(cotest_crates, ".rs")
            if source_file(path)
            and rust_test_like(path, read_source_text(path))
        )
    cotest_e2e = {
        path
        for path in source_paths(cotest / "e2e", ".ts")
        if source_file(path)
    } if (cotest / "e2e").is_dir() else set()
    inkson_e2e = {
        path
        for path in source_paths(inkson / "tests" / "e2e", ".ts")
        if source_file(path)
    } if (inkson / "tests" / "e2e").is_dir() else set()

    return (
        LayerSource("coland_unit", tuple(sorted(coland_unit))),
        LayerSource("coland_http", tuple(sorted(coland_http))),
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
    # Path ordering compares native components (and case-folds on Windows).
    # The hash contract instead orders the exact relative POSIX inventory strings.
    for path in sorted(files, key=relative_path):
        preimage.extend(relative_path(path).encode("utf-8"))
        preimage.append(0)
        preimage.extend(hashlib.sha256(read_source_bytes(path)).digest())
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


def sdk_operation_symbols(text: str, operation_ids: set[str]) -> dict[str, str]:
    """Resolve symbols only through the generated enum/as_str/constant tables."""
    constants: dict[str, str] = {}
    for name, operation in RUST_OPERATION_CONSTANT_DEFINITION.findall(text):
        if not OPERATION_TOKEN.fullmatch(operation):
            continue
        if name in constants or operation not in operation_ids:
            raise ValueError(f"SDK operation constant is duplicated or outside the registry: {name}")
        constants[name] = operation
    if not constants or set(constants.values()) != operation_ids:
        raise ValueError("SDK generated operation constants do not close the registry")

    def unique_block(pattern: str, description: str) -> str:
        matches = list(re.finditer(pattern, text))
        if len(matches) != 1:
            raise ValueError(f"SDK generated {description} is absent or ambiguous")
        opening = matches[0].end() - 1
        return text[opening + 1 : matching_brace(text, opening) - 1]

    enum_body = unique_block(r"\bpub\s+enum\s+ServiceOperationId\s*\{", "operation enum")
    variant_pattern = re.compile(r"\s*([A-Z][A-Za-z0-9]*)\s*,")
    variants = variant_pattern.findall(enum_body)
    if variant_pattern.sub("", enum_body).strip() or len(set(variants)) != len(variants):
        raise ValueError("SDK operation enum contains an unparsed or duplicate variant")

    method = unique_block(
        r"\bpub\s+const\s+fn\s+as_str\(self\)\s*->\s*&'static\s+str\s*\{",
        "operation as_str method",
    )
    match_self = re.fullmatch(r"\s*match\s+self\s*\{(.*)\}\s*", method, re.DOTALL)
    if match_self is None:
        raise ValueError("SDK operation as_str is not a closed match on self")
    arms = match_self.group(1)
    arm_pattern = re.compile(
        r"\s*Self::([A-Z][A-Za-z0-9]*)\s*=>\s*"
        r"(?:\{\s*Self::([A-Z][A-Z0-9_]*)\s*\}\s*,?|Self::([A-Z][A-Z0-9_]*)\s*,)"
    )
    aliases: dict[str, str] = {}
    targets: list[str] = []
    for arm in arm_pattern.finditer(arms):
        variant, braced, direct = arm.groups()
        target = braced or direct
        if variant in aliases or target not in constants:
            raise ValueError(f"SDK operation as_str has a duplicate variant or unknown target: {variant}")
        aliases[variant] = constants[target]
        targets.append(target)
    if (
        arm_pattern.sub("", arms).strip()
        or set(aliases) != set(variants)
        or len(targets) != len(set(targets))
        or set(targets) != set(constants)
    ):
        raise ValueError("SDK operation enum/as_str/constants mapping is not closed")
    return {**constants, **aliases}


def operation_references(
    text: str, suffix: str, constants: dict[str, str]
) -> list[tuple[str, int, int]]:
    references = [(match.group(0), match.start(), match.end()) for match in OPERATION_TOKEN.finditer(text)]
    if suffix == ".rs":
        references.extend(
            (constants[match.group(1)], match.start(), match.end())
            for match in RUST_OPERATION_CONSTANT_REFERENCE.finditer(text)
            if match.group(1) in constants
        )
    return sorted(references, key=lambda reference: reference[1])


def evidence_from_file(
    layer: str,
    path: Path,
    operation_ids: set[str],
    constants: dict[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    text = read_source_text(path)
    scopes = source_scopes(path, text)
    path_text = relative_path(path)
    grouped: dict[tuple[str, str, int], dict[str, Any]] = {}
    classified_non_registry: list[dict[str, Any]] = []
    unknown_literals: list[dict[str, Any]] = []

    for token, start, end in operation_references(text, path.suffix, constants):
        line = text.count("\n", 0, start) + 1
        scope = scope_for_position(scopes, start, line)
        if scope.kind == "module_helper":
            line_start = text.rfind("\n", 0, start) + 1
            line_end = text.find("\n", end)
            line_end = len(text) if line_end < 0 else line_end
            scope_text = text[line_start:line_end]
        else:
            scope_text = text[scope.start : scope.end]

        if token not in operation_ids:
            context_start = max(0, start - 160)
            context_end = min(len(text), end + 160)
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
    for repo_name in ("coland", "cotest"):
        repo = workspace_root / repo_name
        if not repo.is_dir():
            continue
        for path in source_paths(repo, ".rs"):
            if not source_file(path):
                continue
            text = read_source_text(path)
            if rust_test_like(path, text):
                sources.add(path)
    for root in (
        workspace_root / "cotest" / "e2e",
        workspace_root / "inkson" / "tests" / "e2e",
    ):
        if root.is_dir():
            sources.update(path for path in source_paths(root, ".ts") if source_file(path))
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
        constants_path = WORKSPACE_ROOT / "arkret-rust-sdk/crates/wire/src/generated/operation_ids.rs"
        constants_bytes = read_source_bytes(constants_path)
        constants = sdk_operation_symbols(constants_bytes.decode("utf-8"), set(operations))

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
                    layer.name, path, set(operations), constants
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
            text = read_source_text(path)
            if any(token in operations for token, _, _ in operation_references(text, path.suffix, constants)):
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
            "generated_from": {
                "operation_registry": relative_path(REGISTRY_PATH),
                "operation_registry_sha256": sha256_bytes(registry_bytes),
                "operation_constants": relative_path(constants_path),
                "operation_constants_sha256": sha256_bytes(constants_bytes),
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
                "protected_oracle": "coland/crates/storage/src/contract_tests.rs",
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


def acceptance_digest(text: str) -> tuple[int, str]:
    """Bind the remaining criteria, including indented continuation lines."""
    criteria: list[str] = []
    collecting = False
    for line in text.splitlines():
        if re.match(r"^\s*[-*] \[ \] ", line):
            criteria.append(line.rstrip())
            collecting = True
        elif collecting and line[:1].isspace() and line.strip():
            criteria.append(line.rstrip())
        elif line.strip():
            collecting = False
    count = sum(bool(re.match(r"^\s*[-*] \[ \] ", line)) for line in criteria)
    return count, sha256_text("\n".join(criteria))


def validate_acceptance_manifest(workspace_root: Path, manifest: dict[str, Any]) -> dict[str, int]:
    """Check engineering traceability only; never infer execution or a protocol claim."""
    root = workspace_root.resolve()
    if set(manifest) != {"tasks"}:
        raise ValueError("acceptance manifest has unknown or missing fields")
    active = root / "arkret-work/tasks/impl-active"
    if not active.is_dir():
        raise ValueError("acceptance inventory requires the coordination checkout")
    expected = {path.name for path in active.glob("*.md") if path.name != "00-roadmap.md"}
    records = manifest["tasks"]
    if not isinstance(records, list) or not records:
        raise ValueError("acceptance inventory must contain tasks")
    seen: set[str] = set()
    test_count = 0
    criterion_count = 0

    def checked_file(relative: str) -> Path:
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError(f"missing or out-of-workspace acceptance source: {relative}")
        return path

    for record in records:
        fields = {"task", "criteria_count", "criteria_sha256", "spec_refs", "source_refs", "tests", "engineering_checks", "remaining_scenarios"}
        if set(record) != fields:
            raise ValueError("acceptance task has unknown or missing fields")
        task = record["task"]
        if task not in expected or task in seen:
            raise ValueError(f"unknown or duplicate active owner: {task}")
        seen.add(task)
        count, digest = acceptance_digest((active / task).read_text(encoding="utf-8"))
        if not count or count != record["criteria_count"] or digest != record["criteria_sha256"]:
            raise ValueError(f"remaining criteria drifted: {task}")
        criterion_count += count
        if not record["remaining_scenarios"] or not all(isinstance(item, str) and item.strip() for item in record["remaining_scenarios"]):
            raise ValueError(f"active owner must name observable remaining scenarios: {task}")
        if not record["source_refs"]:
            raise ValueError(f"active owner needs implementation sources: {task}")
        for reference in record["spec_refs"]:
            if not reference.startswith("arkret-spec/spec/v1/"):
                raise ValueError(f"acceptance truth must reference current v1 Spec: {reference}")
            checked_file(reference)
        for reference in record["source_refs"]:
            checked_file(reference)
        if not record["tests"] and not record["engineering_checks"]:
            raise ValueError(f"owner needs tests or an engineering oracle: {task}")
        if not record["spec_refs"] and not record["engineering_checks"]:
            raise ValueError(f"protocol owner needs a Spec source: {task}")
        local_tests: set[tuple[str, str]] = set()
        for test in record["tests"]:
            if set(test) != {"path", "symbol", "kind", "covers"} or test["kind"] not in {"contract", "live", "product", "engineering"} or not test["covers"].strip():
                raise ValueError(f"invalid test responsibility: {task}")
            key = (test["path"], test["symbol"])
            if key in local_tests:
                raise ValueError(f"duplicate test responsibility: {task}: {key}")
            local_tests.add(key)
            path = checked_file(test["path"])
            text = path.read_text(encoding="utf-8")
            if path.suffix == ".py":
                symbols = [node.name for node in ast.walk(ast.parse(text)) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")]
            else:
                symbols = [scope.name for scope in source_scopes(path, text)]
            if test["symbol"] not in symbols:
                raise ValueError(f"test entrypoint missing (helper/string is not a test): {key}")
            test_count += 1
    if seen != expected:
        raise ValueError(f"acceptance owners missing: {sorted(expected - seen)}")
    return {"owners": len(seen), "criteria": criterion_count, "test_references": test_count}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--workspace-root", type=Path, default=WORKSPACE_ROOT)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    parser.add_argument("--check-acceptance", action="store_true", help="validate active-owner traceability without claiming execution")
    args = parser.parse_args(argv)
    if args.check_acceptance:
        try:
            summary = validate_acceptance_manifest(args.workspace_root, load_json(args.workspace_root / "cotest/config/implementation-acceptance.json"))
        except (OSError, ValueError, KeyError, TypeError) as error:
            print(f"acceptance traceability failed: {error}", file=sys.stderr)
            return 1
        print(f"acceptance traceability: {summary}; execution/complete claim NOT assessed")
        return 0
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
