from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check_operation_test_coverage.py"
SPEC = importlib.util.spec_from_file_location("operation_test_coverage", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = inventory
SPEC.loader.exec_module(inventory)


OP_ONE = "ak.server.read.describe.v1"
OP_TWO = "ak.self.committed_event.read.scan.v1"
SDK_OPERATIONS = f"""pub enum ServiceOperationId {{
    ServerReadDescribeV1,
    SelfCommittedEventReadScanV1,
}}
impl ServiceOperationId {{
    pub const SERVER_READ_DESCRIBE_V1: &'static str = "{OP_ONE}";
    pub const SELF_COMMITTED_EVENT_READ_SCAN_V1: &'static str =
        "{OP_TWO}";
    pub const fn as_str(self) -> &'static str {{
        match self {{
            Self::ServerReadDescribeV1 => Self::SERVER_READ_DESCRIBE_V1,
            Self::SelfCommittedEventReadScanV1 => {{
                Self::SELF_COMMITTED_EVENT_READ_SCAN_V1
            }}
        }}
    }}
}}
"""


def directory_link(link: Path, target: Path) -> None:
    if os.name == "nt":
        import _winapi
        _winapi.CreateJunction(str(target), str(link))
        if link.lstat().st_reparse_tag != stat.IO_REPARSE_TAG_MOUNT_POINT:
            raise AssertionError("Expected an actual Windows directory junction")
    else:
        link.symlink_to(target, target_is_directory=True)


class OperationTestCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.write(
            "arkret-spec/spec/v1/artifacts/registry/operation-registry.json",
            json.dumps(
                {
                    "operations": [
                        {"operation_id": OP_ONE, "http": "GET /_arkret/describe"},
                        {"operation_id": OP_TWO, "http": "GET /_arkret/self/events"},
                    ]
                }
            ),
        )
        self.write(
            "arkret-rust-sdk/crates/wire/src/generated/operation_ids.rs",
            SDK_OPERATIONS,
        )
        self.write(
            "coland/crates/storage/src/contract_tests.rs",
            rust_test("shared_storage_oracle", OP_ONE, "assert_eq!(value, value);")
        )
        self.write(
            "coland/crates/server/tests/http_api/negative.rs",
            rust_test("rejects_invalid_selector", OP_ONE, "assert!(result.is_err());"),
        )
        duplicate = rust_test("exact_protocol_oracle", OP_TWO, "assert_eq!(actual, expected);")
        self.write("cotest/tests/oracle_a.rs", duplicate)
        self.write("cotest/tests/oracle_b.rs", duplicate)
        self.write(
            "cotest/e2e/tests/flow.spec.ts",
            ts_test("describe product flow", OP_ONE),
        )
        self.write(
            "inkson/tests/e2e/download.spec.ts",
            ts_test("downloads product file", OP_TWO),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8"))

    def test_source_walk_prunes_ignored_and_directory_links_without_losing_sources(self) -> None:
        sources = self.root / "source-walk"
        for relative in ("nested/kept.rs", "nested/deeper/kept.ts", "plain.rs", ".rs", "not-source.txt"):
            self.write("source-walk/" + relative, "#[test] fn source() {}")
        for ignored in inventory.IGNORED_DIRS:
            self.write(f"source-walk/{ignored}/deep/test.rs", "#[test] fn excluded() {}")
            self.write(f"source-walk/nested/{ignored}/test.ts", "test('excluded', () => {});")
        outside = self.root / "outside-sources"
        outside.mkdir()
        (outside / "outside.rs").write_text("#[test] fn external() {}", encoding="utf-8")
        directory_link(sources / "linked-directory", outside)
        if os.name == "nt":
            # A real hardlink needs no symlink privilege. This Windows branch
            # proves hardlink handling, not file-symlink support.
            os.link(outside / "outside.rs", sources / "linked-file.rs")
            missing_directory = self.root / "missing-directory"
            missing_directory.mkdir()
            directory_link(sources / "dangling.rs", missing_directory)
            missing_directory.rmdir()
            self.assertEqual(
                (sources / "dangling.rs").lstat().st_reparse_tag,
                stat.IO_REPARSE_TAG_MOUNT_POINT,
            )
        else:
            (sources / "linked-file.rs").symlink_to(outside / "outside.rs")
            (sources / "dangling.rs").symlink_to(outside / "missing.rs")

        visited = []
        walk = os.walk
        def observed_walk(*args, **kwargs):
            self.assertFalse(kwargs["followlinks"])
            for entry in walk(*args, **kwargs):
                visited.append(Path(entry[0]))
                yield entry
        with mock.patch.object(inventory.os, "walk", side_effect=observed_walk):
            actual = {suffix: set(inventory.source_paths(sources, suffix)) for suffix in (".rs", ".ts")}
        for suffix in (".rs", ".ts"):
            # Windows rglob follows junctions, so explicitly exclude that
            # external directory from the previous-walker comparison.
            previous = {
                path for path in sources.rglob("*" + suffix)
                if inventory.source_file(path)
                and sources / "linked-directory" not in path.parents
            }
            self.assertEqual(actual[suffix], previous)
        self.assertIn(sources / "linked-file.rs", actual[".rs"])
        self.assertIn(sources / "nested/deeper/kept.ts", actual[".ts"])
        self.assertNotIn(sources / "dangling.rs", actual[".rs"])
        self.assertNotIn(sources / "linked-directory/outside.rs", actual[".rs"])
        self.assertTrue(visited)
        self.assertTrue(all(not any(part in inventory.IGNORED_DIRS for part in path.parts) for path in visited))
        self.assertNotIn(sources / "linked-directory", visited)

    def test_source_walk_starting_directory_link_matches_previous_rglob(self) -> None:
        self.write("actual-source/nested/kept.rs", "#[test] fn kept() {}")
        self.write("actual-source/nested/uppercase.RS", "#[test] fn uppercase() {}")
        self.write("actual-source/target/ignored.rs", "#[test] fn excluded() {}")
        root_link = self.root / "root-source-link"
        directory_link(root_link, self.root / "actual-source")
        expected = {path for path in root_link.rglob("*.rs") if inventory.source_file(path)}
        actual = set(inventory.source_paths(root_link, ".rs"))
        self.assertEqual(actual, expected)
        self.assertIn(root_link / "nested/kept.rs", actual)
        self.assertEqual(root_link / "nested/uppercase.RS" in actual, (root_link / "nested/uppercase.RS").match("*.rs"))

    def test_client_scenario_helpers_without_test_attribute_are_collected(self) -> None:
        self.write("cotest/crates/inkson-client-tests/src/scenarios/actual_client.rs", 'async fn live_observer() { let op = "' + OP_TWO + '"; assert!(result.is_ok()); }')
        layers = inventory.discover_layer_sources(self.root)
        cotest = next(layer for layer in layers if layer.name == "cotest_rust")
        self.assertIn(self.root / "cotest/crates/inkson-client-tests/src/scenarios/actual_client.rs", cotest.files)

    def test_retained_evidence_and_linked_external_sources_cannot_change_the_test_inventory(self) -> None:
        expected = inventory.generate(self.root)
        self.write(
            "cotest/artifacts/backup/files/tests/original.rs",
            rust_test("retained_original", OP_ONE, "assert!(result.is_ok());"),
        )
        self.write(
            "cotest/artifacts/backup/files/tests/retired.rs",
            rust_test("retained_retired", "ak.self.retired.command.v1", "assert!(result.is_err());"),
        )
        external = self.root / "outside-inventory"
        external.mkdir()
        (external / "external.rs").write_text(
            rust_test("external_sentinel", "ak.self.unregistered.command.v1", "assert!(result.is_err());"),
            encoding="utf-8",
        )
        directory_link(self.root / "cotest/tests/linked-external", external)
        self.assertEqual(inventory.generate(self.root), expected)

    def test_generates_full_matrix_and_exact_duplicate_oracle(self) -> None:
        result = inventory.generate(self.root)
        self.assertEqual(result["dimensions"]["operation_count"], 2)
        self.assertEqual(result["dimensions"]["matrix_cell_count"], 10)
        self.assertEqual(len(result["matrix"]), 10)
        self.assertEqual(result["closure"]["unknown_test_files"], [])
        self.assertEqual(result["closure"]["unknown_operation_literals"], [])
        self.assertEqual(result["closure"]["unassigned_responsibilities"], [])

        storage = matrix_cell(result, OP_ONE, "coland_unit")["responsibilities"]
        self.assertEqual(len(storage["storage_parity"]), 1)
        self.assertTrue(storage["storage_parity"][0]["protected_oracle"])
        negative = matrix_cell(result, OP_ONE, "coland_http")["responsibilities"]
        self.assertEqual(len(negative["security_negative"]), 1)
        product = matrix_cell(result, OP_ONE, "cotest_e2e")["responsibilities"]
        self.assertEqual(len(product["product_flow"]), 1)

        self.assertEqual(len(result["duplicate_candidates"]), 1)
        candidate = result["duplicate_candidates"][0]
        self.assertEqual(candidate["operation_id"], OP_TWO)
        self.assertEqual(candidate["responsibility"], "protocol_kat")
        self.assertEqual(
            candidate["retained_oracle"]["file"], "cotest/tests/oracle_a.rs"
        )
        self.assertEqual(
            candidate["deletion_candidates"][0]["file"],
            "cotest/tests/oracle_b.rs",
        )

    def test_check_detects_manual_output_edit(self) -> None:
        output = self.root / "inventory.json"
        generated = inventory.serialized(inventory.generate(self.root))
        output.write_text(generated, encoding="utf-8")
        self.assertTrue(inventory.check_output(generated, output))
        output.write_text(generated + " ", encoding="utf-8")
        self.assertFalse(inventory.check_output(generated, output))

    def test_sdk_associated_constants_retain_real_operation_evidence_and_source_lines(self) -> None:
        path = "coland/crates/server/tests/http_api/constants.rs"
        self.write(path, """#[tokio::test]
async fn typed_http_operations() {
    let first = arkret_wire::ServiceOperationId::SERVER_READ_DESCRIBE_V1;
    let second = ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1;
    assert_eq!(actual, expected);
}
""")
        result = inventory.generate(self.root)
        for operation, line in ((OP_ONE, 3), (OP_TWO, 4)):
            evidence = matrix_cell(result, operation, "coland_http")["responsibilities"]["http_binding"]
            row = next(item for item in evidence if item["file"] == path)
            self.assertEqual(row["scope"], "typed_http_operations")
            self.assertEqual(row["occurrence_lines"], [line])
            self.assertTrue(row["assertion_preview"])
        # Names alone in TypeScript do not refer to Rust SDK constants.
        self.assertEqual(inventory.operation_references(
            "ServiceOperationId::SERVER_READ_DESCRIBE_V1", ".ts",
            {"SERVER_READ_DESCRIBE_V1": OP_ONE},
        ), [])

    def test_sdk_constant_reference_cannot_hide_an_unassigned_test_file(self) -> None:
        self.write("coland/other-tests/unassigned.rs", """#[test]
fn typed_operation() {
    let operation = ServiceOperationId::SERVER_READ_DESCRIBE_V1;
    assert!(result.is_ok());
}
""")
        with self.assertRaisesRegex(ValueError, "unknown_test_files"):
            inventory.generate(self.root)

    def test_sdk_constant_outside_formal_registry_fails_closed(self) -> None:
        self.write(
            "arkret-rust-sdk/crates/wire/src/generated/operation_ids.rs",
            "pub const RETIRED_V1: &'static str = \"ak.self.retired.command.v1\";",
        )
        with self.assertRaisesRegex(ValueError, "outside the registry"):
            inventory.generate(self.root)

    def test_sdk_enum_aliases_merge_with_constants_without_changing_fingerprints(self) -> None:
        path = "coland/crates/server/tests/http_api/enums.rs"
        self.write(path, """#[tokio::test]
async fn typed_enum_operations() {
    let first = arkret_wire::ServiceOperationId::ServerReadDescribeV1;
    let same = ServiceOperationId::SERVER_READ_DESCRIBE_V1;
    let literal = "ak.server.read.describe.v1";
    let second = ServiceOperationId::SelfCommittedEventReadScanV1;
    assert_eq!(actual, expected);
}
""")
        result = inventory.generate(self.root)
        with mock.patch.object(
            inventory, "RUST_OPERATION_CONSTANT_REFERENCE",
            re.compile(r"\bServiceOperationId::([A-Z][A-Z0-9_]*)\b"),
        ):
            previous = inventory.generate(self.root)
        old_row = next(
            row for row in matrix_cell(previous, OP_ONE, "coland_http")["responsibilities"]["http_binding"]
            if row["file"] == path
        )
        self.assertEqual(old_row["occurrence_lines"], [4, 5])
        for operation, lines in ((OP_ONE, [3, 4, 5]), (OP_TWO, [6])):
            evidence = matrix_cell(result, operation, "coland_http")["responsibilities"]["http_binding"]
            row = next(item for item in evidence if item["file"] == path)
            self.assertEqual(row["scope_kind"], "rust_test")
            self.assertEqual(row["occurrence_lines"], lines)
            original = (self.root / path).read_text()
            scope = inventory.rust_test_scopes(original)[0]
            fingerprints = inventory.evidence_fingerprints(original[scope.start:scope.end], operation)
            for key, value in fingerprints.items():
                self.assertEqual(row[key], value)
                if operation == OP_ONE:
                    self.assertEqual(row[key], old_row[key])

    def test_sdk_enum_helper_is_not_promoted_to_a_test(self) -> None:
        path = "cotest/tests/enum_helper.rs"
        self.write(path, """fn helper() {
    let operation = ServiceOperationId::ServerReadDescribeV1;
    assert!(result.is_ok());
}
""")
        result = inventory.generate(self.root)
        evidence = matrix_cell(result, OP_ONE, "cotest_rust")["responsibilities"]["protocol_kat"]
        row = next(item for item in evidence if item["file"] == path)
        self.assertEqual(row["scope_kind"], "module_helper")
        self.assertEqual(row["scope"], "<module_helper>")
        self.assertEqual(row["occurrence_lines"], [2])

    def test_sdk_enum_reference_cannot_hide_an_unassigned_test_file(self) -> None:
        self.write("coland/other-tests/unassigned.rs", """#[test]
fn typed_operation() {
    let operation = ServiceOperationId::ServerReadDescribeV1;
    assert!(result.is_ok());
}
""")
        with self.assertRaisesRegex(ValueError, "unknown_test_files"):
            inventory.generate(self.root)

    def test_sdk_enum_as_str_and_constants_must_be_closed(self) -> None:
        mutations = {
            "unknown_target": SDK_OPERATIONS.replace(
                "Self::ServerReadDescribeV1 => Self::SERVER_READ_DESCRIBE_V1,",
                "Self::ServerReadDescribeV1 => Self::UNREGISTERED_V1,",
            ),
            "missing_variant_arm": SDK_OPERATIONS.replace(
                "Self::ServerReadDescribeV1 => Self::SERVER_READ_DESCRIBE_V1,", "",
            ),
            "duplicate_variant_arm": SDK_OPERATIONS.replace(
                "Self::ServerReadDescribeV1 => Self::SERVER_READ_DESCRIBE_V1,",
                "Self::ServerReadDescribeV1 => Self::SERVER_READ_DESCRIBE_V1, "
                "Self::ServerReadDescribeV1 => Self::SERVER_READ_DESCRIBE_V1,",
            ),
            "undeclared_variant": SDK_OPERATIONS.replace(
                "Self::ServerReadDescribeV1 =>", "Self::UndeclaredV1 =>",
            ),
            "reused_target": SDK_OPERATIONS.replace(
                "Self::SELF_COMMITTED_EVENT_READ_SCAN_V1\n", "Self::SERVER_READ_DESCRIBE_V1\n",
            ),
        }
        for name, text in mutations.items():
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "SDK operation"):
                inventory.sdk_operation_symbols(text, {OP_ONE, OP_TWO})

    def test_main_generates_exact_utf8_inventory_on_supported_python(self) -> None:
        output = self.root / "generated-inventory.json"
        self.assertEqual(
            inventory.main(["--workspace-root", str(self.root), "--output", str(output)]),
            0,
        )
        expected = inventory.serialized(inventory.generate(self.root)).encode("utf-8")
        self.assertEqual(output.read_bytes(), expected)
        self.assertTrue(inventory.check_output(expected.decode("utf-8"), output))

    def test_lf_sources_with_escaped_cr_literals_generate_without_rewriting_bytes(self) -> None:
        relative = "cotest/tests/escaped.rs"
        content = rust_test("escaped_literals", OP_ONE, r'assert_eq!("\r\n", "\r\n");')
        self.write(relative, content)
        source = self.root / relative
        original = source.read_bytes()
        self.assertNotIn(b"\r", original)
        self.assertIn(br"\r\n", original)
        output = self.root / "inventory.json"
        self.assertEqual(inventory.main(["--workspace-root", str(self.root), "--output", str(output)]), 0)
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(output.read_bytes(), inventory.serialized(inventory.generate(self.root)).encode("utf-8"))

    def test_non_lf_sources_fail_before_overwriting_existing_output(self) -> None:
        output = self.root / "inventory.json"
        original_output = b"retained previous inventory\n"
        for relative in (
            "coland/crates/storage/src/contract_tests.rs",
            "cotest/tests/oracle_a.rs",
            "cotest/e2e/tests/flow.spec.ts",
            "arkret-rust-sdk/crates/wire/src/generated/operation_ids.rs",
        ):
            source = self.root / relative
            original_source = source.read_bytes()
            for ending in (b"\r\n", b"\r"):
                with self.subTest(source=relative, ending=ending):
                    changed = original_source.replace(b"\n", ending)
                    source.write_bytes(changed)
                    output.write_bytes(original_output)
                    stderr = io.StringIO()
                    with mock.patch.object(sys, "stderr", stderr):
                        result = inventory.main(["--workspace-root", str(self.root), "--output", str(output)])
                    self.assertEqual(result, 1)
                    self.assertIn("LF line endings", stderr.getvalue())
                    self.assertIn(str(source), stderr.getvalue())
                    self.assertEqual(output.read_bytes(), original_output)
                    self.assertEqual(source.read_bytes(), changed)
                source.write_bytes(original_source)

    def test_aggregate_digest_uses_relative_posix_string_order_and_actual_bytes(self) -> None:
        relatives = ["cotest/tests/a/b.rs", "cotest/tests/a.rs", "cotest/tests/Z.rs"]
        for relative in relatives:
            self.write(relative, "// " + relative + "\n")
        files = [self.root / relative for relative in relatives]
        expected_order = sorted(relatives)
        # Component ordering places a/b.rs before a.rs; POSIX strings do not.
        self.assertNotEqual([path.relative_to(self.root).as_posix() for path in sorted(files)], expected_order)
        preimage = b"".join(
            relative.encode("utf-8") + b"\0" + hashlib.sha256((self.root / relative).read_bytes()).digest()
            for relative in expected_order
        )
        with mock.patch.object(inventory, "WORKSPACE_ROOT", self.root.resolve()):
            expected = hashlib.sha256(preimage).hexdigest()
            self.assertEqual(inventory.aggregate_source_digest(files), expected)
            self.assertEqual(inventory.aggregate_source_digest(reversed(files)), expected)
            with (self.root / relatives[0]).open("ab") as source:
                source.write(b"// changed source bytes\n")
            self.assertNotEqual(inventory.aggregate_source_digest(files), expected)

    def test_inventory_is_independent_of_native_discovery_order(self) -> None:
        self.write("cotest/tests/a/b.rs", rust_test("nested_oracle", OP_ONE, "assert_eq!(actual, expected);"))
        self.write("cotest/tests/a.rs", rust_test("sibling_oracle", OP_ONE, "assert_eq!(actual, expected);"))
        expected = inventory.generate(self.root)
        discover = inventory.discover_layer_sources
        def reversed_sources(root):
            return tuple(inventory.LayerSource(layer.name, tuple(reversed(layer.files))) for layer in discover(root))
        with mock.patch.object(inventory, "discover_layer_sources", side_effect=reversed_sources):
            self.assertEqual(inventory.generate(self.root), expected)

    def test_unclassified_operation_shaped_literal_fails_closed(self) -> None:
        self.write(
            "cotest/e2e/tests/unknown.spec.ts",
            ts_test("uses selector", "ak.self.unregistered.command.execute.v1"),
        )
        with self.assertRaisesRegex(ValueError, "unknown_operation_literals"):
            inventory.generate(self.root)


class AcceptanceTraceabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.active = self.root / "arkret-work/tasks/impl-active"
        self.active.mkdir(parents=True)
        self.task = self.active / "owner.md"
        self.task.write_text("# Owner\n- [ ] Exact retry after expiry.\n  Retain until ACK.\n", encoding="utf-8")
        source = self.root / "cotest/tests/probe.rs"
        source.parent.mkdir(parents=True)
        source.write_text(rust_test("expiry_probe", OP_ONE, "assert_eq!(actual, expected);"), encoding="utf-8")
        count, digest = inventory.acceptance_digest(self.task.read_text(encoding="utf-8"))
        self.manifest = {
            "tasks": [{
                "task": "owner.md", "criteria_count": count, "criteria_sha256": digest,
                "spec_refs": [], "source_refs": ["cotest/tests/probe.rs"],
                "engineering_checks": ["Run the selected test with the actual SUT"],
                "remaining_scenarios": ["Restart after expiry with the original outcome"],
                "tests": [{"path": "cotest/tests/probe.rs", "symbol": "expiry_probe", "kind": "live", "covers": "HTTP retry"}],
            }],
        }
        self.addCleanup(self.temp.cleanup)

    def test_traceability_is_not_an_execution_claim(self) -> None:
        result = inventory.validate_acceptance_manifest(self.root, self.manifest)
        self.assertEqual(result, {"owners": 1, "criteria": 1, "test_references": 1})
        self.assertNotIn("passed", result)
        self.manifest["complete_claim"] = True
        with self.assertRaisesRegex(ValueError, "unknown or missing fields"):
            inventory.validate_acceptance_manifest(self.root, self.manifest)

    def test_same_count_scope_edit_and_continuation_edit_invalidate_mapping(self) -> None:
        for text in ("- [ ] Rebuild instead of replay.\n  Retain until ACK.\n", "- [ ] Exact retry after expiry.\n  Delete on expiry.\n"):
            with self.subTest(text=text):
                self.task.write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "criteria drifted"):
                    inventory.validate_acceptance_manifest(self.root, self.manifest)

    def test_new_owner_and_duplicate_owner_cannot_silently_reduce_coverage(self) -> None:
        extra = self.active / "unassigned.md"
        extra.write_text("- [ ] New consumer\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "owners missing"):
            inventory.validate_acceptance_manifest(self.root, self.manifest)
        extra.unlink()
        self.manifest["tasks"].append(self.manifest["tasks"][0])
        with self.assertRaisesRegex(ValueError, "duplicate active owner"):
            inventory.validate_acceptance_manifest(self.root, self.manifest)

    def test_helper_or_comment_cannot_impersonate_a_test(self) -> None:
        (self.root / "cotest/tests/probe.rs").write_text('fn expiry_probe() { let label = "expiry_probe"; }\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "helper/string is not a test"):
            inventory.validate_acceptance_manifest(self.root, self.manifest)

    def test_non_spec_authority_and_workspace_escape_are_rejected(self) -> None:
        record = self.manifest["tasks"][0]
        record["spec_refs"] = ["cotest/tests/probe.rs"]
        with self.assertRaisesRegex(ValueError, "current v1 Spec"):
            inventory.validate_acceptance_manifest(self.root, self.manifest)
        record["spec_refs"] = []
        record["source_refs"] = ["../outside.rs"]
        with self.assertRaisesRegex(ValueError, "out-of-workspace"):
            inventory.validate_acceptance_manifest(self.root, self.manifest)

    def test_missing_scenarios_or_deleted_test_cannot_look_complete(self) -> None:
        record = self.manifest["tasks"][0]
        record["remaining_scenarios"] = []
        with self.assertRaisesRegex(ValueError, "remaining scenarios"):
            inventory.validate_acceptance_manifest(self.root, self.manifest)
        record["remaining_scenarios"] = ["Restart"]
        (self.root / "cotest/tests/probe.rs").unlink()
        with self.assertRaisesRegex(ValueError, "acceptance source"):
            inventory.validate_acceptance_manifest(self.root, self.manifest)


def rust_test(name: str, operation_id: str, assertion: str) -> str:
    return f'''#[test]
fn {name}() {{
    let operation_id = "{operation_id}";
    let actual = operation_id;
    let expected = operation_id;
    {assertion}
}}
'''


def ts_test(name: str, operation_id: str) -> str:
    return f'''test("{name}", async () => {{
  const operationId = "{operation_id}";
  expect(operationId).toContain(".v1");
}});
'''


def matrix_cell(result: dict, operation_id: str, layer: str) -> dict:
    return next(
        cell
        for cell in result["matrix"]
        if cell["operation_id"] == operation_id and cell["test_layer"] == layer
    )


if __name__ == "__main__":
    unittest.main()
