from __future__ import annotations

import importlib.util
import json
import os
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
            "soland/crates/storage/src/contract_tests.rs",
            rust_test("shared_storage_oracle", OP_ONE, "assert_eq!(value, value);")
        )
        self.write(
            "soland/crates/server/tests/http_api/negative.rs",
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

    def test_source_walk_prunes_ignored_and_directory_symlinks_without_losing_sources(self) -> None:
        sources = self.root / "source-walk"
        for relative in ("nested/kept.rs", "nested/deeper/kept.ts", "plain.rs", ".rs", "not-source.txt"):
            self.write("source-walk/" + relative, "#[test] fn source() {}")
        for ignored in inventory.IGNORED_DIRS:
            self.write(f"source-walk/{ignored}/deep/test.rs", "#[test] fn excluded() {}")
            self.write(f"source-walk/nested/{ignored}/test.ts", "test('excluded', () => {});")
        outside = self.root / "outside-sources"
        outside.mkdir()
        (outside / "outside.rs").write_text("#[test] fn external() {}", encoding="utf-8")
        (sources / "linked-directory").symlink_to(outside, target_is_directory=True)
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
            previous = {path for path in sources.rglob("*" + suffix) if inventory.source_file(path)}
            self.assertEqual(actual[suffix], previous)
        self.assertIn(sources / "linked-file.rs", actual[".rs"])
        self.assertIn(sources / "nested/deeper/kept.ts", actual[".ts"])
        self.assertNotIn(sources / "dangling.rs", actual[".rs"])
        self.assertTrue(visited)
        self.assertTrue(all(not any(part in inventory.IGNORED_DIRS for part in path.parts) for path in visited))
        self.assertNotIn(sources / "linked-directory", visited)

    def test_source_walk_starting_directory_symlink_matches_previous_rglob(self) -> None:
        self.write("actual-source/nested/kept.rs", "#[test] fn kept() {}")
        self.write("actual-source/nested/uppercase.RS", "#[test] fn uppercase() {}")
        self.write("actual-source/target/ignored.rs", "#[test] fn excluded() {}")
        root_link = self.root / "root-source-link"
        root_link.symlink_to(self.root / "actual-source", target_is_directory=True)
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

    def test_generates_full_matrix_and_exact_duplicate_oracle(self) -> None:
        result = inventory.generate(self.root)
        self.assertEqual(result["dimensions"]["operation_count"], 2)
        self.assertEqual(result["dimensions"]["matrix_cell_count"], 10)
        self.assertEqual(len(result["matrix"]), 10)
        self.assertEqual(result["closure"]["unknown_test_files"], [])
        self.assertEqual(result["closure"]["unknown_operation_literals"], [])
        self.assertEqual(result["closure"]["unassigned_responsibilities"], [])

        storage = matrix_cell(result, OP_ONE, "soland_unit")["responsibilities"]
        self.assertEqual(len(storage["storage_parity"]), 1)
        self.assertTrue(storage["storage_parity"][0]["protected_oracle"])
        negative = matrix_cell(result, OP_ONE, "soland_http")["responsibilities"]
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

    def test_main_generates_exact_utf8_inventory_on_supported_python(self) -> None:
        output = self.root / "generated-inventory.json"
        self.assertEqual(
            inventory.main(["--workspace-root", str(self.root), "--output", str(output)]),
            0,
        )
        expected = inventory.serialized(inventory.generate(self.root)).encode("utf-8")
        self.assertEqual(output.read_bytes(), expected)
        self.assertTrue(inventory.check_output(expected.decode("utf-8"), output))

    def test_unclassified_operation_shaped_literal_fails_closed(self) -> None:
        self.write(
            "cotest/e2e/tests/unknown.spec.ts",
            ts_test("uses selector", "ak.self.unregistered.command.execute.v1"),
        )
        with self.assertRaisesRegex(ValueError, "unknown_operation_literals"):
            inventory.generate(self.root)


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
