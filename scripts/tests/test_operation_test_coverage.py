from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
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
        path.write_text(content, encoding="utf-8", newline="\n")

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
