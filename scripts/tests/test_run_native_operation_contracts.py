"""Filesystem transport regressions; these fixtures are not native authority evidence."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "native_operation_runner", SCRIPTS / "run-native-operation-contracts.py")
runner = importlib.util.module_from_spec(SPEC)
with patch.object(sys, "path", [str(SCRIPTS), *sys.path]):
    SPEC.loader.exec_module(runner)


class FrozenProductTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cotest-native-product-copy-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "evidence"
        self.output.mkdir()
        self.source = self.root / "target/coland"
        self.source.parent.mkdir()
        self.source.write_bytes(f"#!{sys.executable}\nraise SystemExit(0)\n".encode())
        self.source.chmod(0o751)

    def execute(self, output, name, repository, command, environment):
        (output / "build.log").write_text(json.dumps({
            "reason": "compiler-artifact", "target": {"name": name, "kind": ["bin"]},
            "executable": str(self.source),
        }) + "\n", encoding="utf-8")
        self.command = command
        result = {"log": "build.log", "exit_code": 0, "sources_unchanged": True,
                  "source_fence": "original-source-fence.json", "target_directory": str(self.source.parent)}
        (output / f"{name}-result.json").write_text(json.dumps(result), encoding="utf-8")
        return result

    def build(self):
        with patch.object(runner, "execute", side_effect=self.execute):
            return runner.build(self.output, "coland", {})

    def test_simulated_posix_mode_is_copied_with_the_frozen_bytes(self):
        # Windows does not expose POSIX execute bits. This model exercises the
        # real copy boundary without claiming an actual POSIX process launch.
        modes = {self.source: 0o751}
        original_copy = shutil.copyfile
        original_mode = shutil.copymode

        def copy(source, destination):
            result = original_copy(source, destination)
            modes[Path(destination)] = 0o644
            return result

        def mode(source, destination):
            original_mode(source, destination)
            modes[Path(destination)] = modes[Path(source)]

        with patch.object(shutil, "copyfile", side_effect=copy), patch.object(shutil, "copymode", side_effect=mode):
            product = self.build()
        frozen = Path(product["executable"])
        self.assertEqual(modes[frozen], modes[self.source])
        self.assertEqual(frozen.read_bytes(), self.source.read_bytes())

    @unittest.skipUnless(os.name == "posix", "Actual POSIX direct execution is verified on Linux CI")
    def test_posix_frozen_product_retains_mode_and_can_be_executed_directly(self):
        product = self.build()
        frozen = Path(product["executable"])
        self.assertEqual(stat.S_IMODE(frozen.stat().st_mode), stat.S_IMODE(self.source.stat().st_mode))
        self.assertTrue(os.access(frozen, os.X_OK))
        self.assertEqual(subprocess.run([str(frozen)], check=False).returncode, 0)

    def test_hash_and_producer_binding_still_reference_the_exact_frozen_bytes(self):
        product = self.build()
        producer = json.loads((self.output / product["producer_result"]).read_text())
        self.assertEqual(product["sha256"], runner.digest(self.source))
        self.assertEqual(product["sha256"], runner.digest(Path(product["executable"])))
        self.assertEqual(producer["sha256"], product["sha256"])
        self.assertEqual(producer["executable"], product["executable"])
        self.assertEqual(producer["source_fence"], "original-source-fence.json")
        self.assertTrue(producer["sources_unchanged"])
        self.assertEqual(self.command[-2:], ["--features", "conformance-harness"])

    def test_copy_permission_failure_cannot_publish_a_successful_binding(self):
        with patch.object(shutil, "copymode", side_effect=PermissionError("synthetic resource failure")):
            with self.assertRaises(PermissionError):
                self.build()
        producer = json.loads((self.output / "coland-result.json").read_text())
        self.assertNotIn("executable", producer)
        self.assertNotIn("sha256", producer)

    def test_failure_diagnostics_are_separate_and_do_not_bypass_the_native_gate(self):
        output = self.root / "artifacts/new-run"
        document = runner.gate.declarations()
        products = []
        calls = []
        def build(root, name, environment):
            self.assertNotIn("COTEST_NATIVE_FAILURE_DIAGNOSTICS_DIR", environment)
            product = {"executable": str(self.source), "sha256": runner.digest(self.source)}
            products.append(product)
            return product
        def execute(root, name, repository, command, environment, **kwargs):
            calls.append(name)
            if name == "native":
                diagnostic = Path(environment["COTEST_NATIVE_FAILURE_DIAGNOSTICS_DIR"])
                observation = Path(environment["COTEST_NATIVE_OPERATION_EVIDENCE_DIR"])
                self.assertEqual(diagnostic, output / "diagnostics")
                self.assertTrue(diagnostic.is_dir())
                self.assertFalse(diagnostic.is_relative_to(observation))
                self.assertEqual(command[-3:], ["--", "--nocapture", "--test-threads=1"])
                self.assertFalse(kwargs["require_success"])
                return {"exit_code": 101, "sources_unchanged": True}
            return {"exit_code": 0, "sources_unchanged": True}
        with patch.object(runner.gate, "REPO", self.root), \
                patch.object(runner.gate, "declarations", return_value=document), \
                patch.object(sys, "argv", ["runner", "--output", str(output)]), \
                patch.dict(os.environ, {"COTEST_COAUTH_DATABASE_URL": "synthetic-coauth",
                                       "COTEST_COLAND_DATABASE_URL": "synthetic-coland"}, clear=True), \
                patch.object(runner, "build", side_effect=build), \
                patch.object(runner, "execute", side_effect=execute), \
                patch.object(runner.audit_native_operation_schemas, "audit", return_value={"schema_valid": True}), \
                patch.object(runner.gate, "evidence_coverage") as coverage, \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "native failed"):
                runner.main()
        self.assertEqual(calls, ["service-isolation", "native"])
        self.assertEqual(len(products), 2)
        self.assertEqual(list((output / "observations").iterdir()), [])
        self.assertEqual(json.loads((output / "native-result.json").read_text())["exit_code"], 101)
        coverage.assert_not_called()


if __name__ == "__main__":
    unittest.main()
