"""Pure resource/privacy regressions; no service, Cargo or native proof execution."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "operation_status", Path(__file__).resolve().parents[1] / "publish-native-operation-status.py")
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)
PRIVATE = "PRIVATE_SQL_token_password_https://secret.invalid/path"


class NativeOperationStatusTests(unittest.TestCase):
    def setUp(self):
        # Local commands set TEMP/TMP to D explicitly. Linux CI uses its own
        # system temporary directory without inventing a Windows-shaped path.
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.artifacts = self.root / "artifacts"
        self.run = self.artifacts / "authority-owned"
        self.run.mkdir(parents=True)
        self.declarations = self.root / "declarations.json"
        self.declarations.write_bytes(publisher.DECLARATIONS.read_bytes())
        document = json.loads(self.declarations.read_text(encoding="utf-8"))
        self.scope = {row["operation_id"] for row in document["operations"]}
        self.unmapped = {row["operation_id"] for row in document["operations"] if row["native_case"] is None}
        self.write("native-sources.json", {"coland/src/example.rs": "a" * 64})
        self.write("native-result.json", {
            "exit_code": 0, "sources_unchanged": True, "seconds": 12.5,
            "log": "native.log", "source_fence": "native-sources.json",
            "command": [PRIVATE], "target_directory": PRIVATE,
        })
        self.write("coverage.json", {
            "scope": len(self.scope), "native_covered": len(self.scope - self.unmapped),
            "remaining": len(self.unmapped), "uncovered_operations": sorted(self.unmapped),
            "acceptance": not self.unmapped, "blocker": PRIVATE,
        })
        self.full_log()

    def write(self, name, value):
        (self.run / name).write_text(json.dumps(value), encoding="utf-8")

    def full_log(self):
        lines = [f"test {name} ... \x1b[32mok\x1b[0m" for name in (*publisher.REQUIRED, *publisher.META)]
        lines += [PRIVATE, "test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 12.50s"]
        (self.run / "native.log").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def publish(self, label="public"):
        result = publisher.publish(self.run, self.root / label,
                                   artifacts_root=self.artifacts, declarations=self.declarations)
        self.assertNotIn(PRIVATE, json.dumps(result))
        self.assertEqual(list((self.root / label).iterdir()), [self.root / label / "summary.json"])
        return result

    def test_complete_export_preserves_incomplete_coverage_and_hashes(self):
        result = self.publish()
        self.assertTrue(result["export_complete"])
        self.assertTrue(result["native_execution_complete"])
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["coverage"]["acceptance"])
        self.assertEqual(result["coverage"]["uncovered_operations"], sorted(self.unmapped))
        self.assertEqual(len(result["tests"]), 13)
        self.assertEqual(len(result["meta_tests"]), 2)
        for name in ("native-result.json", "native-sources.json", "native.log", "coverage.json"):
            self.assertEqual(result["hashes"][name], hashlib.sha256((self.run / name).read_bytes()).hexdigest())
        real_publish = publisher.publish
        def isolated(run_root, output_dir):
            return real_publish(run_root, output_dir, artifacts_root=self.artifacts, declarations=self.declarations)
        with patch.object(publisher, "publish", side_effect=isolated), contextlib.redirect_stdout(io.StringIO()):
            code = publisher.main(["--run-root", str(self.run), "--output-dir", str(self.root / "complete-cli")])
        # Successful export cannot turn the separate incomplete-coverage gate green.
        self.assertEqual(code, 0)
        self.assertFalse(json.loads((self.root / "complete-cli/summary.json").read_text())["coverage"]["acceptance"])

    def test_partial_failure_keeps_fixed_observations_without_coverage_credit(self):
        (self.run / "native.log").write_text(
            f"test {publisher.REQUIRED[0]} ... ok\ntest {publisher.REQUIRED[1]} ... FAILED\n{PRIVATE}\n",
            encoding="utf-8")
        result_value = json.loads((self.run / "native-result.json").read_text())
        result_value["exit_code"] = 101
        self.write("native-result.json", result_value)
        result = self.publish()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["export_complete"])
        self.assertFalse(result["native_execution_complete"])
        self.assertIsNone(result["coverage"])
        self.assertEqual([row["status"] for row in result["tests"][:3]], ["passed", "failed", "not_observed"])

    def test_serial_nocapture_body_and_standalone_status_are_consumed(self):
        lines = []
        for index, name in enumerate((*publisher.REQUIRED, *publisher.META)):
            if index % 2:
                lines += [f"test {name} ... {PRIVATE}", PRIVATE, "\x1b[32mok\x1b[0m"]
            else:
                lines += [f"test {name} ... ok"]
        lines += ["test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 12.50s"]
        (self.run / "native.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = self.publish()
        self.assertTrue(result["export_complete"])
        self.assertTrue(all(row["status"] == "passed" for row in result["tests"]))

    def test_truncated_active_test_and_spurious_or_conflicting_status_cannot_credit(self):
        original = (self.run / "native.log").read_text(encoding="utf-8")
        scenarios = [
            f"test {publisher.REQUIRED[0]} ... {PRIVATE}\n",
            f"test {publisher.REQUIRED[0]} ... {PRIVATE}\nok\nFAILED\n",
            original + "ok\n",
            f"test {publisher.REQUIRED[0]} ... {PRIVATE}\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.0s\n",
        ]
        for index, log in enumerate(scenarios):
            with self.subTest(index=index):
                (self.run / "native.log").write_text(log, encoding="utf-8")
                result = self.publish(f"active-{index}")
                self.assertFalse(result["export_complete"])
                self.assertFalse(result["native_execution_complete"])
                self.assertIsNone(result["coverage"])

    def test_tampering_unknown_conflicting_and_false_coverage_is_rejected(self):
        original_log = (self.run / "native.log").read_bytes()
        for number, extra in enumerate((f"test {PRIVATE} ... ok\n",
                                        f"test {publisher.REQUIRED[0]} ... FAILED\n",
                                        f"test {publisher.REQUIRED[0]} ... ok\n")):
            with self.subTest(extra=number):
                (self.run / "native.log").write_bytes(original_log + extra.encode())
                result = self.publish(f"bad-log-{number}")
                self.assertFalse(result["export_complete"])
                self.assertIsNone(result["coverage"])
        (self.run / "native.log").write_bytes(original_log)
        original = json.loads((self.run / "coverage.json").read_text())
        corruptions = [dict(original, uncovered_operations=[PRIVATE]),
                       dict(original, remaining=True),
                       dict(original, native_covered=len(self.scope), remaining=0,
                            uncovered_operations=[], acceptance=True),
                       dict(original, private_url=PRIVATE)]
        for number, value in enumerate(corruptions):
            with self.subTest(coverage=number):
                self.write("coverage.json", value)
                result = self.publish(f"bad-coverage-{number}")
                self.assertFalse(result["export_complete"])
                self.assertIsNone(result["coverage"])

    def test_link_traversal_oversize_and_output_overlap_fail_closed(self):
        outside = self.root / "private.json"
        outside.write_text(PRIVATE, encoding="utf-8")
        (self.run / "native-sources.json").unlink()
        os.link(outside, self.run / "native-sources.json")
        self.assertFalse(self.publish("hardlink")["export_complete"])
        self.assertEqual(outside.read_text(), PRIVATE)
        (self.run / "native-sources.json").unlink()
        self.write("native-sources.json", {"x": "a" * 64})
        with patch.object(publisher, "MAX_LOG", 16):
            self.assertFalse(self.publish("oversized")["export_complete"])
        result = publisher.publish(self.run / ".." / self.run.name, self.root / "traversal",
                                   artifacts_root=self.artifacts, declarations=self.declarations)
        self.assertIn("invalid_run_root", result["diagnostics"])
        for target in (self.run / "public", self.artifacts / "public", self.root / "hardlink"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                publisher.publish(self.run, target, artifacts_root=self.artifacts, declarations=self.declarations)
        self.assertFalse((self.run / "public").exists())
        try:
            (self.artifacts / "linked").symlink_to(self.run, target_is_directory=True)
        except OSError:
            return  # Windows may not grant symlink creation; hardlink coverage above still ran.
        result = publisher.publish(self.artifacts / "linked", self.root / "symlink",
                                   artifacts_root=self.artifacts, declarations=self.declarations)
        self.assertIn("invalid_run_root", result["diagnostics"])

    def test_malformed_inputs_and_cli_exit_do_not_print_private_messages(self):
        for number, raw in enumerate((b'{"exit_code":0,"exit_code":101}', b'{"seconds":NaN}',
                                      PRIVATE.encode("utf-16"), b'\xff' + PRIVATE.encode())):
            with self.subTest(number=number):
                (self.run / "native-result.json").write_bytes(raw)
                result = self.publish(f"malformed-{number}")
                self.assertFalse(result["export_complete"])
                self.assertIsNone(result["native"])
        invalid_number = {"exit_code": 0, "sources_unchanged": True, "seconds": 10 ** 1000,
                          "log": "native.log", "source_fence": "native-sources.json"}
        self.write("native-result.json", invalid_number)
        self.assertIsNone(self.publish("oversized-number")["native"])
        capture = io.StringIO()
        real_publish = publisher.publish
        def isolated(run_root, output_dir):
            return real_publish(run_root, output_dir, artifacts_root=self.artifacts, declarations=self.declarations)
        with patch.object(publisher, "publish", side_effect=isolated), contextlib.redirect_stdout(capture):
            code = publisher.main(["--run-root", str(self.run), "--output-dir", str(self.root / "cli")])
        self.assertEqual(code, 1)
        self.assertNotIn(PRIVATE, capture.getvalue())
        self.assertTrue((self.root / "cli/summary.json").is_file())

    def test_resolve_loop_errors_never_escape_or_expose_private_paths(self):
        original_resolve = Path.resolve
        real_publish = publisher.publish
        def isolated(run_root, output_dir):
            return real_publish(run_root, output_dir, artifacts_root=self.artifacts, declarations=self.declarations)
        for index, target in enumerate((self.run, self.artifacts, self.root / "resolve-output")):
            def raising(path, *args, **kwargs):
                if path == target:
                    raise RuntimeError("Symlink loop from PRIVATE_PATH_MARKER")
                return original_resolve(path, *args, **kwargs)
            output = target if index == 2 else self.root / f"resolve-public-{index}"
            capture = io.StringIO()
            with self.subTest(index=index), patch.object(Path, "resolve", autospec=True, side_effect=raising), \
                    patch.object(publisher, "publish", side_effect=isolated), contextlib.redirect_stdout(capture):
                code = publisher.main(["--run-root", str(self.run), "--output-dir", str(output)])
            self.assertEqual(code, 1)
            self.assertNotIn("PRIVATE_PATH_MARKER", capture.getvalue())
            if index == 2:
                self.assertFalse(output.exists())
            else:
                summary = (output / "summary.json").read_text(encoding="utf-8")
                self.assertNotIn("PRIVATE_PATH_MARKER", summary)
                self.assertIn("invalid_run_root", summary)
        loop = self.artifacts / "os-loop"
        try:
            loop.symlink_to(loop, target_is_directory=True)
        except OSError:
            return  # The portable RuntimeError cases above run on every OS.
        result = real_publish(loop, self.root / "os-loop-public", artifacts_root=self.artifacts,
                              declarations=self.declarations)
        self.assertIn("invalid_run_root", result["diagnostics"])


if __name__ == "__main__":
    unittest.main()
