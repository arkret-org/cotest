"""Pure resource/privacy regressions; no service, Cargo or native proof execution."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
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

    def preflight_only(self, code=101, unchanged=True):
        for name in ("native-result.json", "native-sources.json", "native.log", "coverage.json"):
            (self.run / name).unlink(missing_ok=True)
        result = {"command": [PRIVATE, "-B", PRIVATE], "exit_code": code,
                  "seconds": 1.25, "sources_unchanged": unchanged,
                  "source_fence": "service-isolation-sources.json",
                  "log": "service-isolation.log", "target_directory": PRIVATE}
        self.write("service-isolation-result.json", result)
        self.write("service-isolation-sources.json", {PRIVATE: "a" * 64})
        (self.run / "service-isolation.log").write_bytes(PRIVATE.encode() + b"\xff\x00")
        return result

    def assert_no_native_credit(self, result):
        self.assertFalse(result["export_complete"])
        self.assertFalse(result["native_execution_complete"])
        for field in ("native", "counts", "coverage"):
            self.assertIsNone(result[field])
        self.assertEqual([row["status"] for row in result["tests"]], ["not_observed"] * 13)
        self.assertEqual([row["status"] for row in result["meta_tests"]], ["not_observed"] * 2)

    def test_preflight_failure_exports_only_typed_facts_and_hashes(self):
        self.preflight_only()
        result = self.publish()
        self.assert_no_native_credit(result)
        expected = {"stage": "service_isolation", "exit_code": 101,
                    "sources_unchanged": True, "seconds": 1.25}
        for field, name in (("result_sha256", "service-isolation-result.json"),
                            ("source_fence_sha256", "service-isolation-sources.json"),
                            ("log_sha256", "service-isolation.log")):
            expected[field] = hashlib.sha256((self.run / name).read_bytes()).hexdigest()
        self.assertEqual(result["preflight"], expected)
        self.assertEqual(result["preflight_diagnostics"], [])
        self.assertEqual(result["status"], "incomplete")
        real_publish = publisher.publish
        def isolated(run_root, output_dir):
            return real_publish(run_root, output_dir, artifacts_root=self.artifacts,
                                declarations=self.declarations)
        capture = io.StringIO()
        with patch.object(publisher, "publish", side_effect=isolated), contextlib.redirect_stdout(capture):
            code = publisher.main(["--run-root", str(self.run), "--output-dir", str(self.root / "preflight-cli")])
        self.assertEqual(code, 1)
        self.assertNotIn(PRIVATE, capture.getvalue())

    def test_preflight_success_or_source_change_never_infers_a_native_outcome(self):
        for index, (code, unchanged) in enumerate(((0, True), (0, False), (124, False))):
            self.preflight_only(code, unchanged)
            result = self.publish(f"preflight-scalars-{index}")
            self.assert_no_native_credit(result)
            self.assertEqual(result["preflight"]["exit_code"], code)
            self.assertIs(result["preflight"]["sources_unchanged"], unchanged)
            self.assertEqual(result["status"], "incomplete")
            self.assertNotIn("failed_stage", result)

    def test_preflight_malformed_results_never_export_private_values(self):
        original = self.preflight_only()
        corruptions = [dict(original, **{key: value}) for key, value in (
            ("exit_code", True), ("exit_code", 1.5), ("sources_unchanged", PRIVATE),
            ("seconds", True), ("seconds", float("nan")), ("seconds", 10 ** 1000),
            ("log", "../" + PRIVATE), ("source_fence", "../" + PRIVATE), ("message", PRIVATE))]
        for index, value in enumerate(corruptions):
            self.write("service-isolation-result.json", value)
            result = self.publish(f"preflight-invalid-{index}")
            self.assert_no_native_credit(result)
            self.assertIsNone(result["preflight"])
            self.assertEqual(result["preflight_diagnostics"], ["unavailable_service_isolation"])
        (self.run / "service-isolation-result.json").write_bytes(b'{"exit_code":0,"exit_code":101}')
        self.assertIsNone(self.publish("preflight-duplicate")["preflight"])
        self.write("service-isolation-result.json", original)
        self.write("service-isolation-sources.json", {PRIVATE: PRIVATE})
        self.assertIsNone(self.publish("preflight-invalid-fence")["preflight"])

    def test_preflight_missing_linked_or_unresolvable_inputs_fail_closed(self):
        self.preflight_only()
        for index, name in enumerate(("service-isolation-result.json", "service-isolation-sources.json",
                                      "service-isolation.log")):
            path = self.run / name
            original = path.read_bytes()
            path.unlink()
            self.assertIsNone(self.publish(f"preflight-missing-{index}")["preflight"])
            path.write_bytes(original)
        log = self.run / "service-isolation.log"
        hardlink = self.root / "private-hardlink"
        os.link(log, hardlink)
        try:
            self.assertIsNone(self.publish("preflight-hardlink")["preflight"])
        finally:
            hardlink.unlink()
        original_resolve = Path.resolve
        def raising(path, *args, **kwargs):
            if path == log:
                raise RuntimeError("Symlink loop " + PRIVATE)
            return original_resolve(path, *args, **kwargs)
        with patch.object(Path, "resolve", autospec=True, side_effect=raising):
            self.assertIsNone(self.publish("preflight-resolve-loop")["preflight"])

    def test_preflight_cannot_override_existing_native_execution_or_coverage(self):
        baseline = self.publish("native-baseline")
        self.write("service-isolation-result.json", {"message": PRIVATE})
        result = self.publish("native-optional-preflight")
        for field in ("native", "counts", "coverage", "status", "export_complete",
                      "native_execution_complete", "tests", "meta_tests", "diagnostics"):
            self.assertEqual(result[field], baseline[field])
        self.assertIsNone(result["preflight"])
        self.assertEqual(result["preflight_diagnostics"], [])

    def failure_phase(self):
        source = (publisher.REPO / publisher.MLS_SOURCE).read_bytes()
        lines = source.decode("utf-8").splitlines()
        line = lines.index('        phase.mark("mimi_control", line!());') + 1
        self.write("native-sources.json", {"cotest/" + publisher.MLS_SOURCE: hashlib.sha256(source).hexdigest()})
        (self.run / "diagnostics").mkdir(exist_ok=True)
        return {"case": publisher.MLS_CASE, "stage": "mimi_control", "source": publisher.MLS_SOURCE,
                "line": line, "status": None, "error_code": None}

    def failed_mls_log(self):
        names = (*publisher.REQUIRED, *publisher.META)
        lines = [f"test {name} ... {'FAILED' if name == publisher.MLS_CASE else 'ok'}" for name in names]
        lines += [PRIVATE, "test result: FAILED. 14 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 12.50s"]
        (self.run / "native.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = json.loads((self.run / "native-result.json").read_text())
        self.write("native-result.json", dict(result, exit_code=101))

    def test_failed_mls_phase_is_source_bound_without_http_or_proof_credit(self):
        self.failed_mls_log()
        phase = self.failure_phase()
        self.write("diagnostics/mls-interop.json", phase)
        result = self.publish()
        self.assertEqual(result["failure_phases"], [phase])
        self.assertEqual(result["counts"], {"passed": 14, "failed": 1, "ignored": 0, "measured": 0, "filtered_out": 0})
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["export_complete"])
        self.assertFalse(result["native_execution_complete"])
        self.assertIsNone(result["coverage"])
        self.assertEqual(len(result["tests"]), 13)
        self.assertEqual(len(result["meta_tests"]), 2)
        real_publish = publisher.publish
        def isolated(run_root, output_dir):
            return real_publish(run_root, output_dir, artifacts_root=self.artifacts, declarations=self.declarations)
        with patch.object(publisher, "publish", side_effect=isolated), contextlib.redirect_stdout(io.StringIO()):
            code = publisher.main(["--run-root", str(self.run), "--output-dir", str(self.root / "failed-phase-cli")])
        self.assertEqual(code, 1)

    def test_failure_phase_rejects_unknown_fields_facts_source_and_locations(self):
        self.failed_mls_log()
        phase = self.failure_phase()
        corruptions = [dict(phase, **{key: PRIVATE}) for key in ("case", "stage", "source")]
        corruptions += [dict(phase, line=value) for value in (True, 0, 10001, phase["line"] + 1)]
        corruptions += [dict(phase, status=503), dict(phase, error_code="temporarily_unavailable"),
                        dict(phase, message=PRIVATE), {key: value for key, value in phase.items() if key != "status"}]
        for index, value in enumerate(corruptions):
            with self.subTest(index=index):
                self.write("diagnostics/mls-interop.json", value)
                result = self.publish(f"bad-phase-{index}")
                self.assertEqual(result["failure_phases"], [])
                self.assertIn("unavailable_mls_failure_phase", result["diagnostics"])
                self.assertFalse(result["export_complete"])
                self.assertIsNone(result["coverage"])
        self.write("diagnostics/mls-interop.json", phase)
        self.write("native-sources.json", {"cotest/" + publisher.MLS_SOURCE: "a" * 64})
        self.assertEqual(self.publish("changed-phase-source")["failure_phases"], [])

    def test_failure_phase_duplicate_json_missing_and_hardlinks_are_unavailable(self):
        self.failed_mls_log()
        self.assertEqual(self.publish("missing-phase")["failure_phases"], [])
        phase = self.failure_phase()
        path = self.run / "diagnostics/mls-interop.json"
        raws = [json.dumps(phase)[:-1] + ',"stage":"' + PRIVATE + '"}',
                PRIVATE, '{"line": NaN}', '\x00', 'x' * 4097]
        for index, raw in enumerate(raws):
            path.write_text(raw, encoding="utf-8")
            result = self.publish(f"invalid-phase-json-{index}")
            self.assertEqual(result["failure_phases"], [])
            self.assertIn("unavailable_mls_failure_phase", result["diagnostics"])
        outside = self.root / "private-phase.json"
        outside.write_text(json.dumps(phase), encoding="utf-8")
        path.unlink()
        os.link(outside, path)
        self.assertEqual(self.publish("phase-hardlink")["failure_phases"], [])

    def test_passed_case_never_consumes_failure_phase_or_changes_coverage(self):
        phase = self.failure_phase()
        self.write("diagnostics/mls-interop.json", dict(phase, message=PRIVATE))
        result = self.publish()
        self.assertEqual(result["failure_phases"], [])
        self.assertNotIn("unavailable_mls_failure_phase", result["diagnostics"])
        self.assertTrue(result["export_complete"])
        self.assertEqual(result["coverage"]["remaining"], len(self.unmapped))

    def test_phase_resolve_fault_is_private_and_marker_inventory_matches_source(self):
        self.failed_mls_log()
        self.write("diagnostics/mls-interop.json", self.failure_phase())
        original = Path.resolve
        def raising(path, *args, **kwargs):
            if path.name == "mls-interop.json":
                raise RuntimeError("Symlink loop from " + PRIVATE)
            return original(path, *args, **kwargs)
        with patch.object(Path, "resolve", autospec=True, side_effect=raising):
            self.assertEqual(self.publish("resolve-phase")["failure_phases"], [])
        source = (publisher.REPO / publisher.MLS_SOURCE).read_text(encoding="utf-8")
        stages = re.findall(r'phase\.mark\("([a-z_]+)", line!\(\)\);', source)
        self.assertEqual(set(stages), publisher.MLS_STAGES)
        self.assertEqual(len(stages), len(set(stages)))


if __name__ == "__main__":
    unittest.main()
