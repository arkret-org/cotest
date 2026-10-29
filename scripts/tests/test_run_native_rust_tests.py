"""Exercise the Python adapter with real Python children, never product stubs."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "native_rust_runner", Path(__file__).parents[1] / "run-native-rust-tests.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class NativeChildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cotest-native-adapter-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.raw = self.root / "raw"
        env = os.environ.copy()
        for name in (runner.PROVISION_EVIDENCE, runner.SERVICE_LOGS, runner.CLIENT_CONFIG_SCOPE, "INKSON_CONFIG_PATH"):
            env.pop(name, None)
        env.update(GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="2")
        self.environment = patch.dict(os.environ, env, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def child(self, name, code=0):
        output = self.root / name
        program = (
            "import json,os,pathlib,sys; "
            "e=os.environ.get('COTEST_AGENT_PROVISION_JOINT_DIR'); "
            "p=pathlib.Path(e) if e else None; "
            "info={'evidence':e,'existed':p.exists() if p else None,"
            "'client':os.environ.get('COTEST_NATIVE_CLIENT_CONFIG_ROOT'),"
            "'config':os.environ.get('INKSON_CONFIG_PATH'),"
            "'services':os.environ.get('COTEST_SERVICE_LOG_DIR')}; "
            "p.mkdir(parents=True,exist_ok=True) if p else None; "
            "(p/'browser-runner.log').write_text('private fixture body') if p else None; "
            f"pathlib.Path({str(output)!r}).write_text(json.dumps(info)); sys.exit({code})"
        )
        result = runner.native_child([sys.executable, "-c", program], artifact_root=self.raw)
        return result, json.loads(output.read_text())

    def test_default_invocations_have_distinct_uncreated_leaves_and_client_scopes(self):
        first = self.child("first.json")[1]
        second = self.child("second.json")[1]
        self.assertNotEqual(first["evidence"], second["evidence"])
        self.assertNotEqual(first["client"], second["client"])
        for info in (first, second):
            path = Path(info["evidence"])
            self.assertFalse(info["existed"])
            self.assertTrue(path.is_relative_to(self.raw))
            self.assertEqual(Path(info["config"]), Path(info["client"]) / "inkson/config.json")
            self.assertFalse(Path(info["client"]).exists())
            self.assertTrue((path / "browser-runner.log").exists())
            self.assertTrue(Path(info["services"]).is_dir())
            self.assertTrue(Path(info["services"]).is_relative_to(path.parent))
            if os.name != "nt":
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        self.assertNotIn(runner.PROVISION_EVIDENCE, os.environ)

    def test_absolute_fresh_caller_value_is_preserved(self):
        explicit = self.root / "caller-fresh"
        with patch.dict(os.environ, {runner.PROVISION_EVIDENCE: str(explicit)}):
            _, info = self.child("explicit.json")
        self.assertEqual(info["evidence"], str(explicit))
        self.assertFalse(info["existed"])
        self.assertTrue(self.raw.exists())

    def test_invalid_explicit_paths_fail_before_launch_and_leave_paths_unchanged(self):
        existing = self.root / "existing"
        existing.mkdir()
        marker = existing / "keep.txt"
        marker.write_text("untouched")
        file = self.root / "file"
        file.write_text("untouched file")
        cwd_entries = set(Path.cwd().iterdir())
        cases = ((runner.PROVISION_EVIDENCE, value) for value in ("", "relative-fresh", str(file)))
        services = ((runner.SERVICE_LOGS, value) for value in ("", "relative-services", str(file)))
        for key, value in (*cases, *services):
            with self.subTest(key=key, value=value), patch.dict(os.environ, {key: value}):
                with patch.object(subprocess, "run") as child:
                    with self.assertRaises(RuntimeError):
                        runner.native_child([sys.executable], artifact_root=self.raw)
                    child.assert_not_called()
        self.assertFalse(self.raw.exists())
        self.assertEqual(set(Path.cwd().iterdir()), cwd_entries)
        self.assertEqual(list(existing.iterdir()), [marker])
        self.assertEqual(marker.read_text(), "untouched")
        self.assertEqual(file.read_text(), "untouched file")

    def test_browser_consumers_reject_an_explicit_existing_directory(self):
        existing = self.root / "parent-browser-evidence"
        existing.mkdir()
        marker = existing / "keep.txt"
        marker.write_text("parent evidence")
        with patch.dict(os.environ, {runner.PROVISION_EVIDENCE: str(existing)}):
            for binary in runner.PROVISION_BINARIES:
                with self.subTest(binary=binary), patch.object(subprocess, "run") as child:
                    with self.assertRaises(RuntimeError):
                        runner.native_child([str(self.root / (binary + "-deadbeef"))], artifact_root=self.raw)
                    child.assert_not_called()
        self.assertFalse(self.raw.exists())
        self.assertEqual(list(existing.iterdir()), [marker])
        self.assertEqual(marker.read_text(), "parent evidence")

    def test_nested_nonbrowser_child_inherits_parent_evidence_and_client_scope(self):
        result = self.root / "nested.json"
        inner = (
            "import json,os,pathlib; "
            "p=pathlib.Path(os.environ['COTEST_AGENT_PROVISION_JOINT_DIR']); "
            f"pathlib.Path({str(result)!r}).write_text(json.dumps({{"
            "'evidence':str(p),'existed':p.is_dir(),"
            "'client':os.environ['COTEST_NATIVE_CLIENT_CONFIG_ROOT'],"
            "'config':os.environ['INKSON_CONFIG_PATH']}))"
        )
        outer = (
            "import os,pathlib,runpy,sys; "
            "p=pathlib.Path(os.environ['COTEST_AGENT_PROVISION_JOINT_DIR']); "
            "p.mkdir(); (p/'keep.txt').write_text('parent evidence'); "
            f"runner=runpy.run_path({str(Path(runner.__file__))!r}); "
            f"sys.exit(runner['native_child']([sys.executable,'-c',{inner!r}],"
            f"artifact_root=pathlib.Path({str(self.raw)!r})))"
        )
        self.assertEqual(runner.native_child([sys.executable, "-c", outer], artifact_root=self.raw), 0)
        info = json.loads(result.read_text())
        self.assertTrue(info["existed"])
        self.assertEqual(Path(info["config"]), Path(info["client"]) / "inkson/config.json")
        self.assertFalse(Path(info["client"]).exists())
        self.assertEqual((Path(info["evidence"]) / "keep.txt").read_text(), "parent evidence")
        self.assertEqual(len(list(self.raw.rglob("native-child.json"))), 1)

    def test_explicit_absolute_service_directory_and_fresh_provision_are_preserved(self):
        services = self.root / "explicit-services"
        services.mkdir()
        fresh = self.root / "explicit-provision"
        with patch.dict(os.environ, {runner.SERVICE_LOGS: str(services), runner.PROVISION_EVIDENCE: str(fresh)}):
            _, info = self.child("explicit-services.json")
        self.assertEqual(info["services"], str(services))
        self.assertEqual(info["evidence"], str(fresh))
        self.assertFalse(info["existed"])
        self.assertFalse(self.raw.exists())

    def test_inherited_client_scope_is_unchanged_and_still_gets_evidence(self):
        inherited = self.root / "inherited"
        inherited.mkdir()
        config = str(inherited / "inkson/config.json")
        with patch.dict(os.environ, {runner.CLIENT_CONFIG_SCOPE: str(inherited), "INKSON_CONFIG_PATH": config}):
            _, info = self.child("inherited.json")
        self.assertEqual(info["client"], str(inherited))
        self.assertEqual(info["config"], config)
        self.assertTrue(inherited.exists())
        self.assertFalse(info["existed"])

    def test_invalid_inherited_scope_does_not_launch_or_create_evidence(self):
        with patch.dict(os.environ, {runner.CLIENT_CONFIG_SCOPE: str(self.root / "missing")}):
            with patch.object(subprocess, "run") as child:
                with self.assertRaises(RuntimeError):
                    runner.native_child([sys.executable], artifact_root=self.raw)
                child.assert_not_called()
        self.assertFalse(self.raw.exists())

    def test_nonzero_child_retains_raw_files_and_exact_exit_code(self):
        code, info = self.child("failed.json", 7)
        self.assertEqual(code, 7)
        record = json.loads((Path(info["evidence"]).parent / "native-child.json").read_text())
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["exit_code"], 7)
        self.assertTrue((Path(info["evidence"]) / "browser-runner.log").is_file())

    def test_launch_exception_keeps_raw_files_and_terminal_metadata(self):
        def fail(command, *, env, check):
            leaf = Path(env[runner.PROVISION_EVIDENCE])
            leaf.mkdir()
            (leaf / "browser-runner.log").write_text("private fixture material")
            raise OSError("synthetic launch failure")
        with patch.object(subprocess, "run", side_effect=fail):
            with self.assertRaises(OSError):
                runner.native_child([sys.executable], artifact_root=self.raw)
        records = list(self.raw.rglob("native-child.json"))
        self.assertEqual(len(records), 1)
        self.assertEqual(json.loads(records[0].read_text())["status"], "launch_failed")
        self.assertTrue((records[0].parent / "agent-provision/browser-runner.log").is_file())

    def test_untrusted_run_and_binary_labels_cannot_escape_owned_root(self):
        env = {"GITHUB_RUN_ID": "../../outside", "GITHUB_RUN_ATTEMPT": "../"}
        scope = runner.evidence_scope(["../untrusted/../../binary"], env, self.raw)
        self.assertTrue(scope.is_relative_to(self.raw / "local-0"))
        self.assertFalse(Path(env[runner.PROVISION_EVIDENCE]).exists())
        self.assertEqual(runner.provision_binary("agent_vectors_production-deadbeef.exe"), "agent_vectors_production")
        self.assertIsNone(runner.provision_binary("prefix-agent_vectors_production-deadbeef"))


if __name__ == "__main__":
    unittest.main()
