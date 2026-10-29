"""Exercise execution provenance with synthetic files and injected callbacks only."""

from contextlib import ExitStack, chdir, redirect_stderr, redirect_stdout
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1]


def load_module(name, filename=None):
    specification = importlib.util.spec_from_file_location(name, SCRIPTS / ((filename or name) + ".py"))
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


scope = load_module("native_workspace_scope")
execution = load_module("native_workspace_execution")
runner = load_module("native_rust_runner", "run-native-rust-tests")


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        # The local test command explicitly places TEMP/TMP/TMPDIR on D:.
        # Hosted Linux may use its own run-owned temporary directory.
        self.temporary = tempfile.TemporaryDirectory(prefix="native-execution-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.workspace = self.root / "workspace" / "cotest"
        self.workspace.mkdir(parents=True)
        self.target = self.root / "target"
        self.plan_path = self.root / "receipts" / "private-plan.json"
        self.plan_path.parent.mkdir()
        self.make_plan()

    def make_plan(self, docs=2):
        packages, messages = [], []
        for number in range(docs):
            name = f"member_{number:02}"
            package_root = self.workspace / "crates" / name
            source = package_root / "src" / "lib.rs"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("// Synthetic source, never compiled.\n", encoding="utf-8")
            manifest = package_root / "Cargo.toml"
            manifest.write_text("# Synthetic metadata only.\n", encoding="utf-8")
            target = {"kind": ["lib"], "crate_types": ["lib"], "name": name,
                      "src_path": str(source), "edition": "2024", "doc": True,
                      "doctest": True, "test": True}
            package = {"id": f"path:{package_root}", "name": name, "version": "0.3.0",
                       "source": None, "manifest_path": str(manifest), "targets": [target]}
            packages.append(package)
            executable = self.target / "debug" / "deps" / (name + ".exe")
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_bytes(b"synthetic bytes that must never be executed")
            messages.append({"reason": "compiler-artifact", "package_id": package["id"],
                             "target": copy.deepcopy(target), "features": ["default"],
                             "profile": {"opt_level": "0", "debuginfo": 0,
                                         "debug_assertions": True, "overflow_checks": True,
                                         "test": True}, "fresh": False,
                             "executable": str(executable), "filenames": []})
        messages.append({"reason": "build-finished", "success": True})
        metadata = {"workspace_root": str(self.workspace), "target_directory": str(self.target),
                    "workspace_members": [p["id"] for p in packages], "packages": packages}
        refs = {name: "a" * 40 for name in execution.REPOSITORIES}
        self.plan = scope.create_plan(
            metadata, messages, 4, refs, file_sha256=execution.file_sha256,
            build_context={"source_snapshot_sha256": "b" * 64})
        self.native = self.plan["native_targets"][0]
        self.plan["shard_index"] = self.native["assigned_shard"]
        self.save_plan()
        self.environment = {execution.PLAN_ENV: str(self.plan_path),
                            execution.REAL_DOC_ENV: str(self.root / "unexecuted-rustdoc"),
                            execution.OLD_DOC_ENV: json.dumps("original-rustdoc"),
                            "RUSTDOC": str(SCRIPTS / "run-native-rustdoc.py"),
                            "UNCHANGED_SETTING": "retained"}

    def save_plan(self):
        self.plan_path.write_text(json.dumps(self.plan), encoding="utf-8")
        scope.public_plan(self.plan)

    def native_receipt(self):
        return self.plan_path.parent / "runtime" / "native" / (
            self.native["identity_sha256"] + ".json")

    def doc_receipt(self, row):
        return self.plan_path.parent / "runtime" / "docs" / (row["identity_sha256"] + ".json")

    def assert_adapter_failure_marker(self):
        path = self.plan_path.parent / "runtime" / "adapter-failed.json"
        self.assertEqual(json.loads(path.read_text()), {"failed": True})

    def doc_arguments(self, row=None):
        row = row or self.plan["doctest_targets"][0]
        return ["--crate-name", row["identity"]["name"], "--test",
                os.path.relpath(row["src_path"], self.workspace),
                "--test-run-directory", row["package_manifest_dir"],
                "--edition=2024", "--test-runtool", "python-unexecuted",
                "--test-runtool-arg", "-B", "--cfg", 'feature="default"']

    def assert_clean_child(self, environment):
        self.assertEqual(environment["RUSTDOC"], "original-rustdoc")
        self.assertEqual(environment["UNCHANGED_SETTING"], "retained")
        for key in (execution.PLAN_ENV, execution.DOC_ENV,
                    execution.REAL_DOC_ENV, execution.OLD_DOC_ENV):
            self.assertNotIn(key, environment)

    def test_legacy_without_plan_is_transparent(self):
        environment = {"RUSTDOC": "unchanged", "SETTING": "value"}
        execute = mock.Mock(return_value=19)
        with mock.patch.object(execution.subprocess, "run", side_effect=AssertionError("no tools")):
            self.assertEqual(execution.run_child(["unexecuted.exe", "--exact"], environment, execute), 19)
        self.assertIs(execute.call_args.args[0], environment)
        self.assertFalse((self.plan_path.parent / "runtime").exists())

    def test_assigned_executes_verified_bytes_and_restores_nested_environment(self):
        original = self.environment.copy()
        command = [self.native["executable"], "--exact", "selected_test"]
        def execute(environment):
            self.assert_clean_child(environment)
            return 0
        with mock.patch.object(execution.subprocess, "run", side_effect=AssertionError("no tools")):
            self.assertEqual(execution.run_child(command, self.environment, execute), 0)
        receipt = json.loads(self.native_receipt().read_text())
        self.assertEqual(receipt["status"], "completed")
        self.assertEqual(receipt["exit_code"], 0)
        self.assertEqual(receipt["executable_sha256"], self.native["executable_sha256"])
        self.assertEqual(self.environment, original)
        self.assertEqual(command[1:], ["--exact", "selected_test"])

    def test_assigned_failure_keeps_original_exit_code(self):
        self.assertEqual(execution.run_child(
            [self.native["executable"]], self.environment, lambda _: 7), 7)
        self.assertEqual(json.loads(self.native_receipt().read_text())["exit_code"], 7)

    def test_assigned_exception_records_launch_failure_and_raises(self):
        execute = mock.Mock(side_effect=OSError("PRIVATE_ERROR_MARKER"))
        with self.assertRaises(OSError):
            execution.run_child([self.native["executable"]], self.environment, execute)
        record = json.loads(self.native_receipt().read_text())
        self.assertEqual((record["status"], record["exit_code"]), ("launch_failed", None))
        self.assertNotIn("PRIVATE_ERROR_MARKER", self.native_receipt().read_text())
        self.assert_adapter_failure_marker()

    def test_unassigned_delegation_never_executes_or_grants_credit(self):
        self.plan["shard_index"] = (self.native["assigned_shard"] + 1) % 4
        self.save_plan()
        execute = mock.Mock(side_effect=AssertionError("delegated target executed"))
        self.assertEqual(execution.run_child([self.native["executable"]], self.environment, execute), 0)
        execute.assert_not_called()
        record = json.loads(self.native_receipt().read_text())
        self.assertEqual((record["status"], record["exit_code"], record["executable_sha256"]),
                         ("delegated", None, None))

    def test_changed_binary_is_rejected_before_callback_or_receipt(self):
        Path(self.native["executable"]).write_bytes(b"altered")
        execute = mock.Mock()
        with self.assertRaises(RuntimeError):
            execution.run_child([self.native["executable"]], self.environment, execute)
        execute.assert_not_called()
        self.assertFalse(self.native_receipt().exists())

    def test_unknown_binary_cannot_use_a_temporary_basename_exception(self):
        executable = self.root / "rustdoctest-unowned" / "rust_out.exe"
        executable.parent.mkdir()
        executable.write_bytes(b"never run")
        execute = mock.Mock()
        with self.assertRaises(RuntimeError):
            execution.run_child([str(executable)], self.environment, execute)
        execute.assert_not_called()

    def test_duplicate_native_receipt_is_rejected_without_second_execution(self):
        execute = mock.Mock(return_value=0)
        command = [self.native["executable"]]
        self.assertEqual(execution.run_child(command, self.environment, execute), 0)
        original = self.native_receipt().read_bytes()
        with self.assertRaises((OSError, RuntimeError)):
            execution.run_child(command, self.environment, execute)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(self.native_receipt().read_bytes(), original)

    def test_context_graph_tampering_is_rejected(self):
        self.plan["build_context"]["source_snapshot_sha256"] = "c" * 64
        self.plan_path.write_text(json.dumps(self.plan), encoding="utf-8")
        execute = mock.Mock()
        with self.assertRaises(ValueError):
            execution.run_child([self.native["executable"]], self.environment, execute)
        execute.assert_not_called()

    def test_original_absent_or_empty_rustdoc_is_restored_exactly(self):
        for original in (None, ""):
            environment = self.environment.copy()
            environment[execution.OLD_DOC_ENV] = json.dumps(original)
            environment[execution.DOC_ENV] = "discarded"
            child = execution._child_environment(environment)
            self.assertNotIn(execution.PLAN_ENV, child)
            self.assertNotIn(execution.DOC_ENV, child)
            if original is None:
                self.assertNotIn("RUSTDOC", child)
            else:
                self.assertEqual(child["RUSTDOC"], "")

    def test_configure_non_posix_is_rejected_before_tool_or_plan_lookup(self):
        with mock.patch.object(execution.os, "name", "nt"), \
                mock.patch.object(execution, "load_plan") as load, \
                mock.patch.object(execution.shutil, "which") as which:
            with self.assertRaises(RuntimeError):
                execution.configure_environment(self.environment.copy())
            load.assert_not_called()
            which.assert_not_called()

    def test_non_test_rustdoc_probe_preserves_arguments_and_exit(self):
        arguments = ["--version", "--verbose"]
        with mock.patch.object(execution.subprocess, "run", return_value=SimpleNamespace(returncode=23)) as run:
            self.assertEqual(execution.run_rustdoc(arguments, self.environment), 23)
        self.assertEqual(run.call_args.args[0], [self.environment[execution.REAL_DOC_ENV], *arguments])
        self.assertIs(run.call_args.kwargs["env"], self.environment)
        self.assertFalse((self.plan_path.parent / "runtime").exists())

    def test_workspace_compile_cwd_and_package_test_directory_run_real_context_only(self):
        row = self.plan["doctest_targets"][0]
        arguments = self.doc_arguments(row)
        seen = []
        def rustdoc(command, *, env, check):
            self.assertEqual(command, [self.environment[execution.REAL_DOC_ENV], *arguments])
            self.assertFalse(check)
            context_path = Path(env[execution.DOC_ENV])
            self.assertTrue(context_path.is_file())
            scratch = Path(env["TMPDIR"])
            self.assertEqual(str(scratch), env["TEMP"])
            self.assertEqual(str(scratch), env["TMP"])
            executable = scratch / "rustdoctest-synthetic" / "rust_out.exe"
            executable.parent.mkdir()
            executable.write_bytes(b"not an executable and never launched")
            def execute(child):
                self.assert_clean_child(child)
                seen.append(str(executable))
                return 0
            self.assertEqual(execution.run_child([str(executable), "--test-threads=1"], env, execute), 0)
            return SimpleNamespace(returncode=0)
        with chdir(self.workspace), \
                mock.patch.object(execution, "_verify_wrapper_pid") as active, \
                mock.patch.object(execution.subprocess, "run", side_effect=rustdoc):
            self.assertEqual(execution.run_rustdoc(arguments, self.environment), 0)
        active.assert_called_once()
        self.assertEqual(len(seen), 1)
        self.assertEqual(json.loads(self.doc_receipt(row).read_text())["exit_code"], 0)
        self.assertFalse(Path(seen[0]).exists())

    def test_wrong_doc_source_crate_package_directory_or_compile_cwd_rejected(self):
        row = self.plan["doctest_targets"][0]
        arguments = self.doc_arguments(row)
        variants = []
        wrong_crate = arguments.copy(); wrong_crate[1] = "unknown_crate"; variants.append(wrong_crate)
        wrong_source = arguments.copy(); wrong_source[3] = "unknown.rs"; variants.append(wrong_source)
        wrong_directory = arguments.copy(); wrong_directory[5] = str(self.workspace); variants.append(wrong_directory)
        variants.append(arguments + ["--crate-name", row["identity"]["name"]])
        variants.append(arguments + ["--test-run-directory", row["package_manifest_dir"]])
        with chdir(self.workspace), mock.patch.object(execution.subprocess, "run") as run:
            for altered in variants:
                with self.subTest(arguments=altered), self.assertRaises(RuntimeError):
                    execution.run_rustdoc(altered, self.environment)
            run.assert_not_called()
        with chdir(Path(row["package_manifest_dir"])), mock.patch.object(execution.subprocess, "run") as run:
            with self.assertRaises(RuntimeError):
                execution.run_rustdoc(arguments, self.environment)
            run.assert_not_called()

    def test_dynamic_executable_outside_owned_scratch_is_rejected(self):
        row = self.plan["doctest_targets"][0]
        executable = self.root / "rust_out.exe"
        executable.write_bytes(b"never executed")
        execute = mock.Mock()
        def rustdoc(command, *, env, check):
            with self.assertRaises(RuntimeError):
                execution.run_child([str(executable)], env, execute)
            # A should_panic example could otherwise mistake adapter exit 1
            # for the expected failure and make real rustdoc return zero.
            return SimpleNamespace(returncode=0)
        with chdir(self.workspace), mock.patch.object(execution.subprocess, "run", side_effect=rustdoc):
            self.assertEqual(execution.run_rustdoc(self.doc_arguments(row), self.environment), 1)
        execute.assert_not_called()
        self.assertEqual(json.loads(self.doc_receipt(row).read_text())["exit_code"], 1)
        self.assert_adapter_failure_marker()

    def test_inactive_wrapper_context_rejects_even_an_owned_dynamic_file(self):
        row = self.plan["doctest_targets"][0]
        execute = mock.Mock()
        def rustdoc(command, *, env, check):
            executable = Path(env["TMPDIR"]) / "rust_out.exe"
            executable.write_bytes(b"never executed")
            with self.assertRaises(RuntimeError):
                execution.run_child([str(executable)], env, execute)
            return SimpleNamespace(returncode=1)
        with chdir(self.workspace), \
                mock.patch.object(execution, "_verify_wrapper_pid", side_effect=RuntimeError("inactive")), \
                mock.patch.object(execution.subprocess, "run", side_effect=rustdoc):
            self.assertEqual(execution.run_rustdoc(self.doc_arguments(row), self.environment), 1)
        execute.assert_not_called()
        self.assert_adapter_failure_marker()

    def test_dynamic_context_plan_shard_identity_and_owner_are_not_interchangeable(self):
        row = self.plan["doctest_targets"][0]
        execute = mock.Mock()
        def rustdoc(command, *, env, check):
            executable = Path(env["TMPDIR"]) / "rust_out.exe"
            executable.write_bytes(b"never executed")
            context_path = Path(env[execution.DOC_ENV])
            original = json.loads(context_path.read_text())
            for key, value in [("plan_sha256", "c" * 64),
                               ("shard_index", (self.plan["shard_index"] + 1) % 4),
                               ("target_identity_sha256", "d" * 64)]:
                altered = {**original, key: value}
                context_path.write_text(json.dumps(altered), encoding="utf-8")
                with self.subTest(field=key), self.assertRaises(RuntimeError):
                    execution.run_child([str(executable)], env, execute)
            context_path.write_text(json.dumps(original), encoding="utf-8")
            unowned = self.root / "context.json"
            unowned.write_text(json.dumps(original), encoding="utf-8")
            with self.assertRaises(RuntimeError):
                execution.run_child([str(executable)], {**env, execution.DOC_ENV: str(unowned)}, execute)
            return SimpleNamespace(returncode=1)
        with chdir(self.workspace), \
                mock.patch.object(execution, "_verify_wrapper_pid") as active, \
                mock.patch.object(execution.subprocess, "run", side_effect=rustdoc):
            self.assertEqual(execution.run_rustdoc(self.doc_arguments(row), self.environment), 1)
        execute.assert_not_called()
        active.assert_not_called()
        self.assert_adapter_failure_marker()

    def test_native_target_cannot_borrow_a_doctest_context(self):
        execute = mock.Mock()
        environment = {**self.environment, execution.DOC_ENV: "not-a-native-context"}
        with self.assertRaises(RuntimeError):
            execution.run_child([self.native["executable"]], environment, execute)
        execute.assert_not_called()

    def test_real_rustdoc_interprets_dynamic_exit_including_expected_panic(self):
        row = self.plan["doctest_targets"][0]
        def rustdoc(command, *, env, check):
            executable = Path(env["TMPDIR"]) / "rust_out.exe"
            executable.write_bytes(b"never executed")
            self.assertEqual(execution.run_child([str(executable)], env, lambda _: 7), 7)
            return SimpleNamespace(returncode=0)
        with chdir(self.workspace), \
                mock.patch.object(execution, "_verify_wrapper_pid"), \
                mock.patch.object(execution.subprocess, "run", side_effect=rustdoc):
            self.assertEqual(execution.run_rustdoc(self.doc_arguments(row), self.environment), 0)
        self.assertEqual(json.loads(self.doc_receipt(row).read_text())["exit_code"], 0)

    def test_dynamic_launch_failure_cannot_be_mistaken_for_expected_panic(self):
        row = self.plan["doctest_targets"][0]
        def rustdoc(command, *, env, check):
            executable = Path(env["TMPDIR"]) / "rust_out.exe"
            executable.write_bytes(b"never executed")
            with self.assertRaises(OSError):
                execution.run_child([str(executable)], env,
                                    mock.Mock(side_effect=OSError("PRIVATE_LAUNCH_MARKER")))
            return SimpleNamespace(returncode=0)
        with chdir(self.workspace), \
                mock.patch.object(execution, "_verify_wrapper_pid"), \
                mock.patch.object(execution.subprocess, "run", side_effect=rustdoc):
            self.assertEqual(execution.run_rustdoc(self.doc_arguments(row), self.environment), 1)
        self.assertEqual(json.loads(self.doc_receipt(row).read_text())["exit_code"], 1)
        self.assertNotIn("PRIVATE_LAUNCH_MARKER", self.doc_receipt(row).read_text())
        self.assert_adapter_failure_marker()

    def test_interrupted_real_rustdoc_records_failure_without_pass_credit(self):
        row = self.plan["doctest_targets"][0]
        with chdir(self.workspace), \
                mock.patch.object(execution.subprocess, "run", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                execution.run_rustdoc(self.doc_arguments(row), self.environment)
        record = json.loads(self.doc_receipt(row).read_text())
        self.assertEqual((record["status"], record["exit_code"]), ("launch_failed", None))

    def test_all_31_doc_invocations_are_recorded_and_nonzero_is_retained(self):
        self.make_plan(docs=31)
        codes = [0] * 30 + [9]
        with chdir(self.workspace), \
                mock.patch.object(execution.subprocess, "run",
                                  side_effect=[SimpleNamespace(returncode=x) for x in codes]) as run:
            actual = [execution.run_rustdoc(self.doc_arguments(row), self.environment)
                      for row in self.plan["doctest_targets"]]
        self.assertEqual(actual, codes)
        self.assertEqual(run.call_count, 31)
        records = [json.loads(self.doc_receipt(row).read_text()) for row in self.plan["doctest_targets"]]
        self.assertEqual(sum(x["status"] == "completed" and x["exit_code"] == 0 for x in records), 30)
        self.assertEqual(records[-1]["exit_code"], 9)

    def test_duplicate_doc_receipt_does_not_run_rustdoc_twice(self):
        row = self.plan["doctest_targets"][0]
        with chdir(self.workspace), \
                mock.patch.object(execution.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual(execution.run_rustdoc(self.doc_arguments(row), self.environment), 0)
            with self.assertRaises((OSError, RuntimeError)):
                execution.run_rustdoc(self.doc_arguments(row), self.environment)
        self.assertEqual(run.call_count, 1)

    def mock_cargo_capture(self, content, exit_code=0):
        stack = ExitStack()
        self.addCleanup(stack.close)
        environment = {key: str(self.root) for key in ("TEMP", "TMP", "TMPDIR")}
        stack.enter_context(mock.patch.dict(os.environ, environment, clear=True))
        stack.enter_context(mock.patch.object(runner.shutil, "which", return_value="unexecuted-openssl"))
        def openssl(executable, *arguments):
            for flag in ("-out", "-keyout"):
                if flag in arguments:
                    Path(arguments[arguments.index(flag) + 1]).write_bytes(b"synthetic PKI bytes")
        stack.enter_context(mock.patch.object(runner, "openssl", side_effect=openssl))
        stack.enter_context(mock.patch.object(runner, "cargo_native_runner", side_effect=lambda command, _: command))
        def cargo(command, *, env, stdout, check):
            self.assertEqual(command, self.capture_command())
            self.assertFalse(check)
            stdout.write(content)
            return SimpleNamespace(returncode=exit_code)
        return stack.enter_context(mock.patch.object(runner.subprocess, "run", side_effect=cargo))

    @staticmethod
    def capture_command():
        return ["cargo", "test", "--workspace", "--locked", "--no-fail-fast",
                "--no-run", "--message-format=json"]

    def test_cargo_capture_excludes_outer_lease_stdout_and_preserves_native_failure(self):
        messages = [{"reason": "compiler-message", "message": {"rendered": "synthetic compiler error\n"}},
                    {"reason": "build-finished", "success": False}]
        content = "".join(json.dumps(message) + "\n" for message in messages)
        cargo = self.mock_cargo_capture(content, exit_code=101)
        path = self.root / "cargo-private.jsonl"
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            print("synthetic outer lease before")
            self.assertEqual(runner.run(self.capture_command(), cargo_messages=path), 101)
            print("synthetic outer lease after")
        cargo.assert_called_once()
        self.assertEqual(path.read_text(), content)
        self.assertEqual([json.loads(line) for line in path.read_text().splitlines()], messages)
        self.assertIn("synthetic outer lease before", output.getvalue())
        self.assertIn("synthetic outer lease after", output.getvalue())
        self.assertEqual(errors.getvalue(), "synthetic compiler error\n")

    def test_existing_cargo_capture_is_refused_without_overwrite_or_execution(self):
        cargo = self.mock_cargo_capture("{}\n")
        path = self.root / "existing.jsonl"
        path.write_text("preserved original", encoding="utf-8")
        with self.assertRaises(OSError):
            runner.run(self.capture_command(), cargo_messages=path)
        cargo.assert_not_called()
        self.assertEqual(path.read_text(), "preserved original")

    def test_non_json_cargo_capture_is_rejected_even_with_zero_native_exit(self):
        self.mock_cargo_capture("outer lease text is not a Cargo JSON message\n")
        path = self.root / "invalid.jsonl"
        with self.assertRaises(ValueError):
            runner.run(self.capture_command(), cargo_messages=path)
        self.assertTrue(path.is_file())

    def test_capture_cli_preserves_full_command_and_rejects_other_programs(self):
        path = self.root / "captured.jsonl"
        arguments = ["run-native-rust-tests.py", "--cargo-messages", str(path), *self.capture_command()]
        with mock.patch.object(runner.sys, "argv", arguments), \
                mock.patch.object(runner, "run", return_value=13) as run:
            self.assertEqual(runner.main(), 13)
        run.assert_called_once_with(self.capture_command(), cargo_messages=path)
        with mock.patch.object(runner.sys, "argv", [*arguments[:3], "not-cargo", "test"]), \
                mock.patch.object(runner, "run") as run, redirect_stderr(io.StringIO()):
            self.assertEqual(runner.main(), 2)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
