"""CLI regressions with synthetic data, dummy bytes and mocked read-only tools."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_HERE = Path(__file__).resolve().parent
cli = load("run_native_workspace_cli", _HERE.parent / "run-native-workspace.py")
fixtures = load("native_scope_cli_fixtures", _HERE / "test_native_workspace_scope.py")
_BASE = Path("D:/BuildCache/arkret-ci-20261028/native-scope-tests")


class CliTests(unittest.TestCase):
    def setUp(self):
        _BASE.mkdir(parents=True, exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(dir=_BASE, prefix="scope-cli-")
        self.base = Path(self.scratch.name).resolve()
        self.assertEqual(self.base.parent, _BASE.resolve())
        self.root = self.base / "checkout"
        self.root.mkdir()
        self.target = self.base / "target"
        self.target.mkdir()
        self.metadata, self.messages = fixtures.fixture(
            root=self.root.as_posix(), target=self.target.as_posix(),
            cache=(self.base / "registry").as_posix())
        for message in self.messages:
            executable = message.get("executable")
            if executable:
                path = Path(executable)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((message["package_id"] + message["target"]["name"]).encode())
        self.meta = self.base / "metadata.json"
        self.meta.write_text(json.dumps(self.metadata), encoding="utf-8")
        self.msg = self.base / "messages.jsonl"
        self.msg.write_text("\n".join(json.dumps(m) for m in self.messages), encoding="utf-8")
        self.before = self.base / "before.json"
        self.private = self.base / "shard-0/private-plan.json"
        self.env_file = self.base / "github-env"
        self.refs = fixtures.REFS
        self.environment = patch.dict(os.environ, {
            "NATIVE_SOURCE_REFS": json.dumps(self.refs),
            "CARGO_HOME": str(self.base / "cargo-home"),
            "TEMP": str(_BASE), "TMP": str(_BASE)})
        self.environment.start()
        self.source = patch.object(cli, "_source_snapshot", return_value="a" * 64)
        self.source.start()
        self.versions = patch.object(cli, "_version_hash", return_value="b" * 64)
        self.versions.start()
        self.addCleanup(self.versions.stop)
        self.addCleanup(self.source.stop)
        self.addCleanup(self.environment.stop)
        self.addCleanup(self.scratch.cleanup)

    def invoke(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def prepare(self):
        result = self.invoke(["snapshot", "--metadata", str(self.meta), "--output", str(self.before)])
        self.assertEqual(result[0], 0, result)
        result = self.invoke(["plan", "--metadata", str(self.meta), "--messages", str(self.msg),
                              "--before-context", str(self.before), "--shard-index", "0",
                              "--output", str(self.private), "--github-env-file", str(self.env_file)])
        self.assertEqual(result[0], 0, result)
        return json.loads(self.private.read_text())

    def proofs(self):
        original = self.prepare()
        for shard in range(4):
            private = copy.deepcopy(original)
            private["shard_index"] = shard
            private["raw_metadata"] = {"private": str(self.base)}
            directory = self.base / f"shard-{shard}"
            plan = directory / "private-plan.json"
            cli._atomic_json(plan, private)
            public = cli._module("native_workspace_scope").public_plan(private)
            native, docs = fixtures.complete_receipts([public])
            for kind, receipts in (("native", native), ("docs", docs)):
                for index, receipt in enumerate(receipts):
                    cli._atomic_json(directory / "runtime" / kind / f"{index}.json", receipt)
            proof = directory / "scope-proof.json"
            result = self.invoke(["publish", "--plan", str(plan), "--output", str(proof)])
            self.assertEqual(result[0], 0, result)
        return self.base

    def test_snapshot_plan_exact_hashes_context_and_safe_environment_export(self):
        private = self.prepare()
        self.assertEqual(private["build_context"]["source_snapshot_sha256"], "a" * 64)
        self.assertEqual(self.env_file.read_text().strip(),
                         "COTEST_NATIVE_WORKSPACE_PLAN=" + str(self.private.absolute()))
        for row in private["native_targets"]:
            self.assertEqual(row["executable_sha256"],
                             hashlib.sha256(Path(row["executable"]).read_bytes()).hexdigest())

    def test_source_flags_or_config_drift_between_snapshot_and_plan_is_rejected(self):
        self.assertEqual(self.invoke(["snapshot", "--metadata", str(self.meta),
                                      "--output", str(self.before)])[0], 0)
        arguments = ["plan", "--metadata", str(self.meta), "--messages", str(self.msg),
                     "--before-context", str(self.before), "--shard-index", "0",
                     "--output", str(self.private)]
        for source in ("c" * 64,):
            with patch.object(cli, "_source_snapshot", return_value=source):
                self.assertEqual(self.invoke(arguments)[0], 1)
        with patch.dict(os.environ, {"RUSTFLAGS": "private-source-sensitive-flag"}):
            code, out, error = self.invoke(arguments)
            self.assertEqual(code, 1)
            self.assertEqual(error, "native workspace scope: command failed\n")
            self.assertNotIn("private-source", out + error)
        with patch.object(cli, "_version_hash", return_value="c" * 64):
            self.assertEqual(self.invoke(arguments)[0], 1)
        with patch.dict(os.environ, {"CARGO_PROFILE_DEV_OPT_LEVEL": "3"}):
            self.assertEqual(self.invoke(arguments)[0], 1)
        config = self.root / ".cargo/config.toml"
        config.parent.mkdir()
        config.write_text('[build]\nrustflags = ["--cfg", "changed"]\n')
        self.assertEqual(self.invoke(arguments)[0], 1)
        self.assertFalse(self.private.exists())

    def test_hash_callback_rejects_real_resolved_escape_and_missing_file(self):
        hasher = cli._executable_hasher(self.target)
        with self.assertRaises(FileNotFoundError):
            hasher(self.target / "absent")
        outside = self.base / "outside"
        outside.write_bytes(b"not target bytes")
        with patch.object(Path, "resolve", return_value=outside):
            with self.assertRaises(ValueError):
                hasher(self.target / "a-linked-file")

    def test_only_read_only_version_commands_are_ever_requested(self):
        self.versions.stop()
        with patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 0, stdout=b"tool version\n", stderr=b"")) as run:
            result = self.invoke(["snapshot", "--metadata", str(self.meta), "--output", str(self.before)])
        self.assertEqual(result[0], 0)
        self.assertEqual([c.args[0] for c in run.call_args_list], [["cargo", "-V"], ["rustc", "-vV"]])

    def test_safe_publish_then_exact_four_shard_aggregate(self):
        root = self.proofs()
        output = self.base / "aggregate.json"
        code, stdout, stderr = self.invoke(["aggregate", "--root", str(root), "--output", str(output)])
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(json.loads(stdout)["native_completed_targets"], 7)
        self.assertEqual(json.loads(output.read_text())["completed_doc_receipts"], 8)
        proof = (self.base / "shard-0/scope-proof.json").read_text()
        self.assertNotIn(str(self.base), proof)
        self.assertNotIn("build_context", proof)
        self.assertNotIn("compiled_units", proof)

    def test_real_failed_receipt_is_safely_preserved_but_cannot_aggregate(self):
        self.proofs()
        directory = self.base / "shard-0"
        file = next(f for f in (directory / "runtime/native").glob("*.json")
                    if json.loads(f.read_text())["status"] == "completed")
        receipt = json.loads(file.read_text())
        receipt["exit_code"] = 1
        cli._atomic_json(file, receipt)
        proof = directory / "scope-proof.json"
        self.assertEqual(self.invoke(["publish", "--plan", str(directory / "private-plan.json"),
                                      "--output", str(proof)])[0], 0)
        safe = json.loads(proof.read_text())
        self.assertTrue(safe["export_complete"])
        self.assertTrue(any(r["exit_code"] == 1 for r in safe["native_receipts"]))
        self.assertEqual(self.invoke(["aggregate", "--root", str(self.base)])[0], 1)

    def test_partial_export_is_not_execution_credit(self):
        self.proofs()
        directory = self.base / "shard-0"
        file = next((directory / "runtime/docs").glob("*.json"))
        file.unlink()  # Only a fresh synthetic receipt under the verified D test root.
        self.assertEqual(self.invoke(["publish", "--plan", str(directory / "private-plan.json"),
                                      "--output", str(directory / "scope-proof.json")])[0], 0)
        self.assertEqual(self.invoke(["aggregate", "--root", str(self.base)])[0], 1)

    def test_adapter_failure_marker_cannot_be_hidden_by_successful_rustdoc_receipts(self):
        self.proofs()
        directory = self.base / "shard-0"
        marker = directory / "runtime/adapter-failed.json"
        marker.write_text(json.dumps({"private": str(self.base)}), encoding="utf-8")
        result = self.invoke(["publish", "--plan", str(directory / "private-plan.json"),
                              "--output", str(directory / "scope-proof.json")])
        self.assertEqual(result[0], 1)
        self.assertEqual(result[2], "native workspace scope: command failed\n")
        safe = (directory / "scope-proof.json").read_text()
        self.assertFalse(json.loads(safe)["export_complete"])
        self.assertNotIn(str(marker), safe + result[1] + result[2])
        self.assertNotIn(str(self.base), safe + result[1] + result[2])
        self.assertEqual(self.invoke(["aggregate", "--root", str(self.base)])[0], 1)

    def test_malformed_receipt_and_source_drift_fail_safe_without_private_text(self):
        self.proofs()
        directory = self.base / "shard-0"
        receipt = next((directory / "runtime/native").glob("*.json"))
        data = json.loads(receipt.read_text())
        data["private_diagnostic"] = str(self.base)
        cli._atomic_json(receipt, data)
        result = self.invoke(["publish", "--plan", str(directory / "private-plan.json"),
                              "--output", str(directory / "scope-proof.json")])
        self.assertEqual(result[0], 1)
        safe = (directory / "scope-proof.json").read_text()
        self.assertFalse(json.loads(safe)["export_complete"])
        self.assertNotIn(str(self.base), safe + result[1] + result[2])
        with patch.object(cli, "_source_snapshot", return_value="c" * 64):
            self.assertEqual(self.invoke(["publish", "--plan", str(self.private),
                                          "--output", str(directory / "scope-proof.json")])[0], 1)
        self.assertIsNone(json.loads((directory / "scope-proof.json").read_text())["plan"])

    def test_aggregate_requires_expected_refs_exact_four_files_and_export_complete(self):
        self.proofs()
        with patch.dict(os.environ, {"NATIVE_SOURCE_REFS": json.dumps({"cotest": "c" * 40})}):
            self.assertEqual(self.invoke(["aggregate", "--root", str(self.base)])[0], 1)
        file = self.base / "shard-0/scope-proof.json"
        original = file.read_bytes()
        data = json.loads(original)
        data["export_complete"] = False
        cli._atomic_json(file, data)
        self.assertEqual(self.invoke(["aggregate", "--root", str(self.base)])[0], 1)
        file.write_bytes(original)
        cli._atomic_json(self.base / "extra/scope-proof.json", json.loads(original))
        self.assertEqual(self.invoke(["aggregate", "--root", str(self.base)])[0], 1)


if __name__ == "__main__":
    unittest.main()
