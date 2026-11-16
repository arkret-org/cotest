"""Reject forged owned-host build provenance; these are component checks only."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_native_operation_contracts as gate


class ManagedAppletHostProductGates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Retain the actual complete tracked/nonignored source set once. Each
        # mutation below tests its structural gate, not a native executable.
        cls.current_sources = gate.source_fence()

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="cotest-host-product-component-")
        self.addCleanup(self.scratch.cleanup)
        target_directory = Path(self.scratch.name).resolve()
        executable = target_directory / "debug" / (
            "native_applet_host_worker" + (".exe" if os.name == "nt" else ""))
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"component fixture; never executed or credited as native")
        sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
        target = {"kind": ["bin"], "crate_types": ["bin"], "name": gate.APPLET_HOST_TARGET,
                  "src_path": str(gate.REPO / "src/bin/native_applet_host_worker.rs"),
                  "edition": "2024", "doctest": False, "test": False}
        self.product = {"role": gate.APPLET_HOST_ROLE, "producer_result": "worker-result.json",
                        "executable": str(executable), "sha256": sha256}
        self.producer = {"role": gate.APPLET_HOST_ROLE, "exit_code": 0, "sources_unchanged": True,
                         "command": ["cargo", "build", "--locked", "--bin", gate.APPLET_HOST_TARGET,
                                     "--message-format=json-render-diagnostics"],
                         "compiler_target": target, "executable": str(executable), "sha256": sha256,
                         "target_directory": str(target_directory)}
        self.metadata = {"target_directory": str(target_directory),
                         "packages": [{"name": "cotest", "targets": [target]}]}
        self.artifact = {"reason": "compiler-artifact", "target": target,
                         "executable": str(executable), "profile": {"test": False}}
        self.inputs = copy.deepcopy(self.current_sources)
        self.execution_sources = copy.deepcopy(self.current_sources)

    def verify(self, log=None):
        cargo_log = log if log is not None else (
            json.dumps(self.artifact) + "\n" + json.dumps({"reason": "build-finished", "success": True}))
        with patch.object(gate, "source_fence", return_value=self.current_sources):
            gate.verify_managed_applet_host_product(self.product, self.producer, self.inputs,
                                                    self.execution_sources, self.metadata, cargo_log)

    def test_matching_component_records_are_structurally_accepted_without_native_credit(self):
        self.verify()

    def test_worker_carrier_cannot_reenter_the_integration_test_or_raw_main_suite(self):
        manifest = tomllib.loads((gate.REPO / "Cargo.toml").read_text(encoding="utf-8"))
        matches = [target for target in manifest.get("bin", []) if target["name"] == gate.APPLET_HOST_TARGET]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["path"], "src/bin/native_applet_host_worker.rs")
        self.assertIs(matches[0]["test"], False)
        self.assertIs(matches[0]["bench"], False)
        self.assertTrue(matches[0].get("harness", True))
        self.assertFalse(any(target["name"] == gate.APPLET_HOST_TARGET for target in manifest.get("test", [])))

    def test_libtest_binary_cannot_replace_the_real_worker_main(self):
        changed = copy.deepcopy(self.artifact)
        changed["profile"]["test"] = True
        with self.assertRaisesRegex(ValueError, "test harness instead of its real main"):
            self.verify(json.dumps(changed) + "\n" + json.dumps({"reason": "build-finished", "success": True}))

    def test_single_or_both_source_records_omitting_cotest_are_rejected(self):
        path = "cotest/src/scenarios/_helpers/managed_applet_host.rs"
        self.inputs.pop(path)
        with self.assertRaisesRegex(ValueError, "old or incomplete"):
            self.verify()
        self.execution_sources.pop(path)
        with self.assertRaisesRegex(ValueError, "old or incomplete"):
            self.verify()

    def test_matching_but_stale_cotest_sources_are_rejected(self):
        path = "cotest/src/bin/native_applet_host_worker.rs"
        self.inputs[path] = self.execution_sources[path] = "0" * 64
        with self.assertRaisesRegex(ValueError, "old or incomplete"):
            self.verify()

    def test_missing_bridge_or_sdk_source_is_rejected(self):
        for prefix in ("bridges/", "arkret-rust-sdk/"):
            with self.subTest(prefix=prefix):
                self.inputs = {name: digest for name, digest in self.current_sources.items()
                               if not name.startswith(prefix)}
                self.execution_sources = copy.deepcopy(self.inputs)
                with self.assertRaisesRegex(ValueError, "old or incomplete"):
                    self.verify()

    def test_copied_matching_bytes_cannot_replace_the_reported_cargo_artifact(self):
        original = Path(self.product["executable"])
        alternate = original.parent / "copied" / original.name
        alternate.parent.mkdir()
        alternate.write_bytes(original.read_bytes())
        self.product["executable"] = self.producer["executable"] = str(alternate)
        with self.assertRaisesRegex(ValueError, "actual Cargo compiler artifact"):
            self.verify()

    def test_changed_executable_contents_are_rejected(self):
        Path(self.product["executable"]).write_bytes(b"changed component bytes")
        with self.assertRaisesRegex(ValueError, "exact native Cargo artifact"):
            self.verify()

    def test_wrong_role_worker_target_or_metadata_is_rejected(self):
        self.product["role"] = "coland"
        with self.assertRaisesRegex(ValueError, "another role"):
            self.verify()
        self.product["role"] = gate.APPLET_HOST_ROLE
        self.producer["command"][4] = "native_operation_contracts"
        with self.assertRaisesRegex(ValueError, "exact Cargo binary target"):
            self.verify()
        self.producer["command"][4] = gate.APPLET_HOST_TARGET
        changed = copy.deepcopy(self.artifact)
        changed["target"]["name"] = "native_operation_contracts"
        with self.assertRaisesRegex(ValueError, "exactly one successfully built"):
            self.verify(json.dumps(changed) + "\n" + json.dumps({"reason": "build-finished", "success": True}))
        self.metadata["packages"][0]["targets"] = []
        with self.assertRaisesRegex(ValueError, "actual Cargo metadata"):
            self.verify()

    def test_duplicate_missing_or_failed_build_records_are_rejected(self):
        artifact = json.dumps(self.artifact)
        complete = json.dumps({"reason": "build-finished", "success": True})
        for log in (artifact, artifact + "\n" + artifact + "\n" + complete,
                    artifact + "\n" + json.dumps({"reason": "build-finished", "success": False})):
            with self.subTest(log=log), self.assertRaisesRegex(ValueError, "exactly one successfully built"):
                self.verify(log)


if __name__ == "__main__":
    unittest.main()
