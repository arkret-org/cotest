import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.capture_sdk_artifact import capture
from scripts.sdk_event_type_axes import check_artifact


class CaptureSdkArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sdk_manifest = self.root / "sdk" / "Cargo.toml"
        self.sdk_manifest.parent.mkdir()
        self.sdk_manifest.write_text('[package]\nname="arkret"\n', encoding="utf-8")
        self.profile = {"test": False, "debuginfo": 2, "opt_level": "0"}
        self.messages = []
        self.packages = []
        self.nodes = []
        for name in ("arkret", "chrono", "serde", "serde_json", "ed25519_dalek", "unrelated"):
            package_id = name + "@3.0.0"
            path = self.root / f"lib{name}-current.rlib"
            path.write_bytes(name.encode())
            manifest = self.sdk_manifest if name == "arkret" else self.root / name / "Cargo.toml"
            self.packages.append({"id": package_id, "name": name, "manifest_path": str(manifest)})
            self.nodes.append({"id": package_id, "deps": []})
            self.messages.append({"reason": "compiler-artifact", "package_id": package_id, "manifest_path": str(manifest), "features": ["client", "mls", "signer"] if name == "arkret" else [], "target": {"kind": ["lib"], "name": name}, "profile": self.profile.copy(), "filenames": [str(path)]})
        self.nodes[0]["deps"] = [{"name": name, "pkg": name + "@3.0.0"} for name in ("chrono", "serde", "serde_json", "ed25519_dalek")]
        self.messages.append({"reason": "build-finished", "success": True})

    def run_capture(self):
        messages = self.root / "messages.jsonl"
        metadata = self.root / "metadata.json"
        messages.write_text("\n".join(json.dumps(item) for item in self.messages), encoding="utf-8")
        metadata.write_text(json.dumps({"packages": self.packages, "resolve": {"nodes": self.nodes}}), encoding="utf-8")
        return capture(messages, metadata, self.sdk_manifest, self.root / "sealed")

    def test_seals_real_bytes_and_excludes_an_unrelated_build_product(self):
        manifest = json.loads(self.run_capture().read_text())
        self.assertEqual(set(manifest["externs"]), {"arkret", "chrono", "serde", "serde_json", "ed25519_dalek"})
        self.assertEqual(len(manifest["dependencies"]), 4)
        for item in [manifest["sdk"], *manifest["dependencies"]]:
            self.assertEqual(hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest(), item["sha256"])
        (self.root / "libarkret-current.rlib").write_bytes(b"changed after capture")
        self.assertEqual(Path(manifest["sdk"]["path"]).read_bytes(), b"arkret")

    def test_rejects_a_failed_build(self):
        self.messages[-1]["success"] = False
        with self.assertRaisesRegex(ValueError, "failed build"):
            self.run_capture()

    def test_rejects_missing_required_sdk_features(self):
        self.messages[0]["features"].remove("client")
        with self.assertRaisesRegex(ValueError, "required actual API feature"):
            self.run_capture()

    def test_rejects_a_missing_same_build_extern(self):
        self.messages = [item for item in self.messages if item.get("package_id") != "serde@3.0.0"]
        with self.assertRaisesRegex(ValueError, "same-build serde"):
            self.run_capture()

    def test_rejects_ambiguous_runtime_artifacts(self):
        duplicate = copy.deepcopy(self.messages[2])
        path = self.root / "libserde-other.rlib"
        path.write_bytes(b"ambiguous")
        duplicate["filenames"] = [str(path)]
        self.messages.insert(-1, duplicate)
        with self.assertRaisesRegex(ValueError, "same-build serde"):
            self.run_capture()

    def test_selects_the_runtime_profile_instead_of_a_host_build_profile(self):
        duplicate = copy.deepcopy(self.messages[2])
        path = self.root / "libserde-host.rlib"
        path.write_bytes(b"host serde")
        duplicate["filenames"] = [str(path)]
        duplicate["profile"]["debuginfo"] = 0
        self.messages.insert(-1, duplicate)
        result = json.loads(self.run_capture().read_text())
        self.assertTrue(result["externs"]["serde"].endswith("libserde-current.rlib"))

    def test_selects_the_sdks_actual_dalek_dependency(self):
        older = copy.deepcopy(self.messages[4])
        older["package_id"] = "ed25519_dalek@2.0.0"
        path = self.root / "libed25519_dalek-old.rlib"
        path.write_bytes(b"older generation")
        older["filenames"] = [str(path)]
        self.messages.insert(-1, older)
        self.nodes.append({"id": older["package_id"], "deps": []})
        result = json.loads(self.run_capture().read_text())
        self.assertTrue(result["externs"]["ed25519_dalek"].endswith("libed25519_dalek-current.rlib"))

    def native_input(self):
        directory = self.root / "native-source"
        directory.mkdir()
        (directory / "libpq.so").write_bytes(b"native link input")
        (directory / "libunrelated.so").write_bytes(b"not requested")
        self.messages.insert(-1, {"reason": "build-script-executed", "package_id": "unrelated@3.0.0", "linked_paths": [f"native={directory}"], "linked_libs": ["dylib=pq"]})
        return directory

    def test_seals_only_declared_native_inputs_in_the_sdk_graph(self):
        directory = self.native_input()
        self.nodes[0]["deps"].append({"name": "unrelated", "pkg": "unrelated@3.0.0"})
        result = json.loads(self.run_capture().read_text())
        self.assertEqual(len(result["native_search"]), 1)
        check_artifact(result)
        sealed = Path(result["native_search"][0])
        self.assertEqual([item.name for item in sealed.iterdir()], ["libpq.so"])
        (directory / "libpq.so").write_bytes(b"changed later")
        self.assertEqual((sealed / "libpq.so").read_bytes(), b"native link input")
        entry = next(item for item in result["dependencies"] if item["path"] == str(sealed / "libpq.so"))
        self.assertEqual(entry["sha256"], hashlib.sha256(b"native link input").hexdigest())

    def test_excludes_unrelated_native_search_paths(self):
        self.native_input()
        result = json.loads(self.run_capture().read_text())
        self.assertEqual(result["native_search"], [])

    def test_adapter_rejects_unsealed_native_search_paths(self):
        result = json.loads(self.run_capture().read_text())
        result["native_search"] = [str(self.root / "unsealed")]
        with self.assertRaisesRegex(ValueError, "native search path"):
            check_artifact(result)


if __name__ == "__main__":
    unittest.main()
