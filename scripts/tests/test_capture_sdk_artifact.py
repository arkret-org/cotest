import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.capture_sdk_artifact import capture
from scripts.sdk_event_type_axes import check_artifact


class CaptureSdkArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.library = self.root / "target" / "debug" / "deps"
        self.library.mkdir(parents=True)
        self.sdk_manifest = self.root / "sdk" / "Cargo.toml"
        self.sdk_manifest.parent.mkdir()
        self.sdk_manifest.write_text('[package]\nname="arkret"\n', encoding="utf-8")
        self.profile = {"test": False, "debuginfo": 2, "opt_level": "0"}
        self.messages = []
        self.packages = []
        self.nodes = []
        for name in ("arkret", "chrono", "serde", "serde_json", "ed25519_dalek", "unrelated"):
            package_id = name + "@3.0.0"
            path = self.library / f"lib{name}-current.rlib"
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
        (self.library / "libarkret-current.rlib").write_bytes(b"changed after capture")
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
        path = self.library / "libserde-other.rlib"
        path.write_bytes(b"ambiguous")
        duplicate["filenames"] = [str(path)]
        self.messages.insert(-1, duplicate)
        with self.assertRaisesRegex(ValueError, "same-build serde"):
            self.run_capture()

    def unit(self, artifact, value, dependencies=()):
        path = Path(artifact["filenames"][0])
        target = artifact["target"]["name"]
        suffix = path.stem.removeprefix(f"lib{target}-")
        root = path.parent.parent / ".fingerprint" / f"{target}-{suffix}"
        root.mkdir(parents=True, exist_ok=True)
        (root / f"lib-{target}").write_text(value.to_bytes(8, "little").hex(), encoding="ascii")
        (root / f"lib-{target}.json").write_text(json.dumps({
            "features": json.dumps(artifact["features"]), "rustc": 1,
            "deps": [[0, name, False, fingerprint] for name, fingerprint in dependencies],
        }), encoding="utf-8")

    def test_selects_the_sdks_unit_instead_of_a_host_build_profile(self):
        duplicate = copy.deepcopy(self.messages[2])
        path = self.library / "libserde-host.rlib"
        path.write_bytes(b"host serde")
        duplicate["filenames"] = [str(path)]
        duplicate["profile"]["debuginfo"] = 0
        self.messages.insert(-1, duplicate)
        self.unit(self.messages[0], 100, [("serde", 200)])
        self.unit(self.messages[2], 200)
        self.unit(duplicate, 300)
        result = json.loads(self.run_capture().read_text())
        self.assertTrue(result["externs"]["serde"].endswith("libserde-current.rlib"))

    def test_resolves_equal_profiles_using_the_sdks_dependency_fingerprint(self):
        target = self.messages[1]
        target["features"] = ["serde"]
        host = copy.deepcopy(target)
        host["features"] = ["clock"]
        path = self.library / "libchrono-host.rlib"
        path.write_bytes(b"host chrono")
        host["filenames"] = [str(path)]
        self.messages.insert(1, host)
        self.unit(self.messages[0], 100, [("chrono", 200)])
        self.unit(target, 200)
        self.unit(host, 300)
        result = json.loads(self.run_capture().read_text())
        self.assertTrue(result["externs"]["chrono"].endswith("libchrono-current.rlib"))
        self.assertEqual(result["cargo_unit_selection"]["chrono"]["dependency_fingerprint"], f"{200:016x}")

    def test_package_profile_override_does_not_select_the_host_unit(self):
        target = self.messages[2]
        host = copy.deepcopy(target)
        target["profile"]["opt_level"] = "3"
        path = self.library / "libserde-host.rlib"
        path.write_bytes(b"host serde")
        host["filenames"] = [str(path)]
        self.messages.insert(-1, host)
        self.unit(self.messages[0], 100, [("serde", 200)])
        self.unit(target, 200)
        self.unit(host, 300)
        result = json.loads(self.run_capture().read_text())
        self.assertTrue(result["externs"]["serde"].endswith("libserde-current.rlib"))

    def test_rejects_units_that_do_not_match_the_sdk_fingerprint(self):
        target = self.messages[1]
        other = copy.deepcopy(target)
        path = self.library / "libchrono-other.rlib"
        path.write_bytes(b"other chrono")
        other["filenames"] = [str(path)]
        self.messages.insert(-1, other)
        self.unit(self.messages[0], 100, [("chrono", 999)])
        self.unit(target, 200)
        self.unit(other, 300)
        with self.assertRaisesRegex(ValueError, "same-build chrono"):
            self.run_capture()

    def test_selects_the_sdks_actual_dalek_dependency(self):
        older = copy.deepcopy(self.messages[4])
        older["package_id"] = "ed25519_dalek@2.0.0"
        path = self.library / "libed25519_dalek-old.rlib"
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


class RealCargoUnitTests(unittest.TestCase):
    def test_sealed_externs_preserve_the_sdks_runtime_type_identity(self):
        # Resolver 3 builds the same package twice when host/runtime features
        # differ, even when both compiler messages report identical profiles.
        with tempfile.TemporaryDirectory(prefix="cotest-capture-") as temporary:
            root = Path(temporary)

            def crate(name, manifest, source, build=None):
                folder = root / name
                (folder / "src").mkdir(parents=True)
                (folder / "Cargo.toml").write_text(manifest, encoding="utf-8")
                (folder / "src" / "lib.rs").write_text(source, encoding="utf-8")
                if build is not None:
                    (folder / "build.rs").write_text(build, encoding="utf-8")
                return folder / "Cargo.toml"

            for name in ("serde", "serde_json", "ed25519-dalek"):
                crate(name, f'[package]\nname="{name}"\nversion="0.1.0"\nedition="2021"\n',
                      "pub fn id() -> u8 { 0 }\n")
            crate("chrono", '[package]\nname="chrono"\nversion="0.1.0"\nedition="2021"\n'
                  '[features]\nruntime-role=[]\nhost-role=[]\n',
                  'pub struct Stamp { pub value: u8 }\n'
                  'pub fn stamp() -> Stamp { Stamp { value: if cfg!(feature="runtime-role") { 42 } else { 7 } } }\n')
            sdk = crate("sdk", '[package]\nname="arkret"\nversion="0.1.0"\nedition="2021"\n'
                        '[features]\nclient=[]\nmls=[]\nsigner=[]\n'
                        '[dependencies]\nchrono={path="../chrono",features=["runtime-role"]}\n'
                        'serde={path="../serde"}\nserde_json={path="../serde_json"}\n'
                        'ed25519-dalek={path="../ed25519-dalek"}\n'
                        '[build-dependencies]\nchrono={path="../chrono",features=["host-role"]}\n',
                        'pub fn stamp() -> chrono::Stamp {\n'
                        ' assert_eq!(serde::id()+serde_json::id()+ed25519_dalek::id(),0);\n'
                        ' chrono::stamp()\n}\n',
                        'fn main() { assert_eq!(chrono::stamp().value,7); }\n')
            manifest = crate("consumer", '[package]\nname="consumer"\nversion="0.1.0"\nedition="2021"\n'
                             '[workspace]\nresolver="3"\n'
                             '[dependencies]\narkret={path="../sdk",features=["client","mls","signer"]}\n'
                             '[profile.dev]\ndebug=0\nopt-level=0\ndebug-assertions=true\noverflow-checks=true\n'
                             '[profile.dev.build-override]\ndebug=0\nopt-level=0\ndebug-assertions=true\noverflow-checks=true\n',
                             'pub fn stamp() -> u8 { arkret::stamp().value }\n')
            env = os.environ.copy()
            env.update(CARGO_TARGET_DIR=str(root / "target"), CARGO_BUILD_JOBS="1", CARGO_INCREMENTAL="0")
            # Keep a product workspace's build overrides out of this tiny,
            # offline compiler fixture; these are not SDK/application profiles.
            for name in list(env):
                if name.startswith("CARGO_PROFILE_"):
                    env.pop(name)

            def run(command, success=True):
                result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, encoding="utf-8")
                if success:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                return result

            metadata = root / "metadata.json"
            metadata.write_text(run(["cargo", "metadata", "--manifest-path", str(manifest), "--format-version", "1", "--offline"]).stdout, encoding="utf-8")
            build = run(["cargo", "build", "--manifest-path", str(manifest), "--message-format=json", "--offline"])
            messages = root / "messages.jsonl"
            messages.write_text(build.stdout, encoding="utf-8")
            units = [json.loads(line) for line in build.stdout.splitlines()]
            chronos = [item for item in units if item.get("reason") == "compiler-artifact" and item["target"]["name"] == "chrono"]
            self.assertEqual(len(chronos), 2)
            self.assertEqual(chronos[0]["profile"], chronos[1]["profile"])
            self.assertNotEqual(chronos[0]["features"], chronos[1]["features"])
            sealed = json.loads(capture(messages, metadata, sdk, root / "sealed").read_text(encoding="utf-8"))
            self.assertIn("chrono", sealed["cargo_unit_selection"])
            check_artifact(sealed)
            probe = root / "probe.rs"
            probe.write_text('fn main() { let value: chrono::Stamp = arkret::stamp(); '
                             'assert_eq!(value.value,42); assert_eq!(chrono::stamp().value,42); }\n', encoding="utf-8")
            executable = root / ("probe.exe" if sys.platform == "win32" else "probe")
            command = ["rustc", "--edition=2021", str(probe), "-o", str(executable), "-L", f'dependency={sealed["dependency_search"][0]}']
            for name, path in sealed["externs"].items():
                command += ["--extern", f"{name}={path}"]
            run(command)
            run([str(executable)])
            host = next(item for item in chronos if item["features"] == ["host-role"])
            host_library = next(path for path in host["filenames"] if path.endswith(".rlib"))
            wrong = [f"chrono={host_library}" if value.startswith("chrono=") else value for value in command]
            self.assertIn("mismatched types", run(wrong, success=False).stderr)


if __name__ == "__main__":
    unittest.main()
