"""Seal the SDK and its same-build dependencies from Cargo's JSON output.

This command consumes a successful build; it never invokes Cargo or rebuilds
the SDK. The SDK023 adapter receives copied artifact bytes and explicit externs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


REQUIRED_FEATURES = {"client", "mls", "signer"}
EXTERNS = ("chrono", "serde", "serde_json", "ed25519_dalek")


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def single(values, description):
    if len(values) != 1:
        raise ValueError(f"expected one {description}, found {len(values)}")
    return values[0]


def capture(messages_path, metadata_path, sdk_manifest, output):
    messages = [json.loads(line) for line in Path(messages_path).read_text(encoding="utf-8").splitlines() if line.startswith("{")]
    finished = [item for item in messages if item.get("reason") == "build-finished"]
    if single(finished, "completed Cargo build").get("success") is not True:
        raise ValueError("cannot capture artifacts from a failed build")
    metadata = json.loads(Path(metadata_path).read_text(encoding="utf-8"))
    package = single([item for item in metadata["packages"] if item["name"] == "arkret" and Path(item["manifest_path"]).resolve() == Path(sdk_manifest).resolve()], "SDK package")
    nodes = {item["id"]: item for item in metadata["resolve"]["nodes"]}
    artifacts = {}
    for item in messages:
        if item.get("reason") != "compiler-artifact":
            continue
        for filename in item["filenames"]:
            path = Path(filename).resolve()
            if path.suffix != ".rlib" and not ("proc-macro" in item["target"]["kind"] and path.suffix in {".dll", ".so", ".dylib"}):
                continue
            if path in artifacts:
                previous = artifacts[path]
                if any(previous.get(key) != item.get(key) for key in ("package_id", "features", "profile", "manifest_path")):
                    raise ValueError(f"conflicting Cargo artifacts: {path}")
            artifacts[path] = item

    def library(package_id, name, profile=None):
        choices = [(path, item) for path, item in artifacts.items() if item["package_id"] == package_id and item["target"]["name"] == name and path.suffix == ".rlib" and not item["profile"]["test"]]
        if len(choices) > 1 and profile is not None:
            choices = [(path, item) for path, item in choices if item["profile"] == profile]
        return single(choices, f"same-build {name} library")

    sdk_path, sdk = library(package["id"], "arkret")
    if Path(sdk["manifest_path"]).resolve() != Path(sdk_manifest).resolve():
        raise ValueError("SDK artifact and metadata name different manifests")
    if not REQUIRED_FEATURES.issubset(sdk["features"]):
        raise ValueError("SDK artifact omits a required actual API feature")
    externs = {"arkret": sdk_path}
    for name in EXTERNS:
        dependency = single([item["pkg"] for item in nodes[package["id"]]["deps"] if item["name"] == name], f"SDK {name} dependency")
        externs[name] = library(dependency, name, sdk["profile"])[0]

    reachable = set()
    pending = [package["id"]]
    while pending:
        current = pending.pop()
        if current not in reachable:
            reachable.add(current)
            pending.extend(item["pkg"] for item in nodes[current]["deps"])
    inputs = {path for path, item in artifacts.items() if item["package_id"] in reachable}
    if not set(externs.values()).issubset(inputs):
        raise ValueError("extern inventory leaves the same-build SDK dependency graph")

    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    directory = output / "deps"
    directory.mkdir()
    sealed = {}
    inventory = []
    for source in sorted(inputs):
        target = directory / source.name
        expected = digest(source)
        if target.exists():
            if digest(target) != expected:
                raise ValueError(f"artifact filename collision: {source.name}")
        else:
            shutil.copyfile(source, target)
        if digest(target) != expected or digest(source) != expected:
            raise ValueError(f"artifact changed during capture: {source}")
        sealed[source] = target
        inventory.append({"path": str(target), "sha256": expected})
    sdk_item = next(item for item in inventory if item["path"] == str(sealed[sdk_path]))
    sdk_item.update(features=sdk["features"], package_id=package["id"])
    native_search = []
    for item in messages:
        if item.get("reason") != "build-script-executed" or item["package_id"] not in reachable:
            continue
        for raw in item.get("linked_paths", []):
            kind, separator, path = raw.partition("=")
            if separator and kind not in {"native", "all"}:
                continue
            source_directory = Path(path if separator else raw)
            selected = set()
            for library_name in item.get("linked_libs", []):
                kind, separator, name = library_name.partition("=")
                if not separator:
                    kind, name = "dylib", library_name
                kind = kind.split(":", 1)[0]
                if kind == "framework":
                    continue
                names = [f"{name}.lib"]
                if kind == "static":
                    names += [f"lib{name}.a", f"{name}.a"]
                else:
                    names += [f"lib{name}.so", f"{name}.so", f"lib{name}.dylib", f"{name}.dylib", f"{name}.dll"]
                selected.update(source_directory / filename for filename in names if (source_directory / filename).is_file())
            if not selected:
                continue
            target_directory = output / "native" / str(len(native_search))
            target_directory.mkdir(parents=True)
            native_search.append(str(target_directory))
            for source in sorted(selected):
                target = target_directory / source.name
                expected = digest(source)
                shutil.copyfile(source, target)
                if digest(target) != expected or digest(source) != expected:
                    raise ValueError(f"native artifact changed during capture: {source}")
                inventory.append({"path": str(target), "sha256": expected})
    result = {
        "sdk": sdk_item,
        "dependencies": [item for item in inventory if item is not sdk_item],
        "externs": {name: str(sealed[path]) for name, path in externs.items()},
        "dependency_search": [str(directory)],
        "native_search": native_search,
        "cargo_messages_sha256": digest(messages_path),
        "cargo_metadata_sha256": digest(metadata_path),
    }
    manifest = output / "artifact.json"
    manifest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo-messages", required=True)
    parser.add_argument("--cargo-metadata", required=True)
    parser.add_argument("--sdk-manifest", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    print(capture(args.cargo_messages, args.cargo_metadata, args.sdk_manifest, args.output))


if __name__ == "__main__":
    main()
