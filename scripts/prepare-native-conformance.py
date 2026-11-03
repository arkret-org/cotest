"""Prepare exact native-suite artifacts before Cargo holds the test workspace lock."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def capture(command, output):
    with output.open("w", encoding="utf-8") as stream:
        subprocess.run(command, check=True, stdout=stream)


def prepare(repo, output, *, sdk, binding):
    repo = repo.resolve()
    output.mkdir(parents=True, exist_ok=True)
    environment = {}
    if sdk and not os.environ.get("COTEST_SDK_ARTIFACT_MANIFEST"):
        metadata = output / "sdk-metadata.json"
        messages = output / "sdk-build.jsonl"
        # Capture the same package graph used by the suite. SDK023 itself must
        # only consume these sealed artifacts, never build a replacement SDK.
        capture(["cargo", "metadata", "--manifest-path", str(repo / "Cargo.toml"),
                 "--locked", "--format-version", "1"], metadata)
        capture(["cargo", "build", "--manifest-path", str(repo / "Cargo.toml"),
                 "--locked", "-p", "cotest", "-p", "cotest-inkson-client-tests", "--lib",
                 "--message-format=json-render-diagnostics"], messages)
        from capture_sdk_artifact import capture as seal
        sealed = output / "sdk-artifact"
        seal(messages, metadata, repo.parent / "arkret-rust-sdk/crates/sdk/Cargo.toml", sealed)
        environment["COTEST_SDK_ARTIFACT_MANIFEST"] = str(sealed / "artifact.json")
    if binding and not os.environ.get("COTEST_SAVFOX_BINDING_WORKER"):
        manifest = repo.parent.parent / "savfox-ai/savfox/Cargo.toml"
        metadata = output / "binding-metadata.json"
        messages = output / "binding-build.jsonl"
        capture(["cargo", "metadata", "--manifest-path", str(manifest), "--locked",
                 "--no-deps", "--format-version", "1"], metadata)
        capture(["cargo", "build", "--manifest-path", str(manifest), "--locked",
                 "-p", "savfox-channels", "--no-default-features", "--features", "arkret",
                 "--example", "arkret_binding_worker",
                 "--message-format=json-render-diagnostics"], messages)
        target = Path(json.loads(metadata.read_text())["target_directory"]).resolve()
        artifacts = [json.loads(line) for line in messages.read_text().splitlines() if line.startswith("{")]
        workers = {item["executable"] for item in artifacts
                   if item.get("reason") == "compiler-artifact"
                   and item["target"]["name"] == "arkret_binding_worker"
                   and "example" in item["target"]["kind"] and item.get("executable")}
        if len(workers) != 1:
            raise ValueError("expected exactly one actual native binding worker")
        worker = Path(workers.pop()).resolve()
        if not worker.is_relative_to(target) or not worker.is_file():
            raise ValueError("binding worker is absent or outside its Cargo target directory")
        environment["COTEST_SAVFOX_BINDING_WORKER"] = str(worker)
    for name in ("COTEST_SDK_ARTIFACT_MANIFEST", "COTEST_SAVFOX_BINDING_WORKER"):
        value = environment.get(name, os.environ.get(name))
        if value and not Path(value).is_file():
            raise ValueError(f"{name} must name an existing artifact")
    (output / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sdk", action="store_true")
    parser.add_argument("--binding", action="store_true")
    args = parser.parse_args()
    prepare(args.repo, args.output, sdk=args.sdk, binding=args.binding)


if __name__ == "__main__":
    main()
