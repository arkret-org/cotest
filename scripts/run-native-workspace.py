#!/usr/bin/env python3
"""Plan/export/aggregate complete workspace scope; never builds or runs tests."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


_LOCAL = Path(__file__).resolve().parent
_MODULES = {}
_NATIVE_KEYS = {"shard_index", "target_identity_sha256", "status", "exit_code", "executable_sha256"}
_DOC_KEYS = _NATIVE_KEYS - {"executable_sha256"}


def _require(ok):
    if not ok:
        raise ValueError("invalid workspace scope input")


def _module(name):
    if name not in _MODULES:
        spec = importlib.util.spec_from_file_location(name, _LOCAL / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        _MODULES[name] = module
    return _MODULES[name]


def _json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_encode(value)).hexdigest()


def _sha(value, length=64):
    _require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value))
    return value


def _source_refs(environment_name):
    refs = json.loads(os.environ[environment_name])
    _require(isinstance(refs, dict) and refs)
    for name, sha in refs.items():
        _require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.\-/]+", name))
        _sha(sha, 40)
    return dict(sorted(refs.items()))


def _atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".",
                                         suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(_encode(data) + b"\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _source_snapshot(root, refs):
    return _sha(_module("native_workspace_execution").source_snapshot(root, refs))


def _version_hash(command, root):
    # Read-only tool identity, never a Cargo build/test/metadata invocation.
    result = subprocess.run(command, cwd=root, check=True, capture_output=True, timeout=30)
    _require(result.stdout.strip())
    return hashlib.sha256(result.stdout.replace(b"\r\n", b"\n").strip()).hexdigest()


def _cargo_config_hash(root):
    configurations = {}
    for depth, directory in enumerate((root, *root.parents)):
        for name in ("config.toml", "config"):
            path = directory / ".cargo" / name
            if path.is_file():
                configurations[f"ancestor-{depth}/{name}"] = hashlib.sha256(path.read_bytes()).hexdigest()
    home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    if not home.is_absolute():
        home = root / home
    for name in ("config.toml", "config"):
        path = home / name
        if path.is_file():
            configurations[f"cargo-home/{name}"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return _digest(configurations)


def _build_context(root, refs):
    exact = {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS",
             "RUSTC", "RUSTDOC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP",
             "CARGO_BUILD_TARGET", "CARGO_BUILD_RUSTFLAGS", "CARGO_INCREMENTAL"}
    environment = {k: v for k, v in os.environ.items()
                   if k in exact or k.startswith(("CARGO_PROFILE_", "CARGO_TARGET_", "CARGO_BUILD_"))}
    return {"schema_version": 1, "source_snapshot_sha256": _source_snapshot(root, refs),
            "cargo_version_sha256": _version_hash(["cargo", "-V"], root),
            "rustc_version_sha256": _version_hash(["rustc", "-vV"], root),
            "compile_environment_sha256": _digest(environment),
            "cargo_config_sha256": _cargo_config_hash(root)}


def _metadata(path):
    metadata = _json(path)
    root = Path(metadata["workspace_root"])
    _require(root.is_absolute() and root.is_dir())
    return metadata, root.resolve(strict=True)


def snapshot(args):
    _, root = _metadata(args.metadata)
    refs = _source_refs(args.sources_json_env)
    context = _build_context(root, refs)
    _atomic_json(args.output, {"schema_version": 1, "workspace_root": str(root),
                              "source_refs": refs, "build_context": context})


def _messages(path):
    text = Path(path).read_text(encoding="utf-8-sig")
    result = (json.loads(text) if text.lstrip().startswith("[") else
              [json.loads(line) for line in text.splitlines() if line.strip()])
    _require(isinstance(result, list) and all(isinstance(m, dict) for m in result))
    return result


def _executable_hasher(directory):
    directory = Path(directory).resolve(strict=True)
    _require(directory.is_dir())
    def file_sha256(path):
        path = Path(path).resolve(strict=True)
        path.relative_to(directory)  # Reject real linked-directory escapes.
        _require(path.is_file())
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    return file_sha256


def plan(args):
    metadata, root = _metadata(args.metadata)
    before = _json(args.before_context)
    refs = _source_refs(args.sources_json_env)
    _require(set(before) == {"schema_version", "workspace_root", "source_refs", "build_context"}
             and before["schema_version"] == 1 and before["workspace_root"] == str(root)
             and before["source_refs"] == refs)
    context = _build_context(root, refs)
    _require(context == before["build_context"])
    result = _module("native_workspace_scope").create_plan(
        metadata, _messages(args.messages), args.shards, refs,
        file_sha256=_executable_hasher(metadata["target_directory"]), build_context=context)
    _require(0 <= args.shard_index < args.shards)
    result["shard_index"] = args.shard_index
    # Reuse the strict schema validator before writing a usable private plan.
    _module("native_workspace_scope").public_plan(result)
    output = Path(args.output).absolute()
    _require(not any(c in str(output) for c in "\r\n\x00"))
    _atomic_json(output, result)
    if args.github_env_file:
        with Path(args.github_env_file).open("a", encoding="utf-8", newline="\n") as stream:
            stream.write("COTEST_NATIVE_WORKSPACE_PLAN=" + str(output) + "\n")


def _receipt(row, *, doc):
    _require(isinstance(row, dict) and set(row) == (_DOC_KEYS if doc else _NATIVE_KEYS))
    _require(type(row["shard_index"]) is int and row["shard_index"] >= 0)
    _sha(row["target_identity_sha256"])
    _require(row["status"] in {"started", "completed", "launch_failed", "delegated"})
    _require(row["exit_code"] is None or type(row["exit_code"]) is int)
    if not doc:
        _require(row["executable_sha256"] is None
                 or _sha(row["executable_sha256"]))
    # No arbitrary diagnostics, paths or raw process output enter the proof.
    return dict(row)


def _read_receipts(directory, *, doc):
    directory = Path(directory)
    if not directory.exists():
        return []
    _require(directory.is_dir())
    root = directory.resolve(strict=True)
    result = []
    for path in sorted(directory.glob("*.json")):
        path.resolve(strict=True).relative_to(root)
        result.append(_receipt(_json(path), doc=doc))
    return result


def publish(args):
    proof = {"export_complete": False, "plan": None, "native_receipts": [], "doc_receipts": []}
    try:
        private_path = Path(args.plan)
        private = _json(private_path)
        public = _module("native_workspace_scope").public_plan(private)
        _require(_source_snapshot(Path(private["workspace_root"]), public["source_refs"])
                 == private["build_context"]["source_snapshot_sha256"])
        proof["plan"] = public
        runtime = private_path.parent / "runtime"
        proof["native_receipts"] = _read_receipts(runtime / "native", doc=False)
        proof["doc_receipts"] = _read_receipts(runtime / "docs", doc=True)
        # This certifies safe export only. Missing/started/failed receipts do
        # not gain execution credit: the mandatory aggregate rejects them.
        proof["export_complete"] = True
    except Exception:
        _atomic_json(args.output, proof)
        raise
    _atomic_json(args.output, proof)


def aggregate(args):
    refs = _source_refs(args.expected_sources_json_env)
    root = Path(args.root).resolve(strict=True)
    _require(root.is_dir())
    files = sorted(root.rglob("scope-proof.json"))
    _require(len(files) == 4)
    plans, native, docs = [], [], []
    for path in files:
        path.resolve(strict=True).relative_to(root)
        proof = _json(path)
        _require(set(proof) == {"export_complete", "plan", "native_receipts", "doc_receipts"}
                 and proof["export_complete"] is True)
        _require(proof["plan"]["source_refs"] == refs)
        plans.append(proof["plan"])
        native.extend(proof["native_receipts"])
        docs.extend(proof["doc_receipts"])
    result = _module("native_workspace_scope").validate_aggregate(plans, native, docs)
    if args.output:
        _atomic_json(args.output, result)
    print(json.dumps(result, sort_keys=True))


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, action in (("snapshot", snapshot), ("plan", plan)):
        sub = commands.add_parser(name)
        sub.add_argument("--metadata", required=True)
        sub.add_argument("--sources-json-env", default="NATIVE_SOURCE_REFS")
        sub.add_argument("--output", required=True)
        sub.set_defaults(action=action)
        if name == "plan":
            sub.add_argument("--messages", required=True)
            sub.add_argument("--before-context", required=True)
            sub.add_argument("--shards", type=int, choices=[4], default=4)
            sub.add_argument("--shard-index", required=True, type=int)
            sub.add_argument("--github-env-file")
    sub = commands.add_parser("publish")
    sub.add_argument("--plan", required=True)
    sub.add_argument("--output", required=True)
    sub.set_defaults(action=publish)
    sub = commands.add_parser("aggregate")
    sub.add_argument("--root", required=True)
    sub.add_argument("--expected-sources-json-env", default="NATIVE_SOURCE_REFS")
    sub.add_argument("--output")
    sub.set_defaults(action=aggregate)
    args = parser.parse_args(arguments)
    try:
        args.action(args)
    except Exception:
        # Exception messages can contain paths, source config or tool stderr.
        print("native workspace scope: command failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
