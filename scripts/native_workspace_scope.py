"""Pure planning and receipt validation for complete Cargo workspace test shards.

This module never invokes a tool or reads an executable. The caller supplies the
full metadata/no-run JSON stream and a file hash callback. A private plan gains
``shard_index`` at the caller; only ``public_plan`` output may be uploaded.
Receipts identify targets by ``target_identity_sha256`` and their local shard by
``shard_index``. Delegation is explicitly zero execution credit.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re


_TARGET_KEYS = {"kind", "crate_types", "name", "src_path", "edition", "doc",
                "doctest", "test", "required-features"}
_KINDS = {"lib", "bin", "test", "example", "bench", "custom-build", "proc-macro",
          "rlib", "dylib", "cdylib", "staticlib"}
_PUBLIC_KEYS = {"schema_version", "shard_count", "shard_index", "source_refs",
                "compiled_graph_sha256", "native_targets", "doctest_targets",
                "compile_only_examples"}
_PROVISION = {"agent_provision_production", "agent_vectors_production"}


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _sha(value, length=64):
    _require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value),
             "invalid SHA value")
    return value


def _integer(value, minimum=0):
    _require(type(value) is int and value >= minimum, "invalid integer")
    return value


def _absolute(value):
    _require(isinstance(value, str) and value and "\x00" not in value,
             "invalid absolute path")
    value = value.replace("\\", "/")
    _require(value.startswith("/") or re.match(r"^[A-Za-z]:/", value),
             "path must be absolute")
    # Normalization is lexical and deliberately does not touch a live tree.
    value = posixpath.normpath(value)
    if re.match(r"^[A-Za-z]:/", value):
        value = value[0].upper() + value[1:]
    return value


def _relative(path, root, *, inside=False):
    path, root = _absolute(path), _absolute(root)
    _require((re.match(r"^[A-Z]:", path) or [""])[0]
             == (re.match(r"^[A-Z]:", root) or [""])[0], "different path volumes")
    relative = posixpath.relpath(path, root)
    if inside:
        _require(relative != ".." and not relative.startswith("../"),
                 "path escapes required root")
    return relative


def _strings(value):
    _require(isinstance(value, list) and all(isinstance(x, str) and x for x in value)
             and len(value) == len(set(value)), "invalid or duplicate string list")
    return value


def _target(target):
    _require(isinstance(target, dict) and set(target) <= _TARGET_KEYS,
             "unreviewed Cargo target fields")
    _require(_TARGET_KEYS - {"required-features"} <= set(target), "incomplete Cargo target")
    kinds = _strings(target["kind"])
    _require(kinds and set(kinds) <= _KINDS, "unreviewed target kind")
    _strings(target["crate_types"])
    _strings(target.get("required-features", []))
    _require(all(type(target[k]) is bool for k in ("test", "doc", "doctest")),
             "invalid target flags")
    _require(isinstance(target["name"], str) and target["name"]
             and isinstance(target["edition"], str), "invalid target name/edition")
    return {**target, "src_path": _absolute(target["src_path"]),
            "required-features": target.get("required-features", [])}


def _profile(profile):
    # Preserve the complete Cargo profile, including future fields, in the
    # graph digest. Never select a subset which could hide a graph difference.
    _require(isinstance(profile, dict) and type(profile.get("test")) is bool,
             "invalid compiler test profile flag")
    _canonical(profile)
    return dict(profile)


def _refs(refs):
    _require(isinstance(refs, dict) and refs, "source_refs must be nonempty")
    for name, sha in refs.items():
        _require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.\-/]+", name),
                 "invalid source repository")
        _sha(sha, 40)
    return dict(sorted(refs.items()))


def create_plan(metadata: dict, messages: list[dict], shards: int,
                source_refs: dict, *, file_sha256, build_context=None) -> dict:
    """Bind every declared eligible target to a real completed no-run build.

    ``file_sha256(absolute_executable)`` must read/hash that real artifact and
    raise on an absent/unreadable/escaped file (including linked-directory
    escapes). No fallback executable or synthetic digest is permitted.
    """
    _integer(shards, 1)
    _require(build_context is None or isinstance(build_context, dict), "invalid build context")
    context = json.loads(_canonical(build_context or {}))
    root = _absolute(metadata["workspace_root"])
    target_dir = _absolute(metadata["target_directory"])
    members = _strings(metadata["workspace_members"])
    _require(members, "empty workspace")
    packages = {}
    for package in metadata["packages"]:
        _require(package["id"] not in packages, "duplicate package_id")
        packages[package["id"]] = package
    _require(set(members) <= set(packages), "incomplete workspace membership")
    all_targets, package_units = {}, {}
    native, docs, examples = [], [], []
    for package_id, package in packages.items():
        manifest = _absolute(package["manifest_path"])
        origin = package.get("source")
        _require(origin is None or isinstance(origin, str), "invalid package source")
        package_units[package_id] = {"name": package["name"], "version": package["version"],
                                     "source": origin}
        if origin is None:
            package_units[package_id]["manifest"] = _relative(manifest, root)
        seen = set()
        for raw_target in package["targets"]:
            target = _target(raw_target)
            key = (package_id, tuple(target["kind"]), target["name"], target["src_path"])
            _require(key not in all_targets, "duplicate package target")
            all_targets[key] = target
            if package_id not in members:
                continue
            _require(not target["required-features"], "required-features eligibility needs review")
            identity = {"package": package["name"], "version": package["version"],
                        "kind": target["kind"], "name": target["name"],
                        "source": _relative(target["src_path"], root, inside=True)}
            identity_sha = _digest(identity)
            _require(identity_sha not in seen, "duplicate target identity")
            seen.add(identity_sha)
            row = {"identity": identity, "identity_sha256": identity_sha, "package_id": package_id,
                   "package_manifest_dir": posixpath.dirname(manifest),
                   "src_path": target["src_path"]}
            if target["test"]:
                _require(target["kind"] in [["lib"], ["bin"], ["test"]],
                         "unreviewed executable target kind")
                assigned = int(identity_sha, 16) % shards
                if target["name"] in _PROVISION:
                    assigned = 0
                native.append({**row, "assigned_shard": assigned})
            if target["doctest"]:
                _require(target["kind"] == ["lib"], "unreviewed doctest kind")
                docs.append(dict(row))
            if target["kind"] == ["example"]:
                _require(not target["test"] and not target["doctest"],
                         "example scope requires review")
                examples.append(dict(row))
    _require(native, "no native test targets")
    _require(len({row["identity_sha256"] for row in native}) == len(native),
             "duplicate global target identity")
    _require(isinstance(messages, list) and messages, "empty build message stream")
    finished = [m for m in messages if m.get("reason") == "build-finished"]
    _require(len(finished) == 1 and finished[0].get("success") is True
             and messages[-1].get("reason") == "build-finished", "no unique successful complete build")
    units, artifacts = [], {}
    for message in messages:
        reason = message.get("reason")
        _require(reason in {"compiler-artifact", "compiler-message", "build-script-executed", "build-finished"},
                 "unreviewed build message reason")
        if reason != "compiler-artifact":
            continue
        package_id = message["package_id"]
        _require(package_id in packages, "artifact package_id not in metadata")
        target, profile = _target(message["target"]), _profile(message["profile"])
        key = (package_id, tuple(target["kind"]), target["name"], target["src_path"])
        _require(all_targets.get(key) == target, "artifact target differs from metadata")
        features = sorted(_strings(message["features"]))
        package = packages[package_id]
        canonical_target = {**target, "src_path": _relative(target["src_path"],
                            root if package.get("source") is None
                            else posixpath.dirname(_absolute(package["manifest_path"])))}
        unit = {"package": package_units[package_id], "target": canonical_target,
                "features": features, "profile": profile}
        units.append(unit)
        artifacts.setdefault(key, []).append(message)
    for rows, test_profile in [(native, True), (examples, False)]:
        for row in rows:
            identity = row["identity"]
            source = _absolute(posixpath.join(root, identity["source"]))
            key = (row["package_id"], tuple(identity["kind"]), identity["name"], source)
            candidates = [m for m in artifacts.get(key, []) if m["profile"]["test"] is test_profile]
            _require(len(candidates) == 1, "missing or duplicate eligible compiler artifact")
            executable = _absolute(candidates[0].get("executable"))
            _relative(executable, target_dir, inside=True)
            _require(executable != target_dir, "executable is target directory")
            row.update(executable=executable, executable_sha256=_sha(file_sha256(executable)))
    units.sort(key=_canonical)
    return {"schema_version": 1, "workspace_root": root, "target_directory": target_dir,
            "shard_count": shards, "source_refs": _refs(source_refs),
            "native_targets": sorted(native, key=lambda r: r["identity_sha256"]),
            "doctest_targets": sorted(docs, key=lambda r: r["identity_sha256"]),
            "compile_only_examples": sorted(examples, key=lambda r: r["identity_sha256"]),
            "compiled_units": units, "build_context": context,
            "compiled_graph_sha256": _digest({"units": units, "context": context})}


def _check_public(plan):
    _require(isinstance(plan, dict) and set(plan) == _PUBLIC_KEYS, "unexpected public plan fields")
    _require(type(plan["schema_version"]) is int and plan["schema_version"] == 1,
             "unknown plan schema")
    count = _integer(plan["shard_count"], 1)
    _require(_integer(plan["shard_index"]) < count, "shard index out of range")
    _refs(plan["source_refs"])
    _sha(plan["compiled_graph_sha256"])
    for key in ("native_targets", "doctest_targets", "compile_only_examples"):
        _require(isinstance(plan[key], list), "target collection must be a list")
        seen = set()
        for row in plan[key]:
            fields = {"identity_sha256", "assigned_shard", "executable_sha256"} if key == "native_targets" else {"identity_sha256"}
            _require(isinstance(row, dict) and set(row) == fields, "unexpected public target fields")
            identity = _sha(row["identity_sha256"])
            _require(identity not in seen, "duplicate declared identity")
            seen.add(identity)
            if key == "native_targets":
                _require(_integer(row["assigned_shard"]) < count, "assigned shard out of range")
                _sha(row["executable_sha256"])
    _require(plan["native_targets"], "empty declared native scope")


def public_plan(plan: dict) -> dict:
    """Return only the reviewed upload-safe fields, never absolute build paths."""
    _require(isinstance(plan["build_context"], dict), "invalid private build context")
    _require(_digest({"units": plan["compiled_units"], "context": plan["build_context"]})
             == plan["compiled_graph_sha256"],
             "compiled graph digest mismatch")
    result = {k: plan[k] for k in ("schema_version", "shard_count", "shard_index", "source_refs",
                                  "compiled_graph_sha256")}
    result["source_refs"] = _refs(result["source_refs"])
    for key in ("native_targets", "doctest_targets", "compile_only_examples"):
        rows = []
        for row in plan[key]:
            _require(_digest(row["identity"]) == row["identity_sha256"], "target identity digest mismatch")
            if key == "native_targets":
                assigned = (0 if row["identity"]["name"] in _PROVISION else
                            int(row["identity_sha256"], 16) % plan["shard_count"])
                _require(row["assigned_shard"] == assigned, "target assignment differs from stable identity hash")
            fields = ("identity_sha256", "assigned_shard", "executable_sha256") if key == "native_targets" else ("identity_sha256",)
            rows.append({k: row[k] for k in fields})
        result[key] = rows
    _check_public(result)
    return result


def validate_aggregate(plans: list, native_receipts: list, doc_receipts: list) -> dict:
    """Require complete disjoint native execution plus every shard's real docs.

    Returns target coverage counts only, never a fabricated test-case count.
    Input plans must use the public whitelist, not raw private build plans.
    """
    _require(isinstance(plans, list) and plans, "no shard plans")
    for plan in plans:
        _check_public(plan)
    count = plans[0]["shard_count"]
    _require(len(plans) == count and {p["shard_index"] for p in plans} == set(range(count)),
             "missing or duplicate shard plan")
    base = plans[0]
    def scope(plan, key):
        return sorted((r["identity_sha256"], r.get("assigned_shard")) for r in plan[key])
    for plan in plans:
        _require(plan["shard_count"] == count and plan["source_refs"] == base["source_refs"]
                 and plan["compiled_graph_sha256"] == base["compiled_graph_sha256"],
                 "shards do not share frozen sources and compiled graph")
        for key in ("native_targets", "doctest_targets", "compile_only_examples"):
            _require(scope(plan, key) == scope(base, key), "declared target sets/assignments differ")
    _require(isinstance(native_receipts, list) and isinstance(doc_receipts, list), "invalid receipts")
    native_seen, doc_seen = set(), set()
    by_shard = {p["shard_index"]: p for p in plans}
    for receipt in native_receipts:
        _require(isinstance(receipt, dict) and set(receipt) == {"shard_index", "target_identity_sha256", "status", "exit_code", "executable_sha256"},
                 "unexpected native receipt fields")
        shard = _integer(receipt["shard_index"])
        identity = _sha(receipt["target_identity_sha256"])
        key = (shard, identity)
        _require(shard in by_shard and key not in native_seen, "unknown shard/duplicate native receipt")
        native_seen.add(key)
        targets = {r["identity_sha256"]: r for r in by_shard[shard]["native_targets"]}
        _require(identity in targets, "unknown native target")
        row = targets[identity]
        if row["assigned_shard"] == shard:
            _require(receipt["status"] == "completed" and type(receipt["exit_code"]) is int
                     and receipt["exit_code"] == 0
                     and receipt["executable_sha256"] == row["executable_sha256"],
                     "assigned native target did not complete successfully with planned bytes")
        else:
            _require(receipt["status"] == "delegated" and receipt["exit_code"] is None
                     and receipt["executable_sha256"] is None, "delegation cannot claim execution credit")
    native_ids = {r["identity_sha256"] for r in base["native_targets"]}
    _require(native_seen == {(s, i) for s in range(count) for i in native_ids},
             "missing native execution/delegation receipts")
    doc_ids = {r["identity_sha256"] for r in base["doctest_targets"]}
    for receipt in doc_receipts:
        _require(isinstance(receipt, dict) and set(receipt) == {"shard_index", "target_identity_sha256", "status", "exit_code"},
                 "unexpected doc receipt fields")
        shard = _integer(receipt["shard_index"])
        identity = _sha(receipt["target_identity_sha256"])
        key = (shard, identity)
        _require(shard in by_shard and identity in doc_ids and key not in doc_seen,
                 "unknown/duplicate rustdoc receipt")
        _require(receipt["status"] == "completed" and type(receipt["exit_code"]) is int
                 and receipt["exit_code"] == 0, "rustdoc did not actually complete successfully")
        doc_seen.add(key)
    _require(doc_seen == {(s, i) for s in range(count) for i in doc_ids},
             "missing real rustdoc receipts")
    return {"shards": count, "native_targets": len(native_ids),
            "native_completed_targets": len(native_ids), "doctest_targets": len(doc_ids),
            "completed_doc_receipts": len(doc_seen),
            "compile_only_examples": len(base["compile_only_examples"])}
