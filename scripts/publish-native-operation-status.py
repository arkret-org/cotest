#!/usr/bin/env python3
"""Export fixed-field diagnostics, never raw native authority proof or logs.

This does not replace the native execution, schema audit or coverage gates.
Successful export can report incomplete coverage; invalid or incomplete evidence
exits unsuccessfully. The original authority gate retains its own exit status.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import stat


REPO = Path(__file__).resolve().parents[1]
ARTIFACTS = REPO / "artifacts"
DECLARATIONS = REPO / "tests/fixtures/native-operation-contracts.json"
REQUIRED = (
    "account_identity_creation_preserves_native_issuer_and_pcr_originals",
    "account_device_sessions_preserve_issuer_originals_and_real_consumer",
    "account_device_pairing_retains_real_target_and_admitted_original",
    "account_policy_recovery_retains_accepted_unit_and_issuer_originals",
    "account_private_storage_retains_encryption_and_durable_effects",
    "mls_interop_retains_native_claims_mls_and_mimi_originals",
    "account_consent_retains_holder_current_and_admitted_quarantine",
    "identity_reservations_retain_fresh_authentication_and_published_originals",
    "service_registrations_retain_actual_native_bootstrap_and_receipt",
    "organization_registrations_retain_external_control_and_native_lifecycle",
    "blob_presign_retains_classified_native_object_and_live_policy",
    "peer_keypackage_claims_retain_two_native_authorities_and_original_cas",
    "peer_contacts_retain_two_native_authorities_and_nonempty_originals",
)
META = (
    "mls_interop_entry_future_keeps_large_child_state_on_the_heap",
    "all_native_operation_schema_references_resolve_once",
)
SHA = re.compile(r"[0-9a-f]{64}\Z")
OPERATION = re.compile(r"ak\.[a-z0-9_]+(?:\.[a-z0-9_]+)+\.v[0-9]+\Z")
MAX_JSON = 8 * 1024 * 1024
MAX_LOG = 16 * 1024 * 1024
MLS_CASE = "mls_interop_retains_native_claims_mls_and_mimi_originals"
MLS_SOURCE = "src/scenarios/native_operation_contracts/mls_interop.rs"
MLS_STAGES = frozenset((
    "deployment", "recipient_session", "realm_membership", "keypackage_upload",
    "keypackage_claim", "mls_genesis", "mls_add_welcome", "durable_snapshot",
    "keypackage_consume", "keypackage_revoke", "mimi_control", "peer_membership_reads",
    "peer_signal", "mimi_message", "mimi_notify", "watch_audit", "media_token",
    "peer_invite", "authority_originals", "retain_attempt", "verify_schemas",
    "verify_claim_receipt", "verify_consume_receipt", "verify_realm_commits",
    "verify_mimi_control", "verify_bootstrap_current", "verify_mimi_message",
    "verify_mimi_notify", "verify_watch_audit", "verify_media_token", "verify_peer_invite",
    "verify_peer_membership_reads", "verify_peer_signal", "retain_evidence",
))


def resolved(path: Path) -> Path:
    try:
        return path.resolve()
    except RuntimeError:
        # Python 3.12 reports symlink loops as RuntimeError containing the raw
        # path. Normalize it before any public diagnostic or CLI boundary.
        raise ValueError("unresolvable evidence path") from None


def confined(path: Path, root: Path) -> Path:
    path, root = path.absolute(), root.absolute()
    if resolved(path) != path or resolved(root) != root or not path.is_relative_to(root) or path == root:
        raise ValueError("unowned input")
    return path


def read_file(path: Path, root: Path, maximum: int) -> bytes:
    path = confined(path, root)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
        raise ValueError("invalid input file")
    data = path.read_bytes()
    if len(data) > maximum:
        raise ValueError("oversized input")
    return data


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def invalid_constant(_value):
    raise ValueError("nonfinite JSON")


def decode_json(data: bytes):
    text = data.decode("utf-8-sig", errors="strict")
    if "\x00" in text:
        raise ValueError("invalid encoding")
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def declaration_scope(document):
    cases, operations = document["cases"], document["operations"]
    if not isinstance(cases, dict) or len(cases) != len(REQUIRED):
        raise ValueError("unexpected cases")
    names = []
    for row in cases.values():
        if not isinstance(row, dict) or row.get("target") != "native_operation_contracts":
            raise ValueError("unexpected target")
        names.append(row.get("test"))
    if set(names) != set(REQUIRED) or len(set(names)) != len(names):
        raise ValueError("unexpected test names")
    if not isinstance(operations, list) or not 1 <= len(operations) <= 4096:
        raise ValueError("invalid scope")
    scope, unmapped = set(), set()
    for row in operations:
        identifier, case = row["operation_id"], row["native_case"]
        if not isinstance(identifier, str) or not OPERATION.fullmatch(identifier) or identifier in scope:
            raise ValueError("invalid operation")
        if case is not None and (not isinstance(case, str) or case not in cases):
            raise ValueError("unknown native case")
        scope.add(identifier)
        if case is None:
            unmapped.add(identifier)
    return scope, unmapped


def native_facts(value):
    if not isinstance(value, dict):
        raise ValueError("invalid result")
    code, unchanged, seconds = value["exit_code"], value["sources_unchanged"], value["seconds"]
    if type(code) is not int or not -65535 <= code <= 4294967295 or type(unchanged) is not bool:
        raise ValueError("invalid result types")
    if type(seconds) not in (int, float) or not 0 <= seconds <= 86400 or not math.isfinite(seconds):
        raise ValueError("invalid duration")
    if value.get("log") != "native.log" or value.get("source_fence") != "native-sources.json":
        raise ValueError("unexpected input reference")
    return {"exit_code": code, "sources_unchanged": unchanged, "seconds": seconds}


def service_isolation_facts(root):
    # These are diagnostics for a run that never produced native results.
    # Private commands, paths, source maps and log contents never leave here.
    raw = read_file(root / "service-isolation-result.json", root, MAX_JSON)
    value = decode_json(raw)
    fields = {"command", "exit_code", "seconds", "sources_unchanged",
              "source_fence", "log", "target_directory"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("invalid preflight result")
    code, unchanged, seconds = value["exit_code"], value["sources_unchanged"], value["seconds"]
    if type(code) is not int or not -65535 <= code <= 4294967295 or type(unchanged) is not bool:
        raise ValueError("invalid preflight result types")
    if type(seconds) not in (int, float) or not 0 <= seconds <= 86400 or not math.isfinite(seconds):
        raise ValueError("invalid preflight duration")
    if value["log"] != "service-isolation.log" or value["source_fence"] != "service-isolation-sources.json":
        raise ValueError("unexpected preflight input reference")
    sources = read_file(root / "service-isolation-sources.json", root, MAX_JSON)
    validate_sources(decode_json(sources))
    log = read_file(root / "service-isolation.log", root, MAX_LOG)
    return {"stage": "service_isolation", "exit_code": code, "sources_unchanged": unchanged,
            "seconds": seconds, "result_sha256": hashlib.sha256(raw).hexdigest(),
            "source_fence_sha256": hashlib.sha256(sources).hexdigest(),
            "log_sha256": hashlib.sha256(log).hexdigest()}


def log_status(data: bytes):
    text = data.decode("utf-8-sig", errors="strict")
    text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    if "\x00" in text or "\x1b" in text:
        raise ValueError("invalid log encoding")
    found, counts, started = {}, None, set()
    active = None
    result_ok = None
    for line in text.splitlines():
        if len(line) > 65536:
            raise ValueError("oversized log line")
        match = re.fullmatch(r"test (.+?) \.\.\.(?: ?(.*))?", line)
        if match:
            name, remainder = match.groups()
            if active is not None or name not in (*REQUIRED, *META) or name in started or counts is not None:
                raise ValueError("unknown or repeated test")
            started.add(name)
            active = name
            # With --nocapture the harness prefix and the first body print can
            # share a line. Body text is private; only exact harness statuses
            # close the single active test.
            status = re.fullmatch(r"(ok|FAILED|ignored)(?:, .*)?", remainder or "")
            if status:
                found[active] = {"ok": "passed", "FAILED": "failed", "ignored": "ignored"}[status[1]]
                active = None
        elif re.fullmatch(r"(ok|FAILED|ignored)(?:, .*)?", line):
            if active is None or counts is not None:
                raise ValueError("status without active test")
            status = re.fullmatch(r"(ok|FAILED|ignored)(?:, .*)?", line)
            found[active] = {"ok": "passed", "FAILED": "failed", "ignored": "ignored"}[status[1]]
            active = None
        elif line.startswith("test result:"):
            match = re.fullmatch(
                r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
                r"(\d+) measured; (\d+) filtered out; finished in \d+(?:\.\d+)?s", line)
            if match is None or counts is not None or active is not None:
                raise ValueError("invalid or repeated totals")
            result_ok = match[1] == "ok"
            counts = dict(zip(("passed", "failed", "ignored", "measured", "filtered_out"),
                              map(int, match.groups()[1:])))
    if counts is not None:
        if any(counts[key] != list(found.values()).count(key) for key in ("passed", "failed", "ignored")):
            raise ValueError("totals disagree")
        if result_ok != (counts["failed"] == 0) or counts["measured"] != 0 or counts["filtered_out"] != 0:
            raise ValueError("unexpected totals")
    complete = counts is not None and all(found.get(name) == "passed" for name in REQUIRED)
    return found, counts, complete


def coverage_facts(value, scope, unmapped):
    keys = {"scope", "native_covered", "remaining", "uncovered_operations", "acceptance"}
    if not isinstance(value, dict) or not keys <= set(value) or set(value) - keys - {"blocker"}:
        raise ValueError("unexpected coverage fields")
    for key in ("scope", "native_covered", "remaining"):
        if type(value[key]) is not int or not 0 <= value[key] <= len(scope):
            raise ValueError("invalid coverage count")
    missing = value["uncovered_operations"]
    if not isinstance(missing, list) or any(not isinstance(item, str) or item not in scope for item in missing):
        raise ValueError("unknown uncovered operation")
    missing_set = set(missing)
    if len(missing_set) != len(missing) or not unmapped <= missing_set:
        raise ValueError("unsupported coverage credit")
    if value["scope"] != len(scope) or value["remaining"] != len(missing) or value["native_covered"] + len(missing) != len(scope):
        raise ValueError("coverage count disagreement")
    if type(value["acceptance"]) is not bool or value["acceptance"] != (not missing):
        raise ValueError("invalid acceptance")
    return {"scope": len(scope), "native_covered": value["native_covered"],
            "remaining": len(missing), "acceptance": value["acceptance"],
            "uncovered_operations": sorted(missing)}


def mls_failure_phase(root, sources):
    """Return only a closed, source-bound propagation marker, never an error."""
    raw = read_file(root / "diagnostics/mls-interop.json", root, 4096)
    value = decode_json(raw)
    fields = {"case", "stage", "source", "line", "status", "error_code"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("invalid failure phase")
    if value["case"] != MLS_CASE or value["source"] != MLS_SOURCE:
        raise ValueError("unknown failure source")
    stage, line = value["stage"], value["line"]
    if not isinstance(stage, str) or stage not in MLS_STAGES or type(line) is not int or not 1 <= line <= 10000:
        raise ValueError("unknown failure location")
    if value["status"] is not None or value["error_code"] is not None:
        raise ValueError("unavailable HTTP facts")
    source = read_file(REPO / MLS_SOURCE, REPO, 512 * 1024)
    if not isinstance(sources, dict) or sources.get("cotest/" + MLS_SOURCE) != hashlib.sha256(source).hexdigest():
        raise ValueError("failure source changed")
    lines = source.decode("utf-8", errors="strict").splitlines()
    if line > len(lines) or lines[line - 1].strip() != f'phase.mark("{stage}", line!());':
        raise ValueError("failure location changed")
    return value


def publish(run_root: Path, output_dir: Path, *, artifacts_root=ARTIFACTS, declarations=DECLARATIONS):
    """Read private inputs and create a new, independent safe output directory."""
    output = output_dir.absolute()
    if resolved(output) != output or output.exists() or output.is_relative_to(artifacts_root.absolute()):
        raise ValueError("unsafe public output")
    summary = {"status": "incomplete", "export_complete": False, "native_execution_complete": False,
               "native": None, "tests": [], "meta_tests": [], "counts": None,
               "coverage": None, "hashes": {}, "diagnostics": [], "failure_phases": [],
               "preflight": None, "preflight_diagnostics": []}
    found = {}
    try:
        root = confined(run_root, artifacts_root)
    except (ValueError, OSError):
        summary["diagnostics"].append("invalid_run_root")
        root = None
    scope = unmapped = None
    try:
        # The declaration is tracked source, not an arbitrary path supplied by input JSON.
        raw = read_file(declarations, declarations.parent, MAX_JSON)
        scope, unmapped = declaration_scope(decode_json(raw))
        summary["hashes"]["declarations.json"] = hashlib.sha256(raw).hexdigest()
    except (ValueError, OSError, KeyError, TypeError, RecursionError, OverflowError):
        summary["diagnostics"].append("invalid_declarations")
    values = {}
    if root is not None:
        for name in ("native-result.json", "native-sources.json", "native.log", "coverage.json"):
            try:
                raw = read_file(root / name, root, MAX_LOG if name == "native.log" else MAX_JSON)
                summary["hashes"][name] = hashlib.sha256(raw).hexdigest()
                values[name] = raw if name == "native.log" else decode_json(raw)
            except (ValueError, OSError, TypeError, RecursionError, OverflowError):
                summary["diagnostics"].append("unavailable_" + name.replace(".", "_"))
    for name, action in (
        ("native-result.json", lambda value: summary.update(native=native_facts(value))),
        ("native-sources.json", lambda value: validate_sources(value)),
    ):
        if name in values:
            try:
                action(values[name])
            except (ValueError, KeyError, TypeError):
                summary["diagnostics"].append("invalid_" + name.replace(".", "_"))
    if "native.log" in values:
        try:
            found, summary["counts"], summary["native_execution_complete"] = log_status(values["native.log"])
        except (ValueError, TypeError):
            summary["diagnostics"].append("invalid_native_log")
    native = summary["native"]
    complete = (summary["native_execution_complete"] and native is not None
                and native["exit_code"] == 0 and native["sources_unchanged"]
                and summary["counts"]["failed"] == 0 and summary["counts"]["ignored"] == 0
                and not [item for item in summary["diagnostics"] if item != "unavailable_coverage_json"])
    summary["native_execution_complete"] = bool(complete)
    if "coverage.json" in values and scope is not None:
        try:
            coverage = coverage_facts(values["coverage.json"], scope, unmapped)
            if complete:
                summary["coverage"] = coverage
            else:
                summary["diagnostics"].append("coverage_without_complete_native")
        except (ValueError, KeyError, TypeError):
            summary["diagnostics"].append("invalid_coverage")
    summary["tests"] = [{"test": name, "status": found.get(name, "not_observed")} for name in REQUIRED]
    summary["meta_tests"] = [{"test": name, "status": found.get(name, "not_observed")} for name in META]
    if complete and summary["coverage"] is not None and not summary["diagnostics"]:
        summary["export_complete"] = True
        summary["status"] = "passed" if summary["coverage"]["acceptance"] else "failed"
    elif native is not None and (native["exit_code"] != 0 or not native["sources_unchanged"]):
        summary["status"] = "failed"
    # Auxiliary failure locations cannot change export, execution or coverage credit.
    if root is not None and found.get(MLS_CASE) == "failed":
        try:
            summary["failure_phases"].append(mls_failure_phase(root, values.get("native-sources.json")))
        except (ValueError, OSError, KeyError, TypeError, RecursionError, OverflowError):
            summary["diagnostics"].append("unavailable_mls_failure_phase")
    # A successful preflight does not establish where later work stopped, and
    # neither valid nor unavailable auxiliary facts change native gate credit.
    if root is not None and native is None:
        try:
            summary["preflight"] = service_isolation_facts(root)
        except (ValueError, OSError, KeyError, TypeError, RecursionError, OverflowError):
            summary["preflight_diagnostics"].append("unavailable_service_isolation")
    output.mkdir(parents=True, exist_ok=False)
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def validate_sources(value):
    if not isinstance(value, dict) or not value or any(not isinstance(key, str) or not isinstance(item, str)
                                                     or not SHA.fullmatch(item) for key, item in value.items()):
        raise ValueError("invalid source hashes")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = publish(args.run_root, args.output_dir)
    except (ValueError, OSError):
        print("native operation status export failed")
        return 1
    print("native operation status: " + result["status"])
    return 0 if result["export_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
