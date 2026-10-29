#!/usr/bin/env python3
"""Publish fixed-field status for the two native/browser conjunction targets.

Raw runner logs, JUnit messages, configuration and database material stay private.
This summary is diagnostic evidence, never a replacement for the Rust gates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET


EVIDENCE_ROOT = Path(__file__).resolve().parents[1] / "artifacts" / "native-rust"
TESTS = {
    "agent_provision_production":
        "complete_provision_crosses_native_admission_and_actual_browser_recovery",
    "agent_vectors_production":
        "agent_genesis_cases_cross_real_http_admission_and_preserve_rejected_state",
}
CASES = (
    "Agent creation checks recovery before generating or publishing its DID @agent-provision-recovery-prerequisite",
    "Agent creation continues through the four stages with an active recovery policy @agent-provision-recovery-prerequisite",
    *(f"Agent resumes its original durable ceremony after a lost {cut} response @agent-provision-durable-recovery"
      for cut in ("inception", "provision", "did-binding")),
)
SETUP = "served Inkson bundle was built from the checked-out source"
SOURCES = {
    "arkret-spec", "arkret-rust-sdk", "coland", "cotest", "inkson", "garth",
    "coauth", "chime", "floria", "bridges", "savfox",
}
MAX_BYTES = 4 * 1024 * 1024


def resolve_evidence_path(path: Path) -> Path:
    try:
        return path.resolve()
    except RuntimeError:
        # Python 3.12 includes the private path in symlink-loop errors.
        raise ValueError("invalid linked evidence path") from None


def confined(path: Path, root: Path) -> Path:
    absolute = path.absolute()
    if resolve_evidence_path(absolute) != absolute or not absolute.is_relative_to(root):
        raise ValueError("linked or unowned evidence")
    return absolute


def read_bytes(path: Path, root: Path) -> bytes:
    path = confined(path, root)
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("missing or oversized evidence")
    return path.read_bytes()


def read_json(path: Path, root: Path, hashes: dict[str, str], key: str):
    data = read_bytes(path, root)
    hashes[key] = hashlib.sha256(data).hexdigest()
    return json.loads(data.decode("utf-8-sig"))


def source_map(value) -> bool:
    if not isinstance(value, dict) or set(value) != SOURCES:
        return False
    for row in value.values():
        if not isinstance(row, dict) or set(row) != {"head", "diff_sha256", "changed_file_sha256"}:
            return False
        if not isinstance(row["head"], str) or not re.fullmatch(r"[0-9a-f]{40}", row["head"]):
            return False
        if not isinstance(row["diff_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["diff_sha256"]):
            return False
        changes = row["changed_file_sha256"]
        if not isinstance(changes, dict) or any(
            not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v)
            for v in changes.values()
        ):
            return False
    return True


def junit(data: bytes) -> tuple[list[dict], dict[str, int], bool]:
    text = data.decode("utf-8-sig", errors="strict")
    # NUL is invalid XML text and would otherwise permit BOM-less UTF-16 input.
    if "\x00" in text or "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("DTD is not evidence")
    root = ET.fromstring(text)
    if root.tag not in {"testsuite", "testsuites"}:
        raise ValueError("unexpected JUnit root")
    found = {}
    for case in root.iter("testcase"):
        name = case.get("name")
        if name not in (*CASES, SETUP) or name in found:
            raise ValueError("unknown or duplicate case")
        failed = case.find("failure") is not None or case.find("error") is not None
        skipped = case.find("skipped") is not None
        if failed and skipped:
            raise ValueError("ambiguous case status")
        found[name] = "failed" if failed else "skipped" if skipped else "passed"
    if set(found) != {*CASES, SETUP}:
        raise ValueError("incomplete case inventory")
    rows = [{"name": name, "status": found[name]} for name in CASES]
    counts = {key: sum(row["status"] == key for row in rows)
              for key in ("passed", "failed", "skipped")}
    counts["fixme"] = 0
    return rows, counts, found[SETUP] == "passed"


def inspect_scope(scope: Path, root: Path, meta: dict, metadata_hash: str) -> dict:
    binary = meta["binary"]
    record = {
        "binary": binary, "test": TESTS[binary], "status": "incomplete",
        "exit_code": meta["exit_code"], "browser_counts": None,
        "cases": [], "setup_passed": False, "source_unchanged": None,
        "hashes": {"native-child.json": metadata_hash},
    }
    try:
        hashes = record["hashes"]
        private = scope / "agent-provision"
        summary = read_json(private / "browser/summary.json", root, hashes, "browser/summary.json")
        if not isinstance(summary, dict) or type(summary.get("exit_code")) is not int:
            raise ValueError("invalid browser summary")
        counts = summary.get("test_totals")
        if not isinstance(counts, dict) or set(counts) != {"passed", "failed", "skipped", "fixme"}:
            raise ValueError("invalid counts")
        if any(type(v) is not int or not 0 <= v <= 5 for v in counts.values()):
            raise ValueError("invalid count value")
        data = read_bytes(private / "browser/junit.xml", root)
        hashes["browser/junit.xml"] = hashlib.sha256(data).hexdigest()
        rows, computed, setup = junit(data)
        if counts != computed:
            raise ValueError("inconsistent case counts")
        record.update(browser_counts=computed, cases=rows, setup_passed=setup)
        scan = read_json(private / "browser/secret-scan.json", root, hashes, "browser/secret-scan.json")
        if not isinstance(scan, dict) or scan.get("status") not in {"passed", "failed"}:
            raise ValueError("invalid secret scan")
        before = read_json(private / "input-before.json", root, hashes, "input-before.json")
        after = read_json(private / "input-after.json", root, hashes, "input-after.json")
        if not source_map(before) or not source_map(after):
            raise ValueError("invalid source map")
        record["source_unchanged"] = before == after
        passed = (
            meta["status"] == "completed" and meta["exit_code"] == 0
            and summary["exit_code"] == 0 and summary.get("test_execution") == "executed"
            and computed == {"passed": 5, "failed": 0, "skipped": 0, "fixme": 0}
            and setup and record["source_unchanged"] and scan["status"] == "passed"
        )
        record["status"] = "passed" if passed else "failed"
    except (OSError, ValueError, TypeError, KeyError, ET.ParseError):
        # Input values and exception messages must never enter public output.
        record["status"] = "incomplete"
    return record


def collect(run_root: Path, allowed_root: Path) -> dict:
    allowed_root = allowed_root.absolute()
    run_root = confined(run_root, allowed_root)
    records = []
    invalid = False
    if run_root.is_dir():
        for scope in sorted(run_root.iterdir()):
            try:
                confined(scope, run_root)
                data = read_bytes(scope / "native-child.json", run_root)
                meta = json.loads(data.decode("utf-8"))
                if not isinstance(meta, dict) or set(meta) != {"binary", "status", "exit_code"}:
                    raise ValueError("invalid child record")
                if meta["binary"] is not None and meta["binary"] not in TESTS:
                    raise ValueError("unknown binary")
                if meta["status"] not in {"started", "completed", "launch_failed"}:
                    raise ValueError("invalid child status")
                code = meta["exit_code"]
                if code is not None and (type(code) is not int or not -65535 <= code <= 65535):
                    raise ValueError("invalid child exit code")
                if (meta["status"] == "completed") != (code is not None):
                    raise ValueError("inconsistent child outcome")
                if meta["binary"] is not None:
                    records.append(inspect_scope(scope, run_root, meta, hashlib.sha256(data).hexdigest()))
            except (OSError, ValueError, TypeError):
                invalid = True
    unique = len(records) == len(TESTS) and {r["binary"] for r in records} == set(TESTS)
    complete = unique and not invalid and all(r["status"] != "incomplete" for r in records)
    return {"complete": complete, "all_passed": complete and all(r["status"] == "passed" for r in records),
            "records": sorted(records, key=lambda row: row["binary"])}


def publish(run_root: Path, output_dir: Path, *, allowed_root: Path = EVIDENCE_ROOT) -> dict:
    run_root = run_root.absolute()
    output_dir = output_dir.absolute()
    if resolve_evidence_path(output_dir) != output_dir or output_dir.is_relative_to(run_root):
        raise ValueError("public output must be separate from private evidence")
    result = collect(run_root, allowed_root)
    output_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    (output_dir / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = publish(args.run_root, args.output_dir)
    except (OSError, ValueError, TypeError):
        print("Native evidence export rejected invalid inputs; private data was not published.")
        return 1
    print("Native conjunction public status written; raw evidence remains private.")
    return 0 if result["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
