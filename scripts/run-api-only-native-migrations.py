#!/usr/bin/env python3
"""Run every migrated live API case against the joint deployment, without skips."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from check_api_only_migration import validate_repository


ROOT = Path(__file__).resolve().parents[1]


def command_for(entry: dict, root: Path = ROOT) -> list[str]:
    command = ["cargo", "test", "--locked", "--color", "never", "--manifest-path", str(root / "Cargo.toml"),
            "-p", "cotest", "--test", entry["target"], "--", "--ignored", "--exact", entry["symbol"], "--nocapture"]
    if entry.get("environment", "canonical") == "isolated_station":
        command = [sys.executable, str(root / "scripts/run-native-rust-tests.py"), *command]
    return command


def execution_entries(entries: list[dict]) -> list[dict]:
    jobs = []
    seen = set()
    for entry in entries:
        for test in [entry, *entry.get("supporting_tests", [])]:
            identity = (test["target"], test["symbol"])
            if identity in seen:
                continue
            seen.add(identity)
            jobs.append({key: value for key, value in {"source": entry["source"], **test}.items()
                         if key not in {"supporting_tests", "legacy_case_count", "legacy_projects", "legacy_fully_implemented"}})
    return jobs


def accepted_result(returncode: int, output: str) -> bool:
    return returncode == 0 and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", output) is not None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    validate_repository(ROOT.parent)
    manifest = json.loads((ROOT / "api-only-migration.json").read_text(encoding="utf-8"))
    entries = execution_entries(manifest.get("native_live_migrations", []))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["COTEST_REQUIRE_LIVE_SERVICES"] = "1"
    if any(entry.get("environment") == "isolated_station" for entry in entries) and not environment.get("COLAND_BIN"):
        metadata = subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked",
                                   "--manifest-path", str(ROOT.parent / "coland/Cargo.toml")],
                                  check=True, capture_output=True, text=True, encoding="utf-8")
        binary = Path(json.loads(metadata.stdout)["target_directory"]) / "debug" / ("coland.exe" if os.name == "nt" else "coland")
        if not binary.is_file():
            raise RuntimeError(f"native API migrations require the prebuilt real Station: {binary}")
        environment["COLAND_BIN"] = str(binary)
    results = []
    for entry in entries:
        command = command_for(entry)
        process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, encoding="utf-8", errors="replace")
        lines = []
        assert process.stdout is not None
        with (args.output_dir / f"{entry['target']}-{entry['symbol']}.log").open("w", encoding="utf-8") as log:
            for line in process.stdout:
                log.write(line)
                log.flush()
                print(line, end="", flush=True)
                lines.append(line)
        code = process.wait()
        passed = accepted_result(code, "".join(lines))
        results.append({**entry, "command": command, "exit_code": code, "passed": passed})
        if not passed:
            break
    report = {"scheduled": len(entries), "executed": len(results), "results": results,
              "passed": len(results) == len(entries) and all(row["passed"] for row in results)}
    (args.output_dir / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
