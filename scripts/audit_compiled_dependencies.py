#!/usr/bin/env python3
"""Run strict RustSec checks for the dependencies Cotest actually compiles.

Cargo.lock also records disabled optional dependency backends. Query Cargo's
build graph for every workspace member on the native CI and browser targets.
An advisory may be excluded only while every affected locked package is absent
from both graphs; enabling that backend automatically restores the failure.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = ("x86_64-unknown-linux-gnu", "wasm32-unknown-unknown")
PACKAGE_LINE = re.compile(r"^([A-Za-z0-9_-]+) v([^ ]+)(?: .*)?$")


def parse_tree(output: str) -> set[tuple[str, str]]:
    packages = set()
    for line in output.splitlines():
        if not line.strip():
            continue
        match = PACKAGE_LINE.fullmatch(line)
        if not match:
            raise ValueError(f"unrecognized Cargo dependency line: {line!r}")
        packages.add(match.groups())
    if not packages:
        raise ValueError("Cargo returned an empty dependency graph")
    return packages


def inactive_advisories(report: dict, compiled: set[tuple[str, str]]) -> dict[str, list[str]]:
    findings = defaultdict(list)
    for finding in report["vulnerabilities"]["list"]:
        findings[finding["advisory"]["id"]].append(finding["package"])
    for warnings in report["warnings"].values():
        for finding in warnings:
            # Yanked packages have no advisory ID and remain strict failures.
            if finding.get("advisory"):
                findings[finding["advisory"]["id"]].append(finding["package"])
    return {
        advisory: sorted({f"{package['name']} {package['version']}" for package in packages})
        for advisory, packages in findings.items()
        if all((package["name"], package["version"]) not in compiled for package in packages)
    }


def main() -> int:
    compiled = set()
    for target in TARGETS:
        tree = subprocess.run(
            ["cargo", "tree", "--workspace", "--all-features", "--locked",
             "--target", target, "--prefix", "none", "--format", "{p}"],
            cwd=ROOT, text=True, capture_output=True, check=True,
        )
        selected = parse_tree(tree.stdout)
        print(f"audit graph {target}: {len(selected)} packages", flush=True)
        compiled.update(selected)
    config = tomllib.loads((ROOT / "deny.toml").read_text(encoding="utf-8"))
    exceptions = config["advisories"].get("ignore", [])
    explicit = [entry if isinstance(entry, str) else entry["id"] for entry in exceptions]
    command = ["cargo", "audit", "--deny", "warnings"]
    for advisory in explicit:
        command.extend(["--ignore", advisory])
    preliminary = subprocess.run(command + ["--format", "json"], cwd=ROOT,
                                 text=True, capture_output=True)
    if preliminary.returncode not in (0, 1):
        sys.stderr.write(preliminary.stderr)
        return preliminary.returncode
    report = json.loads(preliminary.stdout)
    inactive = inactive_advisories(report, compiled)
    for advisory, packages in sorted(inactive.items()):
        print(f"inactive optional dependency: {advisory}: {', '.join(packages)}", flush=True)
        command.extend(["--ignore", advisory])
    return subprocess.run(command, cwd=ROOT).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f"compiled dependency audit failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
