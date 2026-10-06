#!/usr/bin/env python3
"""Gate the light build edge of the Cotest workspace.

`crates/test-support` exists so `cotest-provision` and `cotest-wire` can be
built without Inkson, Dioxus or the Soland implementation crates. That property
was only ever asserted by hand -- the 2026-09-11 closeout ran
`cargo tree -p cotest-test-support` once and recorded the answer. A single
`workspace = true` dependency line is enough to lose it again, and nothing
would have failed.

This is that assertion as a gate. It reads the resolved dependency graph from
`cargo metadata` and refuses a graph in which the light edge can reach any
forbidden package.

Edge kinds: from the light-edge package itself the walk follows normal, build
*and* dev edges, because the joint runner builds
`cargo test -p cotest-test-support --test provisioning_live` on every run with
`-StartCoauth`; a dev-dependency on Inkson would cost exactly as much as a
normal one. Past that package only normal and build edges are followed, which
is what `cargo tree --edges normal,build` does and what actually gets compiled.

The root harness must not reach Inkson or Dioxus through normal, build or direct dev edges. The separate client package must exist with real integration targets and reach both the harness and Inkson. A missing client package is not a successful extraction.

Usage:

    python scripts/check_package_graph.py            # gate, exit 1 on violation
    python scripts/check_package_graph.py --json     # machine-readable verdict
"""

from __future__ import annotations

import argparse
import collections
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The package whose dependency graph must stay light.
LIGHT_EDGE_PACKAGE = "cotest-test-support"

# The binaries that exist only because the light edge does. Listed here so a
# rename that quietly moves one of them into the root package is a failure
# rather than a gate that keeps passing about a binary nobody builds any more.
LIGHT_EDGE_BINARIES = ("cotest-provision", "cotest-wire")

# The root package, used for the non-vacuity check below.
ROOT_PACKAGE = "cotest"
CLIENT_PACKAGE = "cotest-inkson-client-tests"
CLIENT_TEST_TARGETS = ('account_blocklist_production_live', 'calendar_rsvp_convergence', 'conformance_vectors', 'invite_frozen_prestate_live', 'kanban_identity_boundary', 'productivity_contracts', 'snapshot_head_disclosure', 'websocket_live')

# Exact package names the light edge must not reach.
FORBIDDEN_EXACT = frozenset({"cotest", "inkson"})

# Name prefixes the light edge must not reach: the whole Dioxus UI stack and
# every Soland implementation crate.
FORBIDDEN_PREFIXES = ("dioxus", "soland-")

COMPILED_KINDS = frozenset({"normal", "build"})
ROOT_KINDS = frozenset({"normal", "build", "dev"})


class GateError(RuntimeError):
    """The metadata cannot answer the question this gate asks."""


def is_forbidden(name: str) -> bool:
    return name in FORBIDDEN_EXACT or name.startswith(FORBIDDEN_PREFIXES)


def load_metadata(manifest_path: Path) -> dict:
    """Resolve the workspace graph without building anything.

    `--locked` keeps the gate from mutating `Cargo.lock` as a side effect of
    being run; a graph that only resolves after a lockfile update is a change
    that belongs in a commit, not in a check.
    """

    completed = subprocess.run(
        [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--manifest-path",
            str(manifest_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        hint = ""
        if "--locked" in completed.stderr:
            hint = (
                "\nhint: a stale Cargo.lock usually means a dependency was added "
                "without refreshing it. Run a build first, then re-run this gate: "
                "the graph it must judge is the one the lockfile pins."
            )
        raise GateError(
            "cargo metadata failed "
            f"(exit={completed.returncode}): {completed.stderr.strip()}{hint}"
        )
    return json.loads(completed.stdout)


def index_metadata(metadata: dict) -> tuple[dict, dict]:
    packages = {package["id"]: package for package in metadata["packages"]}
    resolve = metadata.get("resolve")
    if not resolve:
        raise GateError(
            "cargo metadata carried no resolved graph; this gate needs one "
            "(do not pass --no-deps)"
        )
    nodes = {node["id"]: node for node in resolve["nodes"]}
    return packages, nodes


def package_id(packages: dict, name: str) -> str:
    matches = [pid for pid, package in packages.items() if package["name"] == name]
    if len(matches) != 1:
        raise GateError(
            f"expected exactly one package named {name!r}, found {len(matches)}"
        )
    return matches[0]


def dep_kinds(dep: dict) -> set[str]:
    # A `null` kind is a normal dependency in cargo's metadata encoding.
    return {(entry.get("kind") or "normal") for entry in dep.get("dep_kinds", [])}


def reachable(nodes: dict, packages: dict, root: str) -> dict[str, list[str]]:
    """Breadth-first closure from `root`, carrying the path that reaches each.

    The path is what makes a failure actionable: knowing that Inkson is in the
    graph is much less useful than knowing which edge put it there.
    """

    paths: dict[str, list[str]] = {root: [packages[root]["name"]]}
    queue = collections.deque([root])
    while queue:
        current = queue.popleft()
        allowed = ROOT_KINDS if current == root else COMPILED_KINDS
        for dep in nodes[current]["deps"]:
            if not (dep_kinds(dep) & allowed):
                continue
            target = dep["pkg"]
            if target in paths:
                continue
            paths[target] = paths[current] + [packages[target]["name"]]
            queue.append(target)
    return paths


def evaluate(metadata: dict) -> dict:
    """Return the gate verdict as plain data, so the unit tests can drive it."""

    packages, nodes = index_metadata(metadata)

    light_id = package_id(packages, LIGHT_EDGE_PACKAGE)
    root_id = package_id(packages, ROOT_PACKAGE)
    client_id = package_id(packages, CLIENT_PACKAGE)

    light_targets = {
        target["name"]
        for target in packages[light_id].get("targets", [])
        if "bin" in target.get("kind", [])
    }
    missing_binaries = sorted(set(LIGHT_EDGE_BINARIES) - light_targets)

    light_paths = reachable(nodes, packages, light_id)
    root_paths = reachable(nodes, packages, root_id)
    client_paths = reachable(nodes, packages, client_id)
    client_targets = [target for target in packages[client_id].get("targets", []) if "test" in target.get("kind", [])]

    missing_client_targets = sorted(set(CLIENT_TEST_TARGETS) - {target["name"] for target in client_targets})

    violations = sorted(
        (
            {"package": packages[pid]["name"], "path": path}
            for pid, path in light_paths.items()
            if is_forbidden(packages[pid]["name"])
        ),
        key=lambda entry: entry["package"],
    )

    root_forbidden = sorted(packages[pid]["name"] for pid in root_paths if packages[pid]["name"] == "inkson" or packages[pid]["name"].startswith("dioxus"))
    client_names = {packages[pid]["name"] for pid in client_paths}
    missing_client_dependencies = sorted({"cotest", "inkson"} - client_names)

    return {
        "light_edge_package": LIGHT_EDGE_PACKAGE,
        "light_edge_crates": len(light_paths),
        "root_package": ROOT_PACKAGE,
        "root_crates": len(root_paths),
        "violations": violations,
        "missing_binaries": missing_binaries,
        "root_forbidden": root_forbidden,
        "client_package": CLIENT_PACKAGE,
        "missing_client_targets": missing_client_targets,
        "client_crates": len(client_paths),
        "missing_client_dependencies": missing_client_dependencies,
        "vacuous": bool(missing_client_targets) or bool(missing_client_dependencies),
    }


def render(verdict: dict) -> list[str]:
    lines = [
        f"light edge: {verdict['light_edge_package']} "
        f"({verdict['light_edge_crates']} crates)",
        f"root package: {verdict['root_package']} ({verdict['root_crates']} crates)",
    ]
    for violation in verdict["violations"]:
        lines.append(
            f"FORBIDDEN: {violation['package']} via " + " -> ".join(violation["path"])
        )
    for binary in verdict["missing_binaries"]:
        lines.append(
            f"MISSING BINARY: {binary} is no longer a bin target of "
            f"{verdict['light_edge_package']}"
        )
    for package in verdict["root_forbidden"]:
        lines.append(f"ROOT UI DEPENDENCY: {package}")
    if verdict["vacuous"]:
        lines.append(
            "VACUOUS: the required client package has no real test targets or does not depend on both cotest and Inkson"
        )
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest-path",
        type=Path,
        default=REPO_ROOT / "Cargo.toml",
        help="workspace manifest to resolve (default: the cotest workspace)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the verdict as JSON instead of text",
    )
    args = parser.parse_args(argv)

    try:
        verdict = evaluate(load_metadata(args.manifest_path))
    except GateError as error:
        print(f"package-graph gate: {error}", file=sys.stderr)
        return 2

    failed = bool(
        verdict["violations"] or verdict["missing_binaries"] or verdict["root_forbidden"] or verdict["vacuous"]
    )
    if args.json:
        print(json.dumps({**verdict, "status": "failed" if failed else "passed"}, indent=2))
    else:
        for line in render(verdict):
            print(line)
        print("package-graph gate: " + ("FAILED" if failed else "PASSED"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
