"""Finite counterexamples for the Seal design review, not protocol conformance."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from collections import Counter
from pathlib import Path

from research_seal_scope import join, oracle


def visible_parents(parents):
    cyclic = set()
    for start in parents:
        path = []
        node = start
        while node is not None and node in parents:
            if node in path:
                cyclic.update(path[path.index(node):])
                break
            path.append(node)
            node = parents[node]
    # A suppressed edge is unresolved, not a manufactured root declaration.
    return {node: parent for node, parent in parents.items() if node not in cyclic}


def run_checks():
    counts = Counter()
    old = oracle({"a", "b"})
    revoked = oracle({"a"})
    assert join(old, revoked)[1] == {"b"}
    assert oracle(({"a", "b"} | {"a"}) & {"a"})[1] == {"a"}
    counts["stale_eligibility_snapshot_counterexample"] += 1

    compacted_values = {"b": "B"}
    assert "a" not in compacted_values
    retained_values = {"a": "A", "b": "B"}
    assert [retained_values[n] for n in revoked[1]] == ["A"]
    counts["rollback_requires_predecessor_values"] += 1

    assert visible_parents({"x": "y", "y": None}) == {"x": "y", "y": None}
    assert visible_parents({"x": None, "y": "x"}) == {"x": None, "y": "x"}
    assert visible_parents({"x": "y", "y": "x"}) == {}
    counts["concurrent_reparent_cycle_counterexample"] += 1
    nodes = ("x", "y", "z")
    options = [(None,) + tuple(n for n in nodes if n != node) for node in nodes]
    for values in itertools.product(*options):
        expected = visible_parents(dict(zip(nodes, values)))
        assert visible_parents(expected) == expected
        for order in itertools.permutations(nodes):
            known = {}
            for node in order:
                known[node] = values[nodes.index(node)]
            assert visible_parents(known) == expected
            counts["parent_projection_orders"] += 1

    # Ordinary lifecycle presentation must not revoke its own restore writer.
    archive, restore = "archive", "restore"
    transitions = {archive: frozenset(), restore: frozenset({archive})}
    active = set(transitions) - set().union(*transitions.values())
    assert active == {restore}
    assert "writer_grant" not in transitions
    counts["restore_authority_independent_of_lifecycle"] += 1

    # A producer can choose the same claimed timestamp in both worlds.
    observations = [{"claimed_time": 9, "expires_at": 10} for _ in (9, 11)]
    assert observations[0] == observations[1]
    anchored_before_expiry = {"real_before"}
    assert "forged_after" not in anchored_before_expiry
    counts["producer_time_does_not_prove_before_expiry"] += 1

    # Different acquisition orders allow a wait cycle; one frozen domain order
    # prevents this particular resource deadlock, not all consensus blocking.
    unordered = {"tx1": ("pcr", "realm"), "tx2": ("realm", "pcr")}
    assert unordered["tx1"] == tuple(reversed(unordered["tx2"]))
    ordered = {tx: tuple(sorted(domains)) for tx, domains in unordered.items()}
    assert len(set(ordered.values())) == 1
    counts["cross_domain_lock_order_counterexample"] += 1
    return dict(sorted(counts.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    workspace = Path(__file__).resolve().parents[2]
    paths = [Path(__file__), Path(__file__).with_name("research_seal_scope.py"),
             workspace / "arkret-spec/spec/v1/artifacts/registry/event-kind-registry.json",
             workspace / "arkret-spec/spec/v1/artifacts/schemas/event-payload.schema.json"]
    result = {
        "status": "finite_design_review_only",
        "source_sha256": {str(p.relative_to(workspace)).replace("\\", "/"):
                          hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
        "checks": run_checks(),
        "not_verified": ["complete authorization", "cut production and fairness",
                         "Byzantine consensus and reconfiguration", "atomic commit",
                         "MLS cryptography", "clock trust", "production storage and GC"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "checks": result["checks"]}, indent=2))


if __name__ == "__main__":
    main()
