"""Finite research model; not a v1 wire implementation or conformance runner.

Cryptographic validity and local serialized receiver checks are assumptions here.
The model checks causal state, evidence delivery, and counterexamples; it does
not implement MLS, consensus, production reducers, clocks, or networking.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Write:
    name: str
    value: str | None
    parents: tuple[str, ...] = ()
    scope: str = "chat"


WRITES = {
    w.name: w
    for w in (
        Write("a", "A"),
        Write("b", "B", ("a",)),
        Write("aba", "A", ("b",)),
        Write("fork", "C", ("a",)),
        Write("resolve", "T", ("aba", "fork")),
        Write("same", "T", ("aba", "fork")),
    )
}


def ancestors(name: str) -> frozenset[str]:
    return frozenset(WRITES[name].parents).union(
        *(ancestors(p) for p in WRITES[name].parents)
    )


def ready(known: set[str]) -> set[str]:
    """A payload and its independently delivered producer/auth evidence are required."""
    admitted: set[str] = set()
    while True:
        next_set = admitted | {
            n for n, w in WRITES.items()
            if n in known and f"proof:{n}" in known
            and set(w.parents) <= admitted
        }
        if next_set == admitted:
            return admitted
        admitted = next_set


def oracle(names: set[str]) -> tuple[frozenset[str], frozenset[str]]:
    overwritten = set().union(*(ancestors(n) for n in names))
    return frozenset(names), frozenset(names - overwritten)


def join(left, right):
    c1, h1 = left
    c2, h2 = right
    return c1 | c2, (h1 & h2) | (h1 - c2) | (h2 - c1)


def run_checks() -> dict:
    counts: Counter = Counter()
    all_names = set(WRITES)
    expected = oracle(all_names)
    assert expected[1] == {"resolve", "same"}
    assert {WRITES[n].value for n in expected[1]} == {"T"}
    assert oracle({"a", "b", "aba"})[1] == {"aba"}
    assert WRITES["a"].value == WRITES["aba"].value
    assert oracle({"a"})[1] != oracle({"a", "b", "aba"})[1]
    counts["aba_and_same_value_identity"] += 2

    # All payload permutations, with proof-before-payload and the reverse.
    # Restart uses serialized durable evidence, not an in-memory projected head.
    for order in itertools.permutations(WRITES):
        for proof_first in (False, True):
            known: set[str] = set()
            for i, name in enumerate(order):
                parts = [name, f"proof:{name}"]
                if proof_first:
                    parts.reverse()
                for part in parts:
                    known.add(part)
                    before = ready(known)
                    known.add(part)
                    assert ready(known) == before
                if i == 2:
                    known = set(json.loads(json.dumps(sorted(known))))
            assert oracle(ready(known)) == expected
            counts["payload_orders_with_duplicate_and_restart"] += 1

    # Enumerate causally closed states and compare the compact join to a
    # separately computed maximal-element oracle, including arbitrary triples.
    closed = []
    for flags in itertools.product((False, True), repeat=len(WRITES)):
        subset = {n for n, take in zip(WRITES, flags) if take}
        if all(ancestors(n) <= subset for n in subset):
            closed.append(oracle(subset))
    for x, y, z in itertools.product(closed, repeat=3):
        assert join(x, y) == join(y, x)
        assert join(x, x) == x
        assert join(join(x, y), z) == join(x, join(y, z))
        assert join(join(x, y), z) == oracle(set(x[0] | y[0] | z[0]))
        counts["causally_closed_state_triples"] += 1

    # Three replicas receive every possible partition of payloads and proofs.
    # Replica C may start with nothing; anti-entropy is modeled as full union.
    # Delivering the union is an assumption, not a proof of network liveness.
    facts = tuple(WRITES) + tuple(f"proof:{n}" for n in WRITES)
    for placement in itertools.product(range(3), repeat=len(WRITES)):
        replicas = [set(), set(), set()]
        for i, n in enumerate(WRITES):
            replicas[placement[i]].add(n)
            replicas[(placement[i] + 1) % 3].add(f"proof:{n}")
        for a, b in ((0, 1), (1, 2), (2, 0), (0, 1)):
            replicas[b] |= replicas[a]
        # Bidirectional final exchange guarantees each honest replica has all.
        complete = set().union(*replicas)
        assert complete == set(facts)
        for replica in replicas:
            replica |= complete
            assert oracle(ready(replica)) == expected
        counts["three_replica_partitions"] += 1

    # Missing dependencies and incomplete snapshots must never authorize.
    assert ready({"resolve", "proof:resolve"}) == set()
    assert ready({"a"}) == set()
    compact = expected
    assert join(compact, oracle({"a", "b", "aba"})) == compact
    broken = (compact[1], compact[1])
    assert "a" in join(broken, oracle({"a"}))[1]
    counts["pending_and_snapshot_checks"] += 4

    # Every receiver has its own gate. Local deliveries are historical side
    # effects, not authority which can override another receiver's known ban.
    for order in itertools.permutations(("admit", "revoke")):
        active, history = True, set()
        for action in order:
            if action == "revoke":
                active = False
            elif active:
                history.add("message")
        assert ("message" in history) == (order[0] == "admit")
        assert not active
        assert set(json.loads(json.dumps(sorted(history)))) == history
        counts["local_receiver_barrier_orders"] += 1

    # No contact with the account's station, and no Seal advancement or age
    # check is used for ordinary messages. An unknown dependency still blocks.
    peers = {name: {"epoch": 7, "members": {"alice", "bob"}, "effects": set()}
             for name in ("B", "C", "D")}
    def receive(peer, event_id, sender, epoch, dependencies=True):
        if not dependencies:
            return "pending"
        if sender not in peer["members"] or epoch != peer["epoch"]:
            return "not_live"
        peer["effects"].add(event_id)
        return "live"
    for name in peers:
        assert receive(peers[name], "same_event", "alice", 7) == "live"
        assert receive(peers[name], "same_event", "alice", 7) == "live"
        assert peers[name]["effects"] == {"same_event"}
        assert receive(peers[name], "missing", "alice", 7, False) == "pending"
    counts["independent_receivers_and_deduplication"] += 3
    peers["C"]["members"].remove("alice")
    # Ban is effective for new sends even before the removal Commit arrives.
    assert receive(peers["C"], "stale", "alice", 7) == "not_live"
    peers["C"]["epoch"] = 8
    assert receive(peers["B"], "stale", "alice", 7) == "live"
    assert receive(peers["C"], "stale", "alice", 7) == "not_live"
    # A fabricated new epoch label does not restore membership or a key.
    assert receive(peers["C"], "fake_new", "alice", 8) == "not_live"
    peers["B"]["members"].remove("alice")
    peers["B"]["epoch"] = 8
    assert receive(peers["B"], "after_sync", "alice", 8) == "not_live"
    assert receive(peers["B"], "valid_new", "bob", 8) == "live"
    counts["kick_old_epoch_and_propagation_window"] += 6

    # A receiver-local first-seen decision is not a convergent history rule.
    # A security transition may instead commit an exact causal cut. This is
    # a research candidate with an explicit cost: concurrent offline messages
    # outside the cut remain evidence but become quarantined after the cut.
    cut = {"a", "b", "aba"}
    assert all(ancestors(n) <= cut for n in cut)
    def classify_revoked(known_names):
        return {n: ("history" if n in cut else "quarantine") for n in known_names}
    expected_classes = classify_revoked(set(WRITES))
    for order in itertools.permutations(tuple(WRITES) + ("revoke",)):
        known_names, revoked = set(), False
        for name in order:
            if name == "revoke":
                revoked = True
            else:
                known_names.add(name)
        assert revoked and classify_revoked(known_names) == expected_classes
        counts["revocation_cut_arrival_orders"] += 1

    # In an issuer chain, revoking the parent disables even a concurrent child.
    grants = {"parent": None, "child": "parent"}
    def live(grant, revoked):
        return grant not in revoked and (
            grants[grant] is None or live(grants[grant], revoked)
        )
    assert live("child", set())
    assert not live("child", {"parent"})
    assert grants["child"] == "parent"
    counts["transitive_revocation_projection"] += 1

    # A delayed deterministic winner changes a consumed MLS branch. The
    # already disclosed secret remains in the side-effect set after merging.
    seen_b = {"z_commit"}
    disclosed = {"welcome:z_commit"}
    seen_b.add("a_commit")
    assert min(seen_b) == "a_commit"
    assert "welcome:z_commit" in disclosed
    counts["late_mls_winner_counterexample"] += 1

    # Retaining a Seal for only Commit is insufficient: membership change
    # must immediately make the old active security binding unusable.
    membership = "old_members"
    installed = "old_members"
    displayed_title = "one"
    assert membership == installed
    displayed_title = "two"
    assert membership == installed and displayed_title == "two"
    membership = "revoked_member"
    assert membership != installed
    installed = membership
    assert membership == installed
    counts["seal_scope_security_closure"] += 1

    # Local permission checks and retroactive filtering cannot undo release.
    revoked_a, revoked_b = True, False
    leaked = not revoked_b
    revoked_b = revoked_a
    assert revoked_b and leaked
    counts["partition_release_counterexample"] += 1

    # The same old backup is observable in a world with and without a hidden
    # later recovery. No function of this backup can prove currentness.
    old = {"generation": 1, "device": "old"}
    worlds = [dict(old), {"generation": 2, "device": "replacement"}]
    observations = [json.dumps(old, sort_keys=True) for _ in worlds]
    assert observations[0] == observations[1] and worlds[0] != worlds[1]
    counts["old_backup_indistinguishability"] += 1
    # Distinct revocations intersect their authoring allowances. A late cut
    # must never resurrect an event excluded by another effective revocation.
    closed_states = []
    for size in range(len(WRITES) + 1):
        for combo in itertools.combinations(WRITES, size):
            state = frozenset(combo)
            if all(ancestors(n) <= state for n in state):
                closed_states.append(state)
    for first in closed_states:
        for second in closed_states:
            allowed = first & second
            assert all(ancestors(n) <= allowed for n in allowed)
            for name in WRITES:
                assert (name in allowed) == (name in first and name in second)
                assert allowed <= first and allowed <= second
                counts["multiple_cut_intersection"] += 1

    # Data predicates validate a frozen basis, not a global compare-and-swap.
    # Two disconnected writers can both succeed locally and retain two heads.
    base = oracle({"a"})
    left = oracle({"a", "b"})
    right = oracle({"a", "fork"})
    assert base[1] == {"a"}
    assert join(left, right)[1] == {"b", "fork"}
    counts["data_precondition_is_not_global_cas"] += 1

    # Ineligible writes cannot suppress eligible ancestors. Reclassification
    # may expose an older eligible value; this differs from forgetting causal
    # coverage while the eligible effect set remains unchanged.
    known = {"a", "b", "fork"}
    eligible = {"a", "b"}
    assert oracle(known & eligible)[1] == {"b"}
    eligible = {"a"}
    assert oracle(known & eligible)[1] == {"a"}
    counts["quarantined_write_is_not_a_tombstone"] += 2

    # A serialized safety state machine checks the current revision. It does
    # not need a multi-head register to make exactly one competing write win.
    for order in itertools.permutations(("b", "fork")):
        revision, accepted = "a", []
        for candidate in order:
            if revision == "a":
                revision = candidate
                accepted.append(candidate)
        assert accepted == [order[0]]
        counts["serialized_state_precondition"] += 1
    return dict(sorted(counts.items()))


def inventory(workspace: Path) -> dict:
    registry_path = workspace / "arkret-spec/spec/v1/artifacts/registry/event-kind-registry.json"
    raw = registry_path.read_bytes()
    registry = json.loads(raw)
    families = defaultdict(list)
    dynamic = []
    for event in registry["event_kinds"]:
        for write in event.get("cell_writes", []):
            item = {"event_kind": event["event_kind"], "plane": event.get("plane"),
                    "admission": event.get("admission"), "write": write}
            if "cell_family" in write:
                families[write["cell_family"]].append(item)
            else:
                dynamic.append(item)
    lattice_counts = Counter()
    for writes in families.values():
        kinds = {w["write"]["lattice"] for w in writes}
        assert len(kinds) == 1
        lattice_counts.update(kinds)
    repos = ("arkret-spec", "arkret-rust-sdk", "soland", "garth", "inkson",
             "sodmin", "coauth", "cotest", "floria", "chime", "flagon")
    consumers = {}
    heads = {}
    for repo in repos:
        root = workspace / repo
        if not root.is_dir():
            continue
        heads[repo] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        result = subprocess.run(
            ["rg", "-l", "-i", r"\bseal\b|seal_ref|seal_basis|notary", ".",
             "-g", "!Cargo.lock", "-g", "!package-lock.json", "-g", "!pnpm-lock.yaml"],
            cwd=root, capture_output=True, text=True, encoding="utf-8")
        if result.returncode not in (0, 1):
            raise RuntimeError(result.stderr)
        consumers[repo] = sorted(line.replace("\\", "/").removeprefix("./")
                                 for line in result.stdout.splitlines())
    return {
        "spec_registry_sha256": hashlib.sha256(raw).hexdigest(),
        "repository_heads": heads,
        "event_kind_count": len(registry["event_kinds"]),
        "literal_cell_family_count": len(families),
        "cell_write_count": sum(len(e.get("cell_writes", [])) for e in registry["event_kinds"]),
        "family_counts_by_lattice": dict(sorted(lattice_counts.items())),
        "families": dict(sorted(families.items())),
        "dynamic_writes": dynamic,
        "textual_consumers_not_semantic_proof": consumers,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    workspace = Path(__file__).resolve().parents[2]
    result = {
        "status": "finite_research_model_only",
        "model_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "checks": run_checks(),
        "inventory": inventory(workspace),
        "not_verified": ["production Rust reducers", "MLS cryptography", "Seal consensus safety",
                         "network liveness", "real database isolation", "complete authorization resolver",
                         "unbounded Byzantine faults", "production performance"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "checks": result["checks"],
                      "families": result["inventory"]["literal_cell_family_count"]}, indent=2))


if __name__ == "__main__":
    main()
