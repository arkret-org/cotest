"""Synthetic complete-build/receipt and local cost-file regressions; no subprocess."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


_SPEC = importlib.util.spec_from_file_location(
    "native_workspace_scope", Path(__file__).resolve().parents[1] / "native_workspace_scope.py")
scope = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(scope)


def fixture(root="/work/cotest", target="/cache/target", cache="/registry"):
    def cargo_target(package, kind, name, *, test=True, doctest=False):
        directory = "tests" if kind == "test" else "src"
        if kind == "example":
            directory = "examples"
        return {"kind": [kind], "crate_types": ["lib" if kind == "lib" else "bin"],
                "name": name, "src_path": f"{root}/crates/{package}/{directory}/{name}.rs",
                "edition": "2024", "doc": kind == "lib", "doctest": doctest, "test": test}
    packages = []
    for name in ("one", "two"):
        targets = [cargo_target(name, "lib", "shared_lib", doctest=True),
                   cargo_target(name, "test", "same_test_name")]
        if name == "one":
            targets.extend([cargo_target(name, "test", "agent_provision_production"),
                            cargo_target(name, "test", "agent_vectors_production"),
                            cargo_target(name, "bin", "tool"),
                            cargo_target(name, "example", "pg_evidence", test=False)])
        packages.append({"name": name, "version": "0.3.0", "id": f"path:{root}/{name}",
                         "source": None, "manifest_path": f"{root}/crates/{name}/Cargo.toml",
                         "targets": targets})
    dependency = {"name": "dep", "version": "1.2.3", "id": "registry:dep@1.2.3",
                  "source": "registry+https://github.com/rust-lang/crates.io-index",
                  "manifest_path": f"{cache}/dep-1.2.3/Cargo.toml", "targets": [{
                      "kind": ["lib"], "crate_types": ["lib"], "name": "dep",
                      "src_path": f"{cache}/dep-1.2.3/src/lib.rs", "edition": "2021",
                      "doc": True, "doctest": True, "test": True}]}
    metadata = {"workspace_root": root, "target_directory": target,
                "workspace_members": [p["id"] for p in packages], "packages": packages + [dependency]}
    messages = []
    for package in metadata["packages"]:
        for cargo in package["targets"]:
            is_test = cargo["test"] and package is not dependency
            profile = {"opt_level": "0", "debuginfo": 2, "debug_assertions": True,
                       "overflow_checks": True, "test": is_test}
            messages.append({"reason": "compiler-artifact", "package_id": package["id"],
                             "target": copy.deepcopy(cargo), "profile": profile,
                             "features": ["default"], "fresh": False,
                             "executable": None if package is dependency else
                             f"{target}/debug/deps/{package['name']}-{cargo['name']}",
                             "filenames": []})
    messages.append({"reason": "build-finished", "success": True})
    return metadata, messages


REFS = {"cotest": "a" * 40, "arkret-rust-sdk": "b" * 40}


def hasher(path):
    return hashlib.sha256(path.encode()).hexdigest()


def make_plan(*, shard=0, build_context=None, **options):
    metadata, messages = fixture(**options)
    plan = scope.create_plan(metadata, messages, 4, REFS, file_sha256=hasher,
                             build_context=build_context)
    plan["shard_index"] = shard
    return plan


def complete_receipts(plans):
    native, docs = [], []
    for plan in plans:
        shard = plan["shard_index"]
        for target in plan["native_targets"]:
            assigned = target["assigned_shard"] == shard
            native.append({"shard_index": shard,
                           "target_identity_sha256": target["identity_sha256"],
                           "status": "completed" if assigned else "delegated",
                           "exit_code": 0 if assigned else None,
                           "executable_sha256": target["executable_sha256"] if assigned else None})
        docs.extend({"shard_index": shard, "target_identity_sha256": row["identity_sha256"],
                     "status": "completed", "exit_code": 0} for row in plan["doctest_targets"])
    return native, docs


class PlanTests(unittest.TestCase):
    def test_exact_dynamic_scope_and_private_rustdoc_context(self):
        plan = make_plan()
        self.assertEqual(len(plan["native_targets"]), 7)
        self.assertEqual(len(plan["doctest_targets"]), 2)
        self.assertEqual(len(plan["compile_only_examples"]), 1)
        names = [r for r in plan["native_targets"] if r["identity"]["name"] == "same_test_name"]
        self.assertEqual(len({r["identity_sha256"] for r in names}), 2)
        expected = {("one", "test", "agent_provision_production"): 0,
                    ("one", "test", "agent_vectors_production"): 0,
                    ("two", "test", "same_test_name"): 1,
                    ("one", "bin", "tool"): 2, ("one", "lib", "shared_lib"): 3,
                    ("one", "test", "same_test_name"): 1, ("two", "lib", "shared_lib"): 2}
        self.assertEqual({(r["identity"]["package"], r["identity"]["kind"][0],
                           r["identity"]["name"]): r["assigned_shard"]
                          for r in plan["native_targets"]}, expected)
        for row in plan["doctest_targets"]:
            self.assertTrue(row["src_path"].startswith(row["package_manifest_dir"] + "/"))
            self.assertEqual(row["identity"]["version"], "0.3.0")

    def test_graph_normalizes_host_paths_but_not_features_or_complete_profile(self):
        a = make_plan()
        b = make_plan(root="D:/work/cotest", target="D:/cache/target", cache="D:/cargo/registry")
        self.assertEqual(a["compiled_graph_sha256"], b["compiled_graph_sha256"])
        self.assertEqual([r["identity_sha256"] for r in a["native_targets"]],
                         [r["identity_sha256"] for r in b["native_targets"]])
        metadata, messages = fixture()
        for change in (lambda m: m[0]["features"].append("extra"),
                       lambda m: m[0]["profile"].update(new_cargo_profile_field="reviewed-by-hash")):
            altered = copy.deepcopy(messages)
            change(altered)
            plan = scope.create_plan(metadata, altered, 4, REFS, file_sha256=hasher)
            self.assertNotEqual(a["compiled_graph_sha256"], plan["compiled_graph_sha256"])

    def test_input_order_does_not_change_scope_or_graph(self):
        metadata, messages = fixture()
        a = scope.create_plan(metadata, messages, 4, REFS, file_sha256=hasher)
        metadata["packages"].reverse()
        metadata["workspace_members"].reverse()
        messages[:-1] = list(reversed(messages[:-1]))
        b = scope.create_plan(metadata, messages, 4, REFS, file_sha256=hasher)
        self.assertEqual(a, b)

    def test_package_version_is_part_of_target_identity_and_compiled_graph(self):
        baseline = make_plan()
        metadata, messages = fixture()
        metadata["packages"][0]["version"] = "0.4.0"
        changed = scope.create_plan(metadata, messages, 4, REFS, file_sha256=hasher)
        self.assertNotEqual(baseline["compiled_graph_sha256"], changed["compiled_graph_sha256"])
        before = {r["identity_sha256"] for r in baseline["native_targets"]}
        after = {r["identity_sha256"] for r in changed["native_targets"]}
        self.assertNotEqual(before, after)

    def test_no_run_requires_successful_complete_stream(self):
        for mutation in (lambda m: m.pop(), lambda m: m[-1].update(success=False),
                         lambda m: m.append({"reason": "build-finished", "success": True}),
                         lambda m: m.insert(0, {"reason": "future-unreviewed"})):
            metadata, messages = fixture()
            mutation(messages)
            with self.subTest(messages=messages[-1:]), self.assertRaises(ValueError):
                scope.create_plan(metadata, messages, 4, REFS, file_sha256=hasher)

    def test_missing_duplicate_wrong_profile_or_unbound_artifacts_rejected(self):
        mutations = [lambda m: m.pop(0), lambda m: m.insert(0, copy.deepcopy(m[0])),
                     lambda m: m[0]["profile"].update(test=False),
                     lambda m: m[0].update(package_id="not-the-exact-package-id"),
                     lambda m: m[0]["target"].update(name="other"),
                     lambda m: m[0].update(executable=None),
                     lambda m: m[0].update(executable="/cache/target-elsewhere/evil"),
                     lambda m: m[0].update(executable="/cache/target/../evil")]
        for mutation in mutations:
            metadata, messages = fixture()
            mutation(messages)
            with self.subTest(mutation=mutations.index(mutation)), self.assertRaises(ValueError):
                scope.create_plan(metadata, messages, 4, REFS, file_sha256=hasher)

    def test_compile_only_example_needs_actual_artifact_and_hash(self):
        metadata, messages = fixture()
        messages[:] = [m for m in messages if m.get("target", {}).get("kind") != ["example"]]
        with self.assertRaises(ValueError):
            scope.create_plan(metadata, messages, 4, REFS, file_sha256=hasher)
        metadata, messages = fixture()
        with self.assertRaises(ValueError):
            scope.create_plan(metadata, messages, 4, REFS, file_sha256=lambda _: "synthetic-invalid")
        def absent(_):
            raise FileNotFoundError("hash callback refuses absent bytes")
        with self.assertRaises(FileNotFoundError):
            scope.create_plan(metadata, messages, 4, REFS, file_sha256=absent)

    def test_unreviewed_eligibility_fields_and_members_fail_closed(self):
        changes = [lambda m: m["packages"][0]["targets"][0].update(kind=["proc-macro"]),
                   lambda m: m["packages"][0]["targets"][0].update({"required-features": ["optional"]}),
                   lambda m: m["packages"][0]["targets"][0].update(future_target_flag=True),
                   lambda m: m["packages"][0]["targets"][0].update(src_path="/outside/lib.rs"),
                   lambda m: m["workspace_members"].append(m["workspace_members"][0]),
                   lambda m: m["workspace_members"].append("missing")]
        for change in changes:
            metadata, messages = fixture()
            change(metadata)
            with self.subTest(change=changes.index(change)), self.assertRaises(ValueError):
                scope.create_plan(metadata, messages, 4, REFS, file_sha256=hasher)


class AggregateTests(unittest.TestCase):
    def setUp(self):
        # A different target/cache root on each real job must not force
        # identical executable bytes across machines, only matching receipts.
        self.plans = [scope.public_plan(make_plan(shard=i, target=f"/machine-{i}/target"))
                      for i in range(4)]
        self.native, self.docs = complete_receipts(self.plans)

    def test_complete_exact_once_execution_and_each_shard_real_docs(self):
        result = scope.validate_aggregate(self.plans, self.native, self.docs)
        self.assertEqual(result, {"shards": 4, "native_targets": 7,
                                 "native_completed_targets": 7, "doctest_targets": 2,
                                 "completed_doc_receipts": 8, "compile_only_examples": 1})
        self.assertNotIn("passed", json.dumps(result))

    def test_public_plan_is_strict_upload_whitelist(self):
        private = make_plan()
        private["raw_metadata"] = {"secret": "/private/build/path"}
        public = scope.public_plan(private)
        serialized = json.dumps(public)
        for forbidden in ("workspace_root", "target_directory", "compiled_units",
                          "package_manifest_dir", "src_path", "executable\"", "/private"):
            self.assertNotIn(forbidden, serialized)
        private["compiled_units"][0]["features"].append("unbound")
        with self.assertRaises(ValueError):
            scope.public_plan(private)
        private = make_plan()
        private["native_targets"][0]["assigned_shard"] = (private["native_targets"][0]["assigned_shard"] + 1) % 4
        with self.assertRaises(ValueError):
            scope.public_plan(private)

    def test_shards_sources_graph_or_scope_cannot_drift(self):
        for mutation in (lambda p: p.pop(), lambda p: p.append(copy.deepcopy(p[0])),
                         lambda p: p[1].update(shard_index=0),
                         lambda p: p[1]["source_refs"].update(cotest="c" * 40),
                         lambda p: p[1].update(compiled_graph_sha256="c" * 64),
                         lambda p: p[1]["native_targets"].pop(),
                         lambda p: p[1]["doctest_targets"].pop(),
                         lambda p: p[1]["compile_only_examples"].clear(),
                         lambda p: p[1].update(executable="/must-not-upload")):
            plans = copy.deepcopy(self.plans)
            mutation(plans)
            with self.subTest(mutation=repr(mutation)), self.assertRaises(ValueError):
                scope.validate_aggregate(plans, self.native, self.docs)

    def test_build_context_is_bound_without_exposing_compiler_or_flag_details(self):
        plans = copy.deepcopy(self.plans)
        private = make_plan(shard=1, target="/machine-1/target",
                            build_context={"compiler_sha256": "a" * 64,
                                           "flags_sha256": "b" * 64})
        plans[1] = scope.public_plan(private)
        self.assertNotIn("build_context", plans[1])
        self.assertNotIn("compiler_sha256", json.dumps(plans[1]))
        with self.assertRaises(ValueError):
            scope.validate_aggregate(plans, self.native, self.docs)
        private["build_context"]["flags_sha256"] = "c" * 64
        with self.assertRaises(ValueError):
            scope.public_plan(private)

    def test_native_receipts_reject_omission_duplicate_unknown_and_false_credit(self):
        assigned = next(i for i, r in enumerate(self.native) if r["status"] == "completed")
        delegated = next(i for i, r in enumerate(self.native) if r["status"] == "delegated")
        mutations = [lambda r: r.pop(), lambda r: r.append(copy.deepcopy(r[0])),
                     lambda r: r[0].update(target_identity_sha256="f" * 64),
                     lambda r: r[0].update(shard_index=4),
                     lambda r: r[assigned].update(status="started"),
                     lambda r: r[assigned].update(status="launch_failed"),
                     lambda r: r[assigned].update(exit_code=1),
                     lambda r: r[assigned].update(exit_code=False),
                     lambda r: r[assigned].update(executable_sha256="f" * 64),
                     lambda r: r[assigned].update(status="delegated", exit_code=None, executable_sha256=None),
                     lambda r: r[delegated].update(exit_code=0),
                     lambda r: r[delegated].update(executable_sha256="a" * 64),
                     lambda r: r[delegated].update(status="completed")]
        for mutation in mutations:
            receipts = copy.deepcopy(self.native)
            mutation(receipts)
            with self.subTest(mutation=mutations.index(mutation)), self.assertRaises(ValueError):
                scope.validate_aggregate(self.plans, receipts, self.docs)

    def test_docs_require_each_real_wrapper_completion_not_dynamic_native_credit(self):
        mutations = [lambda r: r.pop(), lambda r: r.append(copy.deepcopy(r[0])),
                     lambda r: r[0].update(status="delegated"),
                     lambda r: r[0].update(exit_code=1),
                     lambda r: r[0].update(exit_code=False),
                     lambda r: r[0].update(target_identity_sha256="f" * 64),
                     lambda r: r[0].update(dynamic_child_executable="/untrusted/test")]
        for mutation in mutations:
            docs = copy.deepcopy(self.docs)
            mutation(docs)
            with self.subTest(mutation=mutations.index(mutation)), self.assertRaises(ValueError):
                scope.validate_aggregate(self.plans, self.native, docs)


class CostAllocationTests(unittest.TestCase):
    def setUp(self):
        self.policy = scope._load_cost_policy()

    @staticmethod
    def row(name):
        identity = {"package": "synthetic", "version": "0.3.0", "kind": ["test"],
                    "name": name, "source": f"tests/{name}.rs"}
        return {"identity": identity, "identity_sha256": scope._digest(identity)}

    def test_positive_unknown_cost_and_fixed_ties_not_input_order(self):
        rows = [self.row(name) for name in ("alpha", "beta", "gamma", "delta")]
        self.assertTrue(all(r["identity_sha256"] not in self.policy["weights"] for r in rows))
        ordered = sorted(rows, key=lambda r: r["identity_sha256"])
        # Four equal positive costs fill shard 0,1,2 then choose 0 again.
        expected = {r["identity_sha256"]: shard for r, shard in zip(ordered, (0, 1, 2, 0))}
        self.assertEqual(scope._assign_native_targets(rows, 3), expected)
        self.assertEqual(scope._assign_native_targets(list(reversed(rows)), 3), expected)

    def test_cost_descending_places_larger_work_first(self):
        rows = [self.row(name) for name in ("large", "medium", "small")]
        policy = copy.deepcopy(self.policy)
        policy["weights"].update({r["identity_sha256"]: weight
                                  for r, weight in zip(rows, (9, 5, 4))})
        with patch.object(scope, "_load_cost_policy", return_value=scope._validate_cost_policy(policy)):
            self.assertEqual(scope._assign_native_targets(rows, 2),
                             {r["identity_sha256"]: shard for r, shard in zip(rows, (0, 1, 1))})

    def test_equal_load_uses_index_even_when_it_has_more_targets(self):
        rows = sorted([self.row(f"tie_{i}") for i in range(7)], key=lambda r: r["identity_sha256"])
        policy = copy.deepcopy(self.policy)
        policy["weights"].update({r["identity_sha256"]: weight
                                  for r, weight in zip(rows, (7, 4, 3, 3, 1, 1, 1))})
        with patch.object(scope, "_load_cost_policy", return_value=scope._validate_cost_policy(policy)):
            # Before the last item, loads are 7/6/6 and counts are 1/3/2.
            # The required tie is index 1, even though index 2 has fewer items.
            self.assertEqual(scope._assign_native_targets(rows, 3),
                             {r["identity_sha256"]: shard
                              for r, shard in zip(rows, (0, 1, 2, 2, 1, 1, 1))})

    def test_reserved_audit_is_singleton_and_both_provisions_stay_zero(self):
        reserved = self.policy["provenance"]["capacity_reservation"]
        rows = [self.row(name) for name in sorted(scope._PROVISION)]
        rows += [{"identity": reserved["identity"], "identity_sha256": reserved["identity_sha256"]}]
        rows += [self.row(f"unknown_{i}") for i in range(6)]
        assigned = scope._assign_native_targets(rows, 8)
        self.assertTrue(all(assigned[r["identity_sha256"]] == 0 for r in rows[:2]))
        self.assertEqual(assigned[reserved["identity_sha256"]], 1)
        self.assertEqual(sum(shard == 1 for shard in assigned.values()), 1)
        drifted = copy.deepcopy(rows)
        drifted[2]["identity"]["version"] = "0.4.0"
        drifted[2]["identity_sha256"] = scope._digest(drifted[2]["identity"])
        with self.assertRaisesRegex(ValueError, "capacity target identity needs review"):
            scope._assign_native_targets(drifted, 8)

    def test_invalid_cost_policy_is_not_silently_replaced(self):
        key = next(iter(self.policy["weights"]))
        changes = [lambda p: p.update(schema_version=True),
                   lambda p: p.update(algorithm="hash-modulo"),
                   lambda p: p.update(default_unknown_weight=0),
                   lambda p: p.update(default_unknown_weight=True),
                   lambda p: p.update(extra="unreviewed"),
                   lambda p: p.update(weights={}),
                   lambda p: p["weights"].update({key: 0}),
                   lambda p: p["weights"].update({key: -1}),
                   lambda p: p["weights"].update({key: 1.5}),
                   lambda p: p["weights"].update({key: True}),
                   lambda p: p["weights"].update({"not-an-identity": 3}),
                   lambda p: p["provenance"].update(failed_observations_are_lower_bounds=False),
                   lambda p: p["provenance"]["historical_observation"].update(runtime_execution_credit=True),
                   lambda p: p["provenance"]["capacity_reservation"].update(identity_sha256="f" * 64),
                   lambda p: p["provenance"]["capacity_reservation"].update(weight=1)]
        for change in changes:
            invalid = copy.deepcopy(self.policy)
            change(invalid)
            with self.subTest(change=changes.index(change)), self.assertRaises(ValueError):
                scope._validate_cost_policy(invalid)

    def test_missing_malformed_duplicate_or_non_utf8_cost_file_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="native-cost-tests-") as directory:
            path = Path(directory) / "costs.json"
            with patch.object(scope, "_COST_PATH", path), self.assertRaises(ValueError):
                make_plan()
            key, value = next(iter(self.policy["weights"].items()))
            valid = json.dumps(self.policy)
            duplicate_id = valid.replace(f'"{key}": {value}',
                                         f'"{key}": {value}, "{key}": {value}', 1)
            for raw in (b"{", b"\xff", b'{"schema_version":1,"schema_version":1}',
                        duplicate_id.encode("utf-8")):
                path.write_bytes(raw)
                with self.subTest(raw_length=len(raw)), patch.object(scope, "_COST_PATH", path):
                    with self.assertRaises(ValueError):
                        make_plan()

    def test_public_plan_rechecks_changed_allocation_with_same_policy(self):
        plan = make_plan()
        public = scope.public_plan(plan)
        self.assertEqual(len(public["native_targets"]), 7)
        for row in plan["native_targets"]:
            changed = copy.deepcopy(plan)
            target = next(r for r in changed["native_targets"] if r["identity_sha256"] == row["identity_sha256"])
            target["assigned_shard"] = (target["assigned_shard"] + 1) % 4
            with self.subTest(identity=row["identity_sha256"]), self.assertRaises(ValueError):
                scope.public_plan(changed)

    def test_full_235_native_31_doc_scope_still_requires_all_eight_shards(self):
        metadata, messages = fixture()
        template_package = metadata["packages"][0]
        template_target = template_package["targets"][0]
        metadata["packages"] = []
        metadata["workspace_members"] = []
        messages = []
        for index in range(31):
            name = f"synthetic_{index:02}"
            package = {**template_package, "name": name, "id": f"path:/work/cotest/{name}",
                       "manifest_path": f"/work/cotest/crates/{name}/Cargo.toml", "targets": []}
            kinds = [("lib", name)]
            if index < 3:
                kinds.append(("bin", f"tool_{index}"))
            # 31 libraries + 3 binaries + 201 integration targets = 235.
            kinds += [("test", f"case_{index}_{j}") for j in range(7 if index < 15 else 6)]
            if index == 0:
                kinds[2:4] = [("test", n) for n in sorted(scope._PROVISION)]
                kinds.append(("example", "pg_evidence"))
            for kind, target_name in kinds:
                target = {**template_target, "kind": [kind], "name": target_name,
                          "crate_types": ["lib" if kind == "lib" else "bin"],
                          "src_path": f"/work/cotest/crates/{name}/{kind}/{target_name}.rs",
                          "test": kind != "example", "doctest": kind == "lib", "doc": kind == "lib"}
                package["targets"].append(target)
                messages.append({"reason": "compiler-artifact", "package_id": package["id"],
                                 "target": target, "profile": {"test": kind != "example"},
                                 "features": ["default"],
                                 "executable": f"/cache/target/debug/{name}-{target_name}"})
            metadata["packages"].append(package)
            metadata["workspace_members"].append(package["id"])
        messages.append({"reason": "build-finished", "success": True})
        private = scope.create_plan(metadata, messages, 8, REFS, file_sha256=hasher)
        plans = [scope.public_plan({**private, "shard_index": i}) for i in range(8)]
        native, docs = complete_receipts(plans)
        result = scope.validate_aggregate(plans, native, docs)
        self.assertEqual((result["native_targets"], result["native_completed_targets"],
                          result["doctest_targets"], result["completed_doc_receipts"]), (235, 235, 31, 248))
        self.assertEqual(len(native), 1880)
        for receipts, other, is_native in ((native, docs, True), (docs, native, False)):
            incomplete = receipts[:-1]
            with self.subTest(native=is_native), self.assertRaises(ValueError):
                scope.validate_aggregate(plans, incomplete if is_native else other,
                                         other if is_native else incomplete)


if __name__ == "__main__":
    unittest.main()
