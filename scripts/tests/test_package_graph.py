"""Unit tests for the light-build-edge dependency gate.

These drive `evaluate` on synthetic `cargo metadata` documents, so they run in
any checkout -- including CI jobs that do not clone the Inkson and Soland
siblings the real workspace resolves against.
"""

import unittest

from scripts.check_package_graph import CLIENT_TEST_TARGETS, GateError, evaluate


def package(name, binaries=()):
    return {
        "id": f"{name} 0.0.0",
        "name": name,
        "targets": ([{"name": target, "kind": ["test"]} for target in CLIENT_TEST_TARGETS] if name == "cotest-inkson-client-tests" else [{"name": binary, "kind": ["bin"]} for binary in binaries]),
    }


def node(name, deps):
    return {
        "id": f"{name} 0.0.0",
        "deps": [
            {"pkg": f"{target} 0.0.0", "dep_kinds": [{"kind": kind}]}
            for target, kind in deps
        ],
    }


def metadata(nodes, packages=None):
    """Build a metadata document from an adjacency list.

    `nodes` maps a package name to a list of `(dependency, kind)` pairs, where
    `kind` is cargo's encoding: `None` for a normal dependency.
    """

    names = set(nodes)
    for edges in nodes.values():
        names.update(target for target, _ in edges)
    declared = packages or {}
    return {
        "packages": [
            package(name, declared.get(name, ())) for name in sorted(names)
        ],
        "resolve": {
            "nodes": [
                node(name, nodes.get(name, [])) for name in sorted(names)
            ]
        },
    }


def clean_workspace(**overrides):
    """A workspace shaped like cotest's: a heavy root over a light edge."""

    nodes = {
        "cotest": [
            ("cotest-test-support", None),
            ("soland-services", None),
        ],
        "cotest-test-support": [("arkret", None), ("garth", None)],
        "cotest-inkson-client-tests": [("cotest", None), ("inkson", None)],
        "inkson": [("dioxus", None)],
        "soland-services": [],
        "dioxus": [],
        "arkret": [],
        "garth": [],
    }
    nodes.update(overrides)
    return metadata(
        nodes,
        packages={
            "cotest-test-support": ("cotest-provision", "cotest-wire"),
        },
    )


class PackageGraphGateTests(unittest.TestCase):
    def test_clean_workspace_passes(self):
        verdict = evaluate(clean_workspace())
        self.assertEqual(verdict["violations"], [])
        self.assertEqual(verdict["missing_binaries"], [])
        self.assertFalse(verdict["vacuous"])

    def test_direct_inkson_dependency_is_reported_with_its_path(self):
        verdict = evaluate(
            clean_workspace(
                **{"cotest-test-support": [("arkret", None), ("inkson", None)]}
            )
        )
        self.assertEqual(
            [entry["package"] for entry in verdict["violations"]], ["dioxus", "inkson"]
        )
        self.assertEqual(
            verdict["violations"][1]["path"], ["cotest-test-support", "inkson"]
        )

    def test_transitive_dioxus_is_reported(self):
        verdict = evaluate(
            clean_workspace(
                **{
                    "cotest-test-support": [("garth", None)],
                    "garth": [("dioxus-core", None)],
                }
            )
        )
        self.assertEqual(
            [entry["package"] for entry in verdict["violations"]], ["dioxus-core"]
        )
        self.assertEqual(
            verdict["violations"][0]["path"],
            ["cotest-test-support", "garth", "dioxus-core"],
        )

    def test_dev_dependency_on_the_light_edge_is_a_violation(self):
        # The joint runner builds `--test provisioning_live` on every run with
        # a live Coauth, so a dev-dependency costs the same as a normal one.
        verdict = evaluate(
            clean_workspace(
                **{
                    "cotest-test-support": [("arkret", None), ("soland-services", "dev")]
                }
            )
        )
        self.assertEqual(
            [entry["package"] for entry in verdict["violations"]], ["soland-services"]
        )

    def test_dev_dependency_further_out_is_not_followed(self):
        # Cargo does not build a third party's dev-dependencies, so following
        # them would fail the gate on graphs that compile perfectly lightly.
        verdict = evaluate(
            clean_workspace(**{"arkret": [("inkson", "dev")]})
        )
        self.assertEqual(verdict["violations"], [])

    def test_build_dependency_is_followed(self):
        verdict = evaluate(
            clean_workspace(**{"garth": [("soland-storage", "build")]})
        )
        self.assertEqual(
            [entry["package"] for entry in verdict["violations"]], ["soland-storage"]
        )

    def test_dependency_back_on_the_root_package_is_a_violation(self):
        verdict = evaluate(
            clean_workspace(**{"cotest-test-support": [("cotest", None)]})
        )
        self.assertIn("cotest", [entry["package"] for entry in verdict["violations"]])

    def test_missing_binary_target_fails(self):
        document = metadata(
            {
                "cotest": [("cotest-test-support", None)],
                "cotest-inkson-client-tests": [("cotest", None), ("inkson", None)],
                "cotest-test-support": [],
                "inkson": [],
            },
            packages={"cotest-test-support": ("cotest-wire",)},
        )
        verdict = evaluate(document)
        self.assertEqual(verdict["missing_binaries"], ["cotest-provision"])

    def test_workspace_without_the_forbidden_shape_is_vacuous(self):
        document = metadata(
            {"cotest": [("cotest-test-support", None)], "cotest-test-support": [], "cotest-inkson-client-tests": []},
            packages={
                "cotest-test-support": ("cotest-provision", "cotest-wire"),
            },
        )
        verdict = evaluate(document)
        self.assertTrue(verdict["vacuous"])
        self.assertEqual(verdict["violations"], [])

    def test_root_dev_ui_dependency_is_rejected(self):
        verdict = evaluate(clean_workspace(**{"cotest": [("cotest-test-support", None), ("inkson", "dev")]}))
        self.assertEqual(verdict["root_forbidden"], ["dioxus", "inkson"])

    def test_missing_client_package_is_rejected(self):
        document = clean_workspace()
        document["packages"] = [p for p in document["packages"] if p["name"] != "cotest-inkson-client-tests"]
        with self.assertRaises(GateError):
            evaluate(document)

    def test_metadata_without_a_resolved_graph_is_refused(self):
        with self.assertRaises(GateError):
            evaluate({"packages": [package("cotest")], "resolve": None})

    def test_ambiguous_package_name_is_refused(self):
        document = clean_workspace()
        duplicate = dict(document["packages"][0])
        duplicate["name"] = "cotest-test-support"
        duplicate["id"] = "cotest-test-support 0.0.1"
        document["packages"].append(duplicate)
        with self.assertRaises(GateError):
            evaluate(document)


if __name__ == "__main__":
    unittest.main()
