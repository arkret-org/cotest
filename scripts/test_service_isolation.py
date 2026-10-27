"""Component regressions for the deployment red line, never native coverage."""
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import check_service_isolation as gate


class IsolationTests(unittest.TestCase):
    def fixture(self, root):
        sources = {}
        for relative in ("coland/crates/server/Cargo.toml", "coauth/crates/backend/Cargo.toml"):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('[package]\nname="fixture"\n', encoding="utf-8")
            sources[relative] = None
        return sources

    def test_workspace_alias_cannot_hide_foreign_storage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = self.fixture(root)
            (root / "coauth/Cargo.toml").write_text(
                '[workspace.dependencies]\nsource={package="coland-storage",path="../coland/crates/storage"}\n', encoding="utf-8")
            path = root / "coauth/crates/backend/Cargo.toml"
            path.write_text(path.read_text() + '[dependencies]\nsource={workspace=true}\n', encoding="utf-8")
            self.assertTrue(any("must not load" in error for error in gate.source_errors(root, sources)))

    def test_foreign_database_field_and_source_inclusion_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = self.fixture(root)
            for source in ('pub governance_database_url: String,',
                           'include!("../../../coland/crates/backend/src/lib.rs");'):
                relative = "coauth/crates/backend/lib.rs"
                (root / relative).write_text(source, encoding="utf-8")
                sources[relative] = None
                self.assertTrue(gate.source_errors(root, sources))

    def test_dev_only_joint_fixtures_do_not_become_production_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = self.fixture(root)
            path = root / "coauth/crates/backend/Cargo.toml"
            path.write_text(path.read_text() + '[dev-dependencies]\ncoland-test-support="0.3"\n', encoding="utf-8")
            self.assertEqual(gate.source_errors(root, sources), [])

    def test_transitive_normal_and_build_edges_reject_foreign_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for kind in (None, "build", "dev"):
                metadata = {
                    "workspace_root": str(root / "coauth"),
                    "workspace_members": ["own"],
                    "packages": [
                        {"id": "own", "name": "coauth-backend", "manifest_path": str(root / "coauth/Cargo.toml")},
                        {"id": "bridge", "name": "innocent", "manifest_path": str(root / "shared/Cargo.toml")},
                        {"id": "foreign", "name": "renamed-storage", "manifest_path": str(root / "coland/crates/storage/Cargo.toml")},
                    ],
                    "resolve": {"nodes": [
                        {"id": "own", "deps": [{"pkg": "bridge", "dep_kinds": [{"kind": kind}]}]},
                        {"id": "bridge", "deps": [{"pkg": "foreign", "dep_kinds": [{"kind": None}]}]},
                        {"id": "foreign", "deps": []},
                    ]},
                }
                errors, _ = gate.graph_errors(root, "coauth", metadata)
                self.assertEqual(bool(errors), kind != "dev")

    def test_empty_runtime_graph_cannot_prove_isolation(self):
        metadata = {"packages": [], "workspace_members": [], "resolve": {"nodes": []}}
        errors, count = gate.graph_errors(Path("fixture"), "coauth", metadata)
        self.assertTrue(errors)
        self.assertEqual(count, 0)

    def test_renamed_git_package_and_foreign_build_source_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = {"id": "own", "name": "innocent", "manifest_path": str(root / "coauth/Cargo.toml"),
                       "source": "git+https://github.com/arkret-org/coland.git?rev=fixture#fixture"}
            metadata = {"workspace_root": str(root / "coauth"), "packages": [package], "workspace_members": ["own"],
                        "resolve": {"nodes": [{"id": "own", "deps": []}]}}
            self.assertTrue(gate.graph_errors(root, "coauth", metadata)[0])
            package["source"] = None
            package["targets"] = [{"kind": ["custom-build"], "src_path": str(root / "coland/build.rs")}]
            self.assertTrue(gate.graph_errors(root, "coauth", metadata)[0])

    def test_unavailable_metadata_fails_closed_for_both_products(self):
        with patch.object(gate.subprocess, "run", return_value=SimpleNamespace(returncode=101)) as run:
            errors, graphs = gate.live_graph_errors(Path("fixture"))
        self.assertEqual(len(errors), 2)
        self.assertEqual(graphs, {})
        for call in run.call_args_list:
            self.assertIn("--locked", call.args[0])
            self.assertIn("--all-features", call.args[0])

    def test_shared_transport_cannot_hide_io_or_database_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = self.fixture(root)
            base = root / "arkret-rust-sdk/crates/deployment-contracts"
            (base / "src").mkdir(parents=True)
            (root / "arkret-rust-sdk/.dockerignore").write_text("artifacts/\n", encoding="utf-8")
            for content in ('[dependencies]\nsqlx="0.8"\n', '[dependencies]\nserde="1"\n'):
                (base / "Cargo.toml").write_text(content, encoding="utf-8")
                (base / "src/lib.rs").write_text('fn hidden() { let _ = std::fs::read("foreign"); }', encoding="utf-8")
                sources[(base / "Cargo.toml").relative_to(root).as_posix()] = None
                sources[(base / "src/lib.rs").relative_to(root).as_posix()] = None
                errors = gate.source_errors(root, sources)
                self.assertTrue(any("IO or custody" in error for error in errors))
                if "sqlx" in content:
                    self.assertTrue(any("non-carrier dependency" in error for error in errors))

    def test_shared_database_or_private_mount_is_rejected(self):
        document = {"services": {
            "coland": {"environment": {"COLAND_DATABASE_URL": "postgresql://one@pg:5432/shared"}},
            "coauth": {"environment": {"COAUTH_DATABASE__URI": "postgres://two@pg/shared"}},
        }}
        self.assertTrue(any("same database" in error for error in gate.compose_errors(document)))
        document["services"]["coauth"]["environment"]["COAUTH_DATABASE__URI"] = "postgres://two@pg/%73hared"
        self.assertTrue(any("same database" in error for error in gate.compose_errors(document)))
        document["services"]["coauth"]["environment"]["COAUTH_DATABASE__URI"] = "postgresql://two@another/private"
        self.assertEqual(gate.compose_errors(document), [])
        for owner in ("coland", "coauth"):
            document["services"][owner]["volumes"] = ["shared:/var/lib/" + owner]
        self.assertTrue(any("private storage" in error for error in gate.compose_errors(document)))

    def test_different_database_hosts_cannot_share_the_same_data_volume(self):
        document = {"services": {
            "coland": {"environment": {"COLAND_DATABASE_URL": "postgresql://one@pg1/own"}},
            "coauth": {"environment": {"COAUTH_DATABASE__URI": "postgresql://two@pg2/own"}},
            "pg1": {"volumes": ["same:/var/lib/postgresql/data"]},
            "pg2": {"volumes": ["same:/var/lib/postgresql/data"]},
        }}
        self.assertTrue(gate.compose_errors(document))
        document["services"]["pg2"]["volumes"] = ["different:/var/lib/postgresql/data"]
        self.assertEqual(gate.compose_errors(document), [])

    def test_duplicate_deployment_keys_and_database_selection_overrides_fail_closed(self):
        document = {"services": {
            "coland": {"environment": {"COLAND_DATABASE_URL": "postgresql://one@pg1/own?dbname=foreign"}},
            "coauth": {"environment": {"COAUTH_DATABASE__URI": "postgresql://two@pg2/own"}},
        }}
        self.assertTrue(any("selection overrides" in error for error in gate.compose_errors(document)))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = self.fixture(root)
            relative = "coauth/docker-compose.integration.yaml"
            (root / relative).write_text("services: {}\nservices: {}\n", encoding="utf-8")
            sources[relative] = None
            with self.assertRaisesRegex(ValueError, "duplicate deployment mapping key"):
                gate.source_errors(root, sources)

    def test_shared_transport_cannot_embed_foreign_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = self.fixture(root)
            base = root / "arkret-rust-sdk/crates/deployment-contracts"
            (base / "src").mkdir(parents=True)
            (root / "arkret-rust-sdk/.dockerignore").write_text("artifacts/\n", encoding="utf-8")
            (base / "Cargo.toml").write_text('[dependencies]\nserde="1"\n', encoding="utf-8")
            (base / "src/lib.rs").write_text('include!("../../../../coauth/hidden.rs");', encoding="utf-8")
            for path in (base / "Cargo.toml", base / "src/lib.rs"):
                sources[path.relative_to(root).as_posix()] = None
            self.assertTrue(any("includes external source" in error for error in gate.source_errors(root, sources)))


if __name__ == "__main__":
    unittest.main()
