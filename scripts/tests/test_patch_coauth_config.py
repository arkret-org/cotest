"""Regression coverage for generated Account Authority configuration."""

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "patch-coauth-config.py"
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("patch_coauth_config", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PatchCoauthConfigTests(unittest.TestCase):
    def test_run_scoped_keystore_and_closed_arkret_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            raw = root / "raw.yaml"
            output = root / "coauth.yaml"
            keystore = root / "keystore" / "coauth.v1"
            master_key = root / "secrets" / "coauth-keystore-master-key"
            storage_root = root / "media"
            raw.write_text(
                "database:\n  uri: postgres://placeholder\n"
                "http:\n  public_base_url: https://placeholder/\n"
                "  issuer: https://placeholder/\n  listeners:\n"
                "  - name: web\n    binds:\n    - address: '127.0.0.1:0'\n"
                "secrets:\n  backend: encrypted_file\n"
                "  path: ./.local/keystore/coauth.v1\n"
                "  master_key_file: ./.local/secrets/coauth-keystore-master-key\n"
                "storage:\n  backend: fs\n  root: ./.local/media\n"
                "arkret:\n  stations: []\n",
                encoding="utf-8",
            )
            common_arguments = [
                str(SCRIPT), str(raw), str(output),
                "--postgres-url", "postgres://test:1amTester!@127.0.0.1/test",
                "--coauth-base-url", "https://coauth.test", "--coauth-bind", "127.0.0.1:9000",
                "--cedar-policy-file", str(root / "policy.cedar"),
                "--keystore-path", str(keystore),
                "--keystore-master-key-file", str(master_key),
                "--storage-root", str(storage_root),
                "--inkson-base-url", "https://inkson.test", "--oauth-client-id", "test",
                "--embedded-webvh-registration-bearer", "test-only",
            ]
            arguments = common_arguments + [
                "--station", "server1", "https://station.test", "station-1-bearer",
            ]
            with patch("sys.argv", arguments):
                self.assertEqual(MODULE.main(), 0)
            result = output.read_text(encoding="utf-8")
            # The runner owns key custody: no config-inline key material, and both
            # KeyStore files are repointed out of the coauth checkout.
            self.assertIn("backend: encrypted_file", result)
            self.assertIn(f'path: {json.dumps(str(keystore.resolve()))}', result)
            self.assertIn(
                f'master_key_file: {json.dumps(str(master_key.resolve()))}', result
            )
            self.assertIn(f'root: {json.dumps(str(storage_root.resolve()))}', result)
            self.assertNotIn("./.local/", result)
            self.assertNotIn("BEGIN PRIVATE KEY", result)
            self.assertNotIn("coauth-service-identity-v1", result)
            arkret = result.split("arkret:\n", 1)[1]
            for retired in ["identity_provider:", "identity_services:", "service_id:"]:
                self.assertNotIn(retired, arkret)
            self.assertIn('endpoint: "https://station.test/"', arkret)
            self.assertIn('internal_authority_shared_secret: "station-1-bearer"', arkret)
            self.assertIn(
                'resolver: "https://station.test/_arkret/root/identity/resolve"',
                arkret,
            )
            self.assertEqual(
                arkret.count("trust_domain: ak:trust_domain:local.host"), 2
            )
            self.assertNotIn("password_login_session_grants_enabled:", arkret)

            with patch("sys.argv", arguments + [
                "--mock-email-base-url", "http://127.0.0.1:4567",
            ]):
                self.assertEqual(MODULE.main(), 0)
            verified_contact = output.read_text(encoding="utf-8")
            self.assertIn(
                "registration_email_delivery_bypass_allowed: false",
                verified_contact,
            )
            self.assertIn(
                'url: "http://127.0.0.1:4567/mock/email/verification/send"',
                verified_contact,
            )

            with patch("sys.argv", common_arguments + [
                "--station", "server1", "https://station-server1.test", "station-1-bearer",
                "--station", "server2", "https://station-server2.test", "station-2-bearer",
                "--station", "server3", "https://station-server3.test", "station-3-bearer",
                "--owning-station", "server2",
                "--inkson-base-url", "https://inkson-server2.test",
            ]):
                self.assertEqual(MODULE.main(), 0)
            indexed = output.read_text(encoding="utf-8")
            self.assertIn("owning_station: server2", indexed)
            self.assertIn('endpoint: "https://station-server3.test/"', indexed)
            for bearer in ("station-1-bearer", "station-2-bearer", "station-3-bearer"):
                self.assertEqual(
                    indexed.count(f'internal_authority_shared_secret: "{bearer}"'),
                    1,
                )
            self.assertIn(
                'resolver: "https://station-server2.test/_arkret/root/identity/resolve"',
                indexed,
            )
            indexed_arkret = indexed.split("arkret:\n", 1)[1]
            self.assertEqual(
                indexed_arkret.count("trust_domain: ak:trust_domain:local.host"), 4
            )
            self.assertIn('"https://inkson-server2.test/auth/callback"', indexed)
            self.assertIn('"https://inkson.test/auth/callback"', indexed)

            with patch("sys.argv", common_arguments + [
                "--station", "server1", "https://station-server1.test", "shared-bearer",
                "--station", "server2", "https://station-server2.test", "shared-bearer",
            ]):
                with self.assertRaisesRegex(SystemExit, "must be unique per Station"):
                    MODULE.main()

            invalid_station_sets = [
                (
                    ["--station", "server1", "https://station-server1.test", "   "],
                    "empty internal-channel bearer",
                ),
                (
                    [
                        "--station", "server1", "https://station-server1.test", "alpha-bearer",
                        "--station", "server1", "https://station-server2.test", "beta-bearer",
                    ],
                    "duplicate Station name",
                ),
                (
                    [
                        "--station", "server1", "https://station-server1.test", "alpha-bearer",
                        "--owning-station", "server2",
                    ],
                    "owning Station is not present",
                ),
            ]
            for station_arguments, expected_message in invalid_station_sets:
                with self.subTest(expected_message=expected_message):
                    with patch("sys.argv", common_arguments + station_arguments):
                        with self.assertRaisesRegex(SystemExit, expected_message):
                            MODULE.main()

    def test_missing_repointed_section_fails_closed_instead_of_appending(self):
        # `replace_top_level_section` would append a section the generator no
        # longer emits, producing a config coauth only rejects at startup.
        for section in ("secrets", "storage"):
            with self.subTest(section=section):
                with self.assertRaisesRegex(SystemExit, f"no `{section}:` section"):
                    MODULE.require_top_level_section(
                        "database:\n  uri: postgres://placeholder\n", section
                    )
        MODULE.require_top_level_section("secrets:\n  backend: encrypted_file\n", "secrets")


if __name__ == "__main__":
    unittest.main()
