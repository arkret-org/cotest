"""Regression coverage for generated Account Authority configuration."""

import importlib.util
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
    def test_current_account_authority_key_and_closed_arkret_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            raw = root / "raw.yaml"
            output = root / "coauth.yaml"
            raw.write_text(
                "database:\n  uri: postgres://placeholder\n"
                "http:\n  public_base_url: https://placeholder/\n"
                "  issuer: https://placeholder/\n  listeners:\n"
                "  - name: web\n    binds:\n    - address: '127.0.0.1:0'\n"
                "secrets:\n  keys:\n  - kid: coauth-account-authority-v1\n"
                "    key: |\n      -----BEGIN PRIVATE KEY-----\n"
                "      placeholder\n      -----END PRIVATE KEY-----\n"
                "arkret:\n  stations: []\n",
                encoding="utf-8",
            )
            arguments = [
                str(SCRIPT), str(raw), str(output),
                "--postgres-url", "postgres://test:1amTester!@127.0.0.1/test",
                "--coauth-base-url", "https://coauth.test", "--coauth-bind", "127.0.0.1:9000",
                "--cedar-policy-file", str(root / "policy.cedar"),
                "--inkson-base-url", "https://inkson.test", "--oauth-client-id", "test",
                "--soland-base-url", "https://station.test",
                "--session-grant-introspection-bearer", "test-only",
                "--embedded-webvh-registration-bearer", "test-only",
            ]
            with patch("sys.argv", arguments):
                self.assertEqual(MODULE.main(), 0)
            result = output.read_text(encoding="utf-8")
            self.assertIn("kid: coauth-account-authority-v1", result)
            self.assertNotIn("coauth-service-identity-v1", result)
            arkret = result.split("arkret:\n", 1)[1]
            for retired in ["identity_provider:", "identity_services:", "service_id:"]:
                self.assertNotIn(retired, arkret)
            self.assertIn('endpoint: "https://station.test/"', arkret)
            self.assertIn("password_login_session_grants_enabled: true", arkret)

    def test_missing_current_key_fails_closed_without_legacy_fallback(self):
        with self.assertRaises(SystemExit):
            MODULE.replace_named_pem_key(
                "  - kid: coauth-service-identity-v1\n    key: |\n      obsolete\n",
                "coauth-account-authority-v1", "replacement",
            )


if __name__ == "__main__":
    unittest.main()
