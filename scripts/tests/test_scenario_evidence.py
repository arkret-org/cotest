from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ScenarioEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="cotest-scenario-evidence-")
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        (root / "scripts").mkdir()
        (root / "e2e/scenarios").mkdir(parents=True)
        script = root / "scripts/generate-scenario-evidence.ps1"
        shutil.copyfile(ROOT / "scripts/generate-scenario-evidence.ps1", script)
        for relative in (
            "discovery/contact-request-ui.spec.ts",
            "identity/account-profile-ui.spec.ts",
            "joint/realm-invite-link-sync.spec.ts",
            "identity/registration-contact-validation.spec.ts",
        ):
            target = root / "e2e/tests" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "e2e/tests" / relative, target)
        for name, source in {
            "import-only": 'import { openRegisteredUserPage } from "../../helpers/users";',
            "injected-session": "await openDpopUserPage(browser, request, 'fixture');",
            "garth-write": "const client = new GarthTestClient(); await client.createRealm();",
        }.items():
            (root / f"e2e/tests/{name}.spec.ts").write_text(source, encoding="utf-8")
        shell = shutil.which("pwsh")
        if shell is None:
            raise RuntimeError("PowerShell is required to verify the evidence generator")
        subprocess.run(
            [shell, "-NoProfile", "-File", str(script)],
            check=True,
            capture_output=True,
            text=True,
        )
        manifest = json.loads((root / "e2e/scenarios/evidence-manifest.json").read_text(encoding="utf-8"))
        cls.scenarios = {entry["scenario_key"]: entry for entry in manifest["scenarios"]}

    def test_real_browser_registration_helpers_keep_their_full_identity_boundary(self) -> None:
        for key in (
            "discovery/contact-request-ui",
            "identity/account-profile-ui",
            "joint/realm-invite-link-sync",
        ):
            with self.subTest(scenario=key):
                entry = self.scenarios[key]
                if key != "joint/realm-invite-link-sync":
                    self.assertEqual(entry["evidence_class"], "live-product")
                self.assertEqual(entry["real_services"], ["coauth", "coland", "inkson"])
                self.assertEqual(entry["identity_establishment"], [
                    "coauth_registration_ui", "inkson_identity_onboarding_ui", "oauth_authorization_ui",
                ])
                self.assertEqual(entry["protocol_object_producers"], ["inkson_product_client"])
                if key != "joint/realm-invite-link-sync":
                    self.assertEqual(entry["declared_test_bypasses"], [])

    def test_registration_does_not_erase_the_realm_prompt_bypass(self) -> None:
        entry = self.scenarios["joint/realm-invite-link-sync"]
        self.assertEqual(entry["evidence_class"], "fixture-only")
        self.assertIn("create_realm_passive_prompt_dismissal", entry["declared_test_bypasses"])
        self.assertIn("mls_backup_unlock_and_missing_recovery_prompt_behavior", entry["claims_excluded"])

    def test_registration_validation_is_ui_without_claiming_completed_identity(self) -> None:
        entry = self.scenarios["identity/registration-contact-validation"]
        self.assertEqual(entry["evidence_class"], "live-product")
        self.assertEqual(entry["real_services"], ["coauth", "coland", "inkson"])
        self.assertEqual(entry["identity_establishment"], ["fixture_or_not_applicable"])

    def test_imports_do_not_claim_a_registration_journey(self) -> None:
        entry = self.scenarios["import-only"]
        self.assertEqual(entry["evidence_class"], "fixture-only")
        self.assertEqual(entry["identity_establishment"], ["fixture_or_not_applicable"])
        self.assertNotIn("inkson_product_client", entry["protocol_object_producers"])

    def test_injected_sessions_remain_excluded_from_real_registration(self) -> None:
        entry = self.scenarios["injected-session"]
        self.assertEqual(entry["evidence_class"], "fixture-only")
        self.assertIn("session_injection", entry["declared_test_bypasses"])
        self.assertIn("registration_login_authorization", entry["claims_excluded"])
        self.assertNotIn("coauth_registration_ui", entry["identity_establishment"])

    def test_garth_writes_do_not_claim_inkson_ui(self) -> None:
        entry = self.scenarios["garth-write"]
        self.assertEqual(entry["evidence_class"], "server-contract")
        self.assertNotIn("inkson_product_client", entry["protocol_object_producers"])


if __name__ == "__main__":
    unittest.main()
