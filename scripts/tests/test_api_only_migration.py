from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check_api_only_migration.py"
SPEC = importlib.util.spec_from_file_location("api_only_migration", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
migration = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = migration
SPEC.loader.exec_module(migration)


class ApiOnlyMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.write(
            "cotest/src/replacement.rs",
            "#[test]\nfn retained_rust_oracle() {}\n",
        )
        specialized = "cotest/e2e/tests/harness/mocks-selftest.spec.ts"
        self.write(specialized, "test('specialized API harness', async () => {});\n")
        self.write(
            "cotest/e2e/tests/browser-flow.spec.ts",
            "test('browser flow', async ({ page }) => { await page.goto('/'); });\n",
        )
        candidates = [
            {
                "source": f"cotest/e2e/tests/removed-{index}.spec.ts",
                "disposition": "duplicate_removed",
                "replacements": [
                    {
                        "file": "cotest/src/replacement.rs",
                        "symbol": "retained_rust_oracle",
                    }
                ],
            }
            for index in range(30)
        ]
        self.manifest = {
            "schema": "arkret.api-only-rust-migration.v1",
            "expected_candidate_count": 30,
            "specialized_api_lanes": [specialized],
            "candidates": candidates,
        }
        self.write(
            "cotest/api-only-migration.json",
            json.dumps(self.manifest),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")

    def test_accepts_closed_migration_and_uses_workspace_manifest(self) -> None:
        migration.validate_repository(self.root)

    def test_rejects_reintroduced_api_only_playwright_spec(self) -> None:
        self.write(
            "cotest/e2e/tests/reintroduced.spec.ts",
            "test('API only', async () => { expect(true).toBe(true); });\n",
        )
        errors = migration.validation_errors(self.root)
        self.assertIn(
            "API-only Playwright spec is not classified: "
            "cotest/e2e/tests/reintroduced.spec.ts",
            errors,
        )

    def test_rejects_missing_rust_evidence_symbol(self) -> None:
        self.manifest["candidates"][0]["replacements"][0]["symbol"] = "missing"
        self.write(
            "cotest/api-only-migration.json",
            json.dumps(self.manifest),
        )
        errors = migration.validation_errors(self.root)
        self.assertTrue(any("replacement symbol 'missing' is missing" in item for item in errors))


if __name__ == "__main__":
    unittest.main()
