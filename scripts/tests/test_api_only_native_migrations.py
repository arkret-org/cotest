import importlib.util
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("native_migrations", SCRIPTS / "run-api-only-native-migrations.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class NativeMigrationsTests(unittest.TestCase):
    def test_isolated_test_uses_native_tls_without_replacing_canonical_trust(self):
        isolated = {"target": "api_mls_migrations", "symbol": "receipt", "environment": "isolated_station"}
        self.assertIn("run-native-rust-tests.py", runner.command_for(isolated)[1])
        self.assertEqual(runner.command_for({**isolated, "environment": "canonical"})[0], "cargo")

    def test_shared_supporting_executor_runs_once_without_historical_slot_credits(self):
        support = {"target": "private_read_marker_api", "symbol": "paired", "operation_ids": ["ak.self.events.command.submit.v1"]}
        entries = [{"source": "receipts", "target": "mls", "symbol": "receipt", "legacy_case_count": 13, "supporting_tests": [support]},
                   {"source": "markers", **support, "legacy_case_count": 6}]
        jobs = runner.execution_entries(entries)
        self.assertEqual(len(jobs), 2)
        self.assertTrue(all("legacy_case_count" not in job for job in jobs))

    def test_exact_live_selection_explicitly_runs_the_ignored_entrypoint(self):
        command = runner.command_for({"target": "realm_genesis_commit_stream", "symbol": "canonical_realm_genesis_api_migration"})
        self.assertEqual(command[command.index("--test") + 1], "realm_genesis_commit_stream")
        self.assertEqual(command[command.index("--") + 1:], ["--ignored", "--exact", "canonical_realm_genesis_api_migration", "--nocapture"])

    def test_only_one_naturally_passed_case_closes_live_coverage(self):
        green = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;"
        self.assertTrue(runner.accepted_result(0, green))
        for text in ["", green.replace("1 passed", "0 passed"), green.replace("0 ignored", "1 ignored"), green.replace("0 failed", "1 failed")]:
            self.assertFalse(runner.accepted_result(0, text))
        self.assertFalse(runner.accepted_result(1, green))
