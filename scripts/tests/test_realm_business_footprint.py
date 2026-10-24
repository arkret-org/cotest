"""Private oracle binding tests; these do not claim protocol/crypto verification."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("realm_business_footprint", Path(__file__).resolve().parents[1] / "realm-business-footprint.py")
oracle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oracle)
REALM = "ak:realm:sample"
SERVICE = "ak:did_core:webvh:governor"
GENESIS = "ak:event:genesis"


class DirectOriginalOracleTests(unittest.TestCase):
    def setUp(self):
        self.commit = {"commit_id": "ak:realm_commit:original", "realm_id": REALM,
                       "stream_ref": {"kind": "realm", "realm_id": REALM}, "stream_position": 37,
                       "event_ref": "ak:event:franking", "signature": {"signature": "disclosed-original"}}
        self.source = {"service_id": SERVICE, "genesis_event_id": GENESIS,
                       "genesis_commit": {"commit_id": "ak:realm_commit:genesis", "stream_position": 0},
                       "expected_commits": [self.commit]}
        self.origin = [{"event_id": GENESIS, "purpose": "direct_conversation",
                        "governance_station_id": SERVICE, "commit": self.source["genesis_commit"]}]
        self.rows = [{"commit": copy.deepcopy(self.commit), "event_id": self.commit["event_ref"],
                      "event_kind": "ak.moderation.franking_proof"}]

    def validate(self):
        oracle.validate_direct_originals(self.origin, self.rows, self.source, REALM, 36, 37)

    def test_exact_original_and_entire_disclosed_commit_match(self):
        self.validate()

    def test_wrong_governor_original_is_rejected(self):
        self.origin[0]["governance_station_id"] = "ak:did_core:webvh:observer"
        with self.assertRaisesRegex(ValueError, "fixed governor Genesis"): self.validate()

    def test_ordinary_realm_cannot_use_direct_fallback(self):
        self.origin[0]["purpose"] = "collaboration"
        with self.assertRaisesRegex(ValueError, "fixed governor Genesis"): self.validate()

    def test_genesis_commit_tampering_is_rejected(self):
        self.origin[0] = copy.deepcopy(self.origin[0])
        self.origin[0]["commit"]["commit_id"] = "ak:realm_commit:changed"
        with self.assertRaises(ValueError): self.validate()

    def test_missing_accepted_genesis_is_rejected(self):
        self.origin = []
        with self.assertRaises(ValueError): self.validate()

    def test_missing_original_never_infers_franking_from_withheld_commit(self):
        self.rows = []
        with self.assertRaisesRegex(ValueError, "incomplete"): self.validate()

    def test_tampered_entire_original_commit_is_rejected(self):
        self.rows[0]["commit"]["signature"]["signature"] = "changed"
        with self.assertRaisesRegex(ValueError, "disclosed Commit"): self.validate()

    def test_business_event_cannot_hide_under_franking_exception(self):
        self.rows[0]["event_kind"] = "ak.message.create"
        with self.assertRaisesRegex(ValueError, "franking Event"): self.validate()

    def test_wrong_event_id_is_rejected(self):
        self.rows[0]["event_id"] = "ak:event:unrelated"
        with self.assertRaises(ValueError): self.validate()

    def test_wrong_scope_even_on_both_sides_is_rejected(self):
        self.source["expected_commits"][0]["stream_ref"] = {"kind": "circle", "realm_id": REALM, "circle_id": "ak:circle:other"}
        self.rows[0]["commit"] = copy.deepcopy(self.source["expected_commits"][0])
        with self.assertRaises(ValueError): self.validate()

    def test_wrong_exact_position_even_on_both_sides_is_rejected(self):
        self.source["expected_commits"][0]["stream_position"] = 38
        self.rows[0]["commit"] = copy.deepcopy(self.source["expected_commits"][0])
        with self.assertRaises(ValueError): self.validate()

    def test_sql_keeps_ordinary_sampling_and_requires_real_direct_origin(self):
        ordinary = oracle.sql_for(REALM, None, 36, 37)
        direct = oracle.sql_for(REALM, None, 36, 37, self.source)
        self.assertIn("JOIN public.canonical_events e ON e.pk=c.event_pk", ordinary)
        self.assertNotIn("'direct_origin'", ordinary)
        self.assertIn("'direct_origin'", direct)
        self.assertIn("c.stream_position=0 AND c.governance_generation=0", direct)
        self.assertIn("e.kind='ak.realm.create'", direct)

    def test_summarize_validates_binding_before_exporting_public_metadata(self):
        tables = ["canonical_events", "realm_commits", "notifications", "capability_grant_current_states",
                  "capability_quota_counters", "capability_quota_buckets", "capability_quota_consumptions",
                  "event_federation_outbox_business"]
        lines = [{"table": t, "rows": []} for t in tables]
        ordinary = oracle.summarize("\n".join(map(json.dumps, lines)))
        self.assertNotIn("stream_successors", ordinary)
        lines.extend([{"stream_successors": self.rows}, {"direct_origin": self.origin}])
        result = oracle.summarize("\n".join(map(json.dumps, lines)), self.source, REALM, 36, 37)
        self.assertEqual(result["stream_successors"], self.rows)
        self.assertNotIn("direct_origin", result)
        self.origin[0]["governance_station_id"] = "ak:did_core:webvh:observer"
        with self.assertRaises(ValueError):
            oracle.summarize("\n".join(map(json.dumps, lines)), self.source, REALM, 36, 37)

    def test_exact_station_lease_refuses_wrong_governor_before_connecting(self):
        with tempfile.TemporaryDirectory(prefix="readonly-direct-oracle-") as directory:
            root = Path(directory)
            topology = root / "topology.json"
            topology.write_text(json.dumps({"lifecycle": "running", "servers": [{"name": "server1", "coland": {
                "service_id": "ak:did_core:webvh:observer", "public_url": "https://observer.invalid"}}]}))
            controls = root / "controls"
            controls.mkdir(mode=0o700)
            control = controls / "server1.json"
            control.write_text(json.dumps({"server": "server1", "station_id": "ak:did_core:webvh:observer",
                                          "public_url": "https://observer.invalid", "database_url": "postgresql://user@127.0.0.1/owned"}))
            control.chmod(0o600)
            with mock.patch.dict(os.environ, {"COTEST_TOPOLOGY_PATH": str(topology), "COTEST_READONLY_DATABASE_CONTROLS": str(controls)}):
                self.assertEqual(oracle.connection_for("server1"), "postgresql://user@127.0.0.1/owned")
                with self.assertRaisesRegex(ValueError, "exact Station lease"):
                    oracle.connection_for("server1", SERVICE)


if __name__ == "__main__":
    unittest.main()
