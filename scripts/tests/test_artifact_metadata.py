"""Distinguish custom artifact labels from actual protocol and external schemas."""

import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / "check_artifact_metadata.py"
spec = importlib.util.spec_from_file_location("artifact_metadata_gate", path)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ArtifactMetadataTests(unittest.TestCase):
    def test_magic_format_labels_are_not_a_contract(self):
        for source in ("schema = 'cotest.build_input_stamp.v1'", 'report_schema = "arkret.test-report.v1"'):
            with self.subTest(source=source):
                self.assertTrue(gate.writer_metadata_errors(source))

    def test_formal_protocol_and_external_schema_references_remain(self):
        self.assertEqual(gate.writer_metadata_errors("schema = 'ak.schema.realm_profile.v1'"), [])
        self.assertEqual(gate.writer_metadata_errors("schema = 'https://example.test/report.schema.json'"), [])


if __name__ == "__main__":
    unittest.main()
