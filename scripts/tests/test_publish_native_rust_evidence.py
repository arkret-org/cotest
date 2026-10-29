"""Synthetic parser fixtures prove privacy and fail-closed status, not SUT success."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET


SPEC = importlib.util.spec_from_file_location(
    "native_evidence_publisher", Path(__file__).parents[1] / "publish-native-rust-evidence.py")
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cotest-native-public-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.raw = self.root / "private"
        self.run = self.raw / "123-2"
        self.run.mkdir(parents=True)
        self.output = self.root / "public"

    def write_json(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def fixture(self, binary, *, failed=False, suffix=""):
        scope = self.run / (binary + suffix)
        private = scope / "agent-provision"
        self.write_json(scope / "native-child.json", {
            "binary": binary, "status": "completed", "exit_code": 1 if failed else 0,
        })
        sources = {name: {"head": "a" * 40, "diff_sha256": "b" * 64,
                          "changed_file_sha256": {}} for name in publisher.SOURCES}
        self.write_json(private / "input-before.json", sources)
        self.write_json(private / "input-after.json", sources)
        counts = {"passed": 4 if failed else 5, "failed": 1 if failed else 0, "skipped": 0, "fixme": 0}
        self.write_json(private / "browser/summary.json", {
            "exit_code": 1 if failed else 0, "test_execution": "executed", "test_totals": counts,
            "private_token": "fixture-secret-do-not-publish", "database_url": "postgres://private",
        })
        self.write_json(private / "browser/secret-scan.json", {"status": "passed"})
        junit = ET.Element("testsuites")
        suite = ET.SubElement(junit, "testsuite", {"hostname": "private-host"})
        for index, name in enumerate((*publisher.CASES, publisher.SETUP)):
            case = ET.SubElement(suite, "testcase", {"name": name, "classname": "private-url"})
            if failed and index == 0:
                failure = ET.SubElement(case, "failure", {"message": "private-password-value"})
                failure.text = "-----BEGIN PRIVATE KEY----- SQL SELECT token FROM private_table"
        ET.ElementTree(junit).write(private / "browser/junit.xml", encoding="utf-8")
        (private / "browser-runner.log").write_text("private browser payload")
        self.write_json(scope / "services/direct-contact-private-diagnostic.json", {
            "contacts": "private-database-facts", "outbox": "private-outbox-payload",
        })
        return private

    def both(self):
        return [self.fixture(binary) for binary in publisher.TESTS]

    def publish(self):
        return publisher.publish(self.run, self.output, allowed_root=self.raw)

    def test_exact_two_complete_records_export_only_fixed_fields(self):
        self.both()
        result = self.publish()
        self.assertTrue(result["complete"])
        self.assertTrue(result["all_passed"])
        self.assertEqual(len(result["records"]), 2)
        self.assertEqual([p.name for p in self.output.iterdir()], ["summary.json"])
        text = (self.output / "summary.json").read_text()
        for secret in ("fixture-secret", "postgres://", "private-host", "private-url", "browser payload",
                       "private-database-facts", "private-outbox-payload"):
            self.assertNotIn(secret, text)
        self.assertTrue(all(len(row["hashes"]) == 6 for row in result["records"]))

    def test_failed_junit_drops_messages_bodies_and_arbitrary_attributes(self):
        first, second = publisher.TESTS
        self.fixture(first, failed=True)
        self.fixture(second)
        result = self.publish()
        self.assertTrue(result["complete"])
        self.assertFalse(result["all_passed"])
        row = next(row for row in result["records"] if row["binary"] == first)
        self.assertEqual(row["browser_counts"]["failed"], 1)
        text = (self.output / "summary.json").read_text()
        for secret in ("private-password", "PRIVATE KEY", "SELECT", "private_table", "private-url"):
            self.assertNotIn(secret, text)

    def test_failure_without_after_fence_still_preserves_safe_case_status(self):
        first, second = publisher.TESTS
        private = self.fixture(first, failed=True)
        (private / "input-after.json").unlink()
        self.fixture(second)
        result = self.publish()
        self.assertFalse(result["complete"])
        row = next(row for row in result["records"] if row["binary"] == first)
        self.assertEqual(row["browser_counts"]["failed"], 1)
        self.assertIsNone(row["source_unchanged"])
        self.assertTrue((private / "browser-runner.log").is_file())

    def test_unknown_secret_case_name_is_rejected_without_echo(self):
        private = self.both()[0]
        path = private / "browser/junit.xml"
        tree = ET.parse(path)
        tree.find(".//testcase").set("name", "secret-client-value")
        tree.write(path)
        self.assertFalse(self.publish()["all_passed"])
        self.assertNotIn("secret-client-value", (self.output / "summary.json").read_text())

    def test_unknown_binary_and_metadata_fields_cannot_leak(self):
        self.both()
        self.write_json(self.run / "extra/native-child.json", {
            "binary": "secret-client-value", "status": "completed", "exit_code": 0,
            "token": "secret-token",
        })
        result = self.publish()
        self.assertFalse(result["complete"])
        for value in ("secret-client-value", "secret-token"):
            self.assertNotIn(value, (self.output / "summary.json").read_text())

    def test_duplicates_and_missing_records_are_not_complete(self):
        self.both()
        self.fixture(next(iter(publisher.TESTS)), suffix="-duplicate")
        self.assertFalse(self.publish()["all_passed"])
        missing = publisher.collect(self.raw / "missing", self.raw)
        self.assertFalse(missing["complete"])
        self.assertFalse(missing["all_passed"])

    def test_unknown_count_types_and_source_changes_fail_closed(self):
        private = self.both()[0]
        path = private / "browser/summary.json"
        value = json.loads(path.read_text())
        value["test_totals"]["passed"] = True
        self.write_json(path, value)
        self.assertFalse(publisher.collect(self.run, self.raw)["complete"])
        value["test_totals"]["passed"] = 5
        self.write_json(path, value)
        source = json.loads((private / "input-after.json").read_text())
        source["coauth"]["head"] = "c" * 40
        self.write_json(private / "input-after.json", source)
        result = self.publish()
        self.assertFalse(result["all_passed"])
        self.assertTrue(any(row["source_unchanged"] is False for row in result["records"]))

    def test_unowned_roots_nested_outputs_and_dtd_are_rejected(self):
        self.both()
        with self.assertRaises(ValueError):
            publisher.collect(self.root / "outside", self.raw)
        with self.assertRaises(ValueError):
            publisher.publish(self.run, self.run / "public", allowed_root=self.raw)
        with self.assertRaises(ValueError):
            publisher.junit(b'<!DOCTYPE testsuites [<!ENTITY x "private">]><testsuites/>')

    def test_oversized_files_and_duplicate_cases_are_not_accepted(self):
        private = self.both()[0]
        path = private / "browser/junit.xml"
        original = path.read_bytes()
        path.write_bytes(b"x" * (publisher.MAX_BYTES + 1))
        self.assertFalse(publisher.collect(self.run, self.raw)["complete"])
        tree = ET.fromstring(original)
        suite = tree.find("testsuite")
        ET.SubElement(suite, "testcase", {"name": publisher.CASES[0]})
        path.write_bytes(ET.tostring(tree))
        self.assertFalse(self.publish()["all_passed"])

    def test_non_utf8_and_utf16_dtd_are_rejected_without_public_content(self):
        private = self.both()[0]
        path = private / "browser/junit.xml"
        source = '<!DOCTYPE testsuites [<!ENTITY x "secret-client-value">]><testsuites/>'
        samples = [source.encode(encoding) for encoding in ("utf-16", "utf-16-le", "utf-16-be")]
        samples.append(b'<testsuites>secret-client-value-\xff</testsuites>')
        for data in samples:
            with self.subTest(prefix=data[:4]):
                with self.assertRaises(ValueError):
                    publisher.junit(data)
                path.write_bytes(data)
                result = publisher.collect(self.run, self.raw)
                self.assertFalse(result["complete"])
                self.assertNotIn("secret-client-value", json.dumps(result))
        self.publish()
        self.assertNotIn("secret-client-value", (self.output / "summary.json").read_text())

    def test_reporter_utf8_bom_is_supported(self):
        private = self.both()[0]
        path = private / "browser/junit.xml"
        path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
        self.assertTrue(self.publish()["all_passed"])


if __name__ == "__main__":
    unittest.main()
