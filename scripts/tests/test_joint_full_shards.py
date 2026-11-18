import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from joint_full_shards import P0, SETUP, merge


class MergeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.plan = root / "plan.json"
        files = {P0: [f"P0 {i}" for i in range(5)], "capacity.spec.ts": ["capacity"]}
        self.plan.write_text(json.dumps({"parts": [[P0], ["capacity.spec.ts"]], "files": files,
                                         "setup": [["../setup/build.ts", "build"]]}))
        self.runs = [root / "one", root / "two"]
        for index, (run, file) in enumerate(zip(self.runs, files), start=1):
            run.mkdir()
            summary = dict(joint_full_shard=index, run_profile="joint-full-shard",
                           shard_plan_sha256=hashlib.sha256(self.plan.read_bytes()).hexdigest(),
                           server_count=3, playwright_projects="chrome", exit_code=0, status="success",
                           source_stable=True, source_coverage="complete", secret_scan_status="passed",
                           managed_service_failure_count=0, selection_gate_failures=[], network_shape="full-mesh",
                           shard_required_scenarios=[], forbid_skipped_tests=True)
            (run / "summary.json").write_text(json.dumps(summary))
            (run / "source-freeze.json").write_text(json.dumps({"inputs": [
                dict(repository="cotest", head="head", source_sha256="source", dirty_sha256="dirty")]}))
            xml = ET.Element("testsuites")
            for project, title, names in [("chrome", file, files[file]), (SETUP, "../setup/build.ts", ["build"])]:
                suite = ET.SubElement(xml, "testsuite", name=title, hostname=project)
                for name in names:
                    ET.SubElement(suite, "testcase", name=name)
            ET.ElementTree(xml).write(run / "junit.xml")
        native = self.runs[0] / "native-api-migrations"
        native.mkdir()
        (native / "summary.json").write_text('{"passed":true,"scheduled":11,"executed":11}')

    def verify(self, runs=None):
        merge(SimpleNamespace(plan=self.plan, runs=runs or self.runs))

    def test_partition_and_duplicate(self):
        self.verify()
        with self.assertRaisesRegex(ValueError, "duplicate shard"):
            self.verify([self.runs[0]] * 2)

    def test_missing_or_extra_case(self):
        path = self.runs[1] / "junit.xml"
        tree = ET.parse(path)
        suite = tree.getroot().find("testsuite")
        suite.remove(suite.find("testcase"))
        for extra in (False, True):
            if extra:
                ET.SubElement(suite, "testcase", name="wrong")
            tree.write(path)
            with self.assertRaisesRegex(ValueError, "JUnit cases"):
                self.verify()

    def test_skipped_p0(self):
        path = self.runs[0] / "junit.xml"
        tree = ET.parse(path)
        ET.SubElement(tree.getroot().find(".//testcase"), "skipped")
        tree.write(path)
        with self.assertRaisesRegex(ValueError, "mandatory case skipped"):
            self.verify()

    def test_different_source(self):
        path = self.runs[1] / "source-freeze.json"
        path.write_text(path.read_text().replace('"head": "head"', '"head": "other"'))
        with self.assertRaisesRegex(ValueError, "different frozen inputs"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
