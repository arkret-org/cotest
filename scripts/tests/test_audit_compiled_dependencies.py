import unittest

from scripts.audit_compiled_dependencies import inactive_advisories, parse_tree


def finding(name, version, advisory):
    return {"package": {"name": name, "version": version}, "advisory": {"id": advisory}}


class DependencyAuditTests(unittest.TestCase):
    def test_enabling_optional_backend_restores_failure(self):
        report = {"vulnerabilities": {"list": [finding("backend", "1.0", "RUSTSEC-1")]},
                  "warnings": {}}
        self.assertEqual(inactive_advisories(report, {("root", "1.0")}),
                         {"RUSTSEC-1": ["backend 1.0"]})
        self.assertEqual(inactive_advisories(report, {("backend", "1.0")}), {})

    def test_one_active_affected_version_prevents_global_ignore(self):
        report = {"vulnerabilities": {"list": [finding("backend", "1.0", "RUSTSEC-1"),
                                               finding("backend", "2.0", "RUSTSEC-1")]},
                  "warnings": {"unmaintained": [finding("macro", "1.0", "RUSTSEC-2")]}}
        self.assertEqual(inactive_advisories(report, {("backend", "2.0"), ("macro", "1.0")}), {})

    def test_yanked_warning_cannot_be_suppressed(self):
        report = {"vulnerabilities": {"list": []},
                  "warnings": {"yanked": [{"package": {"name": "old", "version": "1.0"}}]}}
        self.assertEqual(inactive_advisories(report, set()), {})

    def test_tree_parser_rejects_missing_or_unknown_evidence(self):
        self.assertEqual(parse_tree("root v1.0.0 (/workspace)\ncrypto v0.9.0 (*)\n"),
                         {("root", "1.0.0"), ("crypto", "0.9.0")})
        for output in ("", "unexpected format"):
            with self.assertRaises(ValueError):
                parse_tree(output)
