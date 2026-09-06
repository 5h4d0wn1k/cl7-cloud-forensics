import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "firmware"))

import importlib.util
_spec = importlib.util.spec_from_file_location(
    "cloud_forensics",
    os.path.join(REPO, "firmware", "cloud_forensics.py"),
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(REPO, "fixtures", "cloud_config.json")


def load_fixture():
    with open(FIXTURE, encoding="utf-8") as fh:
        return json.load(fh)


class TestCloudForensicsEngine(unittest.TestCase):

    def test_run_on_fixture_produces_findings(self):
        tool = mod.CloudForensics(load_fixture())
        findings = tool.run()
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertIn(f["severity"], ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
            self.assertTrue(f["detail"])

    def test_mfa_not_enforced(self):
        tool = mod.CloudForensics(load_fixture())
        findings = tool.run()
        self.assertTrue(any("MFA not enforced" in f["detail"] for f in findings))

    def test_root_mfa_disabled(self):
        tool = mod.CloudForensics(load_fixture())
        findings = tool.run()
        self.assertTrue(any("Root account MFA disabled" in f["detail"] for f in findings))

    def test_unknown_assumerole_critical(self):
        tool = mod.CloudForensics(load_fixture())
        findings = tool.run()
        self.assertTrue(any("unknown user" in f["detail"] and f["severity"] == "CRITICAL"
                            for f in findings))

    def test_open_ssh_sg_critical(self):
        tool = mod.CloudForensics(load_fixture())
        findings = tool.run()
        self.assertTrue(any("22 open to 0.0.0.0/0" in f["detail"] and f["severity"] == "CRITICAL"
                            for f in findings))

    def test_security_group_fields_present(self):
        tool = mod.CloudForensics(load_fixture())
        findings = tool.run()
        self.assertTrue(any(f["category"] == "security_group" for f in findings))

    def test_snapshot_manifest_populated(self):
        tool = mod.CloudForensics(load_fixture())
        tool.run()
        self.assertTrue(hasattr(tool, "snapshot_manifest"))
        self.assertGreater(len(tool.snapshot_manifest), 0)

    def test_report_structure(self):
        tool = mod.CloudForensics(load_fixture())
        findings = tool.run()
        critical_high = sum(1 for f in findings if f["severity"] in ("CRITICAL", "HIGH"))
        self.assertGreater(critical_high, 0)
        self.assertEqual(len([f for f in findings]), len(findings))


class TestEmbeddedDemo(unittest.TestCase):

    def test_no_config_uses_demo(self):
        tool = mod.CloudForensics(None)
        findings = tool.run()
        self.assertGreater(len(findings), 0)


if __name__ == "__main__":
    unittest.main()