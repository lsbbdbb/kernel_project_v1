"""Tests for Reporter."""
import os
import json
import tempfile
from agent.tools.reporter import Reporter
from agent.state import StateManager


class TestReporter:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.sm = StateManager(self.tmpdir)
        self.sm.init_run_config(["CVE-2025-21638", "CVE-2024-56659"], "6.6.102-5.2.an23.x86_64")
        self.sm.init_cve_state("CVE-2025-21638")
        self.sm.init_cve_state("CVE-2024-56659")

    def test_generate_report_defaults(self):
        reporter = Reporter(self.tmpdir, "CVE-2025-21638")
        report = reporter.generate_report()
        assert report["cve_id"] == "CVE-2025-21638"
        assert report["status"] == "failed"
        assert "kernel_version" in report

    def test_generate_summary(self):
        reporter = Reporter(self.tmpdir, "CVE-2025-21638")
        reporter.generate_report()
        reporter2 = Reporter(self.tmpdir, "CVE-2024-56659")
        reporter2.generate_report()
        summary = reporter.generate_summary(["CVE-2025-21638", "CVE-2024-56659"])
        assert summary["total_cves"] == 2
        assert summary["success_rate"] == 0.0

    def test_report_contains_patch_ir(self):
        reporter = Reporter(self.tmpdir, "CVE-2025-21638")
        report = reporter.generate_report()
        assert "patch_ir" in report
        assert "change_units" in report

    def test_summary_json_saved(self):
        reporter = Reporter(self.tmpdir, "CVE-2025-21638")
        reporter.generate_report()
        reporter.generate_summary(["CVE-2025-21638"])
        summary_path = os.path.join(self.tmpdir, "summary.json")
        assert os.path.exists(summary_path)
