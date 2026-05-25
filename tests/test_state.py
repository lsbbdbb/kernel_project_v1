"""Tests for StateManager."""
import os
import tempfile
from agent.state import StateManager, VALID_STATES, VALID_FINAL_STATUSES


class TestStateManager:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.sm = StateManager(self.tmpdir)
        self.sm.init_run_config(["CVE-2026-0001"], "6.6.102-5.2.an23.x86_64")

    def test_init_run_config(self):
        config = self.sm.get_run_config()
        assert config["kernel_version"] == "6.6.102-5.2.an23.x86_64"
        assert config["cve_ids"] == ["CVE-2026-0001"]
        assert config["max_attempts"] == 5

    def test_init_cve_state(self):
        state = self.sm.init_cve_state("CVE-2026-0001")
        assert state["cve_id"] == "CVE-2026-0001"
        assert state["state"] == "TaskCreated"
        assert state["attempt"] == 0
        assert state["status"] is None

    def test_transition_to(self):
        self.sm.init_cve_state("CVE-2026-0001")
        state = self.sm.transition_to("CVE-2026-0001", "CveResolved", reason="NVD query completed")
        assert state["state"] == "CveResolved"
        cve_dir = os.path.join(self.tmpdir, "CVE-2026-0001")
        events_path = os.path.join(cve_dir, "events.json")
        assert os.path.exists(events_path)

    def test_increment_attempt(self):
        self.sm.init_cve_state("CVE-2026-0001")
        assert self.sm.increment_attempt("CVE-2026-0001") == 1
        assert self.sm.increment_attempt("CVE-2026-0001") == 2

    def test_set_final_status(self):
        self.sm.init_cve_state("CVE-2026-0001")
        self.sm.set_final_status("CVE-2026-0001", "success")
        state = self.sm.get_state("CVE-2026-0001")
        assert state["status"] == "success"

    def test_valid_states(self):
        assert "TaskCreated" in VALID_STATES
        assert "ReportWritten" in VALID_STATES
        assert "CveResolved" in VALID_STATES
        assert "Skipped" in VALID_STATES
        assert len(VALID_STATES) > 10

    def test_valid_final_statuses(self):
        assert "success" in VALID_FINAL_STATUSES
        assert "failed" in VALID_FINAL_STATUSES
        assert "manual_required" in VALID_FINAL_STATUSES

    def test_cve_dir(self):
        self.sm.init_cve_state("CVE-2026-0001")
        cve_dir = self.sm.cve_dir("CVE-2026-0001")
        assert cve_dir.endswith("CVE-2026-0001")
        assert os.path.exists(cve_dir)

    def test_ensure_subdir(self):
        self.sm.init_cve_state("CVE-2026-0001")
        subdir = self.sm.ensure_subdir("CVE-2026-0001", "patches")
        assert os.path.exists(subdir)
        assert subdir.endswith("patches")

    def test_set_error(self):
        self.sm.init_cve_state("CVE-2026-0001")
        self.sm.set_error("CVE-2026-0001", "Test error")
        state = self.sm.get_state("CVE-2026-0001")
        assert state["last_error"] == "Test error"
