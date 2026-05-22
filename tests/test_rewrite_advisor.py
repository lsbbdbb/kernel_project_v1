"""Tests for RewriteAdvisor."""
import os
import json
import tempfile
from agent.tools.rewrite_advisor import RewriteAdvisor


class TestRewriteAdvisor:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmpdir, "CVE-2025-21638", "patches"))
        self.cve_dir = os.path.join(self.tmpdir, "CVE-2025-21638")
        self.advisor = RewriteAdvisor(self.tmpdir, "CVE-2025-21638")

    def test_rewrite_plan_api_mismatch(self):
        failure = {
            "category": "compile", "reason_code": "api_mismatch",
            "location": {"file": "net/example.c", "function": "example_check"},
            "retryable": True,
        }
        change_units = {
            "units": [{
                "change_id": "CU-001", "file": "net/example.c",
                "function": "example_check", "rewrite_allowed": True,
            }]
        }
        plan = self.advisor.create_rewrite_plan(failure, change_units, attempt=1)
        assert plan["decision"] == "rewrite"
        assert plan["strategy"] == "api_mismatch"

    def test_rewrite_plan_struct_abi(self):
        failure = {
            "category": "kpatch_limit", "reason_code": "struct_or_data_change",
            "retryable": False,
        }
        change_units = {
            "units": [{
                "change_id": "CU-001", "file": "net/example.c",
                "function": "example_check", "rewrite_allowed": False,
            }]
        }
        plan = self.advisor.create_rewrite_plan(failure, change_units, attempt=1)
        assert plan["decision"] == "manual_required"

    def test_rewrite_plan_file_saved(self):
        failure = {
            "category": "compile", "reason_code": "api_mismatch",
            "location": {"file": "net/example.c"}, "retryable": True,
        }
        change_units = {
            "units": [{
                "change_id": "CU-001", "file": "net/example.c",
                "function": "example_check", "rewrite_allowed": True,
            }]
        }
        self.advisor.create_rewrite_plan(failure, change_units, attempt=1)
        plan_path = os.path.join(self.cve_dir, "rewrite_plan.json")
        assert os.path.exists(plan_path)

    def test_semantic_must_keep_not_empty(self):
        failure = {
            "category": "compile", "reason_code": "api_mismatch",
            "location": {"file": "net/example.c"}, "retryable": True,
        }
        change_units = {
            "units": [{
                "change_id": "CU-001", "file": "net/example.c",
                "function": "example_check", "rewrite_allowed": True,
            }]
        }
        plan = self.advisor.create_rewrite_plan(failure, change_units, attempt=1)
        assert len(plan["semantic_must_keep"]) > 0

    def test_missing_include_strategy_loaded_from_yaml(self):
        failure = {
            "category": "compile", "reason_code": "missing_api_or_include",
            "location": {"file": "net/example.c"}, "retryable": True,
        }
        change_units = {
            "units": [{
                "change_id": "CU-001", "file": "net/example.c",
                "function": "example_check", "rewrite_allowed": True,
            }]
        }
        plan = self.advisor.create_rewrite_plan(failure, change_units, attempt=1)
        assert plan["decision"] == "rewrite"
        assert plan["strategy"] == "missing_include"
        assert plan["semantic_must_keep"]

    def test_apply_rewrite_no_original(self):
        plan = {"decision": "rewrite", "strategy": "context_drift"}
        result = self.advisor.apply_rewrite(
            "/nonexistent/original.patch", plan, "/some/source", attempt=1)
        assert result["success"] is False
