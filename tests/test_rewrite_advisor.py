"""Tests for RewriteAdvisor."""
import os
import json
import tempfile
from unittest.mock import MagicMock
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

    def test_llm_does_not_override_struct_abi_manual_gate(self):
        llm = MagicMock()
        llm.ping.return_value = True
        advisor = RewriteAdvisor(self.tmpdir, "CVE-2026-0001", llm_client=llm)
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

        plan = advisor.create_rewrite_plan(failure, change_units, attempt=1)

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

    def test_rule_fallback_must_validate_before_success(self, monkeypatch):
        original = os.path.join(self.cve_dir, "patches", "original.patch")
        with open(original, "w") as f:
            f.write("--- a/net/example.c\n+++ b/net/example.c\n@@ -1,1 +1,1 @@\n-old\n+new\n")
        llm = MagicMock()
        llm.ping.return_value = True
        advisor = RewriteAdvisor(self.tmpdir, "CVE-2026-0001", llm_client=llm)
        monkeypatch.setattr(advisor, "_llm_rewrite", lambda *args: "invalid llm patch")
        validate = MagicMock(return_value=False)
        monkeypatch.setattr(advisor, "_validate_rewrite", validate)

        result = advisor.apply_rewrite(
            original, {"decision": "rewrite", "strategy": "context_drift"},
            "/kernel/source", attempt=1
        )

        assert result["success"] is False
        assert result["output_path"] is None
        assert validate.call_count == 2
        assert not os.path.exists(os.path.join(self.cve_dir, "patches", "attempt_1.patch"))

    def test_rule_rewrite_signals_offset_api_and_include_actions(self):
        patch = "--- a/net/example.c\n+++ b/net/example.c\n@@ -10,2 +10,2 @@\n-old\n+new\n"

        shifted = self.advisor._rule_based_rewrite(patch, "context_drift")
        api_hint = self.advisor._rule_based_rewrite(patch, "api_mismatch")
        include_hint = self.advisor._rule_based_rewrite(patch, "missing_include")

        assert "@@ -13,2 +13,2 @@" in shifted
        assert "REWRITE-NOTE: API mismatch" in api_hint
        assert "REWRITE-NOTE: consider adding necessary includes/defines" in include_hint

    def test_fenced_llm_diff_preserves_git_required_final_newline(self):
        result = self.advisor._extract_diff_from_response(
            "```diff\n--- a/net/example.c\n+++ b/net/example.c\n@@ -1 +1 @@\n-old\n+new\n```"
        )

        assert result.endswith("\n")
