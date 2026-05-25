import json
import os
import tempfile

from agent.planner import LLMPlanner
from agent.state import StateManager


class FakeLLM:
    def __init__(self, response: str):
        self.response = response

    def chat(self, messages):
        return self.response


def test_llmplanner_buildfailed_is_classified_before_llm_decision():
    with tempfile.TemporaryDirectory() as tmpdir:
        cve_id = "CVE-2025-0001"
        state_mgr = StateManager(tmpdir)
        state_mgr.init_run_config([cve_id], "6.6.102-5.2.an23.x86_64", max_attempts=3)
        state_mgr.init_cve_state(cve_id)
        state_mgr.transition_to(cve_id, "BuildFailed", reason="build failed")

        logs_dir = os.path.join(tmpdir, cve_id, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        with open(os.path.join(logs_dir, "build_0.log"), "w", encoding="utf-8") as f:
            f.write("ERROR: fatal compilation failure\n")

        llm_client = FakeLLM(json.dumps({"decision": "manual_required", "reason": "unrecoverable build failure"}))
        planner = LLMPlanner(state_mgr, llm_client=llm_client)

        decision = planner.decide_next(cve_id)

        assert decision["action"] == "classify_failure"
        assert decision["next_state"] == "FailureClassified"
        assert decision["source"] == "rule"


def test_llmplanner_buildfailed_falls_back_to_rule_on_invalid_llm_response():
    with tempfile.TemporaryDirectory() as tmpdir:
        cve_id = "CVE-2025-0002"
        state_mgr = StateManager(tmpdir)
        state_mgr.init_run_config([cve_id], "6.6.102-5.2.an23.x86_64", max_attempts=3)
        state_mgr.init_cve_state(cve_id)
        state_mgr.transition_to(cve_id, "BuildFailed", reason="build failed")

        logs_dir = os.path.join(tmpdir, cve_id, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        with open(os.path.join(logs_dir, "build_0.log"), "w", encoding="utf-8") as f:
            f.write("ERROR: fatal compilation failure\n")

        llm_client = FakeLLM("not a json response")
        planner = LLMPlanner(state_mgr, llm_client=llm_client)

        decision = planner.decide_next(cve_id)

        assert decision["action"] == "classify_failure"
        assert decision["next_state"] == "FailureClassified"
        assert decision["source"] == "rule"


def test_llmplanner_rewritten_build_failure_is_classified_before_llm_decision():
    with tempfile.TemporaryDirectory() as tmpdir:
        cve_id = "CVE-2025-0003"
        state_mgr = StateManager(tmpdir)
        state_mgr.init_run_config([cve_id], "6.6.102-5.2.an23.x86_64", max_attempts=3)
        state_mgr.init_cve_state(cve_id)
        state_mgr.increment_attempt(cve_id)
        state_mgr.transition_to(cve_id, "BuildFailed", reason="rewrite build failed")

        logs_dir = os.path.join(tmpdir, cve_id, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        with open(os.path.join(logs_dir, "build_1.log"), "w", encoding="utf-8") as f:
            f.write("ERROR: fatal compilation failure after rewrite\n")

        llm_client = FakeLLM(json.dumps({"decision": "manual_required", "reason": "still broken"}))
        decision = LLMPlanner(state_mgr, llm_client=llm_client).decide_next(cve_id)

        assert decision["action"] == "classify_failure"
        assert decision["source"] == "rule"


def test_llmplanner_cannot_rewrite_nonretryable_classified_failure():
    with tempfile.TemporaryDirectory() as tmpdir:
        cve_id = "CVE-2025-0004"
        state_mgr = StateManager(tmpdir)
        state_mgr.init_run_config([cve_id], "6.6.102-5.2.an23.x86_64", max_attempts=3)
        state_mgr.init_cve_state(cve_id)
        state_mgr.transition_to(cve_id, "FailureClassified", reason="load failed")
        with open(os.path.join(tmpdir, cve_id, "failure.json"), "w", encoding="utf-8") as f:
            json.dump({"reason_code": "load_failed", "retryable": False,
                       "next_action": "manual_required"}, f)

        llm_client = FakeLLM(json.dumps({"decision": "rewrite", "reason": "try again"}))
        decision = LLMPlanner(state_mgr, llm_client=llm_client).decide_next(cve_id)

        assert decision["action"] == "done"
        assert decision["next_state"] == "ManualRequired"
        assert decision["source"] == "rule"


def test_llmplanner_cannot_rewrite_config_skip():
    with tempfile.TemporaryDirectory() as tmpdir:
        cve_id = "CVE-2025-0005"
        state_mgr = StateManager(tmpdir)
        state_mgr.init_run_config([cve_id], "6.6.102-5.2.an23.x86_64", max_attempts=3)
        state_mgr.init_cve_state(cve_id)
        state_mgr.transition_to(cve_id, "FailureClassified", reason="module disabled")
        with open(os.path.join(tmpdir, cve_id, "failure.json"), "w", encoding="utf-8") as f:
            json.dump({"reason_code": "module_disabled", "retryable": False,
                       "next_action": "skip"}, f)

        llm_client = FakeLLM(json.dumps({"decision": "rewrite", "reason": "force build"}))
        decision = LLMPlanner(state_mgr, llm_client=llm_client).decide_next(cve_id)

        assert decision["action"] == "done"
        assert decision["next_state"] == "Skipped"
        assert decision["source"] == "rule"


def test_llmplanner_cannot_rewrite_environment_fix():
    with tempfile.TemporaryDirectory() as tmpdir:
        cve_id = "CVE-2025-0006"
        state_mgr = StateManager(tmpdir)
        state_mgr.init_run_config([cve_id], "6.6.102-5.2.an23.x86_64", max_attempts=3)
        state_mgr.init_cve_state(cve_id)
        state_mgr.transition_to(cve_id, "FailureClassified", reason="source permissions")
        with open(os.path.join(tmpdir, cve_id, "failure.json"), "w", encoding="utf-8") as f:
            json.dump({"reason_code": "source_permission_denied", "retryable": False,
                       "next_action": "fix_environment"}, f)

        llm_client = FakeLLM(json.dumps({"decision": "rewrite", "reason": "change source"}))
        decision = LLMPlanner(state_mgr, llm_client=llm_client).decide_next(cve_id)

        assert decision["action"] == "fix_environment"
        assert decision["next_state"] == "FixEnvironment"
        assert decision["source"] == "rule"
