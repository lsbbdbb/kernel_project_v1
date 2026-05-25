"""Integration tests for the LLM pipeline layer.

Tests the interaction between LLMPlanner, LLMClient, and the CLI's
graceful degradation when LLM is unavailable or unconfigured.
"""
import json
import os
import subprocess
import sys
import tempfile
from unittest.mock import MagicMock

from agent.llm.client import LLMClient
from agent.llm.config import LLMConfig
from agent.planner import LLMPlanner
from agent.state import StateManager


class FakeLLM:
    """Minimal fake that returns a canned JSON response."""
    def __init__(self, response: str):
        self.response = response
        self.calls = []

    def chat(self, messages):
        self.calls.append(messages)
        return self.response

    def ping(self):
        return True


# ---------------------------------------------------------------------------
# LLMClient graceful degradation
# ---------------------------------------------------------------------------

def test_llmclient_not_configured_no_env(monkeypatch):
    """No API key in env → client init_error is set, ping() is False."""
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)

    config = LLMConfig.from_env()
    client = LLMClient(config)

    assert client.init_error is not None
    assert client.ping() is False


def test_llmclient_chat_fails_when_not_configured():
    """chat() raises RuntimeError when client is not configured."""
    config = LLMConfig(api_key=None)
    client = LLMClient(config)

    import pytest
    with pytest.raises(RuntimeError, match="not configured"):
        client.chat([{"role": "user", "content": "hello"}])


# ---------------------------------------------------------------------------
# LLMPlanner fallback behaviour
# ---------------------------------------------------------------------------

def test_llmplanner_no_llm_flag_uses_rule():
    """no_llm=True → all decisions come from Planner (rule-based) with source='rule'."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cve_id = "CVE-2025-0003"
        state_mgr = StateManager(tmpdir)
        state_mgr.init_run_config([cve_id], "6.6.102-5.2.an23.x86_64")
        state_mgr.init_cve_state(cve_id)

        planner = LLMPlanner(state_mgr, llm_client=None, no_llm=True)

        decision = planner.decide_next(cve_id)
        assert decision["action"] == "resolve_cve"
        assert decision["source"] == "rule"


def test_llmplanner_none_client_falls_back_to_rule():
    """llm_client=None (no LLM available) → fallback to rule decisions."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cve_id = "CVE-2025-0004"
        state_mgr = StateManager(tmpdir)
        state_mgr.init_run_config([cve_id], "6.6.102-5.2.an23.x86_64")
        state_mgr.init_cve_state(cve_id)

        planner = LLMPlanner(state_mgr, llm_client=None)

        decision = planner.decide_next(cve_id)
        assert decision["source"] == "rule"


# ---------------------------------------------------------------------------
# LLMPlanner decision points (FailureClassified)
# ---------------------------------------------------------------------------

def test_llmplainer_on_failure_classified_calls_llm():
    """FailureClassified state → LLMPlanner consults the LLM."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cve_id = "CVE-2025-0005"
        state_mgr = StateManager(tmpdir)
        state_mgr.init_run_config([cve_id], "6.6.102-5.2.an23.x86_64", max_attempts=3)
        state_mgr.init_cve_state(cve_id)
        state_mgr.transition_to(cve_id, "FailureClassified", reason="build failed")

        # Create failure.json with a retryable reason
        cve_dir = os.path.join(tmpdir, cve_id)
        with open(os.path.join(cve_dir, "failure.json"), "w") as f:
            json.dump({"reason_code": "api_mismatch", "category": "compile",
                       "retryable": True}, f)

        llm = FakeLLM(json.dumps({"decision": "prepare_rewrite", "reason": "can fix"}))
        planner = LLMPlanner(state_mgr, llm_client=llm)

        decision = planner.decide_next(cve_id)

        assert decision["action"] == "prepare_rewrite"
        assert decision["source"] == "llm"


def test_llmplainer_decides_manual_required():
    """A non-retryable safety gate resolves to manual before consulting the LLM."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cve_id = "CVE-2025-0006"
        state_mgr = StateManager(tmpdir)
        state_mgr.init_run_config([cve_id], "6.6.102-5.2.an23.x86_64", max_attempts=3)
        state_mgr.init_cve_state(cve_id)
        state_mgr.transition_to(cve_id, "FailureClassified", reason="build failed")

        cve_dir = os.path.join(tmpdir, cve_id)
        with open(os.path.join(cve_dir, "failure.json"), "w") as f:
            json.dump({"reason_code": "struct_or_data_change", "category": "kpatch_limit",
                       "retryable": False}, f)

        llm = FakeLLM(json.dumps({"decision": "manual_required", "reason": "struct ABI change cannot auto-fix"}))
        planner = LLMPlanner(state_mgr, llm_client=llm)

        decision = planner.decide_next(cve_id)

        assert decision["action"] == "done"
        assert decision["next_state"] == "ManualRequired"
        assert decision["source"] == "rule"


def test_llmplainer_invalid_json_falls_back():
    """LLM returns non-JSON → planner falls back to rule-based decision."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cve_id = "CVE-2025-0007"
        state_mgr = StateManager(tmpdir)
        state_mgr.init_run_config([cve_id], "6.6.102-5.2.an23.x86_64", max_attempts=3)
        state_mgr.init_cve_state(cve_id)
        state_mgr.transition_to(cve_id, "FailureClassified", reason="build failed")

        cve_dir = os.path.join(tmpdir, cve_id)
        with open(os.path.join(cve_dir, "failure.json"), "w") as f:
            json.dump({"reason_code": "api_mismatch", "category": "compile",
                       "retryable": True}, f)

        llm = FakeLLM("not json at all")
        planner = LLMPlanner(state_mgr, llm_client=llm)

        decision = planner.decide_next(cve_id)

        assert decision["source"] == "rule"


# ---------------------------------------------------------------------------
# CLI integration: --no-llm flag
# ---------------------------------------------------------------------------

def test_cli_no_llm_flag():
    """Running agent with --no-llm processes CVEs and produces output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cves_file = os.path.join(tmpdir, "cves.txt")
        with open(cves_file, "w") as f:
            f.write("# test\nCVE-2026-0001\n")

        workdir = os.path.join(tmpdir, "run_output")
        result = subprocess.run(
            [sys.executable, "-m", "agent",
             "--cves", cves_file,
             "--workdir", workdir,
             "--no-llm"],
            capture_output=True, text=True, timeout=30,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )

        assert result.returncode == 0, f"CLI failed:\nstdout:{result.stdout}\nstderr:{result.stderr}"
        assert "Loaded 1 CVE(s)" in result.stdout
        assert "CVE-2026-0001" in result.stdout
        assert "Agent run complete" in result.stdout


def test_cli_no_llm_produces_summary():
    """--no-llm run creates summary.json with expected structure."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cves_file = os.path.join(tmpdir, "cves.txt")
        with open(cves_file, "w") as f:
            f.write("CVE-2026-0002\n")

        workdir = os.path.join(tmpdir, "run_output")
        subprocess.run(
            [sys.executable, "-m", "agent",
             "--cves", cves_file,
             "--workdir", workdir,
             "--no-llm"],
            capture_output=True, timeout=30,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )

        summary_path = os.path.join(workdir, "summary.json")
        assert os.path.exists(summary_path), f"summary.json not found at {summary_path}"

        with open(summary_path) as f:
            summary = json.load(f)
        assert "total_cves" in summary
        assert "results" in summary
        assert summary["total_cves"] == 1
