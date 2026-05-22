"""Planner - decides next action based on CVE state machine."""
import json
import os
from typing import Any, Dict, List, Optional

from agent.state import StateManager, VALID_FINAL_STATUSES


class Planner:
    """Determines next action for each CVE based on its current state."""

    def __init__(self, state_mgr: StateManager):
        self.state_mgr = state_mgr

    def decide_next(self, cve_id: str) -> Dict[str, Any]:
        state = self.state_mgr.get_state(cve_id)
        current = state.get("state", "TaskCreated")

        if state.get("status") in VALID_FINAL_STATUSES:
            return {"action": "done", "reason": "Already in final state", "source": "rule"}

        transitions: Dict[str, Any] = {
            "TaskCreated": {"action": "resolve_cve", "next_state": "CveResolved"},
            "CveResolved": {"action": "fetch_patch", "next_state": "PatchFetched"},
            "PatchFetched": {"action": "analyze_patch", "next_state": "PatchAnalyzed"},
            "PatchAnalyzed": {"action": "check_target", "next_state": "TargetChecked"},
            "TargetChecked": {"action": "apply_patch", "next_state": "PatchApplied"},
            "PatchApplied": {"action": "run_build", "next_state": "BuildRunning"},
            "BuildRunning": {"action": "check_build_result", "next_state": None},
            "BuildSucceeded": {"action": "run_verify", "next_state": "LoadTesting"},
            "BuildFailed": {"action": "classify_failure", "next_state": "FailureClassified"},
            "FailureClassified": self._decide_after_classification,
            "RewritePrepared": {"action": "apply_patch", "next_state": "PatchApplied"},
            "LoadTesting": {"action": "check_verify_result", "next_state": None},
            "VerifyFailed": {"action": "classify_verify_failure", "next_state": "FailureClassified"},
            "Verified": {"action": "write_report", "next_state": "ReportWritten"},
            "ManualRequired": {"action": "done", "next_state": None, "reason": "Manual intervention required"},
            "Failed": {"action": "done", "next_state": None, "reason": "Max attempts reached or unrecoverable"},
        }

        if current in transitions:
            decision = transitions[current]
            if callable(decision):
                return decision(state)
            if decision.get("next_state") is None:
                return {
                    "action": decision["action"],
                    "next_state": decision.get("next_state"),
                    "reason": decision.get("reason", ""),
                    "source": "rule",
                }
            return {
                "action": decision["action"],
                "next_state": decision["next_state"],
                "source": "rule",
            }

        return {"action": "unknown", "reason": f"Unknown state: {current}", "source": "rule"}

    def _decide_after_classification(self, state: Dict) -> Dict:
        """After failure classification, decide: retry with rewrite or give up."""
        attempt = state.get("attempt", 0)
        max_attempts = state.get("max_attempts", 5)

        # Check if failure is non-retryable (e.g., no_fentry, struct_abi)
        cve_id = state.get("cve_id", "")
        if cve_id:
            failure_path = os.path.join(self.state_mgr.workdir, cve_id, "failure.json")
            if os.path.exists(failure_path):
                with open(failure_path) as f:
                    failure = json.load(f)
                if not failure.get("retryable", True):
                    return {
                        "action": "done",
                        "next_state": "ManualRequired",
                        "reason": f"Non-retryable failure: {failure.get('reason_code', 'unknown')}",
                        "source": "rule",
                    }

        if attempt < max_attempts:
            return {"action": "prepare_rewrite", "next_state": "RewritePrepared", "source": "rule"}
        return {
            "action": "done",
            "next_state": "Failed",
            "reason": f"Max attempts ({max_attempts}) reached",
            "source": "rule",
        }

    def get_all_cve_dirs(self) -> List[str]:
        items = os.listdir(self.state_mgr.workdir)
        return [
            d for d in items
            if d.startswith("CVE-") and os.path.isdir(os.path.join(self.state_mgr.workdir, d))
        ]

    def get_active_cves(self) -> List[str]:
        active = []
        for cve_id in self.get_all_cve_dirs():
            state = self.state_mgr.get_state(cve_id)
            if state.get("status") not in VALID_FINAL_STATUSES:
                active.append(cve_id)
        return active


class LLMPlanner(Planner):
    """Planner that optionally consults an LLM for decision points.

    If an `llm_client` is provided and responsive, the planner will query
    the model at key decision points to decide whether to rewrite, retry,
    or escalate to manual. Otherwise it falls back to deterministic rules.
    """

    def __init__(self, state_mgr: StateManager, llm_client: Optional[object] = None, no_llm: bool = False):
        super().__init__(state_mgr)
        self.llm = llm_client
        self.no_llm = no_llm

    def decide_next(self, cve_id: str) -> Dict[str, Any]:
        if self.no_llm or self.llm is None:
            return super().decide_next(cve_id)

        state = self.state_mgr.get_state(cve_id)
        current = state.get("state", "TaskCreated")

        # BuildFailed must be classified first so failure.json exists.
        if current in ("FailureClassified", "VerifyFailed"):
            llm_error = None
            try:
                payload = self._decision_payload(cve_id, state)
                system_msg = (
                    "You are an assistant that decides pipeline actions. "
                    "CRITICAL: you are given attempt history. "
                    "If the SAME failure has occurred multiple times with no improvement, "
                    "you MUST return 'manual_required' (or 'done') — do NOT keep retrying. "
                    "Only return 'prepare_rewrite' (or 'rewrite') if you see a NEW failure "
                    "that a different rewrite strategy could plausibly fix. "
                    "Return a JSON object with keys: decision (required), reason (optional)."
                )
                messages = [
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": json.dumps(payload, indent=2, ensure_ascii=False)},
                ]
                parsed = json.loads(self.llm.chat(messages))
                if isinstance(parsed, dict):
                    mapped = self._map_llm_decision(parsed)
                    if mapped is not None:
                        return mapped
                    llm_error = f"Unrecognised LLM decision: {parsed}"
            except Exception as exc:
                llm_error = f"LLM chat failed: {exc}"

            decision = super().decide_next(cve_id)
            if llm_error:
                decision["llm_error"] = llm_error
            return decision

        return super().decide_next(cve_id)

    def _decision_payload(self, cve_id: str, state: Dict[str, Any]) -> Dict[str, Any]:
        attempt = state.get("attempt", 0)
        max_attempts = state.get("max_attempts", 5)
        cve_dir = os.path.join(self.state_mgr.workdir, cve_id)

        history = []
        for i in range(1, attempt + 1):
            hist_path = os.path.join(cve_dir, f"attempt_{i}.json")
            if not os.path.exists(hist_path):
                continue
            try:
                with open(hist_path) as f:
                    hist = json.load(f)
                failure = hist.get("failure", {})
                history.append({
                    "attempt": hist.get("attempt_index", i),
                    "failure_reason": failure.get("reason_code", "?"),
                    "retryable": failure.get("retryable", True),
                })
            except Exception:
                history.append({"attempt": i, "note": "unreadable"})

        failure_info = {}
        failure_path = os.path.join(cve_dir, "failure.json")
        if os.path.exists(failure_path):
            try:
                with open(failure_path) as f:
                    failure_info = json.load(f)
            except Exception:
                failure_info = {"error": "unreadable failure.json"}

        return {
            "cve_id": cve_id,
            "attempt": attempt,
            "max_attempts": max_attempts,
            "previous_attempts": history,
            "current_failure": failure_info,
        }

    @staticmethod
    def _map_llm_decision(parsed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        decision = str(parsed.get("decision") or parsed.get("action") or "").strip().lower()
        reason = parsed.get("reason", "")

        if decision in {"rewrite", "prepare_rewrite"}:
            return {
                "action": "prepare_rewrite",
                "next_state": "RewritePrepared",
                "reason": reason,
                "source": "llm",
            }

        if decision in {"manual_required", "manual", "stop", "done"}:
            return {
                "action": "done",
                "next_state": "ManualRequired",
                "reason": reason,
                "source": "llm",
            }

        return None
