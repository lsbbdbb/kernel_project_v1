"""Prompt templates for LLM-assisted livepatch decisions."""
import json
from typing import Any, Dict, List


SYSTEM_PROMPT = (
    "You are assisting a Linux kernel livepatch pipeline. "
    "Use only the supplied evidence, preserve security semantics, and return "
    "machine-readable output when requested."
)


def _json_block(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)


def diagnose_failure(build_log: str, patch_ir: Dict) -> List[Dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Diagnose this kpatch-build failure. Return JSON with keys: "
                "category, reason_code, evidence, recommended_action.\n\n"
                f"patch_ir:\n{_json_block(patch_ir)}\n\n"
                f"build_log:\n{build_log[-6000:]}"
            ),
        },
    ]


def plan_rewrite_strategy(failure: Dict, change_units: Dict, history: List[Dict]) -> List[Dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Plan a safe rewrite strategy. Return JSON with keys: "
                "decision, strategy, target_change_id, semantic_must_keep, "
                "planned_edits, validation_plan.\n\n"
                f"failure:\n{_json_block(failure)}\n\n"
                f"change_units:\n{_json_block(change_units)}\n\n"
                f"history:\n{_json_block(history)}"
            ),
        },
    ]


def generate_rewrite_diff(
    patch: str,
    failure: Dict,
    units: Dict,
    strategy: Dict,
    context: Dict,
) -> List[Dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Generate a rewritten unified diff only. Do not include markdown. "
                "Preserve the security fix semantics and avoid unrelated edits.\n\n"
                f"failure:\n{_json_block(failure)}\n\n"
                f"units:\n{_json_block(units)}\n\n"
                f"strategy:\n{_json_block(strategy)}\n\n"
                f"context:\n{_json_block(context)}\n\n"
                f"original_patch:\n{patch}"
            ),
        },
    ]


def decide_retry(state: Dict, failure: Dict, attempt: int, max_attempts: int) -> List[Dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Decide whether to retry, rewrite, stop, or require manual review. "
                "Return JSON with keys: decision, reason, next_action.\n\n"
                f"attempt: {attempt}\n"
                f"max_attempts: {max_attempts}\n\n"
                f"state:\n{_json_block(state)}\n\n"
                f"failure:\n{_json_block(failure)}"
            ),
        },
    ]
