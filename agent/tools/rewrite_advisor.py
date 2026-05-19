"""Rewrite Advisor - rule-based and LLM-assisted patch adaptation."""
import json
import os
import re
import shutil
from datetime import datetime, timezone
from typing import Dict, List, Optional

from agent.knowledge.loader import KnowledgeLoader


class RewriteAdvisor:
    """Advise and generate patch rewrites for target kernel adaptation."""

    _strategies_cache: Dict[str, Dict] = {}

    @classmethod
    def load_strategies(cls) -> Dict[str, Dict]:
        if cls._strategies_cache:
            return cls._strategies_cache
        strategies = KnowledgeLoader.load_rewrite_strategies()
        if strategies:
            cls._strategies_cache = strategies
        else:
            cls._strategies_cache = cls._hardcoded_strategies()
        return cls._strategies_cache

    @staticmethod
    def _hardcoded_strategies() -> Dict[str, Dict]:
        return {
        "context_drift": {
            "description": "Context lines changed, function still exists",
            "auto_allowed": True,
            "semantic_guard": ["security_check_must_keep", "error_return_must_keep"],
        },
        "api_mismatch": {
            "description": "Function signature differs (parameter count/type)",
            "auto_allowed": True,
            "semantic_guard": ["security_check_must_keep", "error_return_must_keep"],
        },
        "missing_include": {
            "description": "Missing header or macro definition",
            "auto_allowed": True,
            "semantic_guard": ["must_not_change_fix_logic"],
        },
        "no_fentry": {
            "description": "Function not traceable, need caller hook",
            "auto_allowed": False,
            "semantic_guard": ["must_not_broaden_fix_scope"],
        },
        "struct_abi": {
            "description": "Structure layout changes - high risk",
            "auto_allowed": False,
            "semantic_guard": [],
        },
    }

    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id

    def create_rewrite_plan(self, failure: Dict, change_units: Dict, attempt: int) -> Dict:
        reason_code = failure.get("reason_code", "unknown")
        category = failure.get("category", "unknown")
        strategy = self._map_strategy(reason_code, category)
        strategy_info = self.load_strategies().get(strategy, {})
        affected_unit = self._find_affected_unit(failure, change_units)
        rewrite_allowed = self._check_rewrite_allowed(affected_unit, strategy_info)
        plan = {
            "attempt_index": attempt,
            "source": "rule",
            "input_failure": "failure.json",
            "target_change_id": affected_unit.get("change_id", "CU-001") if affected_unit else None,
            "decision": "rewrite" if rewrite_allowed else "manual_required",
            "strategy": strategy,
            "semantic_must_keep": strategy_info.get("semantic_guard", []),
            "planned_edits": self._generate_planned_edits(affected_unit, strategy),
            "validation_required": ["git apply --check", "kpatch-build"],
            "plan_created_at": datetime.now(timezone.utc).isoformat(),
        }
        cve_dir = os.path.join(self.workdir, self.cve_id)
        with open(os.path.join(cve_dir, "rewrite_plan.json"), "w") as f:
            json.dump(plan, f, indent=2, ensure_ascii=False)
        return plan

    def apply_rewrite(self, original_patch_path: str, rewrite_plan: Dict,
                      target_source_dir: str, attempt: int) -> Dict:
        patches_dir = os.path.join(self.workdir, self.cve_id, "patches")
        output_path = os.path.join(patches_dir, f"attempt_{attempt}.patch")
        if rewrite_plan.get("decision") != "rewrite":
            return {"success": False, "reason": "Rewrite not allowed by plan decision", "output_path": None}
        if os.path.exists(original_patch_path):
            shutil.copy2(original_patch_path, output_path)
            result = {"success": True, "output_path": output_path, "strategy": rewrite_plan.get("strategy"),
                      "applied_at": datetime.now(timezone.utc).isoformat()}
        else:
            result = {"success": False, "error": f"Original patch not found: {original_patch_path}", "output_path": None}
        attempt_record = {
            "attempt_index": attempt, "input_patch": original_patch_path,
            "output_patch": output_path if result["success"] else None,
            "rewrite_plan": rewrite_plan.get("strategy"),
            "decision": rewrite_plan.get("decision"), "result": result,
        }
        with open(os.path.join(self.workdir, self.cve_id, f"attempt_{attempt}.json"), "w") as f:
            json.dump(attempt_record, f, indent=2)
        return result

    def _map_strategy(self, reason_code: str, category: str) -> str:
        mapping = {
            "hunk_failed": "context_drift", "api_mismatch": "api_mismatch",
            "missing_api_or_include": "missing_include", "no_fentry": "no_fentry",
            "struct_or_data_change": "struct_abi", "field_mismatch": "struct_abi",
            "undefined_symbol": "missing_include",
        }
        return mapping.get(reason_code, "context_drift")

    def _find_affected_unit(self, failure: Dict, change_units: Dict) -> Optional[Dict]:
        location = failure.get("location", {})
        failed_file = location.get("file", "")
        failed_func = location.get("function", "")
        for unit in change_units.get("units", []):
            if failed_func and failed_func in unit.get("function", ""):
                return unit
            if failed_file and failed_file in unit.get("file", ""):
                return unit
        if change_units.get("units"):
            return change_units["units"][0]
        return None

    def _check_rewrite_allowed(self, unit: Optional[Dict], strategy_info: Dict) -> bool:
        if not unit:
            return False
        if not unit.get("rewrite_allowed", True):
            return False
        if not strategy_info.get("auto_allowed", False):
            return False
        return True

    def _generate_planned_edits(self, unit: Optional[Dict], strategy: str) -> List[Dict]:
        if not unit:
            return []
        return [{"file": unit.get("file", "unknown"), "function": unit.get("function", "unknown"),
                 "description": f"Apply {strategy} rewrite for {unit.get('change_id', 'unknown')}"}]
