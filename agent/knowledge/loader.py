"""YAML knowledge loader — loads failure patterns and rewrite strategies from YAML files.

Normalizes YAML fields to the Python code's expected format, with hardcoded
values in the calling modules serving as fallback when YAML is unavailable.
"""
import os
from typing import Dict, List

import yaml


class KnowledgeLoader:
    """Load and cache failure patterns and rewrite strategies from YAML files."""

    _failure_patterns: List[Dict] = []
    _rewrite_strategies: Dict[str, Dict] = {}
    _loaded: bool = False

    @classmethod
    def _rules_dir(cls) -> str:
        return os.path.join(os.path.dirname(__file__), "rules")

    @classmethod
    def load_failure_patterns(cls) -> List[Dict]:
        if cls._failure_patterns:
            return cls._failure_patterns
        path = os.path.join(cls._rules_dir(), "failure_patterns.yaml")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or []
        patterns = []
        for item in raw:
            pattern = cls._normalize_failure_pattern(item)
            patterns.append(pattern)
        cls._failure_patterns = patterns
        return patterns

    @classmethod
    def load_rewrite_strategies(cls) -> Dict[str, Dict]:
        if cls._rewrite_strategies:
            return cls._rewrite_strategies
        path = os.path.join(cls._rules_dir(), "rewrite_strategies.yaml")
        if not os.path.exists(path):
            return {}
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or []
        strategies = {}
        for item in raw:
            strategy_id, strategy = cls._normalize_rewrite_strategy(item)
            strategies[strategy_id] = strategy
        cls._rewrite_strategies = strategies
        return strategies

    @staticmethod
    def _derived_stage(pattern_id: str) -> str:
        """Derive the pipeline stage from the pattern_id prefix."""
        if pattern_id.startswith("apply."):
            return "apply"
        if pattern_id.startswith("compile."):
            return "build"
        if pattern_id.startswith("kpatch."):
            return "build"
        if pattern_id.startswith("env."):
            return "env_check"
        return "unknown"

    @staticmethod
    def _action_to_fields(action: str):
        """Map YAML action string to Python retryable + next_action fields."""
        mapping = {
            "rewrite": (True, "rewrite"),
            "manual_required": (False, "manual_required"),
            "fix_environment": (False, "fix_environment"),
        }
        return mapping.get(action, (False, "manual_required"))

    @classmethod
    def _normalize_failure_pattern(cls, item: Dict) -> Dict:
        retryable, next_action = cls._action_to_fields(item.get("action", "manual_required"))
        return {
            "pattern_id": item["pattern_id"],
            "stage": cls._derived_stage(item["pattern_id"]),
            "category": item.get("category", "unknown"),
            "reason_code": item.get("reason_code", "unknown"),
            "matchers": item.get("matchers", []),
            "retryable": retryable,
            "next_action": next_action,
        }

    @staticmethod
    def _normalize_rewrite_strategy(item: Dict):
        strategy_id = item["strategy_id"]
        strategy = {
            "description": item.get("description", ""),
            "auto_allowed": item.get("allowed", False),
            "semantic_guard": item.get("semantic_guards", []),
        }
        return strategy_id, strategy
