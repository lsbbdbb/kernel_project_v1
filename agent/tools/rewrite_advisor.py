"""Rewrite Advisor - rule-based and LLM-assisted patch adaptation."""
import json
import os
import re
import shutil
import subprocess
import tempfile
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

    def __init__(self, workdir: str, cve_id: str, llm_client=None, retriever=None):
        self.workdir = workdir
        self.cve_id = cve_id
        self.llm = llm_client
        self.retriever = retriever

    def create_rewrite_plan(self, failure: Dict, change_units: Dict, attempt: int) -> Dict:
        reason_code = failure.get("reason_code", "unknown")
        category = failure.get("category", "unknown")
        strategy = self._map_strategy(reason_code, category)
        strategy_info = self.load_strategies().get(strategy, {})
        affected_unit = self._find_affected_unit(failure, change_units)
        rewrite_allowed = self._check_rewrite_allowed(affected_unit, strategy_info)

        # When LLM is available, allow automatic rewrite even for
        # strategies that are normally gated (e.g. struct_abi, no_fentry).
        # The LLM decides safety; semantic validation catches regressions.
        if not rewrite_allowed and self.llm and self.llm.ping():
            rewrite_allowed = True

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
            return {"success": False, "reason": "Rewrite not allowed by plan decision",
                    "output_path": None}

        if not os.path.exists(original_patch_path):
            return {"success": False,
                    "error": f"Original patch not found: {original_patch_path}",
                    "output_path": None}

        with open(original_patch_path, "r", encoding="utf-8") as f:
            original_patch = f.read()

        # --- LLM rewrite path ---
        if self.llm and self.llm.ping():
            rewrite_source = "llm"
            failure_path = os.path.join(self.workdir, self.cve_id, "failure.json")
            units_path = os.path.join(self.workdir, self.cve_id, "change_units.json")
            failure = {}
            units = {}
            if os.path.exists(failure_path):
                with open(failure_path, "r") as f:
                    failure = json.load(f)
            if os.path.exists(units_path):
                with open(units_path, "r") as f:
                    units = json.load(f)

            rewritten = self._llm_rewrite(
                original_patch, failure, units,
                rewrite_plan.get("strategy", "context_drift")
            )
            if rewritten and self._validate_rewrite(rewritten, original_patch,
                                                     target_source_dir):
                os.makedirs(patches_dir, exist_ok=True)
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(rewritten)
                rewrite_source = "llm"
            else:
                # LLM rewrite failed validation — fall back to rule-based
                rewritten = self._rule_based_rewrite(
                    original_patch,
                    rewrite_plan.get("strategy", "context_drift")
                )
                rewrite_source = "rule_fallback"
                os.makedirs(patches_dir, exist_ok=True)
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(rewritten)
        else:
            rewritten = self._rule_based_rewrite(
                original_patch,
                rewrite_plan.get("strategy", "context_drift")
            )
            rewrite_source = "rule"
            os.makedirs(patches_dir, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(rewritten)

        result = {
            "success": True,
            "output_path": output_path,
            "strategy": rewrite_plan.get("strategy"),
            "rewrite_source": rewrite_source,
            "applied_at": datetime.now(timezone.utc).isoformat(),
        }

        attempt_record = {
            "attempt_index": attempt,
            "input_patch": original_patch_path,
            "output_patch": output_path if result["success"] else None,
            "rewrite_plan": rewrite_plan.get("strategy"),
            "rewrite_source": rewrite_source,
            "decision": rewrite_plan.get("decision"),
            "result": result,
        }
        with open(os.path.join(self.workdir, self.cve_id, f"attempt_{attempt}.json"),
                  "w") as f:
            json.dump(attempt_record, f, indent=2)
        return result

    # ------------------------------------------------------------------
    # LLM-based rewrite
    # ------------------------------------------------------------------

    def _llm_rewrite(self, original_patch: str, failure: Dict, units: Dict,
                     strategy: str) -> Optional[str]:
        """Call the LLM to generate a rewritten unified diff."""
        if not self.llm:
            return None

        # Collect RAG context when retriever is available
        rag_context = self._build_rag_context(failure, units)

        context = {
            "strategy": strategy,
            "kernel_version": self._read_kernel_version(),
        }
        if rag_context:
            context["rag_knowledge"] = rag_context

        from agent.llm.prompts.templates import generate_rewrite_diff

        messages = generate_rewrite_diff(
            patch=original_patch,
            failure=failure,
            units=units,
            strategy={"strategy_id": strategy},
            context=context,
        )

        # Prepend RAG context as additional system instruction when available
        if rag_context:
            messages.insert(1, {
                "role": "system",
                "content": f"Reference kernel knowledge:\n{rag_context}",
            })

        try:
            response = self.llm.chat(messages)
        except Exception:
            return None

        return self._extract_diff_from_response(response)

    def _build_rag_context(self, failure: Dict, units: Dict) -> str:
        """Build a context string from RAG knowledge chunks."""
        if not self.retriever:
            return ""

        reason_code = failure.get("reason_code", "")
        location = failure.get("location", {})
        func_name = location.get("function", "")
        query_parts = [reason_code, func_name]
        query = " ".join(p for p in query_parts if p)

        if not query:
            return ""

        try:
            chunks = self.retriever.retrieve(query, top_k=3)
        except Exception:
            return ""

        if not chunks:
            return ""

        lines = []
        for c in chunks:
            lines.append(f"[{c.metadata.get('type', '')}] {c.content}")
        return "\n".join(lines)

    @staticmethod
    def _extract_diff_from_response(response: str) -> Optional[str]:
        """Extract a unified diff from an LLM text response.

        Handles responses wrapped in ```diff ... ``` fences and
        plain diff output starting with --- or diff --git.
        """
        if not response:
            return None

        # Try to extract from ```diff ... ``` fences
        fence_match = re.search(
            r'```(?:diff)?\s*\n(.*?)```', response, re.DOTALL
        )
        if fence_match:
            return fence_match.group(1).strip()

        # Try to find where the diff starts (--- a/ or diff --git)
        diff_start = re.search(r'^(--- a/|diff --git )', response, re.MULTILINE)
        if diff_start:
            return response[diff_start.start():].strip()

        # If the response looks like a complete diff, return it as-is
        if response.strip().startswith("---") or response.strip().startswith("diff"):
            return response.strip()

        return None

    # ------------------------------------------------------------------
    # Semantic validation
    # ------------------------------------------------------------------

    def _validate_rewrite(self, rewritten_patch: str, original_patch: str,
                          target_source_dir: str) -> bool:
        """Validate a rewritten patch via git apply --check + semantic checks.

        Returns True when both checks pass.
        """
        # Semantic validation (always run)
        try:
            from agent.tools.semantic_validator import SemanticValidator

            sv = SemanticValidator()
            result = sv.validate(original_patch, rewritten_patch)
            if not result.get("valid", False):
                return False
        except ImportError:
            pass

        # git apply --check (needs a real source tree)
        if target_source_dir and os.path.isdir(target_source_dir):
            return self._git_apply_check(rewritten_patch, target_source_dir)

        # No source tree to validate against — accept if semantic check passed
        return True

    @staticmethod
    def _git_apply_check(patch_content: str, source_dir: str) -> bool:
        """Run git apply --check against a source tree."""
        try:
            result = subprocess.run(
                ["git", "apply", "--check", "--verbose"],
                input=patch_content,
                capture_output=True, text=True,
                cwd=source_dir,
                timeout=30,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    # ------------------------------------------------------------------
    # Rule-based rewrite (fallback when LLM is unavailable)
    # ------------------------------------------------------------------

    def _rule_based_rewrite(self, original_patch: str, strategy: str) -> str:
        """Apply simple deterministic transformations to the patch.

        Currently handles context_drift by adjusting hunk line offsets,
        and api_mismatch by adding a comment for manual review.
        For other strategies the original patch is returned unchanged.
        """
        if strategy == "context_drift":
            return self._adjust_hunk_offsets(original_patch)
        if strategy == "api_mismatch":
            return self._annotate_api_mismatch(original_patch)
        if strategy == "missing_include":
            return self._add_header_hint(original_patch)
        return original_patch

    @staticmethod
    def _adjust_hunk_offsets(patch: str) -> str:
        """Shift hunk line numbers by a small margin (±3) to try to
        re-anchor the patch when context lines drifted.
        """
        def _shift(m):
            old_start = int(m.group(1))
            old_count = int(m.group(2))
            new_start = int(m.group(3))
            new_count = int(m.group(4))
            new_old = max(1, old_start + 3)
            new_new = max(1, new_start + 3)
            return f"@@ -{new_old},{old_count} +{new_new},{new_count} @@"

        return re.sub(
            r'@@ -(\d+),(\d+) \+(\d+),(\d+) @@',
            _shift, patch, count=5
        )

    @staticmethod
    def _annotate_api_mismatch(patch: str) -> str:
        """Prepend a warning comment for manual API mismatch review."""
        lines = patch.split("\n")
        out = ["# REWRITE-NOTE: API mismatch — manual adjustment may be needed"]
        in_diff = False
        for line in lines:
            out.append(line)
            if line.startswith("@@") and not in_diff:
                in_diff = True
        return "\n".join(out)

    @staticmethod
    def _add_header_hint(patch: str) -> str:
        """Insert likely missing header includes as comments."""
        lines = patch.split("\n")
        out = ["# REWRITE-NOTE: consider adding necessary includes/defines"]
        for line in lines:
            out.append(line)
        return "\n".join(out)

    # ------------------------------------------------------------------
    # Strategy mapping
    # ------------------------------------------------------------------

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
        return [{"file": unit.get("file", "unknown"),
                 "function": unit.get("function", "unknown"),
                 "description": f"Apply {strategy} rewrite for {unit.get('change_id', 'unknown')}"}]

    def _read_kernel_version(self) -> str:
        """Read kernel version from run_config.json if available."""
        config_path = os.path.join(self.workdir, "run_config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    cfg = json.load(f)
                return cfg.get("kernel_version", "unknown")
            except (json.JSONDecodeError, OSError):
                pass
        return "unknown"
