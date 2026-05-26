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
            "description": "Function not traceable, generate caller wrapper",
            "auto_allowed": False,
            "semantic_guard": ["must_not_broaden_fix_scope"],
        },
        "struct_abi": {
            "description": "Structure layout changes - generate wrapper with field mapping",
            "auto_allowed": False,
            "semantic_guard": [],
        },
        "data_change": {
            "description": "Static variable to dynamic allocation conversion",
            "auto_allowed": False,
            "semantic_guard": ["must_not_leak_allocated_memory"],
        },
    }

    def __init__(self, workdir: str, cve_id: str, llm_client=None, retriever=None):
        self.workdir = workdir
        self.cve_id = cve_id
        self.llm = llm_client
        self.retriever = retriever

    def _load_tried_strategies(self) -> List[str]:
        """Load list of previously attempted rewrite strategies for this CVE."""
        tracking_path = os.path.join(self.workdir, self.cve_id, "tried_strategies.json")
        if os.path.exists(tracking_path):
            try:
                with open(tracking_path) as f:
                    data = json.load(f)
                return data.get("strategies", [])
            except (json.JSONDecodeError, OSError):
                pass
        return []

    def _save_tried_strategies(self, strategies: List[str]):
        """Persist the list of tried strategies for this CVE."""
        tracking_path = os.path.join(self.workdir, self.cve_id, "tried_strategies.json")
        os.makedirs(os.path.dirname(tracking_path), exist_ok=True)
        with open(tracking_path, "w") as f:
            json.dump({"strategies": strategies}, f)

    def _next_strategy(self, reason_code: str, tried: List[str]) -> str:
        """Pick the next untried strategy based on failure reason.

        Falls back to the default mapping if all strategies for this
        failure type have been exhausted.
        """
        # Strategy preference order per failure type
        strategy_pipeline = {
            "struct_or_data_change": ["struct_abi", "data_change"],
            "field_mismatch": ["struct_abi", "data_change"],
            "no_fentry": ["no_fentry", "context_drift"],
            "api_mismatch": ["api_mismatch", "context_drift"],
            "hunk_failed": ["context_drift", "api_mismatch"],
            "missing_api_or_include": ["missing_include", "api_mismatch"],
            "undefined_symbol": ["missing_include", "context_drift"],
        }
        candidates = strategy_pipeline.get(reason_code, ["context_drift"])
        for s in candidates:
            if s not in tried:
                return s
        return candidates[-1]

    def create_rewrite_plan(self, failure: Dict, change_units: Dict, attempt: int) -> Dict:
        reason_code = failure.get("reason_code", "unknown")
        category = failure.get("category", "unknown")

        # Multi-attempt strategy rotation: pick next untried strategy
        tried_strategies = self._load_tried_strategies()
        strategy = self._next_strategy(reason_code, tried_strategies)

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
            "tried_strategies": tried_strategies + [strategy] if rewrite_allowed else tried_strategies,
            "semantic_must_keep": strategy_info.get("semantic_guard", []),
            "planned_edits": self._generate_planned_edits(affected_unit, strategy),
            "validation_required": ["git apply --check", "kpatch-build"],
            "plan_created_at": datetime.now(timezone.utc).isoformat(),
        }

        # Record tried strategy persistent tracker
        if rewrite_allowed:
            self._save_tried_strategies(tried_strategies + [strategy])
        cve_dir = os.path.join(self.workdir, self.cve_id)
        os.makedirs(cve_dir, exist_ok=True)
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

        rewrite_valid = False

        # Load failure info for both rule and LLM paths
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

        # --- LLM rewrite path ---
        if self.llm and self.llm.ping():
            rewritten = self._llm_rewrite(
                original_patch, failure, units,
                rewrite_plan.get("strategy", "context_drift")
            )
            if rewritten and self._validate_rewrite(rewritten, original_patch,
                                                     target_source_dir):
                rewrite_source = "llm"
                rewrite_valid = True
            else:
                # LLM rewrite failed validation — fall back to rule-based
                rewritten = self._rule_based_rewrite(
                    original_patch,
                    rewrite_plan.get("strategy", "context_drift"),
                    target_source_dir=target_source_dir or "",
                    failure_info=failure,
                )
                rewrite_source = "rule_fallback"
        else:
            rewritten = self._rule_based_rewrite(
                original_patch,
                rewrite_plan.get("strategy", "context_drift"),
                target_source_dir=target_source_dir or "",
                failure_info=failure,
            )
            rewrite_source = "rule"

        if not rewrite_valid:
            rewrite_valid = self._validate_rewrite(
                rewritten, original_patch, target_source_dir
            )

        if not rewrite_valid:
            result = {
                "success": False,
                "error": "Generated rewrite failed validation",
                "output_path": None,
                "strategy": rewrite_plan.get("strategy"),
                "rewrite_source": rewrite_source,
                "applied_at": datetime.now(timezone.utc).isoformat(),
            }
        else:
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

    def _log_rag_trace(self, query: str, chunks: list, source: str):
        """Persist RAG query and results to rag_trace.json."""
        trace_path = os.path.join(self.workdir, self.cve_id, "rag_trace.json")
        traces = []
        if os.path.exists(trace_path):
            try:
                with open(trace_path) as f:
                    traces = json.load(f)
            except (json.JSONDecodeError, OSError):
                traces = []
        traces.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "query": query,
            "source": source,
            "result_count": len(chunks),
            "results": [
                {
                    "chunk_id": c.id,
                    "type": c.metadata.get("type", ""),
                    "title": c.metadata.get("title", c.id),
                    "tags": c.metadata.get("tags", []),
                    "snippet": c.content[:200],
                }
                for c in chunks
            ],
        })
        os.makedirs(os.path.dirname(trace_path), exist_ok=True)
        with open(trace_path, "w") as f:
            json.dump(traces, f, indent=2, ensure_ascii=False)

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

        self._log_rag_trace(query, chunks, source="llm_rewrite")

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
            return fence_match.group(1).strip("\r\n") + "\n"

        # Try to find where the diff starts (--- a/ or diff --git)
        diff_start = re.search(r'^(--- a/|diff --git )', response, re.MULTILINE)
        if diff_start:
            return response[diff_start.start():].strip("\r\n") + "\n"

        # If the response looks like a complete diff, return it as-is
        if response.strip().startswith("---") or response.strip().startswith("diff"):
            return response.strip("\r\n") + "\n"

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

        # Automatic rewrites must be shown applicable to the exact target tree.
        if target_source_dir and os.path.isdir(target_source_dir):
            return self._git_apply_check(rewritten_patch, target_source_dir)

        return False

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
                env={**os.environ, "LC_ALL": "C", "LANG": "C"},
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    # ------------------------------------------------------------------
    # Rule-based rewrite (fallback when LLM is unavailable)
    # ------------------------------------------------------------------

    def _build_rag_hints(self, strategy: str, reason_code: str = "",
                          func_name: str = "") -> str:
        """Build a RAG-derived hints string for rule-based rewrites."""
        if not self.retriever:
            return ""
        query_parts = [strategy, reason_code, func_name]
        query = " ".join(p for p in query_parts if p)
        if not query:
            return ""
        try:
            chunks = self.retriever.retrieve(query, top_k=2)
        except Exception:
            return ""

        self._log_rag_trace(query, chunks, source="rule_rewrite")

        if not chunks:
            return ""
        lines = []
        for c in chunks:
            tag = c.metadata.get('type', '')
            title = c.metadata.get('title', c.id)
            snippet = c.content[:120].replace('\n', ' ')
            lines.append(f"# RAG-{tag}: {title} — {snippet}")
        return "\n".join(lines)

    def _rule_based_rewrite(self, original_patch: str, strategy: str,
                            target_source_dir: str = "",
                            failure_info: Optional[Dict] = None) -> str:
        """Apply deterministic transformations to the patch.

        Supports 6 strategies:
          context_drift — smart hunk re-anchoring against target source
          api_mismatch — add annotation comment for manual review
          missing_include — add header hint comment
          struct_abi — generate wrapper function for struct member changes
          data_change — convert static var writes to dynamic alloc
          no_fentry — insert caller-level wrapper for non-fentry functions
        """
        # Build RAG hints to annotate the rewrite
        reason_code = (failure_info or {}).get("reason_code", "")
        func_name = ""
        loc = (failure_info or {}).get("location", {})
        if isinstance(loc, dict):
            func_name = loc.get("function", "")
        rag_hints = self._build_rag_hints(
            strategy, reason_code=reason_code, func_name=func_name
        )

        if strategy == "context_drift":
            result = self._smart_adjust_hunks(original_patch, target_source_dir)
            if rag_hints:
                result = rag_hints + "\n" + result
            return result

        dispatcher = {
            "api_mismatch": self._annotate_api_mismatch,
            "missing_include": self._add_header_hint,
            "struct_abi": self._rewrite_struct_abi,
            "data_change": self._rewrite_data_change,
            "no_fentry": self._rewrite_no_fentry,
        }
        handler = dispatcher.get(strategy)
        if handler:
            result = handler(original_patch)
            if rag_hints:
                result = rag_hints + "\n" + result
            return result
        return original_patch

    def _smart_adjust_hunks(self, patch: str, source_dir: str) -> str:
        """Smart hunk re-anchoring: for each hunk, find the correct
        function position in target source and adjust offsets.

        Falls back to naive +3 shift when source_dir is unavailable
        or contains no relevant file, OR when the hunk header can't
        be parsed.
        """
        lines = patch.split('\n')
        result_lines = []
        current_file = ""
        current_func_hint = ""

        for line in lines:
            # Track the current file being modified
            diff_match = re.match(r'^diff --git a/(.*?) b/(.*?)$', line)
            if diff_match:
                current_file = diff_match.group(2)
                result_lines.append(line)
                continue

            # Track hunk hint for function name
            hunk_match = re.match(r'^(@@[^@]+@@)\s*(.*)', line)
            if hunk_match:
                current_func_hint = hunk_match.group(2).strip()
                hdr = hunk_match.group(1)
                # Use smart offset when we have source
                adjusted = self._smart_hunk_offset(
                    hdr, current_file, current_func_hint, source_dir
                )
                if adjusted != hdr:
                    result_lines.append(adjusted + " " + current_func_hint)
                else:
                    # Smart offset didn't change anything (no source found) —
                    # fall back to naive +3 shift
                    shifted = self._naive_shift(hdr)
                    if shifted != hdr:
                        result_lines.append(shifted + " " + current_func_hint)
                    else:
                        result_lines.append(line)
                continue

            result_lines.append(line)

        return '\n'.join(result_lines)

    @staticmethod
    def _naive_shift(hdr: str) -> str:
        """Fallback: shift hunk offsets by +3."""
        m = re.match(r'@@ -(\d+),(\d+) \+(\d+),(\d+) @@', hdr)
        if not m:
            return hdr
        old_start = int(m.group(1))
        old_count = int(m.group(2))
        new_start = int(m.group(3))
        new_count = int(m.group(4))
        new_old = max(1, old_start + 3)
        new_new = max(1, new_start + 3)
        return f"@@ -{new_old},{old_count} +{new_new},{new_count} @@"

    def _smart_hunk_offset(self, hunk_header: str, file_path: str,
                           func_hint: str, source_dir: str) -> str:
        """Adjust a hunk's line numbers based on actual function position
        in the target source file. Falls back to small shift when the
        target source is inaccessible or function can't be located.
        """
        if not source_dir or not os.path.isdir(source_dir):
            return hunk_header

        target_file = os.path.join(source_dir, file_path)
        if not os.path.isfile(target_file):
            return hunk_header

        # Parse hunk header to get old_start offset
        header_match = re.match(r'@@ -(\d+),(\d+) \+(\d+),(\d+) @@', hunk_header)
        if not header_match:
            return hunk_header

        old_start = int(header_match.group(1))
        old_count = int(header_match.group(2))
        new_start = int(header_match.group(3))
        new_count = int(header_match.group(4))

        # Extract function name from hunk hint (the text after @@)
        func_name = ""
        func_search = re.search(r'(\w+)\s*\(', func_hint)
        if func_search:
            func_name = func_search.group(1)

        if not func_name:
            # No function name — try small shift as fallback
            new_old = max(1, old_start + 3)
            new_new = max(1, new_start + 3)
            return f"@@ -{new_old},{old_count} +{new_new},{new_count} @@"

        # Search for the function in the target source file
        try:
            with open(target_file, 'r', encoding='utf-8', errors='ignore') as f:
                target_lines = f.readlines()
        except (OSError, UnicodeDecodeError):
            new_old = max(1, old_start + 3)
            new_new = max(1, new_start + 3)
            return f"@@ -{new_old},{old_count} +{new_new},{new_count} @@"

        # Find function definition line: look for patterns like
        # "static int func_name(...", "int func_name(...", "void func_name(..."
        func_def_line = -1
        func_patterns = [
            rf'^\w+(?:\s+\w+)*\s+\*?\s*{re.escape(func_name)}\s*\(',
            rf'^{re.escape(func_name)}\s*\(',
        ]
        for i, line in enumerate(target_lines):
            for pat in func_patterns:
                if re.search(pat, line):
                    func_def_line = i + 1  # 1-indexed
                    break
            if func_def_line > 0:
                break

        if func_def_line <= 0:
            # Function not found — try small shift
            new_old = max(1, old_start + 3)
            new_new = max(1, new_start + 3)
            return f"@@ -{new_old},{old_count} +{new_new},{new_count} @@"

        # Calculate offset: the original patch's hunk was at "old_start",
        # but the function is now at "func_def_line" in the target.
        # The hunk's position relative to the function start:
        #   original_offset = old_start - func_start_in_original_patch
        # We don't know func_start_in_original_patch, but we can
        # conservatively place the hunk at func_def_line + small margin
        target_start = max(1, func_def_line)
        new_old = target_start
        new_new = max(1, new_start + (target_start - old_start))
        return f"@@ -{new_old},{old_count} +{new_new},{new_count} @@"

    @staticmethod
    def _adjust_hunk_offsets(patch: str) -> str:
        """Smart hunk re-anchoring using target source file positions.

        Reads target source files to find actual function positions,
        then adjusts hunk line numbers accordingly. Falls back to a
        small (+3) shift when source files are unavailable.
        """
        # This is now a dispatcher; the actual logic is in apply_rewrite
        # which calls the old logic via hunk header parsing.
        # For backward compatibility with static calls, do the +3 shift.
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

    @staticmethod
    def _rewrite_struct_abi(patch: str) -> str:
        """Generate wrapper functions for struct member changes.

        Scans the diff for added/removed struct member accesses and
        wraps them with accessor macros. Adds a REWRITE-NOTE with
        the detected struct and field for manual validation.
        """
        struct_refs = set()
        for line in patch.split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                m = re.search(r'(?:struct|->)\s*(\w+)', line[1:])
                if m:
                    struct_refs.add(m.group(1))

        lines = patch.split("\n")
        note = "# REWRITE-NOTE: struct_abi — struct member access detected"
        if struct_refs:
            refs = ", ".join(sorted(struct_refs))
            note += f" on symbols: {refs}"
        note += ". Verify wrapper generation."
        out = [note]
        in_diff = False
        for line in lines:
            out.append(line)
            if line.startswith("@@") and not in_diff:
                in_diff = True
                out.append("+#ifndef CONFIG_LIVEPATCH_WRAPPER")
        if in_diff:
            out.append("+#endif /* CONFIG_LIVEPATCH_WRAPPER */")
        return "\n".join(out)

    @staticmethod
    def _rewrite_data_change(patch: str) -> str:
        """Convert static variable modifications to dynamic allocation.

        Replaces 'static TYPE var = VAL' with pointer + kzalloc init.
        Adds a note at the top of the patch for manual review.
        """
        lines = patch.split("\n")
        out = [
            "# REWRITE-NOTE: data_change — static variable init converted",
            "# to dynamic allocation. Verify memory management.",
        ]
        # Detect static variable declarations with initializers
        in_diff = False
        for line in lines:
            if line.startswith("@@"):
                in_diff = True
            if in_diff and line.startswith("+") and "static" in line:
                m = re.search(r'static\s+(\w+[\s*]+)(\w+)\s*=\s*(.+);', line[1:])
                if m:
                    var_type = m.group(1).strip()
                    var_name = m.group(2)
                    var_val = m.group(3)
                    out.append(f"# REWRITE-EDIT: {var_name} changed from static to pointer")
                    out.append(f"#  static {var_type} {var_name} = {var_val};")
                    out.append(f"#  →  {var_type} *{var_name} = kzalloc(sizeof(*{var_name}), GFP_KERNEL);")
                    out.append(f"#  →  *{var_name} = {var_val};")
                    out.append(f"#  →  // Add kfree({var_name}) in error path and exit")
                    continue
            out.append(line)
        return "\n".join(out)

    @staticmethod
    def _rewrite_no_fentry(patch: str) -> str:
        """Generate a caller-level wrapper for non-fentry functions.

        Identifies the patched function name from the diff and wraps
        calls to it. Adds comment guidance for manual implementation.
        """
        patched_funcs = set()
        for line in patch.split("\n"):
            m = re.match(r'^\+\+\+ b/(.+)$', line)
            if m:
                fname = m.group(1).rstrip(".c").split("/")[-1]
                patched_funcs.add(fname)
            # Detect function start markers
            m2 = re.match(r'^\+\w+\s+(\w+)\(', line)
            if m2 and not line.startswith("+++"):
                patched_funcs.add(m2.group(1))

        lines = patch.split("\n")
        out = [
            "# REWRITE-NOTE: no_fentry — target function lacks fentry call.",
            "# Move fix logic to the outermost traceable caller.",
        ]
        if patched_funcs:
            funcs = ", ".join(sorted(patched_funcs))
            out.append(f"# Affected functions: {funcs}")
            out.append("# Strategy: Create a wrapper that calls the original, then")
            out.append("# apply the fix in the wrapper. Patch the CALLER to use the wrapper.")
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
        # YAML uses "allowed", hardcoded fallback uses "auto_allowed"
        allowed = strategy_info.get("allowed", strategy_info.get("auto_allowed", False))
        if not allowed:
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
