"""Failure Classifier - classifies build failures from logs into structured categories."""
import json
import os
import re
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timezone

from agent.knowledge.loader import KnowledgeLoader


class FailureClassifier:
    """Classify kpatch-build failures from build logs."""

    _patterns_cache: List[Dict] = []

    @classmethod
    def load_patterns(cls) -> List[Dict]:
        if cls._patterns_cache:
            return cls._patterns_cache
        patterns = KnowledgeLoader.load_failure_patterns()
        if patterns:
            cls._patterns_cache = patterns
        else:
            cls._patterns_cache = cls._hardcoded_patterns()
        return cls._patterns_cache

    @staticmethod
    def _hardcoded_patterns() -> List[Dict]:
        return [
        {
            "pattern_id": "apply.reversed_patch", "stage": "apply",
            "category": "kpatch_limit", "reason_code": "already_backported",
            "matchers": [r"Reversed \(or previously applied\) patch detected",
                         r"hunks ignored"],
            "retryable": False, "next_action": "manual_required",
        },
        {
            "pattern_id": "apply.hunk_failed", "stage": "apply",
            "category": "patch_apply", "reason_code": "hunk_failed",
            "matchers": [r"hunk FAILED", r"patch does not apply",
                         r"error: patch failed", r"fuzz", r"file failed to apply"],
            "retryable": True, "next_action": "rewrite",
        },
        {
            "pattern_id": "apply.file_missing", "stage": "apply",
            "category": "patch_apply", "reason_code": "file_missing",
            "matchers": [r"No such file or directory", r"cannot find file"],
            "retryable": False, "next_action": "manual_required",
        },
        {
            "pattern_id": "compile.api_args", "stage": "build",
            "category": "compile", "reason_code": "api_mismatch",
            "matchers": [r"too many arguments to function", r"too few arguments to function",
                         r"error: passing argument"],
            "retryable": True, "next_action": "rewrite",
        },
        {
            "pattern_id": "compile.implicit_decl", "stage": "build",
            "category": "compile", "reason_code": "missing_api_or_include",
            "matchers": [r"implicit declaration of function", r"error: implicit declaration"],
            "retryable": True, "next_action": "rewrite",
        },
        {
            "pattern_id": "compile.unknown_field", "stage": "build",
            "category": "compile", "reason_code": "field_mismatch",
            "matchers": [r"has no member named"],
            "retryable": False, "next_action": "manual_required",
        },
        {
            "pattern_id": "kpatch.no_fentry", "stage": "build",
            "category": "kpatch_limit", "reason_code": "no_fentry",
            "matchers": [r"no fentry call", r"function is not traceable"],
            "retryable": False, "next_action": "manual_required",
        },
        {
            "pattern_id": "kpatch.data_change", "stage": "build",
            "category": "kpatch_limit", "reason_code": "struct_or_data_change",
            "matchers": [r"data structure layout change", r"static variable changed",
                         r"unreconcilable difference", r"section change"],
            "retryable": False, "next_action": "manual_required",
        },
        {
            "pattern_id": "env.no_vmlinux", "stage": "env_check",
            "category": "env_missing", "reason_code": "missing_vmlinux",
            "matchers": [r"vmlinux not found", r"cannot find vmlinux", r"ERROR:.*vmlinux"],
            "retryable": False, "next_action": "fix_environment",
        },
        {
            "pattern_id": "compile.undefined_symbol", "stage": "build",
            "category": "compile", "reason_code": "undefined_symbol",
            "matchers": [r"undefined reference", r"undefined symbol"],
            "retryable": True, "next_action": "rewrite",
        },
    ]

    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id

    def classify(self, build_log_path: str, attempt: int = 1) -> Dict:
        if not os.path.exists(build_log_path):
            failure = {
                "stage": "unknown", "category": "unknown",
                "reason_code": "log_not_found", "retryable": False,
                "next_action": "manual_required",
                "error": f"Build log not found: {build_log_path}"
            }
            cve_dir = os.path.join(self.workdir, self.cve_id)
            with open(os.path.join(cve_dir, "failure.json"), "w") as f:
                json.dump(failure, f, indent=2, ensure_ascii=False)
            return failure
        with open(build_log_path) as f:
            log_content = f.read()
        for pattern in self.load_patterns():
            for matcher in pattern["matchers"]:
                match = re.search(matcher, log_content, re.IGNORECASE)
                if match:
                    location = self._extract_location(log_content, match)
                    signals = [{
                        "pattern": matcher,
                        "signal": match.group(0),
                        "source": build_log_path,
                        "line_start": self._find_line_number(log_content, match.start()),
                    }]
                    failure = {
                        "stage": pattern["stage"], "category": pattern["category"],
                        "reason_code": pattern["reason_code"],
                        "severity": "medium", "classifier": "rule",
                        "retryable": pattern["retryable"],
                        "next_action": pattern["next_action"],
                        "summary": f"Matched error pattern: {pattern['pattern_id']}",
                        "signals": signals, "location": location,
                        "related_inputs": {"build_log": build_log_path},
                        "classified_at": datetime.now(timezone.utc).isoformat(),
                    }
                    cve_dir = os.path.join(self.workdir, self.cve_id)
                    with open(os.path.join(cve_dir, "failure.json"), "w") as f:
                        json.dump(failure, f, indent=2, ensure_ascii=False)
                    return failure
        failure = {
            "stage": "unknown", "category": "unknown",
            "reason_code": "unrecognized", "severity": "high",
            "classifier": "rule", "retryable": False,
            "next_action": "manual_required",
            "summary": "Build failure not recognized by any rule pattern",
            "signals": [{"pattern": "unrecognized", "source": build_log_path}],
            "location": {}, "related_inputs": {"build_log": build_log_path},
            "classified_at": datetime.now(timezone.utc).isoformat(),
        }
        cve_dir = os.path.join(self.workdir, self.cve_id)
        with open(os.path.join(cve_dir, "failure.json"), "w") as f:
            json.dump(failure, f, indent=2, ensure_ascii=False)
        return failure

    def _extract_location(self, log: str, match: Any) -> Dict:
        location = {}
        line_start = max(0, match.start() - 500)
        context = log[line_start:match.end() + 200]
        file_match = re.search(r'(?:In file included from|/.*?\.c:\d+)', context)
        if file_match:
            location["file"] = file_match.group(0)
        func_match = re.search(r'function\s+`?(\w+)', context)
        if func_match:
            location["function"] = func_match.group(1)
        return location

    @staticmethod
    def _find_line_number(content: str, pos: int) -> int:
        return content[:pos].count("\n") + 1

    def classify_verify_log(self, verify_log_path: str, dmesg_path: Optional[str] = None) -> Dict:
        failure = {
            "stage": "verify", "category": "verify",
            "reason_code": "verify_failed", "retryable": False,
            "next_action": "manual_required",
            "classified_at": datetime.now(timezone.utc).isoformat(),
        }
        if os.path.exists(verify_log_path):
            with open(verify_log_path) as f:
                log = f.read()
            if "ERROR" in log or "failed" in log.lower():
                failure["reason_code"] = "load_failed"
                failure["summary"] = "Module load failed in VM"
        if dmesg_path and os.path.exists(dmesg_path):
            with open(dmesg_path) as f:
                dmesg = f.read()
            failure["dmesg_summary"] = dmesg[-500:] if len(dmesg) > 500 else dmesg
        return failure
