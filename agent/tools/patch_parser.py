"""Patch Parser - parses unified diff into structured patch_ir.json and change_units.json."""
import json
import os
import re
from typing import Dict, List, Optional
from datetime import datetime, timezone


class PatchParser:
    """Parse unified diff files into structured intermediate representation."""

    INIT_PATTERN = re.compile(r'\b__init\b')
    STATIC_PATTERN = re.compile(r'\bstatic\s+(struct|int|char|bool|long|unsigned|void\s*\*)\s+\w+\s*[=;]')
    GLOBAL_PATTERN = re.compile(r'^(?!static)\s*(struct|int|char|bool|long|unsigned|void\s*\*)\s+\w+\s*[=;]', re.MULTILINE)
    NO_FENTRY_PATTERN = re.compile(r'(no fentry|not traceable|FTRACE_NOT_AVAILABLE)')
    STRUCT_PATTERN = re.compile(r'^diff.*struct\s+\w+', re.MULTILINE)

    SEMANTIC_ROLE_PATTERNS = {
        "security_boundary_check": [
            r'\bif\s*\(.*len\s*[><=]', r'\bif\s*\(.*size\s*[><=]',
            r'\bif\s*\(.*ptr\s*==\s*NULL', r'\bif\s*\(!.*ptr\b',
            r'return\s*-?E(?:Access|INVAL|FAULT|PERM)'],
        "permission_check": [r'capable\(', r'ns_capable\(', r'permitted\('],
        "refcount_lifetime": [r'\bkref_get\b', r'\bkref_put\b', r'\bget_device\b', r'\bput_device\b',
                              r'\bmodule_get\b', r'\bmodule_put\b'],
        "locking_order": [r'\bmutex_lock\b', r'\bmutex_unlock\b', r'\bspin_lock\b', r'\bspin_unlock\b',
                          r'\bdown_read\b', r'\bup_read\b'],
        "init_path_change": [r'__init\b', r'__exit\b', r'late_initcall', r'early_initcall'],
        "logging_only": [r'^\s*[+-]\s*(printk|pr_err|pr_info|pr_warn|pr_debug|dev_err|dev_info)\('],
    }

    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id

    def parse_patch(self, patch_path: str) -> Dict:
        with open(patch_path) as f:
            content = f.read()
        files = self._parse_files(content)
        if not files:
            raise ValueError(f"Patch contains no unified diff: {patch_path}")
        functions = self._extract_functions(content, files)
        risk_tags = self._detect_risks(content, functions)
        semantic_summary = self._generate_semantic_summary(content)
        patch_ir = {
            "cve_id": self.cve_id,
            "parsed_at": datetime.now(timezone.utc).isoformat(),
            "files": files,
            "functions": functions,
            "risk_tags": list(set(risk_tags)),
            "target_status": "need_backport",
            "semantic_summary": semantic_summary,
        }
        change_units = self._generate_change_units(patch_ir)
        cve_dir = os.path.join(self.workdir, self.cve_id)
        os.makedirs(cve_dir, exist_ok=True)
        with open(os.path.join(cve_dir, "patch_ir.json"), "w") as f:
            json.dump(patch_ir, f, indent=2, ensure_ascii=False)
        with open(os.path.join(cve_dir, "change_units.json"), "w") as f:
            json.dump(change_units, f, indent=2, ensure_ascii=False)
        return patch_ir

    def _parse_files(self, content: str) -> List[Dict]:
        files = []
        for match in re.finditer(r'^diff --git a/(.*?) b/(.*?)$', content, re.MULTILINE):
            files.append({"path": match.group(2), "status": "modified", "hunk_count": 1})
        return files

    def _extract_functions(self, content: str, files: List[Dict]) -> List[Dict]:
        functions = []
        seen = set()
        # Track which file the current hunk is in by scanning backward
        # for the most recent "diff --git a/... b/..." line
        file_index = 0
        for line in content.splitlines():
            diff_match = re.match(r'^diff --git a/(.*?) b/(.*?)$', line)
            if diff_match:
                # Find matching file index
                target_path = diff_match.group(2)
                file_index = 0
                for i, f in enumerate(files):
                    if f["path"] == target_path:
                        file_index = i
                        break
            hunk_match = re.match(r'^@@[^\n]+@@\s*([^\n]*)', line)
            if hunk_match:
                func_hint = hunk_match.group(1).strip()
                func_match = re.search(r'(\w+)\s*\(', func_hint)
                if func_match and func_match.group(1) not in seen:
                    seen.add(func_match.group(1))
                    current_file = files[file_index]["path"] if file_index < len(files) else "unknown"
                    functions.append({
                        "name": func_match.group(1),
                        "file": current_file,
                        "risk_tags": self._function_risk_tags(content, func_match.group(1)),
                    })
        if not functions:
            first_file = files[0]["path"] if files else "unknown"
            functions.append({
                "name": "unknown",
                "file": first_file,
                "risk_tags": [],
            })
        return functions

    def _function_risk_tags(self, content: str, func_name: str) -> List[str]:
        tags = []
        # Bounded quantifier prevents catastrophic backtracking on large diffs
        func_region = re.search(rf'[+-].*{re.escape(func_name)}[^\n]*(?:\n[+-][^\n]*){{0,100}}', content)
        if func_region:
            region = func_region.group()
            if self.INIT_PATTERN.search(region):
                tags.append("init_function")
            if self.STATIC_PATTERN.search(region):
                tags.append("static_data")
            if self.GLOBAL_PATTERN.search(region):
                tags.append("global_data")
        return tags

    def _detect_risks(self, content: str, functions: List[Dict]) -> List[str]:
        risks = []
        for func in functions:
            risks.extend(func.get("risk_tags", []))
        if self.STRUCT_PATTERN.search(content):
            risks.append("struct_abi")
        if self.NO_FENTRY_PATTERN.search(content):
            risks.append("no_fentry")
        return risks

    def _generate_semantic_summary(self, content: str) -> str:
        added_lines = re.findall(r'^\+(?!\+\+)', content, re.MULTILINE)
        parts = []
        for role, patterns in self.SEMANTIC_ROLE_PATTERNS.items():
            matched = False
            for p in patterns:
                try:
                    if re.search(p, content):
                        matched = True
                        break
                except re.error:
                    pass
            if matched:
                if role == "security_boundary_check":
                    parts.append("add security boundary check")
                elif role == "permission_check":
                    parts.append("add permission check")
                elif role == "refcount_lifetime":
                    parts.append("modify reference counting")
                elif role == "locking_order":
                    parts.append("modify locking")
                elif role == "init_path_change":
                    parts.append("modify initialization path")
        return "; ".join(parts) if parts else "general bug fix"

    def _generate_change_units(self, patch_ir: Dict) -> Dict:
        units = []
        for idx, func in enumerate(patch_ir.get("functions", [])):
            change_id = f"CU-{idx+1:03d}"
            role = self._classify_semantic_role(func.get("name", ""), patch_ir)
            risk_tags = func.get("risk_tags", [])
            rewrite_allowed = not any(t in risk_tags for t in
                                       ["init_function", "global_data", "struct_abi"])
            unit = {
                "change_id": change_id,
                "file": func.get("file", "unknown"),
                "function": func.get("name", "unknown"),
                "change_type": "modify",
                "semantic_role": role,
                "risk_tags": risk_tags + patch_ir.get("risk_tags", []),
                "rewrite_allowed": rewrite_allowed,
                "target_context": {
                    "status": "need_backport",
                    "target_function_exists": True,
                    "signature_changed": False,
                    "context_similarity": 0.8,
                }
            }
            units.append(unit)
        return {
            "cve_id": self.cve_id,
            "kernel_version": "6.6.102-5.2.an23.x86_64",
            "fix_intent": {
                "summary": patch_ir.get("semantic_summary", ""),
                "source": "patch_analysis",
                "confidence": 0.8,
            },
            "units": units,
        }

    def _classify_semantic_role(self, func_name: str, patch_ir: Dict) -> str:
        risk_tags = []
        for f in patch_ir.get("functions", []):
            risk_tags.extend(f.get("risk_tags", []))
        risk_tags.extend(patch_ir.get("risk_tags", []))
        if "struct_abi" in risk_tags:
            return "struct_abi_change"
        if "init_function" in risk_tags:
            return "init_path_change"
        if "security_boundary_check" in patch_ir.get("semantic_summary", ""):
            return "security_boundary_check"
        if "locking" in patch_ir.get("semantic_summary", ""):
            return "locking_order"
        if "reference counting" in patch_ir.get("semantic_summary", ""):
            return "refcount_lifetime"
        return "security_boundary_check"
