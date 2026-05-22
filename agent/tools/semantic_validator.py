"""Semantic Validator — verify rewritten patch preserves security semantics."""
import re
from typing import Dict, List


class SemanticValidator:
    """Validate that a rewritten patch preserves essential security semantics."""

    # Security-relevant patterns that must not be removed
    SECURITY_CHECKS = [
        r'\bif\s*\(\s*!\s*\w+\s*\)',           # if (!ptr)
        r'\bif\s*\(\s*\w+\s*==\s*NULL\s*\)',    # if (ptr == NULL)
        r'\bif\s*\(\s*\w+\s*[<>]=?\s*\w+\s*\)',  # bounds check: if (len > MAX)
        r'\bif\s*\(\s*\w+\s*<=\s*0\s*\)',        # if (len <= 0)
        r'\bWARN_ON\s*\(',                      # WARN_ON(...)
        r'\bBUG_ON\s*\(',                       # BUG_ON(...)
        r'\bunlikely\s*\(',                     # unlikely(...)
    ]

    # Error return paths that must be preserved
    ERROR_RETURNS = [
        r'return\s+-E[A-Z]+\s*;',              # return -EINVAL;
        r'return\s+-E[A-Z0-9_]+\s*;',           # return -ERANGE;
        r'return\s+NULL\s*;',                   # return NULL;
        r'return\s+-\w+\s*;',                   # return -errno;
        r'goto\s+\w+_err\b',                    # goto cleanup_err;
        r'goto\s+out\b',                        # goto out;
    ]

    # Patterns that indicate new global state (should NOT appear if absent in original)
    GLOBAL_PATTERNS = [
        r'\bstatic\s+(?:struct|int|long|char|void)\s+\w+\s*=',  # static variable def
        r'\bEXPORT_SYMBOL\s*\(',                                 # EXPORT_SYMBOL(...)
        r'\bmodule_param\s*\(',                                  # module_param(...)
    ]

    # __init functions that must not be modified
    INIT_FUNCTIONS = [
        r'__init\b',
        r'__exit\b',
    ]

    def __init__(self):
        self.issues: List[str] = []

    def validate(self, original_patch: str, rewritten_patch: str) -> Dict:
        """Run all semantic checks. Returns {valid: bool, issues: [...]}."""
        self.issues = []

        orig_security = self._extract_security_checks(original_patch)
        new_security = self._extract_security_checks(rewritten_patch)
        self._check_preserved(orig_security, new_security, "security check")

        orig_errors = self._extract_error_returns(original_patch)
        new_errors = self._extract_error_returns(rewritten_patch)
        self._check_preserved(orig_errors, new_errors, "error return path")

        self._check_no_new_globals(original_patch, rewritten_patch)
        self._check_init_functions_untouched(original_patch, rewritten_patch)
        self._check_semantic_role_preserved(original_patch, rewritten_patch)

        return {
            "valid": len(self.issues) == 0,
            "issues": list(self.issues),
        }

    def _extract_security_checks(self, patch: str) -> set:
        found = set()
        for pattern in self.SECURITY_CHECKS:
            for match in re.finditer(pattern, patch):
                found.add(match.group())
        return found

    def _extract_error_returns(self, patch: str) -> set:
        found = set()
        for pattern in self.ERROR_RETURNS:
            for match in re.finditer(pattern, patch):
                found.add(match.group())
        return found

    def _check_preserved(self, original: set, rewritten: set, label: str):
        missing = original - rewritten
        if missing:
            self.issues.append(
                f"Missing {label}(s): {', '.join(sorted(missing)[:5])}"
            )

    def _check_no_new_globals(self, original_patch: str, rewritten_patch: str):
        orig_globals = set()
        new_globals = set()
        for pattern in self.GLOBAL_PATTERNS:
            for match in re.finditer(pattern, original_patch):
                orig_globals.add(match.group())
            for match in re.finditer(pattern, rewritten_patch):
                new_globals.add(match.group())
        added = new_globals - orig_globals
        if added:
            self.issues.append(
                f"New global/export introduced: {', '.join(sorted(added)[:5])}"
            )

    def _check_init_functions_untouched(self, original_patch: str, rewritten_patch: str):
        """Ensure __init/__exit functions were not modified by the rewrite."""
        for pattern in self.INIT_FUNCTIONS:
            orig_count = len(re.findall(pattern, original_patch))
            new_count = len(re.findall(pattern, rewritten_patch))
            if orig_count != new_count:
                self.issues.append(
                    f"Init/exit function count changed ({pattern}): "
                    f"{orig_count} → {new_count}"
                )

    def _check_semantic_role_preserved(self, original_patch: str, rewritten_patch: str):
        """Ensure the diff still targets the same functions and files."""
        orig_funcs = set(re.findall(r'@@.*@@\s+\w+\s+(\w+)\s*\(', original_patch))
        new_funcs = set(re.findall(r'@@.*@@\s+\w+\s+(\w+)\s*\(', rewritten_patch))
        if orig_funcs and not (orig_funcs & new_funcs):
            self.issues.append(
                f"All original functions lost: {orig_funcs} → {new_funcs}"
            )
