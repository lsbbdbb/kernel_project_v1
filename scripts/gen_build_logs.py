#!/usr/bin/env python3
"""Generate build logs and expected outputs for real CVE test data.

Each CVE gets assigned a test scenario that the FailureClassifier should
detect. The build log text contains the specific error markers for each
classification.
"""

import json
import os
import re
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Each real CVE assigned to a failure scenario
# (cve_id, scenario, expected_category, expected_reason_code, expected_retryable)
CVE_REAL = [
    # One success case:
    ("CVE-2025-21638",  "success",           "success",     "",                    True),
    # Nine failure cases:
    ("CVE-2024-56659",  "api_mismatch",      "compile",     "api_mismatch",        True),
    ("CVE-2024-53156",  "no_fentry",         "kpatch_limit", "no_fentry",          False),
    ("CVE-2025-21767",  "struct_abi",        "kpatch_limit", "struct_or_data_change", False),
    ("CVE-2024-46733",  "static_data",       "kpatch_limit", "struct_or_data_change", False),
    ("CVE-2024-56764",  "hunk_failed",       "patch_apply", "hunk_failed",         True),
    ("CVE-2025-21656",  "missing_include",   "compile",     "missing_api_or_include", True),
    ("CVE-2024-56763",  "undefined_symbol",  "compile",     "missing_api_or_include", True),
    ("CVE-2025-21799",  "init_function",     "kpatch_limit", "no_fentry",          False),
    ("CVE-2025-21646",  "multi_file",        "compile",     "field_mismatch",      False),
]

LOG_TEMPLATES = {
    "success": """\
kpatch-build: building livepatch for {cve_id}
Patch: {patch_file}
Applying patch...
git apply --check: OK
git apply: OK
Patch applied cleanly
Building original kernel...
make -j8
Build original: OK
Building patched kernel...
make -j8
Build patched: OK
Extracting changed objects...
Changed obj: {changed_obj}
Creating kpatch module...
kpatch: created /root/kpatch-build/{cve_id}.ko
SUCCESS: kpatch module generated at /root/kpatch-build/{cve_id}.ko
""",
    "hunk_failed": """\
kpatch-build: building livepatch for {cve_id}
Patch: {patch_file}
Applying patch...
error: patch failed: {first_file}:{line_no}
hunk FAILED
error: patch does not apply
kpatch-build: patch application FAILED
""",
    "api_mismatch": """\
kpatch-build: building livepatch for {cve_id}
Patch: {patch_file}
Applying patch...
git apply --check: OK
git apply: OK
Patch applied cleanly
Building patched kernel...
make -j8
{first_file}: In function '{func_name}':
{first_file}:{line_no}: error: too few arguments to function '{missing_api}'
make: *** [scripts/Makefile.build:244: {first_file}] Error 1
kpatch-build: compilation FAILED
""",
    "no_fentry": """\
kpatch-build: building livepatch for {cve_id}
Patch: {patch_file}
Applying patch...
git apply --check: OK
git apply: OK
Patch applied cleanly
Building patched kernel...
Build patched: OK
Extracting changed objects...
Warning: No fentry calls found in modified function(s)
kpatch-build: FAILED: livepatch creation requires fentry traceable functions
kpatch-build: The function(s) modified do not have fentry/mcount entries.
""",
    "struct_abi": """\
kpatch-build: building livepatch for {cve_id}
Patch: {patch_file}
Applying patch...
git apply --check: OK
git apply: OK
Patch applied cleanly
Building patched kernel...
Build patched: OK
Extracting changed objects...
Warning: Structure layout change detected in {first_file}
Checking CRC...
Error: CRC mismatch for struct {struct_name}
kpatch-build: FAILED: struct or data layout change detected
""",
    "static_data": """\
kpatch-build: building livepatch for {cve_id}
Patch: {patch_file}
Applying patch...
git apply --check: OK
git apply: OK
Patch applied cleanly
Building patched kernel...
Build patched: OK
Extracting changed objects...
Warning: Static data modification in compilation unit
kpatch-build: FAILED: struct or data layout change detected
""",
    "missing_include": """\
kpatch-build: building livepatch for {cve_id}
Patch: {patch_file}
Applying patch...
git apply --check: OK
git apply: OK
Patch applied cleanly
Building patched kernel...
make -j8
{first_file}:{line_no}: warning: implicit declaration of function '{missing_api}'
{first_file}:{line_no}: error: '{missing_api}' undeclared
make: *** [scripts/Makefile.build:244: {first_file}] Error 1
kpatch-build: compilation FAILED
""",
    "undefined_symbol": """\
kpatch-build: building livepatch for {cve_id}
Patch: {patch_file}
Applying patch...
git apply --check: OK
git apply: OK
Patch applied cleanly
Building patched kernel...
make -j8
{first_file}:{line_no}: error: implicit declaration of function '{missing_api}'
{first_file}:{line_no}: undefined reference to '{missing_api}'
make: *** [scripts/Makefile.build:244: {first_file}] Error 1
kpatch-build: compilation FAILED
""",
    "init_function": """\
kpatch-build: building livepatch for {cve_id}
Patch: {patch_file}
Applying patch...
git apply --check: OK
git apply: OK
Patch applied cleanly
Building patched kernel...
Build patched: OK
Extracting changed objects...
Warning: Modified function '{func_name}' is __init/__devinit
kpatch-build: FAILED: modified functions must not be __init/__devinit
""",
    "multi_file": """\
kpatch-build: building livepatch for {cve_id}
Patch: {patch_file}
Applying patch...
git apply --check: OK
git apply: OK
Patch applied cleanly
Building patched kernel...
make -j8
{first_file}:{line_no}: error: 'struct {struct_name}' has no member named '{field_name}'
make: *** [scripts/Makefile.build:244: {first_file}] Error 1
build failed in {second_file}: similar error
kpatch-build: compilation FAILED
""",
}

EXPECTED_OUTPUTS = {
    "success": {
        "stage": "parse",
        "category": "parse_success",
        "expected_file": "patch_ir.json",
    },
    "hunk_failed": {
        "stage": "apply",
        "category": "patch_apply",
        "reason_code": "hunk_failed",
        "retryable": True,
        "next_action": "rewrite",
    },
    "api_mismatch": {
        "stage": "compile",
        "category": "compile",
        "reason_code": "api_mismatch",
        "retryable": True,
        "next_action": "rewrite",
    },
    "no_fentry": {
        "stage": "kpatch_check",
        "category": "kpatch_limit",
        "reason_code": "no_fentry",
        "retryable": False,
        "next_action": "manual_review",
    },
    "struct_abi": {
        "stage": "kpatch_check",
        "category": "kpatch_limit",
        "reason_code": "struct_or_data_change",
        "retryable": False,
        "next_action": "manual_review",
    },
    "static_data": {
        "stage": "kpatch_check",
        "category": "kpatch_limit",
        "reason_code": "struct_or_data_change",
        "retryable": False,
        "next_action": "manual_review",
    },
    "missing_include": {
        "stage": "compile",
        "category": "compile",
        "reason_code": "missing_api_or_include",
        "retryable": True,
        "next_action": "rewrite",
    },
    "undefined_symbol": {
        "stage": "compile",
        "category": "compile",
        "reason_code": "missing_api_or_include",
        "retryable": True,
        "next_action": "rewrite",
    },
    "init_function": {
        "stage": "kpatch_check",
        "category": "kpatch_limit",
        "reason_code": "no_fentry",
        "retryable": False,
        "next_action": "manual_review",
    },
    "multi_file": {
        "stage": "compile",
        "category": "compile",
        "reason_code": "field_mismatch",
        "retryable": False,
        "next_action": "manual_review",
    },
}


def get_patch_info(patch_path):
    """Extract info from a real patch file for log generation."""
    with open(patch_path) as f:
        content = f.read()

    diff_files = re.findall(r'--- a/(.*?)\n\+\+\+ b/', content)
    first_file = diff_files[0] if diff_files else "unknown.c"
    second_file = diff_files[1] if len(diff_files) > 1 else first_file

    func_match = re.search(r'@@ -\d+,\d+ \+(\d+),\d+ @@\s*(?:\w+\s+)?(\w+)', content)
    func_name = func_match.group(2) if func_match else "unknown_function"
    line_no = func_match.group(1) if func_match else 42

    struct_match = re.search(r'struct (\w+)', content)
    struct_name = struct_match.group(1) if struct_match else "unknown_struct"
    field_match = re.search(r'\.(\w+)\s*=', content)
    field_name = field_match.group(1) if field_match else "unknown_field"

    return {
        "first_file": first_file,
        "second_file": second_file,
        "func_name": func_name,
        "line_no": int(line_no.split(",")[0]) if "," in str(line_no) else int(line_no),
        "struct_name": struct_name,
        "field_name": field_name,
        "patch_file": os.path.basename(patch_path),
        "changed_obj": first_file.replace(".c", ".o"),
        "missing_api": func_name,
    }


def main():
    patches_dir = os.path.join(PROJECT_ROOT, "tests", "testdata", "patches")
    build_logs_dir = os.path.join(PROJECT_ROOT, "tests", "testdata", "build_logs")
    expected_dir = os.path.join(PROJECT_ROOT, "tests", "testdata", "expected")

    os.makedirs(build_logs_dir, exist_ok=True)
    os.makedirs(expected_dir, exist_ok=True)

    for cve_id, scenario, cat, code, retryable in CVE_REAL:
        # Find the patch file
        patch_files = [f for f in os.listdir(patches_dir) if f.startswith(cve_id)]
        if not patch_files:
            print("WARNING: No patch file for {}, skipping".format(cve_id))
            continue

        patch_file = patch_files[0]
        patch_path = os.path.join(patches_dir, patch_file)
        info = get_patch_info(patch_path)

        # Generate build log
        template = LOG_TEMPLATES[scenario]
        log_content = template.format(cve_id=cve_id, **info)

        log_name = "{}_build_1.log".format(cve_id)
        log_path = os.path.join(build_logs_dir, log_name)
        with open(log_path, "w") as f:
            f.write(log_content)
        print("  Build log: {}".format(log_name))

        # Generate expected output
        if scenario == "success":
            expected_output = {
                "stage": "parse",
                "category": "parse_success",
                "expected_file": "{}_patch_ir.json".format(cve_id),
            }
        else:
            expected_output = EXPECTED_OUTPUTS[scenario]

        expected_name = "{}_patch_ir.json".format(cve_id) if scenario == "success" else "{}_failure.json".format(cve_id)
        expected_path = os.path.join(expected_dir, expected_name)
        with open(expected_path, "w") as f:
            json.dump(expected_output, f, indent=2)
        print("  Expected: {}".format(expected_name))

    print("\n=== CVE registration list for conftest.py ===")
    print("# (cve_id, scenario, expected_category, expected_reason_code, expected_retryable)")
    for cve_id, scenario, cat, code, retryable in CVE_REAL:
        print('    ("{}", "{}", "{}", "{}", {}),'.format(cve_id, scenario, cat, code, retryable))


if __name__ == "__main__":
    main()
