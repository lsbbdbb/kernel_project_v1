"""Shared test fixtures and helpers for CVE test data.

This conftest provides:
- Easy access to all 10 CVE test patches
- Methods to load patches as strings or write them to temp directories
- CVE metadata loader
- Build log loader
- Test scenario classifier (success/failure category)
"""

import os
import json
import tempfile
from typing import Dict, List, Optional, Tuple

import pytest


# ---------------------------------------------------------------------------
# Test data paths
# ---------------------------------------------------------------------------
TESTDATA_DIR = os.path.join(os.path.dirname(__file__), "testdata")
PATCHES_DIR = os.path.join(TESTDATA_DIR, "patches")
BUILD_LOGS_DIR = os.path.join(TESTDATA_DIR, "build_logs")
METADATA_DIR = os.path.join(TESTDATA_DIR, "metadata")
EXPECTED_DIR = os.path.join(TESTDATA_DIR, "expected")


# ---------------------------------------------------------------------------
# CVE test case registry – every CVE we test
# ---------------------------------------------------------------------------
# Each entry: (cve_id, scenario, expected_category, expected_reason_code, expected_retryable)
CVE_TEST_CASES: List[Tuple[str, str, str, str, bool]] = [
    ("CVE-2026-0001", "boundary_check",       "success",     "",                    True),
    ("CVE-2026-0002", "api_mismatch",          "compile",     "api_mismatch",        True),
    ("CVE-2026-0003", "no_fentry",             "kpatch_limit", "no_fentry",          False),
    ("CVE-2026-0004", "struct_abi",            "kpatch_limit", "struct_or_data_change", False),
    ("CVE-2026-0005", "static_data",           "kpatch_limit", "struct_or_data_change", False),
    ("CVE-2026-0006", "hunk_failed",           "patch_apply", "hunk_failed",         True),
    ("CVE-2026-0007", "missing_include",       "compile",     "missing_api_or_include", True),
    ("CVE-2026-0008", "undefined_symbol",      "compile",     "missing_api_or_include", True),
    ("CVE-2026-0009", "init_function",         "kpatch_limit", "no_fentry",          False),
    ("CVE-2026-0010", "multi_file",            "compile",     "field_mismatch",      False),
]


def get_patch_path(cve_id: str) -> str:
    """Get the path to a CVE patch file."""
    # Look up the scenario from the CVE id
    scenario = None
    for cve, scenario_name, _, _, _ in CVE_TEST_CASES:
        if cve == cve_id:
            scenario = scenario_name
            break
    if not scenario:
        raise ValueError(f"Unknown CVE: {cve_id}")
    patch_path = os.path.join(PATCHES_DIR, f"{cve_id}_{scenario}.patch")
    if not os.path.exists(patch_path):
        raise FileNotFoundError(f"Patch not found: {patch_path}")
    return patch_path


def get_build_log_path(cve_id: str, attempt: int = 1) -> str:
    """Get the path to a CVE build log."""
    log_path = os.path.join(BUILD_LOGS_DIR, f"{cve_id}_build_{attempt}.log")
    if not os.path.exists(log_path):
        raise FileNotFoundError(f"Build log not found: {log_path}")
    return log_path


def get_metadata_path(cve_id: str) -> str:
    """Get the path to a CVE metadata JSON file."""
    meta_path = os.path.join(METADATA_DIR, f"{cve_id}_metadata.json")
    if not os.path.exists(meta_path):
        raise FileNotFoundError(f"Metadata not found: {meta_path}")
    return meta_path


def get_expected_path(cve_id: str, artifact: str) -> str:
    """Get the path to an expected output file."""
    exp_path = os.path.join(EXPECTED_DIR, f"{cve_id}_{artifact}.json")
    return exp_path


def load_patch(cve_id: str) -> str:
    """Load a CVE patch as a string."""
    with open(get_patch_path(cve_id)) as f:
        return f.read()


def load_build_log(cve_id: str, attempt: int = 1) -> str:
    """Load a CVE build log as a string."""
    with open(get_build_log_path(cve_id, attempt)) as f:
        return f.read()


def load_metadata(cve_id: str) -> Dict:
    """Load CVE metadata JSON."""
    with open(get_metadata_path(cve_id)) as f:
        return json.load(f)


def load_expected(cve_id: str, artifact: str) -> Optional[Dict]:
    """Load expected output JSON if it exists."""
    path = get_expected_path(cve_id, artifact)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None


def create_cve_workdir(cve_id: str, patches_dir=None, logs_dir=None) -> str:
    """Create a temporary CVE working directory with patches subdir."""
    tmpdir = tempfile.mkdtemp()
    cve_dir = os.path.join(tmpdir, cve_id)
    os.makedirs(os.path.join(cve_dir, "patches"), exist_ok=True)
    os.makedirs(os.path.join(cve_dir, "logs"), exist_ok=True)
    os.makedirs(os.path.join(cve_dir, "metadata"), exist_ok=True)
    os.makedirs(os.path.join(cve_dir, "artifacts"), exist_ok=True)

    # Copy the patch file
    patch_src = get_patch_path(cve_id)
    patch_dst = os.path.join(cve_dir, "patches", "original.patch")
    with open(patch_src) as f_src:
        content = f_src.read()
    with open(patch_dst, "w") as f_dst:
        f_dst.write(content)

    return tmpdir


# ---------------------------------------------------------------------------
# pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def cve_ids() -> List[str]:
    """Return the list of all CVE test case IDs."""
    return [c[0] for c in CVE_TEST_CASES]


@pytest.fixture
def all_cve_patches() -> Dict[str, str]:
    """Load all CVE patches as {cve_id: patch_content}."""
    result = {}
    for cve_id, _, _, _, _ in CVE_TEST_CASES:
        result[cve_id] = load_patch(cve_id)
    return result


@pytest.fixture
def cve_workdir(request) -> str:
    """Create a temp working directory with patch for the given CVE.
    
    Usage: pass cve_id via request.param or use the parametrize marker.
    """
    cve_id = getattr(request, "param", "CVE-2026-0001")
    return create_cve_workdir(cve_id)


@pytest.fixture
def cve_resolver_cases() -> List[Dict]:
    """Return all CVE metadata as test data for resolver tests."""
    result = []
    for cve_id, _, _, _, _ in CVE_TEST_CASES:
        meta = load_metadata(cve_id)
        result.append({
            "cve_id": cve_id,
            "description": meta["nvd"]["description"],
            "cvss_score": meta["nvd"]["cvss"]["score"],
            "has_references": len(meta["nvd"]["references"]) > 0,
        })
    return result
