"""Shared fixtures and helpers for acceptance tests.

Acceptance tests verify the full pipeline success path using 3 real
CVE patches (CVE-2025-21638, CVE-2024-56659, CVE-2024-53156) that
successfully apply to the target kernel and produce .ko artifacts.
"""

import json
import os
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Acceptance test data paths
# ---------------------------------------------------------------------------
TESTDATA_DIR = os.path.join(os.path.dirname(__file__), "..", "testdata", "acceptance")
PATCHES_DIR = os.path.join(TESTDATA_DIR, "patches")
BUILD_LOGS_DIR = os.path.join(TESTDATA_DIR, "build_logs")
VERIFY_LOGS_DIR = os.path.join(TESTDATA_DIR, "verify_logs")
METADATA_DIR = os.path.join(TESTDATA_DIR, "metadata")
EXPECTED_DIR = os.path.join(TESTDATA_DIR, "expected")
ARTIFACTS_DIR = os.path.join(TESTDATA_DIR, "artifacts"  )

# ---------------------------------------------------------------------------
# Acceptance test case registry — real CVEs that demonstrate success paths
# ---------------------------------------------------------------------------
# Each entry: (cve_id, scenario, num_files_changed, patch_source)
ACCEPTANCE_TEST_CASES: List[Tuple[str, str, int, str]] = [
    ("CVE-2025-21638",  "sctp_sysctl",     1, "linux-6.6.y"),
    ("CVE-2024-56659",  "lapb_header",     1, "linux-6.6.y"),
    ("CVE-2024-53156",  "ath9k_oob",       1, "linux-6.6.y"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_patch_path(cve_id: str) -> str:
    """Get the path to an acceptance test patch file."""
    for cve_id_entry, scenario, _, _ in ACCEPTANCE_TEST_CASES:
        if cve_id_entry == cve_id:
            return os.path.join(PATCHES_DIR, f"{cve_id}_{scenario}.patch")
    raise ValueError(f"Unknown acceptance CVE: {cve_id}")


def get_build_log_path(cve_id: str) -> str:
    """Get the path to an acceptance test build log."""
    for cve_id_entry, scenario, _, _ in ACCEPTANCE_TEST_CASES:
        if cve_id_entry == cve_id:
            return os.path.join(BUILD_LOGS_DIR, f"{cve_id}_build_1.log")
    raise ValueError(f"Unknown acceptance CVE: {cve_id}")


def get_metadata_path(cve_id: str) -> str:
    """Get the path to acceptance CVE metadata."""
    meta_path = os.path.join(METADATA_DIR, f"{cve_id}_metadata.json")
    if not os.path.exists(meta_path):
        raise FileNotFoundError(f"Acceptance metadata not found: {meta_path}")
    return meta_path


def get_expected_path(cve_id: str) -> str:
    """Get the path to the expected output JSON."""
    # Find scenario from registry
    for cve_id_entry, scenario, _, _ in ACCEPTANCE_TEST_CASES:
        if cve_id_entry == cve_id:
            return os.path.join(EXPECTED_DIR, f"{cve_id}_success.json")
    raise ValueError(f"Unknown acceptance CVE: {cve_id}")


def load_patch(cve_id: str) -> str:
    """Load an acceptance CVE patch as a string."""
    with open(get_patch_path(cve_id)) as f:
        return f.read()


def load_build_log(cve_id: str) -> str:
    """Load an acceptance CVE build log as a string."""
    with open(get_build_log_path(cve_id)) as f:
        return f.read()


def load_metadata(cve_id: str) -> Dict:
    """Load acceptance CVE metadata JSON."""
    with open(get_metadata_path(cve_id)) as f:
        return json.load(f)


def load_expected(cve_id: str) -> Dict:
    """Load expected output JSON."""
    with open(get_expected_path(cve_id)) as f:
        return json.load(f)
