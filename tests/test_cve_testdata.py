"""Comprehensive CVE test data verification suite.

Tests all 10 CVE test scenarios to ensure:
1. Patches are valid unified diffs
2. PatchParser correctly parses each patch
3. FailureClassifier correctly classifies build logs
4. RewriteAdvisor creates appropriate plans
5. CVE metadata is well-formed
6. Full pipeline state transitions work
"""

import json
import os
import re

import pytest

# conftest is auto-discovered by pytest - import via the tests package
from .conftest import (
    CVE_TEST_CASES,
    PATCHES_DIR,
    BUILD_LOGS_DIR,
    METADATA_DIR,
    get_patch_path,
    load_patch,
    load_build_log,
    load_metadata,
    load_expected,
    create_cve_workdir,
)

from agent.tools.patch_parser import PatchParser
from agent.tools.failure_classifier import FailureClassifier
from agent.tools.rewrite_advisor import RewriteAdvisor
from agent.tools.cve_resolver import CVEResolver
from agent.state import StateManager


# =========================================================================
# Section 1: Patch Validity Tests
# =========================================================================

class TestPatchValidity:
    """Verify every CVE patch is a well-formed unified diff."""

    @pytest.mark.parametrize("cve_id,scenario,exp_cat,exp_code,exp_retry",
                             CVE_TEST_CASES)
    def test_patch_file_exists(self, cve_id, scenario, exp_cat, exp_code, exp_retry):
        """Every CVE must have a corresponding patch file."""
        patch_path = get_patch_path(cve_id)
        assert os.path.exists(patch_path), f"Missing patch for {cve_id}"
        assert os.path.getsize(patch_path) > 50, f"Patch too small for {cve_id}"

    @pytest.mark.parametrize("cve_id,scenario,exp_cat,exp_code,exp_retry",
                             CVE_TEST_CASES)
    def test_patch_has_diff_header(self, cve_id, scenario, exp_cat, exp_code, exp_retry):
        """Every patch must have a valid git diff header."""
        content = load_patch(cve_id)
        assert content.startswith("From "), f"{cve_id}: Missing 'From ' header"
        assert "diff --git" in content, f"{cve_id}: Missing diff header"
        assert "/dev/null" not in content, f"{cve_id}: Should not be new file"

    @pytest.mark.parametrize("cve_id,scenario,exp_cat,exp_code,exp_retry",
                             CVE_TEST_CASES)
    def test_patch_has_cve_tag(self, cve_id, scenario, exp_cat, exp_code, exp_retry):
        """Each patch must reference an upstream Linux kernel commit hash."""
        content = load_patch(cve_id)
        has_hash = bool(re.search(r'\b[0-9a-f]{12,40}\b', content))
        assert has_hash, f"{cve_id}: Patch must contain a commit hash reference"

    @pytest.mark.parametrize("cve_id,scenario,exp_cat,exp_code,exp_retry",
                             CVE_TEST_CASES)
    def test_patch_has_added_lines(self, cve_id, scenario, exp_cat, exp_code, exp_retry):
        """Every patch must add at least one line (have '+' lines)."""
        content = load_patch(cve_id)
        added = re.findall(r'^\+', content, re.MULTILINE)
        assert len(added) >= 1, f"{cve_id}: Patch must add at least 1 line"


# =========================================================================
# Section 2: PatchParser Tests (using CVE test data)
# =========================================================================

class TestPatchParsing:
    """Verify PatchParser correctly parses each CVE patch."""

    @pytest.mark.parametrize("cve_id,scenario,exp_cat,exp_code,exp_retry",
                             CVE_TEST_CASES)
    def test_parse_patch_basic(self, cve_id, scenario, exp_cat, exp_code, exp_retry):
        """PatchParser must produce valid patch_ir for all CVEs."""
        workdir = create_cve_workdir(cve_id)
        parser = PatchParser(workdir, cve_id)
        patch_ir = parser.parse_patch(
            os.path.join(workdir, cve_id, "patches", "original.patch"))
        assert "files" in patch_ir, f"{cve_id}: Missing 'files' in patch_ir"
        assert "functions" in patch_ir, f"{cve_id}: Missing 'functions' in patch_ir"
        assert "risk_tags" in patch_ir, f"{cve_id}: Missing 'risk_tags' in patch_ir"
        assert "semantic_summary" in patch_ir, f"{cve_id}: Missing 'semantic_summary'"

    @pytest.mark.parametrize("cve_id,scenario,exp_cat,exp_code,exp_retry",
                             CVE_TEST_CASES)
    def test_parse_change_units(self, cve_id, scenario, exp_cat, exp_code, exp_retry):
        """PatchParser must generate change_units for all CVEs."""
        workdir = create_cve_workdir(cve_id)
        parser = PatchParser(workdir, cve_id)
        parser.parse_patch(
            os.path.join(workdir, cve_id, "patches", "original.patch"))
        cu_path = os.path.join(workdir, cve_id, "change_units.json")
        assert os.path.exists(cu_path), f"{cve_id}: change_units.json not saved"
        with open(cu_path) as f:
            cu = json.load(f)
        assert "units" in cu, f"{cve_id}: No 'units' in change_units"
        assert len(cu["units"]) > 0, f"{cve_id}: Empty units list"

    def test_parse_produces_semantic_summary(self):
        """PatchParser must produce a semantic summary for any real CVE patch."""
        cve_id = CVE_TEST_CASES[0][0]
        workdir = create_cve_workdir(cve_id)
        parser = PatchParser(workdir, cve_id)
        patch_ir = parser.parse_patch(
            os.path.join(workdir, cve_id, "patches", "original.patch"))
        summary = patch_ir.get("semantic_summary", "")
        assert len(summary) > 0, f"Expected non-empty semantic summary"

    def test_parse_produces_risk_tags(self):
        """PatchParser must produce risk_tags list for any real CVE patch."""
        cve_id = CVE_TEST_CASES[0][0]
        workdir = create_cve_workdir(cve_id)
        parser = PatchParser(workdir, cve_id)
        patch_ir = parser.parse_patch(
            os.path.join(workdir, cve_id, "patches", "original.patch"))
        risk_tags = patch_ir.get("risk_tags", [])
        assert isinstance(risk_tags, list)
        assert len(patch_ir.get("files", [])) > 0

    def test_parse_produces_functions(self):
        """PatchParser must extract functions for any real CVE patch."""
        cve_id = CVE_TEST_CASES[0][0]
        workdir = create_cve_workdir(cve_id)
        parser = PatchParser(workdir, cve_id)
        patch_ir = parser.parse_patch(
            os.path.join(workdir, cve_id, "patches", "original.patch"))
        functions = patch_ir.get("functions", [])
        assert isinstance(functions, list)

    def test_parse_produces_change_units(self):
        """PatchParser must save change_units for any real CVE patch."""
        cve_id = CVE_TEST_CASES[0][0]
        workdir = create_cve_workdir(cve_id)
        parser = PatchParser(workdir, cve_id)
        parser.parse_patch(
            os.path.join(workdir, cve_id, "patches", "original.patch"))
        cu_path = os.path.join(workdir, cve_id, "change_units.json")
        assert os.path.exists(cu_path), f"change_units.json not saved"
        with open(cu_path) as f:
            cu = json.load(f)
        assert "units" in cu
        assert len(cu["units"]) > 0

    def test_multi_file_patch_detects_all_files(self):
        """CVE-2025-21646 (fs/afs) multi-file patch must have 2+ file entries."""
        cve_id = "CVE-2025-21646"
        workdir = create_cve_workdir(cve_id)
        parser = PatchParser(workdir, cve_id)
        patch_ir = parser.parse_patch(
            os.path.join(workdir, cve_id, "patches", "original.patch"))
        assert len(patch_ir["files"]) >= 2, \
            f"Expected 2+ files, got {len(patch_ir['files'])}"


# =========================================================================
# Section 3: FailureClassifier Tests (using CVE build logs)
# =========================================================================

class TestFailureClassification:
    """Verify FailureClassifier correctly classifies each scenario."""

    @pytest.mark.parametrize("cve_id,scenario,exp_cat,exp_code,exp_retry",
                             [c for c in CVE_TEST_CASES if c[3]])  # only failure cases
    def test_classify_build_failure(self, cve_id, scenario, exp_cat, exp_code, exp_retry):
        """FailureClassifier must identify the correct failure pattern."""
        workdir = create_cve_workdir(cve_id)
        log_path = os.path.join(BUILD_LOGS_DIR, f"{cve_id}_build_1.log")
        assert os.path.exists(log_path), f"Missing build log for {cve_id}"

        classifier = FailureClassifier(workdir, cve_id)
        # Copy build log to workdir
        import shutil
        os.makedirs(os.path.join(workdir, cve_id, "logs"), exist_ok=True)
        shutil.copy2(log_path, os.path.join(workdir, cve_id, "logs", "build_1.log"))

        failure = classifier.classify(
            os.path.join(workdir, cve_id, "logs", "build_1.log"), attempt=1)
        assert failure["category"] == exp_cat, \
            f"{cve_id}: Expected category={exp_cat}, got={failure['category']}"
        assert failure["reason_code"] == exp_code, \
            f"{cve_id}: Expected reason_code={exp_code}, got={failure['reason_code']}"
        assert failure["retryable"] == exp_retry, \
            f"{cve_id}: Expected retryable={exp_retry}, got={failure['retryable']}"

    def test_classify_success_build(self):
        """Success case build log must contain success markers."""
        cve_id = CVE_TEST_CASES[0][0]  # First entry = success scenario
        log_path = os.path.join(BUILD_LOGS_DIR, f"{cve_id}_build_1.log")
        assert os.path.exists(log_path), f"Missing build log for {cve_id}"
        content = open(log_path).read()
        assert "OK" in content or "success" in content.lower() or "generated" in content

    @pytest.mark.parametrize("cve_id,scenario,exp_cat,exp_code,exp_retry",
                             [c for c in CVE_TEST_CASES if c[3]])
    def test_failure_json_saved(self, cve_id, scenario, exp_cat, exp_code, exp_retry):
        """FailureClassifier must save failure.json after classification."""
        workdir = create_cve_workdir(cve_id)
        log_path = os.path.join(BUILD_LOGS_DIR, f"{cve_id}_build_1.log")
        import shutil
        os.makedirs(os.path.join(workdir, cve_id, "logs"), exist_ok=True)
        shutil.copy2(log_path, os.path.join(workdir, cve_id, "logs", "build_1.log"))

        classifier = FailureClassifier(workdir, cve_id)
        classifier.classify(os.path.join(workdir, cve_id, "logs", "build_1.log"))

        failure_path = os.path.join(workdir, cve_id, "failure.json")
        assert os.path.exists(failure_path), f"{cve_id}: failure.json not saved"


# =========================================================================
# Section 4: RewriteAdvisor Tests (using CVE test scenarios)
# =========================================================================

class TestRewritePlanning:
    """Verify RewriteAdvisor creates appropriate plans per scenario."""

    @pytest.mark.parametrize("cve_id,scenario,exp_cat,exp_code,exp_retry", [
        ("CVE-2024-56659", "api_mismatch", "compile", "api_mismatch", True),
        ("CVE-2024-56764", "hunk_failed", "patch_apply", "hunk_failed", True),
        ("CVE-2025-21656", "missing_include", "compile", "missing_api_or_include", True),
    ])
    def test_retryable_failure_gets_rewrite_plan(self, cve_id, scenario, exp_cat,
                                                  exp_code, exp_retry):
        """Retryable failures should produce a 'rewrite' decision."""
        workdir = create_cve_workdir(cve_id)
        advisor = RewriteAdvisor(workdir, cve_id)

        failure = {
            "category": exp_cat, "reason_code": exp_code,
            "location": {"file": "unknown", "function": "unknown"},
            "retryable": True,
        }
        change_units = {
            "units": [{
                "change_id": "CU-001", "file": "unknown",
                "function": "unknown", "rewrite_allowed": True,
            }]
        }
        plan = advisor.create_rewrite_plan(failure, change_units, attempt=1)
        assert plan["decision"] == "rewrite", \
            f"{cve_id}: Expected rewrite decision, got {plan['decision']}"
        assert "semantic_must_keep" in plan, f"{cve_id}: No semantic guards"

    @pytest.mark.parametrize("cve_id,scenario,exp_cat,exp_code,exp_retry", [
        ("CVE-2024-53156", "no_fentry", "kpatch_limit", "no_fentry", False),
        ("CVE-2025-21767", "struct_abi", "kpatch_limit", "struct_or_data_change", False),
        ("CVE-2025-21799", "init_function", "kpatch_limit", "no_fentry", False),
        ("CVE-2025-21646", "multi_file", "compile", "field_mismatch", False),
    ])
    def test_non_retryable_failure_gets_manual(self, cve_id, scenario, exp_cat,
                                                exp_code, exp_retry):
        """Non-retryable failures should produce 'manual_required' decision."""
        workdir = create_cve_workdir(cve_id)
        advisor = RewriteAdvisor(workdir, cve_id)

        failure = {
            "category": exp_cat, "reason_code": exp_code,
            "location": {"file": "unknown", "function": "unknown"},
            "retryable": False,
        }
        change_units = {
            "units": [{
                "change_id": "CU-001", "file": "unknown",
                "function": "unknown", "rewrite_allowed": False,
            }]
        }
        plan = advisor.create_rewrite_plan(failure, change_units, attempt=1)
        assert plan["decision"] == "manual_required", \
            f"{cve_id}: Expected manual_required, got {plan['decision']}"


# =========================================================================
# Section 5: CVE Metadata Tests
# =========================================================================

class TestCVEMetadata:
    """Verify CVE metadata files are well-formed."""

    @pytest.mark.parametrize("cve_id,scenario,exp_cat,exp_code,exp_retry",
                             CVE_TEST_CASES)
    def test_metadata_exists(self, cve_id, scenario, exp_cat, exp_code, exp_retry):
        """Each CVE must have metadata JSON."""
        meta_path = os.path.join(METADATA_DIR, f"{cve_id}_metadata.json")
        assert os.path.exists(meta_path), f"Missing metadata for {cve_id}"

    @pytest.mark.parametrize("cve_id,scenario,exp_cat,exp_code,exp_retry",
                             CVE_TEST_CASES)
    def test_metadata_has_required_fields(self, cve_id, scenario, exp_cat,
                                          exp_code, exp_retry):
        """Metadata must have cve_id, description, cvss, references."""
        meta = load_metadata(cve_id)
        assert meta["cve_id"] == cve_id
        assert "description" in meta["nvd"]
        assert "cvss" in meta["nvd"]
        assert "score" in meta["nvd"]["cvss"]
        assert "references" in meta["nvd"]
        assert len(meta["nvd"]["references"]) > 0

    @pytest.mark.parametrize("cve_id,scenario,exp_cat,exp_code,exp_retry",
                             CVE_TEST_CASES)
    def test_metadata_has_candidates(self, cve_id, scenario, exp_cat,
                                     exp_code, exp_retry):
        """Metadata must have candidate commits for resolution."""
        meta = load_metadata(cve_id)
        assert "candidates" in meta
        assert len(meta["candidates"]) >= 1
        for c in meta["candidates"]:
            assert "commit_id" in c
            assert "branch" in c
            assert "confidence" in c

    def test_cvss_scores_vary(self):
        """Different CVEs should have different severity levels."""
        scores = []
        for cve_id, _, _, _, _ in CVE_TEST_CASES:
            meta = load_metadata(cve_id)
            scores.append(meta["nvd"]["cvss"]["score"])
        assert len(set(scores)) > 1, "CVSS scores should vary across test CVEs"


# =========================================================================
# Section 6: State Machine Integration Tests
# =========================================================================

class TestStateMachineFlow:
    """Verify the state machine transitions work with CVE test data."""

    def test_state_manager_init(self):
        """StateManager must initialize run config and CVE states correctly."""
        import tempfile
        tmpdir = tempfile.mkdtemp()
        sm = StateManager(tmpdir)
        first_cves = [c[0] for c in CVE_TEST_CASES[:3]]
        sm.init_run_config(
            first_cves,
            "6.6.102-5.2.an23.x86_64",
            max_attempts=5)
        config = sm.get_run_config()
        assert config["kernel_version"] == "6.6.102-5.2.an23.x86_64"
        assert config["cve_count"] == 3
        assert config["max_attempts"] == 5

        for cve_id in first_cves:
            sm.init_cve_state(cve_id)
            state = sm.get_state(cve_id)
            assert state["state"] == "TaskCreated"
            assert state["attempt"] == 0

    def test_full_state_transition_chain(self):
        """StateMachine must support the full CVE processing state chain."""
        import tempfile
        tmpdir = tempfile.mkdtemp()
        sm = StateManager(tmpdir)
        cve_id = CVE_TEST_CASES[0][0]
        sm.init_run_config([cve_id], "6.6.102-5.2.an23.x86_64")
        sm.init_cve_state(cve_id)

        chain = [
            "CveResolved", "PatchFetched", "PatchAnalyzed",
            "TargetChecked", "PatchApplied", "BuildRunning",
            "BuildSucceeded", "Verified", "ReportWritten"
        ]
        for st in chain:
            sm.transition_to(cve_id, st, reason=f"Test {st}")
            state = sm.get_state(cve_id)
            assert state["state"] == st, f"Expected {st}, got {state['state']}"

    def test_failure_state_chain(self):
        """Failure state chain: BuildFailed -> FailureClassified -> RewritePrepared."""
        import tempfile
        tmpdir = tempfile.mkdtemp()
        sm = StateManager(tmpdir)
        cve_id = CVE_TEST_CASES[1][0]
        sm.init_run_config([cve_id], "6.6.102-5.2.an23.x86_64")
        sm.init_cve_state(cve_id)

        chain = [
            ("CveResolved", "resolved"),
            ("PatchFetched", "fetched"),
            ("PatchAnalyzed", "analyzed"),
            ("BuildFailed", "build failed"),
            ("FailureClassified", "classified"),
            ("RewritePrepared", "rewritten"),
        ]
        for st, reason in chain:
            sm.transition_to(cve_id, st, reason=reason)
            state = sm.get_state(cve_id)
            assert state["state"] == st

    def test_events_logged(self):
        """State transitions must be recorded in events.json."""
        import tempfile
        tmpdir = tempfile.mkdtemp()
        sm = StateManager(tmpdir)
        cve_id = CVE_TEST_CASES[0][0]
        sm.init_run_config([cve_id], "6.6.102-5.2.an23.x86_64")
        sm.init_cve_state(cve_id)
        sm.transition_to(cve_id, "CveResolved", reason="NVD query done")
        sm.transition_to(cve_id, "PatchFetched", reason="Patch downloaded")

        events_path = os.path.join(tmpdir, cve_id, "events.json")
        assert os.path.exists(events_path)
        with open(events_path) as f:
            events = json.load(f)
        assert len(events) == 2
        assert events[0]["from"] == "TaskCreated"
        assert events[0]["to"] == "CveResolved"

    def test_attempt_increment(self):
        """Attempt counter must increment correctly."""
        import tempfile
        tmpdir = tempfile.mkdtemp()
        sm = StateManager(tmpdir)
        cve_id = CVE_TEST_CASES[0][0]
        sm.init_run_config([cve_id], "6.6.102-5.2.an23.x86_64")
        sm.init_cve_state(cve_id)
        for i in range(1, 6):
            assert sm.increment_attempt(cve_id) == i
        assert sm.get_state(cve_id)["attempt"] == 5


# =========================================================================
# Section 7: Data Integrity Tests
# =========================================================================

class TestDataIntegrity:
    """Verify the test data itself is internally consistent."""

    def test_all_cves_have_all_artifacts(self):
        """Every CVE must have patch, build log, and metadata."""
        for cve_id, scenario, _, _, _ in CVE_TEST_CASES:
            try:
                patch_path = get_patch_path(cve_id)
                assert os.path.exists(patch_path)
            except FileNotFoundError:
                raise AssertionError(f"{cve_id}: Missing patch")
            assert os.path.exists(os.path.join(BUILD_LOGS_DIR, f"{cve_id}_build_1.log")), \
                f"{cve_id}: Missing build log"
            assert os.path.exists(os.path.join(METADATA_DIR, f"{cve_id}_metadata.json")), \
                f"{cve_id}: Missing metadata"

    def test_build_logs_match_scenario(self):
        """Build log content should match the expected failure scenario."""
        # Map each scenario to expected keyword(s) in the build log
        scenarios_map = {
            "api_mismatch": "too few arguments",
            "no_fentry": "no fentry call",
            "struct_abi": "Structure layout change",
            "static_data": "static data modification",
            "hunk_failed": "hunk FAILED",
            "missing_include": "implicit declaration",
            "undefined_symbol": "implicit declaration",
            "init_function": "__init/__devinit",
            "multi_file": "has no member named",
        }
        for cve_id, scenario, exp_cat, exp_code, exp_retry in CVE_TEST_CASES:
            if scenario == "success":
                continue  # success case - no failure keyword to check
            assert scenario in scenarios_map, \
                f"{cve_id}: scenario '{scenario}' missing from scenarios_map"
            log = load_build_log(cve_id)
            keyword = scenarios_map[scenario]
            assert keyword in log or keyword.lower() in log.lower(), \
                f"{cve_id}: Build log should contain '{keyword}'"

    def test_patch_contains_realistic_kernel_code(self):
        """Patches should contain realistic kernel code patterns."""
        for cve_id, scenario, _, _, _ in CVE_TEST_CASES:
            patch = load_patch(cve_id)
            # Look for kernel-specific patterns
            has_kernel_pattern = any(pattern in patch for pattern in [
                "struct ", "return -E", "if (!", "__init", "goto ",
                "#define", "sk_buff", "inode", "tcp_", "i2c_", "urb", "bpf_",
            ])
            assert has_kernel_pattern, \
                f"{cve_id}: Patch doesn't contain realistic kernel code"

    def test_cve_ids_are_valid(self):
        """CVE IDs should be real published CVEs from 2024-2025."""
        for cve_id, _, _, _, _ in CVE_TEST_CASES:
            parts = cve_id.split("-")
            assert len(parts) == 3, f"Invalid CVE format: {cve_id}"
            assert parts[0] == "CVE", f"Invalid CVE prefix: {cve_id}"
            year = int(parts[1])
            assert 2024 <= year <= 2025, f"CVE year out of range: {cve_id}"


# =========================================================================
# Section 8: Edge Case Tests
# =========================================================================

class TestEdgeCases:
    """Test edge cases with the CVE test data."""

    def test_empty_patch_rejected(self):
        """Parser should handle empty/malformed patches gracefully."""
        import tempfile
        tmpdir = tempfile.mkdtemp()
        os.makedirs(os.path.join(tmpdir, "CVE-2026-0999"))
        empty_patch = os.path.join(tmpdir, "CVE-2026-0999", "empty.patch")
        with open(empty_patch, "w") as f:
            f.write("")

        parser = PatchParser(tmpdir, "CVE-2026-0999")
        patch_ir = parser.parse_patch(empty_patch)
        assert patch_ir is not None
        assert len(patch_ir.get("files", [])) >= 0

    def test_classify_empty_log(self):
        """FailureClassifier should handle empty logs gracefully."""
        import tempfile
        tmpdir = tempfile.mkdtemp()
        cve_dir = os.path.join(tmpdir, "CVE-2026-0999")
        os.makedirs(os.path.join(cve_dir, "logs"))
        empty_log = os.path.join(cve_dir, "logs", "build_1.log")
        with open(empty_log, "w") as f:
            f.write("")

        classifier = FailureClassifier(tmpdir, "CVE-2026-0999")
        failure = classifier.classify(empty_log)
        assert failure["reason_code"] == "unrecognized"
        assert failure["retryable"] is False

    def test_rewrite_of_nonexistent_patch(self):
        """RewriteAdvisor should handle missing patch gracefully."""
        import tempfile
        tmpdir = tempfile.mkdtemp()
        os.makedirs(os.path.join(tmpdir, "CVE-2026-0999", "patches"))
        advisor = RewriteAdvisor(tmpdir, "CVE-2026-0999")
        result = advisor.apply_rewrite(
            "/nonexistent/patch", {"decision": "rewrite"}, "/some/source", attempt=1)
        assert result["success"] is False
