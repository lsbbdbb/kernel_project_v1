#!/usr/bin/env python3
"""CLI entry point for Kernel CVE Livepatch Auto-Generation Agent.

Orchestrates the full pipeline:
  resolve_cve → fetch_patch → analyze_patch → check_target → apply_patch
  → run_build → (classify_failure → prepare_rewrite)* → run_verify → write_report
"""
import argparse
import os
import sys
import json
import datetime
import re
import subprocess
import shutil

from typing import Dict, List, Optional

from agent.state import StateManager
from agent.planner import Planner, LLMPlanner

# Tool imports
from agent.tools.cve_resolver import CVEResolver
from agent.tools.patch_fetcher import PatchFetcher
from agent.tools.patch_parser import PatchParser
from agent.tools.kpatch_builder import KpatchBuilder
from agent.tools.failure_classifier import FailureClassifier
from agent.tools.rewrite_advisor import RewriteAdvisor
from agent.tools.verifier import Verifier
from agent.tools.reporter import Reporter
from agent.tools.kernel_config_checker import KernelConfigChecker


def validate_cve_id(cve_id: str) -> bool:
    """Validate CVE ID format: CVE-YYYY-NNNNNNNN or CVE-YYYY-NNNN."""
    return bool(re.match(r'^CVE-\d{4}-\d{4,}$', cve_id))


def parse_cves_file(path: str) -> list:
    """Parse cves.txt, return list of valid CVE IDs with duplicates recorded."""
    if not os.path.exists(path):
        print(f"Error: CVEs file not found: {path}", file=sys.stderr)
        sys.exit(1)

    valid = []
    invalid = []
    seen = set()

    with open(path) as f:
        for line in f:
            cve_id = line.strip()
            if not cve_id or cve_id.startswith('#'):
                continue
            if not validate_cve_id(cve_id):
                invalid.append(cve_id)
            elif cve_id in seen:
                print(f"Warning: Duplicate CVE skipped: {cve_id}")
            else:
                valid.append(cve_id)
                seen.add(cve_id)

    if invalid:
        print(f"Warning: Invalid CVE IDs skipped: {invalid}", file=sys.stderr)

    return valid


def _target_source_dir(workdir: str, kernel_version: str) -> str:
    """Resolve target kernel source path for host and container layouts."""
    env_source = os.getenv("KERNEL_SRC")
    if env_source:
        return env_source

    kernel_root = os.path.join(os.path.dirname(workdir), "kernel-src")
    exact = os.path.join(kernel_root, "linux-" + kernel_version)
    if os.path.isdir(exact):
        return exact

    # Backward-compatible fallback for older workdirs/scripts that omitted arch.
    stripped = os.path.join(kernel_root, "linux-" + kernel_version.replace(".x86_64", ""))
    return stripped


def _apply_llm_overrides(cfg, provider: str = None, model: str = None):
    """Apply explicit CLI LLM settings while keeping provider config aligned."""
    from agent.llm.config import DEFAULT_BASE_URLS, LLMConfig

    if provider:
        cfg.provider = provider
        cfg.api_key = LLMConfig._api_key_from_env(provider)
        cfg.base_url = os.getenv("LLM_BASE_URL") or DEFAULT_BASE_URLS.get(provider)
    if model:
        cfg.model = LLMConfig.normalize_model(model)
    return cfg


# ---------------------------------------------------------------------------
# Action executors – each maps to one planner action
# ---------------------------------------------------------------------------

def _action_resolve_cve(cve_id: str, workdir: str, state_mgr: StateManager) -> Dict:
    """Query NVD + Linux stable for CVE metadata."""
    resolver = CVEResolver(workdir, cve_id)
    result = resolver.resolve()
    state_mgr.transition_to(cve_id, "CveResolved",
                            reason="CVE resolved via NVD + stable")
    return result


def _action_fetch_patch(cve_id: str, workdir: str, state_mgr: StateManager) -> Dict:
    """Download original patch from Linux stable or NVD references."""
    fetcher = PatchFetcher(workdir, cve_id)
    # Try to get patch URL from CVE metadata
    metadata_path = os.path.join(workdir, cve_id, "metadata", "cve_metadata.json")
    patch_url = None
    if os.path.exists(metadata_path):
        with open(metadata_path) as f:
            meta = json.load(f)
        nvd = meta.get("nvd", {})
        for ref in nvd.get("references", []):
            url = ref.get("url", "")
            # Direct .patch URL → prefer this
            if url.endswith(".patch") or "/patch" in url:
                patch_url = url
                break
            # kernel.org commit URL → convert to patch URL
            # https://git.kernel.org/stable/c/<hash> → .../linux.git/patch/?id=<hash>
            import re as _re
            _m = _re.match(r'(https?://git\.kernel\.org)/.*?/c/([0-9a-f]+)', url)
            if _m:
                patch_url = f"{_m.group(1)}/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={_m.group(2)}"
                break

    if patch_url:
        result = fetcher.fetch_from_url(patch_url)
    if not patch_url:
        result = {
            "success": False,
            "error": "No patch URL found in CVE metadata",
            "path": None,
        }
        patches_dir = os.path.join(workdir, cve_id, "patches")
        os.makedirs(patches_dir, exist_ok=True)
        with open(os.path.join(patches_dir, "patch_source.json"), "w") as f:
            json.dump(result, f, indent=2)

    if result.get("success"):
        state_mgr.transition_to(cve_id, "PatchFetched",
                                reason="Patch fetched",
                                evidence={"original_patch": result.get("path")})
    else:
        source_record = os.path.join(workdir, cve_id, "patches", "patch_source.json")
        state_mgr.set_error(cve_id, result.get("error", "Patch retrieval failed"))
        state_mgr.set_final_status(cve_id, "failed")
        state_mgr.transition_to(cve_id, "Failed",
                                reason="Upstream patch retrieval failed",
                                evidence={"patch_source": source_record})
    return result


def _action_analyze_patch(cve_id: str, workdir: str, state_mgr: StateManager) -> Dict:
    """Parse unified diff into patch_ir.json and change_units.json."""
    patch_path = os.path.join(workdir, cve_id, "patches", "original.patch")
    parser = PatchParser(workdir, cve_id)
    patch_ir = parser.parse_patch(patch_path)
    state_mgr.transition_to(cve_id, "PatchAnalyzed",
                            reason="Patch parsed to IR")
    return patch_ir


def _action_check_target(cve_id: str, workdir: str, state_mgr: StateManager) -> Dict:
    """Check target source availability and whether patched objects are configured."""
    run_config = state_mgr.get_run_config()
    kernel_version = run_config.get("kernel_version", "6.6.102-5.2.an23.x86_64")
    source_dir = _target_source_dir(workdir, kernel_version)

    target_status = {"source_dir": source_dir, "exists": os.path.isdir(source_dir)}
    patch_ir_path = os.path.join(workdir, cve_id, "patch_ir.json")
    if target_status["exists"] and os.path.isfile(patch_ir_path):
        with open(patch_ir_path) as patch_ir_file:
            patch_ir = json.load(patch_ir_file)
        patched_files = [
            item.get("path", "") for item in patch_ir.get("files", [])
            if item.get("path") and item.get("path") != "unknown"
        ]
        target_status["config_check"] = KernelConfigChecker(source_dir).check_files(
            patched_files
        )
    ctx_path = os.path.join(workdir, cve_id, "context_match.json")
    with open(ctx_path, "w") as f:
        json.dump(target_status, f, indent=2)

    if target_status.get("config_check", {}).get("skipped"):
        state_mgr.set_final_status(cve_id, "skipped")
        state_mgr.transition_to(
            cve_id, "Skipped",
            reason="Patch targets object disabled by target kernel configuration",
            evidence={"context_match": ctx_path},
        )
    elif target_status["exists"]:
        state_mgr.transition_to(cve_id, "TargetChecked",
                                reason="Target source tree found")
    else:
        state_mgr.transition_to(cve_id, "TargetChecked",
                                reason="Target source tree not found, continuing anyway")
    return target_status


def _action_apply_patch(cve_id: str, workdir: str, state_mgr: StateManager) -> Dict:
    """Dry-run patch application against target source."""
    state = state_mgr.get_state(cve_id)
    attempt = state.get("attempt", 0)

    # Determine which patch to apply: try attempt-specific patch first, fall back to original
    if attempt > 0:
        patch_path = os.path.join(workdir, cve_id, "patches", f"attempt_{attempt}.patch")
        if not os.path.isfile(patch_path):
            patch_path = os.path.join(workdir, cve_id, "patches", "original.patch")
    else:
        patch_path = os.path.join(workdir, cve_id, "patches", "original.patch")

    run_config = state_mgr.get_run_config()
    kernel_version = run_config.get("kernel_version", "6.6.102-5.2.an23.x86_64")
    source_dir = _target_source_dir(workdir, kernel_version)

    result = {"patch_path": patch_path, "source_dir": source_dir,
              "dry_run_ok": False, "error": None, "stage": "apply"}

    if os.path.isdir(source_dir) and os.path.isfile(patch_path):
        # Stage 1: strict git apply --check
        try:
            proc = subprocess.run(
                ["git", "apply", "--check", patch_path],
                cwd=source_dir, capture_output=True, text=True, timeout=30,
                env={**os.environ, "LC_ALL": "C", "LANG": "C"})
            result["dry_run_ok"] = proc.returncode == 0
            if proc.returncode != 0:
                result["error"] = proc.stderr[:500]
        except Exception as e:
            result["error"] = str(e)

        # Stage 2: if forward fails, check if patch is already applied
        if not result["dry_run_ok"]:
            try:
                rev_proc = subprocess.run(
                    ["git", "apply", "--check", "--reverse", patch_path],
                    cwd=source_dir, capture_output=True, text=True, timeout=30,
                    env={**os.environ, "LC_ALL": "C", "LANG": "C"})
                if rev_proc.returncode == 0:
                    result["dry_run_ok"] = True
                    result["already_applied"] = True
                    result["note"] = "Patch already applied in target kernel"
                    result["error"] = None
            except Exception:
                pass

        # Stage 3: fallback to patch --dry-run with fuzz
        if not result["dry_run_ok"]:
            try:
                patch_proc = subprocess.run(
                    ["patch", "-p1", "--dry-run", "-F2", "-i", patch_path],
                    cwd=source_dir, capture_output=True, text=True, timeout=30)
                if patch_proc.returncode == 0:
                    result["dry_run_ok"] = True
                    result["note"] = "Patch applies with fuzz (patch --dry-run)"
                    result["error"] = None
            except Exception:
                pass
    elif not os.path.isdir(source_dir):
        result["dry_run_ok"] = True
        result["note"] = "Source tree not available, skipping dry-run"

    if result.get("already_applied"):
        state_mgr.set_final_status(cve_id, "skipped")
        state_mgr.transition_to(cve_id, "Skipped",
                                reason="Patch already applied in target kernel")
    elif result["dry_run_ok"]:
        state_mgr.transition_to(cve_id, "PatchApplied",
                                reason="Patch passed dry-run check")
    else:
        logs_dir = os.path.join(workdir, cve_id, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        log_path = os.path.join(logs_dir, f"build_{attempt}.log")
        with open(log_path, "w") as log:
            log.write(result.get("error") or "patch dry-run failed\n")
        result["log_path"] = log_path
        state_mgr.transition_to(cve_id, "BuildFailed",
                                reason="Patch failed dry-run check",
                                evidence={"build_log": log_path})
    return result


def _action_run_build(cve_id: str, workdir: str, state_mgr: StateManager) -> Dict:
    """Run kpatch-build on the current patch."""
    state = state_mgr.get_state(cve_id)
    attempt = state.get("attempt", 0)

    # Determine which patch to build: try attempt-specific patch first, fall back to original
    if attempt > 0:
        patch_path = os.path.join(workdir, cve_id, "patches", f"attempt_{attempt}.patch")
        if not os.path.isfile(patch_path):
            patch_path = os.path.join(workdir, cve_id, "patches", "original.patch")
    else:
        patch_path = os.path.join(workdir, cve_id, "patches", "original.patch")

    run_config = state_mgr.get_run_config()
    kernel_version = run_config.get("kernel_version", "6.6.102-5.2.an23.x86_64")
    source_dir = _target_source_dir(workdir, kernel_version)
    vmlinux_path = os.path.join(source_dir, "vmlinux")

    # Ensure kernel .config is fresh before building (fixes syncconfig errors)
    _ensure_kernel_config(source_dir)

    # Detect actual kernel release after config fix (make olddefconfig may
    # change the version string, e.g. adding git hash suffix). Use the
    # ACTUAL release for validation, not the configured one.
    actual_version = _detect_kernel_release(source_dir) or kernel_version

    builder = KpatchBuilder(workdir, cve_id)
    result = builder.build(patch_path, source_dir, vmlinux_path,
                           kernel_devel_path=None, attempt=attempt,
                           expected_kernel_version=actual_version)

    # Clean source tree after build to prevent pollution of subsequent runs
    _clean_kernel_source(source_dir)

    if result["success"]:
        state_mgr.transition_to(cve_id, "BuildSucceeded",
                                reason="kpatch-build succeeded",
                                evidence={"artifact": result.get("artifact_path")})
    else:
        state_mgr.transition_to(cve_id, "BuildFailed",
                                reason="kpatch-build failed",
                                evidence={"build_log": result.get("log_path")})
    return result


def _action_check_build_result(cve_id: str, workdir: str, state_mgr: StateManager) -> Dict:
    """Planner calls this to decide after BuildRunning; no action needed here."""
    # The state is already set by _action_run_build.
    return {"note": "State already transitioned by run_build"}


def _action_classify_failure(cve_id: str, workdir: str, state_mgr: StateManager) -> Dict:
    """Classify build failure from logs."""
    state = state_mgr.get_state(cve_id)
    attempt = state.get("attempt", 1)
    log_path = os.path.join(workdir, cve_id, "logs", f"build_{attempt}.log")

    classifier = FailureClassifier(workdir, cve_id)
    failure = classifier.classify(log_path, attempt=attempt)

    # Preserve rewrite provenance when a rewritten build later fails.
    attempt_path = os.path.join(workdir, cve_id, f"attempt_{attempt}.json")
    attempt_rec = {}
    if os.path.exists(attempt_path):
        with open(attempt_path) as existing_attempt:
            attempt_rec = json.load(existing_attempt)
    attempt_rec.update({
        "attempt_index": attempt,
        "build_log": log_path,
        "failure": failure,
    })
    with open(attempt_path, "w") as f:
        json.dump(attempt_rec, f, indent=2, ensure_ascii=False)

    state_mgr.transition_to(cve_id, "FailureClassified",
                            reason="Failure classified",
                            evidence={"failure_json": os.path.join(workdir, cve_id, "failure.json")})
    return failure


def _action_classify_verify_failure(cve_id: str, workdir: str, state_mgr: StateManager) -> Dict:
    """Classify verification failure."""
    verify_log = os.path.join(workdir, cve_id, "logs", "verify_1.log")
    dmesg_log = os.path.join(workdir, cve_id, "logs", "dmesg_1.log")

    classifier = FailureClassifier(workdir, cve_id)
    failure = classifier.classify_verify_log(verify_log, dmesg_log)

    with open(os.path.join(workdir, cve_id, "failure.json"), "w") as f:
        json.dump(failure, f, indent=2, ensure_ascii=False)

    state_mgr.transition_to(cve_id, "FailureClassified",
                            reason="Verify failure classified")
    return failure


def _action_prepare_rewrite(cve_id: str, workdir: str, state_mgr: StateManager, llm_client=None) -> Dict:
    """Prepare rewrite plan and generate attempt_N.patch."""
    state = state_mgr.get_state(cve_id)
    attempt = state_mgr.increment_attempt(cve_id)

    failure_path = os.path.join(workdir, cve_id, "failure.json")
    change_units_path = os.path.join(workdir, cve_id, "change_units.json")

    with open(failure_path) as f:
        failure = json.load(f)
    change_units = {}
    if os.path.exists(change_units_path):
        with open(change_units_path) as f:
            change_units = json.load(f)

    # Build retriever for RAG injection when LLM is available
    retriever = None
    if llm_client and llm_client.ping():
        try:
            from agent.rag.knowledge_base import KnowledgeBase
            from agent.rag.retriever import KnowledgeRetriever
            kb = KnowledgeBase()
            kb.load_all()
            retriever = KnowledgeRetriever(kb)
        except Exception:
            pass

    advisor = RewriteAdvisor(workdir, cve_id, llm_client=llm_client, retriever=retriever)
    plan = advisor.create_rewrite_plan(failure, change_units, attempt)

    if plan.get("decision") == "rewrite":
        original_patch = os.path.join(workdir, cve_id, "patches", "original.patch")
        kernel_version = state_mgr.get_run_config().get(
            "kernel_version", "6.6.102-5.2.an23.x86_64"
        )
        target_source_dir = _target_source_dir(workdir, kernel_version)
        rewrite_result = advisor.apply_rewrite(original_patch, plan, target_source_dir, attempt)
        if rewrite_result.get("success"):
            state_mgr.transition_to(cve_id, "RewritePrepared",
                                    reason=f"Rewrite prepared (attempt {attempt})")
            return rewrite_result
        else:
            state_mgr.set_final_status(cve_id, "manual_required")
            state_mgr.transition_to(cve_id, "ManualRequired",
                                    reason="Rewrite application failed")
            return rewrite_result
    else:
        state_mgr.set_final_status(cve_id, "manual_required")
        state_mgr.transition_to(cve_id, "ManualRequired",
                                reason="Rewrite not allowed by plan")
        return plan


def _action_run_verify(cve_id: str, workdir: str, state_mgr: StateManager,
                       vm_host: str = None, poc_path: str = None) -> Dict:
    """Verify .ko in target VM (or local modinfo if VM not available)."""
    ko_path = os.path.join(workdir, cve_id, "artifacts", "livepatch.ko")
    verifier = Verifier(workdir, cve_id)
    result = verifier.verify(ko_path, vm_host=vm_host, poc_path=poc_path)

    if result.get("result") == "passed":
        state_mgr.transition_to(cve_id, "Verified",
                                reason="Verification passed")
    else:
        state_mgr.transition_to(cve_id, "VerifyFailed",
                                reason="Verification failed")
    return result


def _action_check_verify_result(cve_id: str, workdir: str, state_mgr: StateManager) -> Dict:
    """Planner helper – state already set by run_verify."""
    return {"note": "State already transitioned by run_verify"}


def _action_write_report(cve_id: str, workdir: str, state_mgr: StateManager, cve_ids: List[str]) -> Dict:
    """Generate report.json for this CVE and summary.json for the batch."""
    reporter = Reporter(workdir, cve_id)
    state = state_mgr.get_state(cve_id)
    final_state = state.get("state", "ReportWritten")

    # Set final status based on state machine position
    status_map = {
        "Verified": "success",
        "ReportWritten": state.get("status") or "success",
        "ManualRequired": "manual_required",
        "Failed": "failed",
        "Skipped": "skipped",
    }
    final_status = status_map.get(final_state, "failed")
    if not state.get("status"):
        state_mgr.set_final_status(cve_id, final_status)

    state_mgr.transition_to(cve_id, "ReportWritten",
                            reason="Report written")
    report = reporter.generate_report()
    return report


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def process_cve(cve_id: str, workdir: str, state_mgr: StateManager, planner: Planner,
                cve_ids: List[str], llm_client=None, vm_host: str = None,
                poc_path: str = None) -> None:
    """Run the full pipeline for a single CVE."""
    max_iterations = 50  # Safety limit to prevent infinite loops
    iteration = 0

    while iteration < max_iterations:
        iteration += 1
        decision = planner.decide_next(cve_id)
        action = decision.get("action", "unknown")

        if action == "done":
            # Ensure final status and report are generated for all exit paths
            next_st = decision.get("next_state")
            if next_st == "Failed":
                state_mgr.set_final_status(cve_id, "failed")
            elif next_st == "Skipped":
                state_mgr.set_final_status(cve_id, "skipped")
            elif next_st == "ManualRequired" or state_mgr.get_state(cve_id).get("status") == "manual_required":
                state_mgr.set_final_status(cve_id, "manual_required")
            elif not state_mgr.get_state(cve_id).get("status"):
                state_mgr.set_final_status(cve_id, "failed")
            state_mgr.transition_to(cve_id, "ReportWritten",
                                    reason=decision.get("reason", "Finalized"))
            _action_write_report(cve_id, workdir, state_mgr, cve_ids)
            break

        if action == "unknown":
            print(f"  [{cve_id}] Unknown action: {decision.get('reason', '')}")
            state_mgr.set_final_status(cve_id, "failed")
            state_mgr.transition_to(cve_id, "ReportWritten",
                                    reason=f"Unknown action: {decision.get('reason', '')}")
            break

        handler = ACTION_MAP.get(action)
        if handler is None:
            print(f"  [{cve_id}] No handler for action: {action}")
            break

        print(f"  [{cve_id}] Executing: {action}")
        try:
            if action == "write_report":
                result = handler(cve_id, workdir, state_mgr, cve_ids)
            elif action == "prepare_rewrite":
                result = handler(cve_id, workdir, state_mgr, llm_client)
            elif action == "run_verify":
                result = handler(cve_id, workdir, state_mgr, vm_host, poc_path)
            else:
                result = handler(cve_id, workdir, state_mgr)
            print(f"  [{cve_id}]   -> {action} completed")
        except Exception as e:
            print(f"  [{cve_id}]   -> {action} FAILED: {e}")
            state_mgr.set_error(cve_id, str(e))
            state_mgr.set_final_status(cve_id, "failed")
            state_mgr.transition_to(cve_id, "ReportWritten",
                                    reason=f"Exception in {action}: {e}")
            break

        # After report is written, stop
        current_state = state_mgr.get_state(cve_id).get("state", "")
        if current_state == "ReportWritten":
            break


def _ensure_kernel_config(source_dir: str):
    """Ensure kernel .config is fresh before kpatch-build.

    Also ensures include/config/auto.conf.cmd exists — this file is
    generated by 'make syncconfig' (not by 'make olddefconfig') and
    is required by the kernel Makefile at line 787. Without it, the
    build will fail with:
      Makefile:787: include/config/auto.conf.cmd: No such file or directory

    Tries 'make olddefconfig' with srctree and CC overrides if the
    simple invocation fails. Runs 'make syncconfig' if auto.conf.cmd
    is still missing.

    In the Docker build environment, use: docker compose up agent
    """
    if not os.path.isdir(source_dir):
        return False
    config_path = os.path.join(source_dir, ".config")
    if not os.path.isfile(config_path):
        return False
    # Try simple invocation first (works in Docker)
    for cmd in [
        ["make", "olddefconfig"],
        ["make", "olddefconfig", "srctree=.", "CC=gcc"],
    ]:
        try:
            proc = subprocess.run(
                cmd, cwd=source_dir, capture_output=True, text=True,
                timeout=120,
                env={**os.environ, "LC_ALL": "C", "LANG": "C"},
            )
            if proc.returncode == 0:
                break
        except Exception:
            continue
    else:
        return False

    # auto.conf.cmd is NOT created by olddefconfig — only by syncconfig.
    # If missing, run syncconfig (which tolerates errors) to generate it.
    # The Makefile 'include include/config/auto.conf.cmd' (line 787) will
    # fail fatally if this file is absent when kpatch-build runs make.
    auto_conf_cmd = os.path.join(source_dir, "include", "config", "auto.conf.cmd")
    if not os.path.isfile(auto_conf_cmd):
        syncconfig_cmds = [
            ["make", "syncconfig", "srctree=.", "CC=gcc"],
            ["make", "syncconfig"],
        ]
        for cmd in syncconfig_cmds:
            try:
                proc = subprocess.run(
                    cmd, cwd=source_dir, capture_output=True, text=True,
                    timeout=120,
                    env={**os.environ, "LC_ALL": "C", "LANG": "C"},
                )
                # syncconfig exits non-zero but still writes auto.conf.cmd
                if os.path.isfile(auto_conf_cmd):
                    break
            except Exception:
                continue

    # Touch auto.conf and auto.conf.cmd to be newer than .config,
    # preventing the kernel Makefile from re-triggering syncconfig.
    # Without this, kpatch-build's make will run syncconfig which
    # fails due to kpatch-cc wrapper in CC variable.
    auto_conf = os.path.join(source_dir, "include", "config", "auto.conf")
    auto_conf_cmd = os.path.join(source_dir, "include", "config", "auto.conf.cmd")
    if os.path.isfile(auto_conf) and os.path.isfile(auto_conf_cmd):
        import time
        config_mtime = os.path.getmtime(config_path)
        min_new = config_mtime + 1.0
        for f in (auto_conf, auto_conf_cmd):
            if os.path.getmtime(f) <= config_mtime:
                os.utime(f, (min_new, min_new))

    return True


def _clean_kernel_source(source_dir: str):
    """Restore kernel source tree to a clean state after kpatch-build.

    Called before and after kpatch-build to prevent build artifacts
    from polluting subsequent runs.
    """
    if not os.path.isdir(source_dir):
        return

    # Method 1: git checkout (fastest, for git-managed trees)
    git_dir = os.path.join(source_dir, ".git")
    if os.path.isdir(git_dir):
        try:
            subprocess.run(
                ["git", "checkout", "--", "."],
                cwd=source_dir, capture_output=True, timeout=60,
            )
            subprocess.run(
                ["git", "clean", "-fd"],
                cwd=source_dir, capture_output=True, timeout=60,
            )
            return
        except Exception:
            pass

    # Method 2: restore from .orig backup files (for non-git trees)
    try:
        for root, dirs, files in os.walk(source_dir):
            for f in files:
                if f.endswith(".orig"):
                    orig_path = os.path.join(root, f)
                    src_path = orig_path[:-5]
                    shutil.move(orig_path, src_path)
    except Exception:
        pass


def _detect_kernel_release(source_dir: str) -> Optional[str]:
    """Detect the actual kernel release string from the source tree."""
    if not os.path.isdir(source_dir):
        return None
    try:
        proc = subprocess.run(
            ["make", "-s", "kernelrelease"],
            cwd=source_dir, capture_output=True, text=True, timeout=30,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:
        pass
    return None


def _action_fix_environment(cve_id: str, workdir: str, state_mgr: StateManager) -> Dict:
    """Fix environment issues detected by failure classifier."""
    # Read failure to determine which fix to apply
    failure_path = os.path.join(workdir, cve_id, "failure.json")
    reason_code = "unknown"
    if os.path.exists(failure_path):
        with open(failure_path) as f:
            failure = json.load(f)
        reason_code = failure.get("reason_code", "unknown")

    run_config = state_mgr.get_run_config()
    kernel_version = run_config.get("kernel_version", "6.6.102-5.2.an23.x86_64")
    source_dir = _target_source_dir(workdir, kernel_version)

    result = {"fix": reason_code, "source_dir": source_dir, "success": False, "message": ""}

    if reason_code == "syncconfig" and os.path.isdir(source_dir):
        # Try multiple make olddefconfig variants
        for cmd in [
            ["make", "olddefconfig"],
            ["make", "olddefconfig", "srctree=.", "CC=gcc"],
        ]:
            try:
                proc = subprocess.run(
                    cmd, cwd=source_dir, capture_output=True, text=True,
                    timeout=120,
                    env={**os.environ, "LC_ALL": "C", "LANG": "C"},
                )
                if proc.returncode == 0:
                    result["success"] = True
                    result["message"] = f"{' '.join(cmd)} completed successfully"
                    break
                result["message"] = f"{' '.join(cmd)} failed: {proc.stderr[:200]}"
            except Exception as e:
                result["message"] = str(e)
        # Also ensure auto.conf.cmd exists (syncconfig only)
        auto_conf_cmd = os.path.join(source_dir, "include", "config", "auto.conf.cmd")
        if not os.path.isfile(auto_conf_cmd):
            for cmd in [
                ["make", "syncconfig", "srctree=.", "CC=gcc"],
                ["make", "syncconfig"],
            ]:
                try:
                    proc = subprocess.run(
                        cmd, cwd=source_dir, capture_output=True, text=True,
                        timeout=120,
                        env={**os.environ, "LC_ALL": "C", "LANG": "C"},
                    )
                    if os.path.isfile(auto_conf_cmd):
                        result["success"] = True
                        result["message"] += " + syncconfig (generated auto.conf.cmd)"
                        break
                except Exception:
                    continue
    elif reason_code in (
        "missing_vmlinux", "source_permission_denied", "git_unsafe_ownership",
        "kernel_mismatch", "setlocalversion_incompatible",
    ):
        result["message"] = f"Environment issue {reason_code} requires manual intervention"
    else:
        result["message"] = f"No automated fix available for {reason_code}"

    if result["success"]:
        state_mgr.transition_to(cve_id, "FixEnvironment",
                                reason=result["message"],
                                evidence={"env_fix": result})
    else:
        state_mgr.set_final_status(cve_id, "manual_required")
        state_mgr.transition_to(cve_id, "ManualRequired",
                                reason=result["message"],
                                evidence={"env_fix": result})
    return result


# Map action names to handler functions
ACTION_MAP = {
    "resolve_cve": _action_resolve_cve,
    "fetch_patch": _action_fetch_patch,
    "analyze_patch": _action_analyze_patch,
    "check_target": _action_check_target,
    "apply_patch": _action_apply_patch,
    "run_build": _action_run_build,
    "check_build_result": _action_check_build_result,
    "classify_failure": _action_classify_failure,
    "classify_verify_failure": _action_classify_verify_failure,
    "prepare_rewrite": _action_prepare_rewrite,
    "run_verify": _action_run_verify,
    "check_verify_result": _action_check_verify_result,
    "fix_environment": _action_fix_environment,
    "write_report": _action_write_report,
}


def _check_docker_env():
    """Warn if we appear to be running outside the Docker build environment."""
    if not os.path.exists("/.dockerenv"):
        try:
            proc = subprocess.run(
                ["kpatch-build", "--version"],
                capture_output=True, timeout=5,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            proc = None
        if proc is None or proc.returncode != 0:
            print("⚠  未检测到 Docker 环境和 kpatch-build 命令")
            print("   建议在 Docker 中运行：docker compose up agent")
            print("   或安装依赖：pip install -r requirements.txt && pip install -e .\n")


def main():
    _check_docker_env()
    parser = argparse.ArgumentParser(
        description="Kernel CVE Livepatch Auto-Generation Agent")
    parser.add_argument("--cves", required=True,
                        help="Path to cves.txt (one CVE ID per line)")
    parser.add_argument("--kernel-version",
                        default="6.6.102-5.2.an23.x86_64",
                        help="Target kernel version")
    parser.add_argument("--workdir", default=None,
                        help="Output working directory (default: auto-create)")
    parser.add_argument("--max-attempts", type=int, default=5,
                        help="Max rewrite attempts per CVE (default: 5)")
    parser.add_argument("--no-llm", action="store_true",
                        help="Disable LLM usage and run rule-only planner")
    parser.add_argument("--llm-provider", default=None,
                        help="LLM provider name (e.g., deepseek, openai, ollama)")
    parser.add_argument("--llm-model", default=None,
                        help="LLM model name to request from provider")
    parser.add_argument("--vm-host", default=None,
                        help="SSH target for runtime module verification, e.g. root@anolis-vm")
    parser.add_argument("--vm-poc", default=None,
                        help="Optional VM checker path; it must exit 0 only when mitigation holds")

    args = parser.parse_args()

    cve_ids = parse_cves_file(args.cves)
    if not cve_ids:
        print("Error: No valid CVE IDs found.", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(cve_ids)} CVE(s): {', '.join(cve_ids)}")

    if args.workdir:
        workdir = args.workdir
    else:
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        workdir = os.path.join(os.getcwd(), f"run_{timestamp}")

    os.makedirs(workdir, exist_ok=True)
    print(f"Working directory: {workdir}")

    state_mgr = StateManager(workdir)
    state_mgr.init_run_config(cve_ids, args.kernel_version, args.max_attempts)

    # Initialize LLM client if requested and available. Fall back gracefully.
    llm_client = None
    if not args.no_llm:
        try:
            from agent.llm.config import LLMConfig
            from agent.llm.client import LLMClient

            # Prefer an env-based config if available
            if hasattr(LLMConfig, 'from_env'):
                cfg = LLMConfig.from_env()
            else:
                cfg = LLMConfig()
            cfg = _apply_llm_overrides(cfg, args.llm_provider, args.llm_model)

            llm_client = LLMClient(cfg)
            if not getattr(llm_client, 'ping', lambda: False)():
                print("LLM client ping failed; continuing in --no-llm mode")
                llm_client = None
        except Exception:
            print("LLM client not available or failed to initialize; running in no-llm mode")

    planner = LLMPlanner(state_mgr, llm_client=llm_client, no_llm=(args.no_llm or llm_client is None))

    for cve_id in cve_ids:
        state_mgr.init_cve_state(cve_id)
        print(f"  Initialized: {cve_id}")

    run_config = state_mgr.get_run_config()
    print(f"\nRun configuration saved.")
    print(f"  Kernel version: {run_config['kernel_version']}")
    print(f"  Max attempts per CVE: {run_config['max_attempts']}")
    print(f"\nAgent initialized. Starting pipeline for {len(cve_ids)} CVE(s).\n")

    # Process each CVE through the full pipeline
    for cve_id in cve_ids:
        print(f"[Processing] {cve_id}")
        process_cve(cve_id, workdir, state_mgr, planner, cve_ids, llm_client,
                    args.vm_host, args.vm_poc)
        final_state = state_mgr.get_state(cve_id)
        print(f"[Done] {cve_id}: state={final_state.get('state')}, "
              f"status={final_state.get('status')}\n")

    # Generate batch summary
    print("Generating batch summary...")
    reporter = Reporter(workdir, "")
    summary = reporter.generate_summary(cve_ids)
    print(f"  Total: {summary['total_cves']} CVE(s)")
    print(f"  Success: {summary['results']['success']}")
    print(f"  Failed: {summary['results']['failed']}")
    print(f"  Manual: {summary['results']['manual_required']}")
    print(f"  Skipped: {summary['results']['skipped']}")
    print(f"\nSummary written to: {os.path.join(workdir, 'summary.json')}")
    print("Agent run complete.")

    # Generate organized out/ folder
    out_dir = os.path.join(workdir, "out")
    _generate_out_folder(workdir, out_dir, cve_ids, summary)


def _generate_out_folder(workdir: str, out_dir: str, cve_ids: list, summary: dict):
    """Generate organized out/ folder with results and reports."""
    os.makedirs(out_dir, exist_ok=True)

    # Copy summary
    import shutil as _shutil
    src_summary = os.path.join(workdir, "summary.json")
    if os.path.exists(src_summary):
        _shutil.copy2(src_summary, os.path.join(out_dir, "summary.json"))

    # Per-CVE results
    for cve_id in cve_ids:
        cve_out = os.path.join(out_dir, cve_id)
        os.makedirs(cve_out, exist_ok=True)

        cve_dir = os.path.join(workdir, cve_id)
        if not os.path.isdir(cve_dir):
            continue

        # Copy report
        for fname in ["report.json", "state.json", "failure.json",
                       "verification.json", "patch_ir.json", "events.json"]:
            src = os.path.join(cve_dir, fname)
            if os.path.exists(src):
                _shutil.copy2(src, os.path.join(cve_out, fname))

        # Copy logs
        logs_src = os.path.join(cve_dir, "logs")
        logs_dst = os.path.join(cve_out, "logs")
        if os.path.isdir(logs_src):
            if os.path.exists(logs_dst):
                _shutil.rmtree(logs_dst)
            _shutil.copytree(logs_src, logs_dst)

        # Copy artifacts (.ko files)
        art_src = os.path.join(cve_dir, "artifacts")
        art_dst = os.path.join(cve_out, "artifacts")
        if os.path.isdir(art_src):
            if os.path.exists(art_dst):
                _shutil.rmtree(art_dst)
            _shutil.copytree(art_src, art_dst)

        # Copy patches
        patch_src = os.path.join(cve_dir, "patches")
        patch_dst = os.path.join(cve_out, "patches")
        if os.path.isdir(patch_src):
            if os.path.exists(patch_dst):
                _shutil.rmtree(patch_dst)
            _shutil.copytree(patch_src, patch_dst)

    # Write run metadata
    import datetime as _dt
    meta = {
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "workdir": workdir,
        "cve_count": len(cve_ids),
        "results": summary.get("results", {}),
    }
    with open(os.path.join(out_dir, "run_metadata.json"), "w") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    print(f"\nOutput written to: {out_dir}")
    for cve_id in cve_ids:
        has_ko = os.path.exists(os.path.join(out_dir, cve_id, "artifacts", "livepatch.ko"))
        print(f"  {cve_id}: {'livepatch.ko' if has_ko else 'no artifact'}")


if __name__ == "__main__":
    main()
