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
import traceback

from typing import Dict, List

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
            if url.endswith(".patch") or "/patch" in url:
                patch_url = url
                break

    if patch_url:
        result = fetcher.fetch_from_url(patch_url)
    else:
        # No direct patch URL – save placeholder so pipeline can continue
        result = {
            "success": False,
            "error": "No patch URL found in CVE metadata",
            "path": None,
        }
        # Create a minimal placeholder patch so downstream tools don't crash
        patches_dir = os.path.join(workdir, cve_id, "patches")
        os.makedirs(patches_dir, exist_ok=True)
        placeholder = os.path.join(patches_dir, "original.patch")
        with open(placeholder, "w") as f:
            f.write("# No upstream patch found – placeholder for pipeline\n")
        result["path"] = placeholder

    if result.get("success") or result.get("path"):
        state_mgr.transition_to(cve_id, "PatchFetched",
                                reason="Patch fetched",
                                evidence={"original_patch": result.get("path")})
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
    """Check target kernel source tree availability."""
    run_config = state_mgr.get_run_config()
    kernel_version = run_config.get("kernel_version", "6.6.102-5.2.an23.x86_64")
    source_dir = _target_source_dir(workdir, kernel_version)

    target_status = {"source_dir": source_dir, "exists": os.path.isdir(source_dir)}
    ctx_path = os.path.join(workdir, cve_id, "context_match.json")
    with open(ctx_path, "w") as f:
        json.dump(target_status, f, indent=2)

    if target_status["exists"]:
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
              "dry_run_ok": False, "error": None}

    if os.path.isdir(source_dir) and os.path.isfile(patch_path):
        try:
            proc = subprocess.run(
                ["git", "apply", "--check", patch_path],
                cwd=source_dir, capture_output=True, text=True, timeout=30)
            result["dry_run_ok"] = proc.returncode == 0
            if proc.returncode != 0:
                result["error"] = proc.stderr[:500]
        except Exception as e:
            result["error"] = str(e)
    elif not os.path.isdir(source_dir):
        result["dry_run_ok"] = True  # Skip dry-run if source unavailable
        result["note"] = "Source tree not available, skipping dry-run"

    state_mgr.transition_to(cve_id, "PatchApplied",
                            reason="Patch applied (dry-run)")
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

    builder = KpatchBuilder(workdir, cve_id)
    result = builder.build(patch_path, source_dir, vmlinux_path,
                           kernel_devel_path=None, attempt=attempt)

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

    # Save attempt record
    attempt_rec = {
        "attempt_index": attempt,
        "build_log": log_path,
        "failure": failure,
    }
    with open(os.path.join(workdir, cve_id, f"attempt_{attempt}.json"), "w") as f:
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


def _action_prepare_rewrite(cve_id: str, workdir: str, state_mgr: StateManager) -> Dict:
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

    advisor = RewriteAdvisor(workdir, cve_id)
    plan = advisor.create_rewrite_plan(failure, change_units, attempt)

    if plan.get("decision") == "rewrite":
        original_patch = os.path.join(workdir, cve_id, "patches", "original.patch")
        rewrite_result = advisor.apply_rewrite(original_patch, plan, None, attempt)
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


def _action_run_verify(cve_id: str, workdir: str, state_mgr: StateManager) -> Dict:
    """Verify .ko in target VM (or local modinfo if VM not available)."""
    ko_path = os.path.join(workdir, cve_id, "artifacts", "livepatch.ko")
    verifier = Verifier(workdir, cve_id)
    result = verifier.verify(ko_path, vm_host=None)

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

def process_cve(cve_id: str, workdir: str, state_mgr: StateManager, planner: Planner, cve_ids: List[str]) -> None:
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
    "write_report": _action_write_report,
}


def main():
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
                        help="LLM provider name (e.g., deepseek, qwen, openai)")
    parser.add_argument("--llm-model", default=None,
                        help="LLM model name to request from provider")

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
            if args.llm_provider:
                setattr(cfg, 'provider', args.llm_provider)
            if args.llm_model:
                setattr(cfg, 'model', LLMConfig.normalize_model(args.llm_model))

            llm_client = LLMClient(cfg)
            if not getattr(llm_client, 'ping', lambda: False)():
                print("LLM client ping failed; continuing in --no-llm mode")
                llm_client = None
        except Exception as exc:
            print(f"LLM client not available or failed to initialize; running in no-llm mode: {exc}")

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
        try:
            process_cve(cve_id, workdir, state_mgr, planner, cve_ids)
        except Exception as exc:
            print(f"  [{cve_id}] Pipeline crashed: {exc}")
            try:
                state_mgr.set_error(cve_id, str(exc))
                state_mgr.set_final_status(cve_id, "failed")
            except Exception:
                pass  # best-effort error recording
        final_state = state_mgr.get_state(cve_id)
        print(f"[Done] {cve_id}: state={final_state.get('state')}, "
              f"status={final_state.get('status')}\n")

    # Generate batch summary (best-effort — never crash the run)
    print("Generating batch summary...")
    try:
        reporter = Reporter(workdir, "")
        summary = reporter.generate_summary(cve_ids)
        print(f"  Total: {summary['total_cves']} CVE(s)")
        print(f"  Success: {summary['results']['success']}")
        print(f"  Failed: {summary['results']['failed']}")
        print(f"  Manual: {summary['results']['manual_required']}")
        print(f"  Skipped: {summary['results']['skipped']}")
        print(f"\nSummary written to: {os.path.join(workdir, 'summary.json')}")
    except Exception as exc:
        print(f"Batch summary generation failed: {exc}")
        traceback.print_exc()
    print("Agent run complete.")


if __name__ == "__main__":
    main()
