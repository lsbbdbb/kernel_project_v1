"""Web control panel for kernel-livepatch-agent."""
import os
import json
import queue
import threading
import time
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime, timezone

from flask import Flask, jsonify, Response, request, render_template, stream_with_context

from agent.state import StateManager, VALID_STATES, VALID_FINAL_STATUSES
from agent.planner import Planner

app = Flask(__name__, template_folder="templates")

# ---------------------------------------------------------------------------
# Cached state helpers
# ---------------------------------------------------------------------------
_WORKDIR_CACHE: Dict[str, Dict] = {}
_workdir = None
_event_queue: queue.Queue = queue.Queue()
_run_process: Optional[subprocess.Popen] = None
_run_thread: Optional[threading.Thread] = None


def _find_latest_workdir() -> Optional[str]:
    """Find the most recent run_* directory."""
    candidates = sorted(
        [d for d in os.listdir(".") if d.startswith("run_") and os.path.isdir(d)],
        key=lambda d: os.path.getmtime(d),
        reverse=True,
    )
    for c in candidates:
        if os.path.isfile(os.path.join(c, "run_config.json")):
            return os.path.abspath(c)
    # Also check output_artifacts
    if os.path.isdir("output_artifacts"):
        return os.path.abspath("output_artifacts")
    return None


def _scan_workdir(workdir: str) -> Dict:
    """Scan a workdir and return structured status."""
    now = time.time()
    cache_key = workdir
    cached = _WORKDIR_CACHE.get(cache_key)
    if cached and (now - cached.get("_ts", 0)) < 2.0:
        return cached

    sm = StateManager(workdir)
    run_config = sm.get_run_config()
    cve_ids = run_config.get("cve_ids", [])
    planner = Planner(sm)

    cves = []
    for cve_id in cve_ids:
        state = sm.get_state(cve_id)
        cve_dir = os.path.join(workdir, cve_id)

        # Read events
        events_path = os.path.join(cve_dir, "events.json")
        events = []
        if os.path.exists(events_path):
            try:
                with open(events_path) as f:
                    events = json.load(f)
            except Exception:
                pass

        # Read failure
        failure_path = os.path.join(cve_dir, "failure.json")
        failure = {}
        if os.path.exists(failure_path):
            try:
                with open(failure_path) as f:
                    failure = json.load(f)
            except Exception:
                pass

        # Read report
        report_path = os.path.join(cve_dir, "report.json")
        report = {}
        if os.path.exists(report_path):
            try:
                with open(report_path) as f:
                    report = json.load(f)
            except Exception:
                pass

        # List patches
        patches_dir = os.path.join(cve_dir, "patches")
        patches = sorted(
            [p for p in os.listdir(patches_dir) if p.endswith(".patch")]
        ) if os.path.isdir(patches_dir) else []

        # Has artifact?
        has_ko = os.path.isfile(os.path.join(cve_dir, "artifacts", "livepatch.ko"))

        cves.append({
            "cve_id": cve_id,
            "state": state.get("state", "unknown"),
            "status": state.get("status"),
            "attempt": state.get("attempt", 0),
            "max_attempts": state.get("max_attempts", 5),
            "error": state.get("last_error"),
            "events": events[-20:],  # last 20 events
            "failure": failure,
            "report": report,
            "patches": patches,
            "has_artifact": has_ko,
            "updated_at": state.get("updated_at", ""),
        })

    result = {
        "workdir": workdir,
        "kernel_version": run_config.get("kernel_version", ""),
        "cve_count": len(cve_ids),
        "cves": cves,
        "max_attempts": run_config.get("max_attempts", 5),
        "created_at": run_config.get("created_at", ""),
        "_ts": now,
    }
    _WORKDIR_CACHE[cache_key] = result
    return result


def _status_from_cves(cves: list) -> str:
    """Derive overall agent status from CVE states."""
    if _run_process and _run_process.poll() is None:
        return "running"
    has_active = any(c.get("status") is None for c in cves)
    if has_active:
        return "idle"  # has incomplete work but not running
    if all(c.get("status") == "success" for c in cves if c.get("status")):
        return "completed"
    return "completed"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    global _workdir
    if _workdir is None:
        _workdir = _find_latest_workdir()
    if _workdir is None:
        return jsonify({"status": "no_data", "workdir": None, "cves": []})

    data = _scan_workdir(_workdir)
    status = _status_from_cves(data["cves"])
    data["status"] = status
    data["run_active"] = (_run_process is not None and _run_process.poll() is None)
    return jsonify(data)


@app.route("/api/cves")
def api_cves():
    global _workdir
    if _workdir is None:
        _workdir = _find_latest_workdir()
    if _workdir is None:
        return jsonify([])
    data = _scan_workdir(_workdir)
    return jsonify(data["cves"])


@app.route("/api/cve/<cve_id>")
def api_cve_detail(cve_id):
    global _workdir
    if _workdir is None:
        _workdir = _find_latest_workdir()
    if _workdir is None:
        return jsonify({"error": "No workdir found"}), 404

    cve_dir = os.path.join(_workdir, cve_id)
    if not os.path.isdir(cve_dir):
        return jsonify({"error": f"CVE {cve_id} not found"}), 404

    # Read all attempt JSONs
    attempts = []
    for i in range(1, 20):
        ap = os.path.join(cve_dir, f"attempt_{i}.json")
        if os.path.exists(ap):
            try:
                with open(ap) as f:
                    attempts.append(json.load(f))
            except Exception:
                pass

    # Read patch contents
    patches_dir = os.path.join(cve_dir, "patches")
    patches = {}
    if os.path.isdir(patches_dir):
        for p in sorted(os.listdir(patches_dir)):
            if p.endswith(".patch"):
                pp = os.path.join(patches_dir, p)
                try:
                    with open(pp) as f:
                        patches[p] = f.read()[:5000]  # first 5000 chars
                except Exception:
                    patches[p] = "(unreadable)"

    # Read metadata
    meta = {}
    meta_path = os.path.join(cve_dir, "metadata", "cve_metadata.json")
    if os.path.exists(meta_path):
        try:
            with open(meta_path) as f:
                meta = json.load(f)
        except Exception:
            pass

    # Read change_units
    cu = {}
    cu_path = os.path.join(cve_dir, "change_units.json")
    if os.path.exists(cu_path):
        try:
            with open(cu_path) as f:
                cu = json.load(f)
        except Exception:
            pass

    return jsonify({
        "cve_id": cve_id,
        "attempts": attempts,
        "patches": patches,
        "metadata": meta,
        "change_units": cu,
    })


@app.route("/api/logs/<cve_id>/<int:attempt>")
def api_logs(cve_id, attempt):
    global _workdir
    if _workdir is None:
        _workdir = _find_latest_workdir()
    if _workdir is None:
        return jsonify({"error": "No workdir"}), 404

    log_path = os.path.join(_workdir, cve_id, "logs", f"build_{attempt}.log")
    if not os.path.exists(log_path):
        return jsonify({"error": "Log not found"}), 404

    try:
        with open(log_path) as f:
            content = f.read()
        return jsonify({"content": content[-50000:]})  # last 50KB
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/pipeline/states")
def api_pipeline_states():
    """Return the state machine definition with transitions."""
    transitions = {
        "TaskCreated": {"action": "resolve_cve", "next": "CveResolved"},
        "CveResolved": {"action": "fetch_patch", "next": "PatchFetched"},
        "PatchFetched": {"action": "analyze_patch", "next": "PatchAnalyzed"},
        "PatchAnalyzed": {"action": "check_target", "next": "TargetChecked"},
        "TargetChecked": {"action": "apply_patch", "next": "PatchApplied"},
        "PatchApplied": {"action": "run_build", "next": "BuildRunning"},
        "BuildRunning": {"action": "check_build_result", "next": None},
        "BuildSucceeded": {"action": "run_verify", "next": "LoadTesting"},
        "BuildFailed": {"action": "classify_failure", "next": "FailureClassified"},
        "FailureClassified": {"action": "decide", "next": None},
        "RewritePrepared": {"action": "apply_patch", "next": "PatchApplied"},
        "LoadTesting": {"action": "check_verify_result", "next": None},
        "VerifyFailed": {"action": "classify_verify_failure", "next": "FailureClassified"},
        "Verified": {"action": "write_report", "next": "ReportWritten"},
        "FixEnvironment": {"action": "run_build", "next": "BuildRunning"},
        "ManualRequired": {"action": "done", "next": None},
        "Failed": {"action": "done", "next": None},
        "Skipped": {"action": "done", "next": None},
        "ReportWritten": {"action": "done", "next": None},
    }
    return jsonify({
        "states": VALID_STATES,
        "valid_final_statuses": VALID_FINAL_STATUSES,
        "transitions": transitions,
    })


@app.route("/api/environment")
def api_environment():
    """Return environment information."""
    docker = os.path.exists("/.dockerenv")
    info = {
        "docker": docker,
        "python": sys.version,
        "workdir": _workdir,
        "kernel_src": os.getenv("KERNEL_SRC", ""),
        "vmlinux_path": os.getenv("VMLINUX_PATH", ""),
        "llm_provider": os.getenv("LLM_PROVIDER", ""),
        "deepseek_key_set": bool(os.getenv("DEEPSEEK_API_KEY")),
        "openai_key_set": bool(os.getenv("OPENAI_API_KEY")),
    }
    if _workdir and os.path.isfile(os.path.join(_workdir, "run_config.json")):
        try:
            with open(os.path.join(_workdir, "run_config.json")) as f:
                info["run_config"] = json.load(f)
        except Exception:
            pass
    return jsonify(info)


# ---------------------------------------------------------------------------
# SSE — real-time event stream
# ---------------------------------------------------------------------------

@app.route("/api/events")
def api_events():
    def generate():
        global _workdir
        # Send initial snapshot
        if _workdir is None:
            _workdir = _find_latest_workdir()
        data = _scan_workdir(_workdir) if _workdir else {"status": "no_data"}
        yield f"data: {json.dumps(data, default=str)}\n\n"

        # Then poll for changes
        last_cached = _WORKDIR_CACHE.get(_workdir or "", {}).get("_ts", 0)
        while True:
            time.sleep(3)
            if _workdir:
                try:
                    data = _scan_workdir(_workdir)
                    ts = data.get("_ts", 0)
                    if ts > last_cached:
                        last_cached = ts
                        data["status"] = _status_from_cves(data["cves"])
                        yield f"data: {json.dumps(data, default=str)}\n\n"
                except Exception:
                    pass
            yield ": keepalive\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Agent run control
# ---------------------------------------------------------------------------

def _run_agent_worker(cves_path: str, workdir: str, kernel_version: str,
                       max_attempts: int, no_llm: bool):
    """Run the agent in a background thread."""
    global _run_process
    cmd = [
        sys.executable, "-m", "agent",
        "--cves", cves_path,
        "--workdir", workdir,
        "--kernel-version", kernel_version,
        "--max-attempts", str(max_attempts),
    ]
    if no_llm:
        cmd.append("--no-llm")

    # Pass through LLM env vars
    env = os.environ.copy()

    try:
        _run_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=env, text=True, bufsize=1,
        )
        for line in _run_process.stdout:
            _event_queue.put({"type": "log", "line": line.rstrip()})
        _run_process.wait()
    except Exception as e:
        _event_queue.put({"type": "error", "message": str(e)})
    finally:
        _run_process = None
        _event_queue.put({"type": "run_completed"})


@app.route("/api/run", methods=["POST"])
def api_run():
    global _run_thread, _workdir

    if _run_thread and _run_thread.is_alive():
        return jsonify({"error": "Agent is already running"}), 409

    data = request.get_json(silent=True) or {}
    cves_path = data.get("cves", "sample_cves.txt")
    kernel_version = data.get("kernel_version", "6.6.102-5.2.an23.x86_64")
    max_attempts = data.get("max_attempts", 5)
    no_llm = data.get("no_llm", False)

    # Create timestamped workdir
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    workdir = os.path.join(os.getcwd(), f"run_{timestamp}")
    os.makedirs(workdir, exist_ok=True)
    _workdir = workdir

    _run_thread = threading.Thread(
        target=_run_agent_worker,
        args=(cves_path, workdir, kernel_version, max_attempts, no_llm),
        daemon=True,
    )
    _run_thread.start()

    return jsonify({"status": "started", "workdir": workdir})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    global _run_process
    if _run_process and _run_process.poll() is None:
        _run_process.terminate()
        try:
            _run_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _run_process.kill()
        _run_process = None
        return jsonify({"status": "stopped"})
    return jsonify({"status": "not_running"})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Rescan a specific workdir."""
    global _workdir
    data = request.get_json(silent=True) or {}
    wd = data.get("workdir") or _find_latest_workdir()
    if wd and os.path.isdir(wd):
        _workdir = wd
        _WORKDIR_CACHE.pop(wd, None)
        return jsonify({"status": "ok", "workdir": wd})
    return jsonify({"error": "Workdir not found"}), 404


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    port = int(os.getenv("WEB_PORT", "8080"))
    host = os.getenv("WEB_HOST", "0.0.0.0")
    debug = os.getenv("WEB_DEBUG", "").lower() in ("1", "true", "yes")

    global _workdir
    _workdir = _find_latest_workdir()

    print(f"🌐 Web control panel: http://{host}:{port}")
    print(f"📁 Workdir: {_workdir or '(none)'}")
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    main()
