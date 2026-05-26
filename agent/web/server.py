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


def _docker_available() -> bool:
    """Check if Docker is available (running inside container OR CLI accessible)."""
    if os.path.exists("/.dockerenv"):
        return True
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=5,
        )
        return proc.returncode == 0 and bool(proc.stdout.strip())
    except Exception:
        return False


def _find_latest_workdir() -> Optional[str]:
    """Find the most recent run_* or docker_run directory."""
    # Prefer docker_run if it exists (explicit Docker-run indicator)
    if os.path.isdir("docker_run") and os.path.isfile(os.path.join("docker_run", "run_config.json")):
        return os.path.abspath("docker_run")

    candidates = sorted(
        [d for d in os.listdir(".") if (
            d.startswith("run_") and os.path.isdir(d)
        )],
        key=lambda d: os.path.getmtime(d),
        reverse=True,
    )
    for c in candidates:
        if os.path.isfile(os.path.join(c, "run_config.json")):
            return os.path.abspath(c)
    # Also check output_artifacts / out
    for alt in ["output_artifacts", "out"]:
        if os.path.isdir(alt):
            cfg = os.path.join(alt, "run_config.json")
            if os.path.isfile(cfg):
                return os.path.abspath(alt)
            # Check one level deeper
            for sub in os.listdir(alt):
                sub_path = os.path.join(alt, sub)
                if os.path.isdir(sub_path) and os.path.isfile(os.path.join(sub_path, "run_config.json")):
                    return os.path.abspath(sub_path)
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


@app.route("/api/cve/<cve_id>/trace")
def api_cve_trace(cve_id):
    """Return the engineering pipeline trace for a CVE.

    Synthesizes events timeline + failure classification + rewrite
    attempts + RAG queries into a structured chain.
    """
    global _workdir
    if _workdir is None:
        _workdir = _find_latest_workdir()
    if _workdir is None:
        return jsonify({"error": "No workdir"}), 404

    cve_dir = os.path.join(_workdir, cve_id)
    if not os.path.isdir(cve_dir):
        return jsonify({"error": f"CVE {cve_id} not found"}), 404

    # 1. Events → pipeline stages
    events_path = os.path.join(cve_dir, "events.json")
    stages = []
    if os.path.exists(events_path):
        try:
            with open(events_path) as f:
                events = json.load(f)
            for idx, ev in enumerate(events):
                stage = {
                    "order": idx + 1,
                    "from": ev.get("from", ""),
                    "to": ev.get("to", ""),
                    "reason": ev.get("reason", ""),
                    "timestamp": ev.get("timestamp", ""),
                    "type": "transition",
                }
                # Annotate RAG-involved stages
                if "RewritePrepared" in (ev.get("from", ""), ev.get("to", "")):
                    stage["type"] = "rewrite"
                    stage["rag_involved"] = True
                if "FailureClassified" in (ev.get("from", ""), ev.get("to", "")):
                    stage["type"] = "classify"
                if "BuildFailed" in (ev.get("from", ""), ev.get("to", "")):
                    stage["type"] = "build_failure"
                stages.append(stage)
        except Exception:
            pass

    # 2. Failure classification
    failure_path = os.path.join(cve_dir, "failure.json")
    failure = {}
    if os.path.exists(failure_path):
        try:
            with open(failure_path) as f:
                failure = json.load(f)
        except Exception:
            pass

    # 3. RAG traces
    rag_path = os.path.join(cve_dir, "rag_trace.json")
    rag_traces = []
    if os.path.exists(rag_path):
        try:
            with open(rag_path) as f:
                rag_traces = json.load(f)
        except Exception:
            pass

    # 4. Attempt records
    attempts = []
    for i in range(1, 20):
        ap = os.path.join(cve_dir, f"attempt_{i}.json")
        if os.path.exists(ap):
            try:
                with open(ap) as f:
                    att = json.load(f)
                attempts.append({
                    "attempt_index": att.get("attempt_index", i),
                    "strategy": att.get("rewrite_plan", {}).get("strategy",
                                  att.get("strategy", "")),
                    "source": att.get("rewrite_source", att.get("source", "")),
                    "success": att.get("result", {}).get("success", False),
                    "failure_code": att.get("failure", {}).get("reason_code", ""),
                })
            except Exception:
                pass

    # 5. Compute durations between stages
    timeline = []
    for i, stage in enumerate(stages):
        entry = dict(stage)
        if i > 0 and stages[i - 1].get("timestamp") and stage.get("timestamp"):
            try:
                t1 = datetime.fromisoformat(stages[i - 1]["timestamp"])
                t2 = datetime.fromisoformat(stage["timestamp"])
                entry["duration_s"] = round((t2 - t1).total_seconds(), 1)
            except Exception:
                pass
        timeline.append(entry)

    return jsonify({
        "cve_id": cve_id,
        "timeline": timeline,
        "stages": len(timeline),
        "failure": {
            "reason_code": failure.get("reason_code", ""),
            "category": failure.get("category", ""),
            "severity": failure.get("severity", ""),
            "retryable": failure.get("retryable", False),
            "summary": failure.get("summary", ""),
        } if failure else None,
        "rag_traces": rag_traces,
        "rag_query_count": len(rag_traces),
        "attempts": attempts,
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
    docker_inside = os.path.exists("/.dockerenv")
    docker_cli = _docker_available()
    info = {
        "docker": docker_inside,
        "docker_available": docker_cli,
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
# Pre-flight checks
# ---------------------------------------------------------------------------

@app.route("/api/check")
def api_check():
    """Run pre-flight environment checks and return pass/fail for each."""
    checks = []
    kernel_version = "6.6.102-5.2.an23.x86_64"

    # 1. kpatch-build
    kpatch_ok = False
    kpatch_version = ""
    try:
        proc = subprocess.run(
            ["kpatch-build", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        kpatch_ok = proc.returncode == 0
        kpatch_version = proc.stdout.strip() or proc.stderr.strip()
    except Exception:
        pass
    checks.append({
        "name": "kpatch-build",
        "ok": kpatch_ok,
        "value": kpatch_version or ("not found" if not kpatch_ok else ""),
        "hint": "安装 kpatch-build：docker compose build agent" if not kpatch_ok else "",
        "severity": "error",
    })

    # 2. Docker environment
    docker_inside = os.path.exists("/.dockerenv")
    docker_cli = _docker_available()
    docker_ok = docker_inside or docker_cli
    docker_label = "内部运行" if docker_inside else ("CLI 可用" if docker_cli else "未安装")
    checks.append({
        "name": "Docker 环境",
        "ok": docker_ok,
        "value": docker_label,
        "hint": "" if docker_ok else "安装 Docker：dnf install docker",
        "severity": "info" if docker_ok else "warning",
    })

    # 3. Kernel source tree
    env_src = os.getenv("KERNEL_SRC", "")
    candidates = []
    if env_src:
        candidates.append(("KERNEL_SRC env", env_src))
    candidates.append(("kernel-src/", f"kernel-src/linux-{kernel_version}"))
    candidates.append(("容器路径", f"/kernel-src/linux-{kernel_version}"))
    # acceptance_vm source tree (host-side fallback)
    version_noarch = kernel_version.replace(".x86_64", "")
    for d in sorted(os.listdir(".")):
        if d.startswith("acceptance_vm_") or d.startswith("build_"):
            candidates.append((d, f"{d}/source_tree/linux-{version_noarch}"))

    src_found = None
    for label, path in candidates:
        expanded = os.path.expandvars(os.path.expanduser(path))
        vmlinux = os.path.join(expanded, "vmlinux")
        if os.path.isdir(expanded) and os.path.isfile(vmlinux):
            src_found = (label, expanded)
            break
        elif os.path.isdir(expanded):
            if src_found is None:
                src_found = (label, expanded, "missing vmlinux")

    src_ok = src_found and isinstance(src_found, tuple) and len(src_found) == 2
    src_value = ""
    src_hint = ""
    if src_found and len(src_found) == 2:
        src_value = f"{src_found[0]}: {src_found[1]}"
    elif src_found and len(src_found) == 3:
        src_value = f"{src_found[0]}: {src_found[1]} ({src_found[2]})"
        src_hint = f"执行: cd {src_found[1]} && make defconfig && make -j$(nproc) vmlinux modules_prepare"
    else:
        src_value = "未找到"
        src_hint = "下载内核源码: bash scripts/download_kernel_src.sh 或设置 KERNEL_SRC 环境变量"
    checks.append({
        "name": "内核源码树",
        "ok": src_ok,
        "value": src_value,
        "hint": src_hint,
        "severity": "error" if not src_found else ("warning" if not src_ok else "ok"),
    })

    # 4. vmlinux
    env_vmlinux = os.getenv("VMLINUX_PATH", "")
    vmlinux_ok = False
    vmlinux_value = ""
    if env_vmlinux and os.path.isfile(env_vmlinux):
        vmlinux_ok = True
        vmlinux_value = f"VMLINUX_PATH: {env_vmlinux}"
    elif src_found and isinstance(src_found, tuple) and len(src_found) == 2:
        vm = os.path.join(src_found[1], "vmlinux")
        if os.path.isfile(vm):
            vmlinux_ok = True
            vmlinux_value = vm
    if not vmlinux_ok:
        vmlinux_value = "未找到 vmlinux"
    checks.append({
        "name": "vmlinux",
        "ok": vmlinux_ok,
        "value": vmlinux_value,
        "hint": "" if vmlinux_ok else "kpatch-build -v 参数需要 vmlinux。设置 VMLINUX_PATH 环境变量或先构建内核",
        "severity": "error" if not vmlinux_ok else "ok",
    })

    # 5. LLM keys
    deepseek = bool(os.getenv("DEEPSEEK_API_KEY"))
    openai = bool(os.getenv("OPENAI_API_KEY"))
    llm_ok = deepseek or openai
    checks.append({
        "name": "LLM API Key",
        "ok": llm_ok,
        "value": "DeepSeek: " + ("✅" if deepseek else "❌") + ", OpenAI: " + ("✅" if openai else "❌"),
        "hint": "" if llm_ok else "设置 DEEPSEEK_API_KEY 或 OPENAI_API_KEY 环境变量启用 LLM 模式（纯规则模式不需要）",
        "severity": "info",
    })

    # 6. sample_cves.txt
    cves_file = os.path.isfile("sample_cves.txt")
    checks.append({
        "name": "CVE 列表文件",
        "ok": cves_file,
        "value": "sample_cves.txt" + (" ✅" if cves_file else " ❌ 未找到"),
        "hint": "",
        "severity": "error" if not cves_file else "ok",
    })

    # 7. Git safe directory (for kernel source if it's a git repo)
    if src_found and isinstance(src_found, tuple) and len(src_found) >= 2:
        src_path = src_found[1] if len(src_found) == 2 else src_found[1]
        git_dir = os.path.join(src_path, ".git")
        git_safe = not os.path.isdir(git_dir)  # if not a git repo, no issue
        if os.path.isdir(git_dir):
            try:
                proc = subprocess.run(
                    ["git", "config", "--global", "--get", "safe.directory", src_path],
                    capture_output=True, text=True, timeout=5,
                )
                git_safe = proc.returncode == 0
            except Exception:
                pass
        checks.append({
            "name": "Git 安全目录",
            "ok": git_safe,
            "value": "内核源码是 Git 仓库" + (" ✅" if git_safe else " ❌ 未注册 safe.directory"),
            "hint": "" if git_safe else f"执行: git config --global --add safe.directory {src_path}",
            "severity": "warning" if not git_safe else "ok",
        })

    # Summary
    errors = sum(1 for c in checks if c["severity"] == "error" and not c["ok"])
    warnings = sum(1 for c in checks if c["severity"] == "warning" and not c["ok"])
    ok = errors == 0

    return jsonify({
        "ok": ok,
        "summary": {
            "total": len(checks),
            "passed": sum(1 for c in checks if c["ok"]),
            "errors": errors,
            "warnings": warnings,
        },
        "checks": checks,
    })


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
                       max_attempts: int, no_llm: bool, use_docker: bool = False):
    """Run the agent in a background thread (host or Docker)."""
    global _run_process

    if use_docker:
        # Docker mode — use the project's compose env
        workdir_name = os.path.basename(workdir)
        extra_args = ["--no-llm"] if no_llm else []
        cmd = [
            "docker", "compose", "run", "--rm",
            "-e", f"WORKDIR=/app/{workdir_name}",
            "-e", "KERNEL_SRC=/kernel-src/linux-6.6.102-5.2.an23.x86_64",
            "-e", f"DEEPSEEK_API_KEY={os.environ.get('DEEPSEEK_API_KEY', '')}",
            "agent",
            "sh", "-c",
            f"python3 -m agent --cves /app/{cves_path} "
            f"--workdir /app/{workdir_name} "
            f"--kernel-version {kernel_version} "
            f"--max-attempts {max_attempts} "
            f"{' '.join(extra_args)}",
        ]
        env = {}
    else:
        # Host mode — run python directly
        cmd = [
            sys.executable, "-m", "agent",
            "--cves", cves_path,
            "--workdir", workdir,
            "--kernel-version", kernel_version,
            "--max-attempts", str(max_attempts),
        ]
        if no_llm:
            cmd.append("--no-llm")
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

    # Decide: Docker available? Use it (avoids compiler_mismatch on host)
    use_docker = _docker_available() and not os.path.exists("/.dockerenv")

    # Create timestamped workdir
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    prefix = "docker_" if use_docker else "run_"
    workdir = os.path.join(os.getcwd(), f"{prefix}{timestamp}")
    os.makedirs(workdir, exist_ok=True)
    _workdir = workdir

    _run_thread = threading.Thread(
        target=_run_agent_worker,
        args=(cves_path, workdir, kernel_version, max_attempts, no_llm, use_docker),
        daemon=True,
    )
    _run_thread.start()

    mode = "Docker" if use_docker else "host"
    return jsonify({"status": "started", "workdir": workdir, "mode": mode})


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
