#!/usr/bin/env python3
"""Patch server.py to bind the Start button to demo.sh with real-time SSE output."""

import re
import sys

SERVER_PATH = "/home/lee/kernel-livepatch-agent/agent/web/server.py"

with open(SERVER_PATH, "r") as f:
    content = f.read()

changes = 0

# ---- Patch 1: api_events — also forward log/error/run_completed events ----
old_block = (
    "            # Check event queue for non-status events (clean_result, etc.)\n"
    "            clean_event = None\n"
    "            while not _event_queue.empty():\n"
    "                try:\n"
    "                    evt = _event_queue.get_nowait()\n"
    '                    if evt.get("type") == "clean_result":\n'
    '                        clean_event = evt["result"]\n'
    "                except queue.Empty:\n"
    "                    break\n"
    "            if clean_event:\n"
    "                yield f\"data: {json.dumps({'type': 'clean_result', 'result': clean_event}, default=str)}\\n\\n\""
)

new_block = (
    "            # Drain event queue for real-time log streaming\n"
    "            while not _event_queue.empty():\n"
    "                try:\n"
    "                    evt = _event_queue.get_nowait()\n"
    '                    etype = evt.get("type")\n'
    '                    if etype == "clean_result":\n'
    "                        yield f\"data: {json.dumps({'type': 'clean_result', 'result': evt['result']}, default=str)}\\n\\n\"\n"
    '                    elif etype == "log":\n'
    "                        yield f\"data: {json.dumps({'type': 'log', 'line': evt['line']}, default=str)}\\n\\n\"\n"
    '                    elif etype == "error":\n'
    "                        yield f\"data: {json.dumps({'type': 'error', 'message': evt['message']}, default=str)}\\n\\n\"\n"
    '                    elif etype == "run_completed":\n'
    "                        yield f\"data: {json.dumps({'type': 'run_completed'})}\\n\\n\"\n"
    "                except queue.Empty:\n"
    "                    break"
)

if old_block in content:
    content = content.replace(old_block, new_block)
    changes += 1
    print("Patch 1 (api_events log streaming): OK")
else:
    print("Patch 1: FAILED — old block not found")
    sys.exit(1)

# ---- Patch 2: _run_agent_worker → run demo.sh ----
func_start = content.find("def _run_agent_worker(")
func_end_marker = '_event_queue.put({"type": "run_completed"})'
func_end = content.find(func_end_marker, func_start)
if func_end == -1:
    print("Patch 2: FAILED — function end marker not found")
    sys.exit(1)
func_end += len(func_end_marker)

new_worker = (
    'def _run_agent_worker(cves_path: str, workdir: str, kernel_version: str,\n'
    '                       max_attempts: int, no_llm: bool, use_docker: bool = False):\n'
    '    """Run demo.sh and stream output to the event queue."""\n'
    "    global _run_process\n"
    "\n"
    '    demo_script = "/home/lee/kernel-livepatch-agent/demo.sh"\n'
    '    cwd = "/home/lee/kernel-livepatch-agent"\n'
    "\n"
    "    try:\n"
    "        _run_process = subprocess.Popen(\n"
    '            ["bash", demo_script],\n'
    "            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,\n"
    "            cwd=cwd, text=True, bufsize=1,\n"
    "            start_new_session=True,\n"
    "        )\n"
    "        for line in _run_process.stdout:\n"
    '            _event_queue.put({"type": "log", "line": line.rstrip()})\n'
    "        _run_process.wait()\n"
    "    except Exception as e:\n"
    '        _event_queue.put({"type": "error", "message": str(e)})\n'
    "    finally:\n"
    "        _run_process = None\n"
    '        _event_queue.put({"type": "run_completed"})\n'
)

content = content[:func_start] + new_worker + content[func_end:]
changes += 1
print("Patch 2 (_run_agent_worker → demo.sh): OK")

# ---- Patch 3: api_run — simplified, no params needed ----
route_start = content.find('@app.route("/api/run", methods=["POST"])')
route_end_marker = 'return jsonify({"status": "started", "workdir": workdir, "mode": mode})'
route_end = content.find(route_end_marker, route_start)
if route_end == -1:
    print("Patch 3: FAILED — route end marker not found")
    sys.exit(1)
route_end += len(route_end_marker)

new_api_run = (
    '@app.route("/api/run", methods=["POST"])\n'
    "def api_run():\n"
    "    global _run_thread, _workdir\n"
    "\n"
    "    if _run_thread and _run_thread.is_alive():\n"
    '        return jsonify({"error": "Agent is already running"}), 409\n'
    "\n"
    "    # Find latest workdir for the UI to track\n"
    "    _workdir = _find_latest_workdir()\n"
    "\n"
    "    _run_thread = threading.Thread(\n"
    "        target=_run_agent_worker,\n"
    "        daemon=True,\n"
    "    )\n"
    "    _run_thread.start()\n"
    "\n"
    '    return jsonify({"status": "started", "mode": "demo"})\n'
)

content = content[:route_start] + new_api_run + content[route_end:]
changes += 1
print("Patch 3 (api_run simplified): OK")

# ---- Write back ----
with open(SERVER_PATH, "w") as f:
    f.write(content)

print(f"\nTotal changes: {changes} — server.py patched successfully.")
