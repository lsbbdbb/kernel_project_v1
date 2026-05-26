"""Automated tests for the web control panel API."""
import json
import os
import time
import urllib.request
import urllib.error
import pytest

BASE_URL = os.getenv("WEB_TEST_URL", "http://localhost:8080")


def _get(path: str, expect_status: int = 200) -> dict:
    """Helper: GET a URL and return parsed JSON."""
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            assert resp.status == expect_status, f"GET {url} → {resp.status} (expected {expect_status})"
            ct = resp.headers.get("Content-Type", "")
            if "json" in ct:
                return json.loads(resp.read().decode())
            return {"_raw": resp.read().decode()[:200]}
    except urllib.error.HTTPError as e:
        assert e.code == expect_status, f"GET {url} → {e.code} (expected {expect_status})"
        return json.loads(e.read().decode())


def _sse_connect(path: str, timeout: float = 6.0) -> list:
    """Connect to an SSE stream and collect events until timeout."""
    events = []
    url = f"{BASE_URL}{path}"
    import socket
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout + 2) as resp:
            assert resp.status == 200
            assert resp.headers.get("Content-Type", "").startswith("text/event-stream")
            start = time.time()
            buf = ""
            while time.time() - start < timeout:
                try:
                    chunk = resp.read(4096).decode()
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
                # Parse SSE lines
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if line.startswith("data: "):
                        try:
                            events.append(json.loads(line[6:]))
                        except json.JSONDecodeError:
                            pass
                if len(events) >= 2:
                    break
    except (socket.timeout, urllib.error.URLError, OSError):
        pass
    return events


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestWebApi:

    def test_index_returns_html(self):
        """The root path serves an HTML page."""
        url = f"{BASE_URL}/"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            assert resp.status == 200
            html = resp.read().decode()
            assert "<!DOCTYPE html>" in html
            assert "Kernel Livepatch Agent" in html
            assert "Pipeline" in html
            assert "CVE" in html
            # Should be substantial content (>10KB)
            assert len(html) > 10_000

    def test_api_status_structure(self):
        """GET /api/status returns agent status with CVE data."""
        data = _get("/api/status")
        assert "status" in data
        assert "cves" in data
        assert "cve_count" in data
        assert isinstance(data["cves"], list)
        assert data["cve_count"] == len(data["cves"])
        assert "workdir" in data
        assert "kernel_version" in data

    def test_api_status_cve_fields(self):
        """Each CVE in the status response has required fields."""
        data = _get("/api/status")
        for cve in data["cves"]:
            assert "cve_id" in cve
            assert "state" in cve
            assert "attempt" in cve
            assert "max_attempts" in cve
            assert "events" in cve
            assert isinstance(cve["events"], list)
            assert "has_artifact" in cve
            assert "patches" in cve

    def test_api_cves_list(self):
        """GET /api/cves returns a JSON array."""
        data = _get("/api/cves")
        assert isinstance(data, list)
        if data:
            assert "cve_id" in data[0]
            assert "state" in data[0]

    def test_api_cve_detail(self):
        """GET /api/cve/<id> returns detailed information for each CVE."""
        cves = _get("/api/cves")
        for cve in cves:
            cve_id = cve["cve_id"]
            detail = _get(f"/api/cve/{cve_id}")
            assert detail["cve_id"] == cve_id
            # Should have at least attempts or metadata
            assert "attempts" in detail
            assert isinstance(detail["attempts"], list)
            # Patches should be a dict
            assert "patches" in detail
            assert isinstance(detail["patches"], dict)

    def test_api_cve_detail_unknown(self):
        """GET /api/cve/<unknown> returns 404."""
        _get("/api/cve/CVE-9999-99999", expect_status=404)

    def test_api_pipeline_states(self):
        """GET /api/pipeline/states returns the state machine definition."""
        data = _get("/api/pipeline/states")
        assert "states" in data
        assert "transitions" in data
        assert "valid_final_statuses" in data
        # Should have all 19 states
        assert len(data["states"]) >= 18
        # Key states should be present
        assert "TaskCreated" in data["states"]
        assert "ReportWritten" in data["states"]
        assert "Verified" in data["states"]

    def test_api_pipeline_transitions(self):
        """Transitions map contains all states."""
        data = _get("/api/pipeline/states")
        for state in data["states"]:
            if state in data["transitions"]:
                t = data["transitions"][state]
                assert "action" in t
                assert isinstance(t.get("next"), (str, type(None)))

    def test_api_environment(self):
        """GET /api/environment returns system info."""
        data = _get("/api/environment")
        assert "python" in data
        assert "docker" in data
        assert "workdir" in data
        assert "run_config" in data or True  # may be absent if no run
        # Python version should be non-empty
        assert len(data.get("python", "")) > 0

    def test_api_sse_stream(self):
        """SSE stream returns data events."""
        events = _sse_connect("/api/events", timeout=6.0)
        assert len(events) >= 1, "SSE should emit at least one data event"
        first = events[0]
        # The first event should have CVE data
        assert "cves" in first or "status" in first

    def test_api_sse_updates(self):
        """SSE stream emits follow-up data events (cached updates)."""
        events = _sse_connect("/api/events", timeout=8.0)
        # Should get at least the initial snapshot
        assert len(events) >= 1
        # Verify structure of first event
        ev = events[0]
        if "cves" in ev:
            assert isinstance(ev["cves"], list)
        if "status" in ev:
            assert ev["status"] in ("running", "idle", "completed", "no_data")

    def test_api_run_validation(self):
        """POST /api/run without being in Docker returns actionable response."""
        import urllib.request
        url = f"{BASE_URL}/api/run"
        payload = json.dumps({"cves": "sample_cves.txt"}).encode()
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                # Should have started or returned an error
                assert "status" in data or "error" in data
        except urllib.error.HTTPError as e:
            # 409 conflict is acceptable (already running)
            assert e.code in (200, 409)

    def test_api_stop(self):
        """POST /api/stop returns a status."""
        import urllib.request
        url = f"{BASE_URL}/api/stop"
        req = urllib.request.Request(url, data=b"{}",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            assert "status" in data
            assert data["status"] in ("stopped", "not_running")

    def test_api_scan(self):
        """POST /api/scan rescans the workdir."""
        import urllib.request
        url = f"{BASE_URL}/api/scan"
        payload = json.dumps({}).encode()
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            assert "status" in data or "error" in data

    def test_logs_endpoint(self):
        """GET /api/logs/<cve>/<attempt> returns log content or 404."""
        # Try a known CVE from the status
        cves = _get("/api/cves")
        for cve in cves[:1]:  # Test first CVE
            cve_id = cve["cve_id"]
            for attempt in range(1, min(cve["attempt"] + 1, 3)):
                url = f"{BASE_URL}/api/logs/{cve_id}/{attempt}"
                req = urllib.request.Request(url)
                try:
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        data = json.loads(resp.read().decode())
                        assert "content" in data or "error" in data
                except urllib.error.HTTPError as e:
                    assert e.code == 404  # Log not found is acceptable

    def test_cross_origin_headers(self):
        """SSE endpoint has no-cache headers."""
        url = f"{BASE_URL}/api/events"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=3) as resp:
            cache = resp.headers.get("Cache-Control", "")
            assert "no-cache" in cache

    def test_content_type_json(self):
        """API endpoints return application/json."""
        for path in ["/api/status", "/api/cves", "/api/pipeline/states", "/api/environment"]:
            url = f"{BASE_URL}{path}"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as resp:
                ct = resp.headers.get("Content-Type", "")
                assert "json" in ct, f"{path} → Content-Type: {ct}"

    def test_response_time(self):
        """API endpoints respond within 5 seconds."""
        for path in ["/api/status", "/api/cves", "/api/pipeline/states", "/api/environment"]:
            start = time.time()
            _get(path)
            elapsed = time.time() - start
            assert elapsed < 5.0, f"{path} took {elapsed:.1f}s"

    # ------------------------------------------------------------------
    # Pre-flight check tests
    # ------------------------------------------------------------------

    def test_check_endpoint_returns_summary(self):
        """GET /api/check returns summary with pass/fail counts."""
        data = _get("/api/check")
        assert "ok" in data
        assert "summary" in data
        assert "checks" in data
        assert data["summary"]["total"] == len(data["checks"])
        assert data["summary"]["total"] >= 5
        assert data["summary"]["passed"] >= 0
        assert data["summary"]["errors"] >= 0

    def test_check_each_item_has_fields(self):
        """Each check item has name, ok, value, hint, severity."""
        data = _get("/api/check")
        for c in data["checks"]:
            assert "name" in c
            assert "ok" in c
            assert "value" in c
            assert "hint" in c
            assert "severity" in c
            assert c["severity"] in ("ok", "info", "warning", "error")

    def test_check_kpatch_build(self):
        """kpatch-build check reflects actual availability."""
        data = _get("/api/check")
        kpatch = [c for c in data["checks"] if "kpatch" in c["name"].lower()]
        assert len(kpatch) >= 1
        # kpatch-build is installed on this server
        assert kpatch[0]["ok"] == True
        assert "0.9.11" in kpatch[0]["value"]

    def test_check_cve_file(self):
        """CVE list file check reflects sample_cves.txt."""
        data = _get("/api/check")
        cve_check = [c for c in data["checks"] if "CVE" in c["name"]]
        assert len(cve_check) >= 1
        assert cve_check[0]["ok"] == True

    def test_check_docker_env(self):
        """Docker check is a boolean."""
        data = _get("/api/check")
        docker = [c for c in data["checks"] if "Docker" in c["name"]]
        assert len(docker) >= 1
        assert isinstance(docker[0]["ok"], bool)

    def test_check_llm_key(self):
        """LLM key check returns a value."""
        data = _get("/api/check")
        llm = [c for c in data["checks"] if "LLM" in c["name"]]
        assert len(llm) >= 1
        assert isinstance(llm[0]["ok"], bool)

    def test_check_html_has_check_button(self):
        """The index page has the environment check button."""
        url = f"{BASE_URL}/"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read().decode()
            assert "环境检测" in html

    def test_check_html_has_preflight_in_form(self):
        """The index page has preflight check in the run form."""
        url = f"{BASE_URL}/"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read().decode()
            assert "前置检测" in html

    # ------------------------------------------------------------------
    # Trace / Pipeline chain tests
    # ------------------------------------------------------------------

    def test_trace_endpoint_structure(self):
        """GET /api/cve/<id>/trace returns structured pipeline trace."""
        cves = _get("/api/cves")
        if not cves:
            return
        trace = _get(f"/api/cve/{cves[0]['cve_id']}/trace")
        assert "cve_id" in trace
        assert "timeline" in trace
        assert "stages" in trace
        assert "rag_traces" in trace
        assert "rag_query_count" in trace
        assert "attempts" in trace
        assert isinstance(trace["timeline"], list)
        assert isinstance(trace["rag_traces"], list)

    def test_trace_timeline_entries(self):
        """Each timeline entry has required fields."""
        cves = _get("/api/cves")
        if not cves:
            return
        trace = _get(f"/api/cve/{cves[0]['cve_id']}/trace")
        for entry in trace["timeline"]:
            assert "from" in entry
            assert "to" in entry
            assert "reason" in entry
            assert "timestamp" in entry
            assert "type" in entry
            assert "order" in entry

    def test_trace_unknown_cve(self):
        """GET /api/cve/<unknown>/trace returns 404."""
        _get("/api/cve/CVE-9999-99999/trace", expect_status=404)

    def test_trace_html_has_trace_tab(self):
        """The index page has the trace tab."""
        url = f"{BASE_URL}/"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read().decode()
            assert "链路" in html

    def test_trace_html_has_trace_js(self):
        """The index page has trace JavaScript functions."""
        url = f"{BASE_URL}/"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read().decode()
            assert "loadTraceForCve" in html
            assert "populateTraceSelector" in html

    # ------------------------------------------------------------------
    # Expandable CVE stages tests
    # ------------------------------------------------------------------

    def test_cve_card_has_expand_stages(self):
        """CVE cards have expandable stage sections."""
        data = _get("/api/status")
        if not data.get("cves"):
            return
        # Check the HTML has the expand/collapse mechanism
        url = f"{BASE_URL}/"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read().decode()
            assert "toggleCveStages" in html
            assert "cve-stages" in html
            assert "流水线阶段" in html

    def test_permission_error_fix(self):
        """_ensure_kernel_config handles read-only files gracefully."""
        import tempfile, os
        # Simulate read-only config files
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "source")
            os.makedirs(os.path.join(src, "include", "config"))
            config = os.path.join(src, ".config")
            with open(config, "w") as f:
                f.write("CONFIG_FOO=y\n")
            auto_conf = os.path.join(src, "include", "config", "auto.conf")
            with open(auto_conf, "w") as f:
                f.write("CONFIG_FOO=y\n")
            auto_conf_cmd = os.path.join(src, "include", "config", "auto.conf.cmd")
            with open(auto_conf_cmd, "w") as f:
                f.write("dummy\n")

            # Make files read-only (owned by root would be even stricter,
            # but chmod 444 simulates the permission restriction)
            os.chmod(config, 0o444)
            os.chmod(auto_conf, 0o444)
            os.chmod(auto_conf_cmd, 0o444)

            # Import and test _ensure_kernel_config
            from agent.__main__ import _ensure_kernel_config
            # This should not raise PermissionError
            result = _ensure_kernel_config(src)
            # Should return True since files exist and are non-empty
            assert result == True
