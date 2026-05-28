"""State Manager - maintains state.json and run_config.json per v1.md design."""
import json
import shutil
import os
import datetime
from datetime import timezone
from typing import Optional, Dict, Any, List


VALID_STATES = [
    "TaskCreated", "CveResolved", "PatchFetched", "PatchAnalyzed",
    "TargetChecked", "PatchApplied", "BuildRunning", "BuildSucceeded",
    "BuildFailed", "FailureClassified", "RewritePrepared", "ManualRequired",
    "Failed", "Skipped", "LoadTesting", "Verified", "VerifyFailed", "ReportWritten",
    "FixEnvironment"
]

VALID_FINAL_STATUSES = ["success", "failed", "manual_required", "skipped"]


class StateManager:
    """Manages per-CVE state and batch run configuration."""

    def __init__(self, workdir: str):
        self.workdir = workdir
        self.run_config_path = os.path.join(workdir, "run_config.json")
        self._cached_run_config: Optional[Dict] = None
        self._cached_source_dir: Optional[str] = None

    def init_run_config(self, cve_ids: List[str], kernel_version: str,
                        max_attempts: int = 5) -> Dict:
        config = {
            "created_at": datetime.datetime.now(timezone.utc).isoformat(),
            "kernel_version": kernel_version,
            "max_attempts": max_attempts,
            "cve_count": len(cve_ids),
            "cve_ids": cve_ids,
        }
        self._write_json(self.run_config_path, config)
        return config

    def get_run_config(self) -> Dict:
        if self._cached_run_config is not None:
            return self._cached_run_config
        self._cached_run_config = self._read_json(self.run_config_path)
        return self._cached_run_config

    def get_kernel_version(self) -> str:
        """Convenience: get kernel version from cached run config."""
        return self.get_run_config().get("kernel_version", "6.6.102-5.2.an23.x86_64")

    def init_cve_state(self, cve_id: str) -> Dict:
        cve_dir = os.path.join(self.workdir, cve_id)
        os.makedirs(cve_dir, exist_ok=True)
        state = {
            "cve_id": cve_id,
            "state": "TaskCreated",
            "attempt": 0,
            "max_attempts": self.get_run_config().get("max_attempts", 5),
            "status": None,
            "created_at": datetime.datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.datetime.now(timezone.utc).isoformat(),
            "last_error": None,
            "evidence_paths": {},
        }
        self._write_json(os.path.join(cve_dir, "state.json"), state)
        return state

    def get_state(self, cve_id: str) -> Dict:
        return self._read_json(os.path.join(self.workdir, cve_id, "state.json"))

    def transition_to(self, cve_id: str, new_state: str,
                      reason: str = "", evidence: Optional[Dict] = None):
        state = self.get_state(cve_id)
        if new_state not in VALID_STATES:
            raise ValueError(f"Invalid state: {new_state}")
        old_state = state["state"]
        state["state"] = new_state
        state["updated_at"] = datetime.datetime.now(timezone.utc).isoformat()
        if evidence:
            state["evidence_paths"].update(evidence)
        transition = {
            "from": old_state,
            "to": new_state,
            "reason": reason,
            "timestamp": state["updated_at"],
        }
        events = self._read_json(
            os.path.join(self.workdir, cve_id, "events.json"), default=[])
        events.append(transition)
        self._write_json(
            os.path.join(self.workdir, cve_id, "events.json"), events)
        self._write_json(os.path.join(self.workdir, cve_id, "state.json"), state)
        return state

    def increment_attempt(self, cve_id: str) -> int:
        state = self.get_state(cve_id)
        state["attempt"] += 1
        state["updated_at"] = datetime.datetime.now(timezone.utc).isoformat()
        self._write_json(os.path.join(self.workdir, cve_id, "state.json"), state)
        return state["attempt"]

    def set_final_status(self, cve_id: str, status: str):
        if status not in VALID_FINAL_STATUSES:
            raise ValueError(f"Invalid final status: {status}")
        state = self.get_state(cve_id)
        state["status"] = status
        state["updated_at"] = datetime.datetime.now(timezone.utc).isoformat()
        self._write_json(os.path.join(self.workdir, cve_id, "state.json"), state)

    def set_error(self, cve_id: str, error: str):
        state = self.get_state(cve_id)
        state["last_error"] = error
        state["updated_at"] = datetime.datetime.now(timezone.utc).isoformat()
        self._write_json(os.path.join(self.workdir, cve_id, "state.json"), state)

    def cve_dir(self, cve_id: str) -> str:
        return os.path.join(self.workdir, cve_id)

    def ensure_subdir(self, cve_id: str, subdir: str) -> str:
        path = os.path.join(self.workdir, cve_id, subdir)
        os.makedirs(path, exist_ok=True)
        return path
    def reset_cve(self, cve_id: str) -> Dict:
        """Reset a CVE to TaskCreated by removing and re-initializing its state."""
        cve_dir = os.path.join(self.workdir, cve_id)
        if os.path.isdir(cve_dir):
            shutil.rmtree(cve_dir)
        return self.init_cve_state(cve_id)

    @staticmethod
    def _write_json(path: str, data: Any):
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def _read_json(path: str, default=None) -> Any:
        if not os.path.exists(path):
            return default if default is not None else {}
        with open(path) as f:
            return json.load(f)
