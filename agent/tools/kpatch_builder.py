"""kpatch-build integration - execute builds and capture results."""
import json
import os
import shutil
import subprocess
import hashlib
from datetime import datetime, timezone
from typing import Dict, Optional


class KpatchBuilder:
    """Wrapper around kpatch-build tool."""

    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id
        self.logs_dir = os.path.join(workdir, cve_id, "logs")
        self.artifacts_dir = os.path.join(workdir, cve_id, "artifacts")
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(self.artifacts_dir, exist_ok=True)

    def build(self, patch_path: str, source_dir: str, vmlinux_path: str,
              kernel_source_rpm: Optional[str] = None,
              kernel_devel_path: Optional[str] = None,
              attempt: int = 1,
              expected_kernel_version: Optional[str] = None) -> Dict:
        log_path = os.path.join(self.logs_dir, f"build_{attempt}.log")
        result = {
            "attempt": attempt,
            "input_patch": patch_path,
            "source_dir": source_dir,
            "vmlinux": vmlinux_path,
            "kpatch_build_binary": None,
            "kpatch_build_ref": os.environ.get("KPATCH_BUILD_REF"),
            "expected_kernel_version": expected_kernel_version,
            "detected_kernel_version": None,
            "return_code": -1,
            "success": False,
            "artifact_path": None,
            "sha256": None,
            "log_path": log_path,
            "error": None,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        patch_path = os.path.abspath(patch_path)
        source_dir = os.path.abspath(source_dir)
        vmlinux_path = os.path.abspath(vmlinux_path)
        if expected_kernel_version:
            release_error = self._validate_kernel_release(source_dir, expected_kernel_version, result)
            if release_error:
                with open(log_path, "w") as log_file:
                    log_file.write(f"ERROR: {release_error}\n")
                result["error"] = release_error
                result["return_code"] = 2
                return self._save_result(result, attempt)
        kpatch_build_bin = os.environ.get("KPATCH_BUILD_BIN", "kpatch-build")
        result["kpatch_build_binary"] = shutil.which(kpatch_build_bin) or kpatch_build_bin
        cmd = [kpatch_build_bin, "-s", source_dir, "-v", vmlinux_path, patch_path]
        if kernel_devel_path:
            cmd.extend(["-d", kernel_devel_path])
        try:
            # Pass srctree=. and CC=gcc in environment — without them the
            # Docker-compiled scripts/kconfig/conf cannot find cc-version.sh
            build_env = {**os.environ, "srctree": source_dir, "CC": "gcc", "LD": "ld"}
            with open(log_path, "w") as log_file:
                proc = subprocess.run(
                    cmd, stdout=log_file, stderr=subprocess.STDOUT, timeout=7200,
                    cwd=self.artifacts_dir, env=build_env)
            result["return_code"] = proc.returncode
            result["success"] = proc.returncode == 0
            if proc.returncode == 0:
                ko_path = self._find_ko(self.artifacts_dir, source_dir)
                if ko_path:
                    result["sha256"] = self._hash_file(ko_path)
                    dest = os.path.join(self.artifacts_dir, "livepatch.ko")
                    if os.path.abspath(ko_path) != os.path.abspath(dest):
                        shutil.copy2(ko_path, dest)
                    result["artifact_path"] = dest
                    with open(os.path.join(self.artifacts_dir, "livepatch.ko.sha256"), "w") as f:
                        f.write(f"{result['sha256']}  livepatch.ko\n")
        except subprocess.TimeoutExpired:
            result["error"] = "Build timed out after 30 minutes"
        except FileNotFoundError:
            result["error"] = f"{kpatch_build_bin} not found in PATH"
        except Exception as e:
            result["error"] = str(e)

        # On failure, append kpatch's own detailed log (~/.kpatch/build.log)
        # so the classifier sees root-cause messages like "Reversed patch detected"
        if not result["success"]:
            kpatch_log = os.path.expanduser("~/.kpatch/build.log")
            if os.path.exists(kpatch_log):
                try:
                    with open(kpatch_log) as kl:
                        kpatch_detail = kl.read()
                    if kpatch_detail.strip():
                        with open(log_path, "a") as log_file:
                            log_file.write("\n--- kpatch build.log ---\n")
                            log_file.write(kpatch_detail)
                except Exception:
                    pass

        return self._save_result(result, attempt)

    @staticmethod
    def _validate_kernel_release(source_dir: str, expected: str, result: Dict) -> Optional[str]:
        try:
            proc = subprocess.run(
                ["make", "-s", "kernelrelease"], cwd=source_dir,
                capture_output=True, text=True, timeout=60,
                env={**os.environ, "LC_ALL": "C", "LANG": "C"},
            )
        except Exception as exc:
            return f"unable to determine source kernel release: {exc}"
        detected = proc.stdout.strip()
        result["detected_kernel_version"] = detected or None
        if proc.returncode != 0:
            return f"unable to determine source kernel release: {proc.stderr.strip()}"
        if detected != expected:
            return f"kernel release mismatch: expected {expected}, got {detected}"
        return None

    def _save_result(self, result: Dict, attempt: int) -> Dict:
        result["finished_at"] = datetime.now(timezone.utc).isoformat()
        tool_result_path = os.path.join(self.logs_dir, f"build_result_{attempt}.json")
        with open(tool_result_path, "w") as f:
            json.dump(result, f, indent=2)
        return result

    def check_environment(self) -> Dict:
        env_check = {"kpatch_build": False, "gcc": False, "make": False}
        for cmd in ["kpatch-build", "gcc", "make"]:
            try:
                subprocess.run([cmd, "--version"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=10)
                env_check[cmd.replace("-", "_")] = True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
        return env_check

    def _find_ko(self, *search_dirs: str) -> Optional[str]:
        candidates = []
        for search_dir in search_dirs:
            if not search_dir or not os.path.isdir(search_dir):
                continue
            for root, dirs, files in os.walk(search_dir):
                for f in files:
                    if f.endswith(".ko") and "livepatch" in f:
                        path = os.path.join(root, f)
                        candidates.append((os.path.getmtime(path), path))
        if not candidates:
            return None
        candidates.sort(reverse=True)
        return candidates[0][1]

    @staticmethod
    def _hash_file(path: str) -> str:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
