"""Verifier - validates livepatch .ko in target VM environment."""
import json
import os
import re
import subprocess
import hashlib
import time
from datetime import datetime, timezone
from typing import Dict, Optional


class Verifier:
    """Verify livepatch module in Anolis OS VM."""

    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id
        self.logs_dir = os.path.join(workdir, cve_id, "logs")
        self.artifacts_dir = os.path.join(workdir, cve_id, "artifacts")
        os.makedirs(self.logs_dir, exist_ok=True)

    @staticmethod
    def _validate_vm_host(vm_host: str) -> bool:
        """Validate vm_host format: user@hostname or hostname only. Prevents shell injection."""
        return bool(re.match(r'^(?:[a-zA-Z0-9._-]+@)?[a-zA-Z0-9._-]+$', vm_host))

    @staticmethod
    def _validate_poc_path(poc_path: str) -> bool:
        """Allow execution only of an explicitly named absolute VM-side binary."""
        return bool(re.match(r"^/[a-zA-Z0-9_./-]+$", poc_path))

    def verify(self, ko_path: str, vm_host: Optional[str] = None,
               poc_path: Optional[str] = None, attempt: int = 1) -> Dict:
        verify_log = os.path.join(self.logs_dir, f"verify_{attempt}.log")
        dmesg_log = os.path.join(self.logs_dir, f"dmesg_{attempt}.log")
        result = {
            "artifact": {"path": ko_path, "sha256": self._hash_file(ko_path) if ko_path and os.path.exists(ko_path) else None},
            "target_kernel": self._get_target_kernel(),
            "load": None, "runtime_check": None, "unload": None,
            "dmesg": dmesg_log, "result": "not_tested",
        }
        if not ko_path or not os.path.exists(ko_path):
            result["result"] = "not_tested"
            result["dmesg"] = None
            result["error"] = f"Artifact not found: {ko_path}"
            self._save_verification(result)
            return result
        if vm_host:
            result = self._verify_remote(ko_path, vm_host, verify_log, dmesg_log, poc_path)
        else:
            result = self._verify_local(ko_path, verify_log)
        self._save_verification(result)
        return result

    def _verify_local(self, ko_path: str, verify_log: str) -> Dict:
        result = {
            "artifact": {"path": ko_path, "sha256": self._hash_file(ko_path)},
            "target_kernel": self._get_target_kernel(),
            "load": None, "runtime_check": None, "unload": None, "dmesg": None,
            "result": "verification_local_only",
        }
        try:
            with open(verify_log, "w") as log:
                proc = subprocess.run(["modinfo", ko_path], stdout=log, stderr=subprocess.STDOUT, timeout=30)
            result["modinfo_return_code"] = proc.returncode
            result["modinfo_valid"] = proc.returncode == 0
        except FileNotFoundError:
            result["modinfo_error"] = "modinfo not available"
        return result

    def _verify_remote(self, ko_path: str, vm_host: str, verify_log: str,
                       dmesg_log: str, poc_path: Optional[str] = None) -> Dict:
        if not self._validate_vm_host(vm_host):
            return {
                "artifact": {"path": ko_path, "sha256": self._hash_file(ko_path)},
                "target_kernel": self._get_target_kernel(),
                "load": None, "runtime_check": None, "unload": None, "dmesg": dmesg_log,
                "result": "failed",
                "error": f"Invalid vm_host format: {vm_host}",
            }
        if poc_path and not self._validate_poc_path(poc_path):
            return {
                "artifact": {"path": ko_path, "sha256": self._hash_file(ko_path)},
                "target_kernel": self._get_target_kernel(),
                "load": None, "runtime_check": None, "functional_check": None,
                "unload": None, "dmesg": dmesg_log, "result": "failed",
                "error": f"Invalid VM PoC path: {poc_path}",
            }
        result = {
            "artifact": {"path": ko_path, "sha256": self._hash_file(ko_path)},
            "target_kernel": self._get_target_kernel(),
            "running_kernel": None,
            "kernel_match": None,
            "load": None, "runtime_check": None, "functional_check": None,
            "unload": None, "dmesg": dmesg_log,
        }
        module_name = os.path.splitext(os.path.basename(ko_path))[0].replace("-", "_")
        with open(verify_log, "w") as log:
            try:
                proc = subprocess.run(["ssh", "-F", "/dev/null", vm_host, "uname", "-r"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
                uname = proc.stdout.decode().strip()
                log.write(f"Target uname -r: {uname}\n")
                result["running_kernel"] = uname
                result["kernel_match"] = proc.returncode == 0 and uname == result["target_kernel"]
                if not result["kernel_match"]:
                    result["load"] = {
                        "return_code": -1,
                        "error": (
                            f"Kernel mismatch: expected {result['target_kernel']}, "
                            f"running {uname or 'unknown'}"
                        ),
                    }
            except Exception as e:
                log.write(f"SSH uname failed: {e}\n")
                result["kernel_match"] = False
                result["load"] = {"return_code": -1, "error": str(e)}
            try:
                if result["load"] is None:
                    proc = subprocess.run(
                        ["scp", "-F", "/dev/null", ko_path, f"{vm_host}:/tmp/livepatch.ko"],
                        stdout=log, stderr=subprocess.STDOUT, timeout=60,
                    )
                    if proc.returncode != 0:
                        result["load"] = {"return_code": proc.returncode,
                                          "error": "Failed to transfer module to VM"}
            except Exception as e:
                log.write(f"SCP failed: {e}\n")
                result["load"] = {"return_code": -1, "error": str(e)}
            try:
                if result["load"] is None:
                    proc = subprocess.run(
                        ["ssh", "-F", "/dev/null", vm_host, "modinfo", "-F", "name", "/tmp/livepatch.ko"],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
                    )
                    discovered_name = proc.stdout.decode().strip()
                    if proc.returncode == 0 and re.match(r"^[A-Za-z0-9_-]+$", discovered_name):
                        module_name = discovered_name.replace("-", "_")
                    proc = subprocess.run(
                        ["ssh", "-F", "/dev/null", vm_host, "sudo", "insmod", "/tmp/livepatch.ko"],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
                    )
                    log.write(f"insmod output: {proc.stdout.decode()}\n")
                    result["load"] = {"return_code": proc.returncode,
                                      "command": "insmod /tmp/livepatch.ko",
                                      "module_name": module_name}
            except Exception as e:
                log.write(f"insmod failed: {e}\n")
                result["load"] = {"return_code": -1, "error": str(e)}
            try:
                sysfs_path = f"/sys/kernel/livepatch/{module_name}"
                proc = subprocess.run(
                    ["ssh", "-F", "/dev/null", vm_host, "test", "-d", sysfs_path],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
                )
                result["runtime_check"] = {
                    "return_code": proc.returncode,
                    "sysfs_path": sysfs_path,
                    "visible": proc.returncode == 0,
                }
            except Exception as e:
                log.write(f"livepatch sysfs check failed: {e}\n")
                result["runtime_check"] = {"return_code": -1, "error": str(e)}
            try:
                if poc_path and result.get("runtime_check", {}).get("visible") is True:
                    proc = subprocess.run(
                        ["ssh", "-F", "/dev/null", vm_host, poc_path],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120,
                    )
                    output = proc.stdout.decode()
                    log.write(f"PoC output: {output}\n")
                    result["functional_check"] = {
                        "return_code": proc.returncode, "command": poc_path,
                        "output": output[-2000:],
                    }
            except Exception as e:
                log.write(f"PoC failed: {e}\n")
                result["functional_check"] = {"return_code": -1, "error": str(e)}
            try:
                if result.get("load", {}).get("return_code") == 0:
                    disable_proc = None
                    transition_complete = False
                    if result.get("runtime_check", {}).get("visible") is True:
                        disable_proc = subprocess.run(
                            [
                                "ssh", vm_host, "sudo", "tee",
                                f"/sys/kernel/livepatch/{module_name}/enabled",
                            ],
                            input=b"0\n", stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=30,
                        )
                        log.write(f"disable output: {disable_proc.stdout.decode()}\n")
                        if disable_proc.returncode == 0:
                            for _ in range(30):
                                transition_proc = subprocess.run(
                                    [
                                        "ssh", vm_host, "sudo", "cat",
                                        f"/sys/kernel/livepatch/{module_name}/transition",
                                    ],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=30,
                                )
                                transition = transition_proc.stdout.decode().strip()
                                log.write(f"transition output: {transition}\n")
                                if transition_proc.returncode != 0 or transition == "0":
                                    transition_complete = True
                                    break
                                time.sleep(1)
                    if (
                        result.get("runtime_check", {}).get("visible") is not True
                        or disable_proc is None
                        or disable_proc.returncode != 0
                        or not transition_complete
                    ):
                        result["unload"] = {
                            "return_code": -1,
                            "error": "Failed to disable livepatch before module unload",
                        }
                    else:
                        proc = subprocess.run(
                            ["ssh", "-F", "/dev/null", vm_host, "sudo", "rmmod", module_name],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
                        )
                        log.write(f"rmmod output: {proc.stdout.decode()}\n")
                        result["unload"] = {
                            "return_code": proc.returncode,
                            "command": f"rmmod {module_name}",
                            "disabled_before_unload": True,
                        }
                else:
                    result["unload"] = {"return_code": -1,
                                        "error": "Module was not loaded"}
            except Exception as e:
                log.write(f"rmmod failed: {e}\n")
                result["unload"] = {"return_code": -1, "error": str(e)}
            try:
                proc = subprocess.run(
                    ["ssh", "-F", "/dev/null", vm_host, "sudo", "dmesg"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
                )
                dmesg_output = proc.stdout.decode()
                with open(dmesg_log, "w") as dm:
                    dm.write(dmesg_output[-10000:] if len(dmesg_output) > 10000 else dmesg_output)
                result["dmesg"] = dmesg_log
            except Exception as e:
                log.write(f"dmesg failed: {e}\n")
        load_ok = result.get("load", {}).get("return_code") == 0
        runtime_ok = result.get("runtime_check", {}).get("visible") is True
        poc_ok = not poc_path or result.get("functional_check", {}).get("return_code") == 0
        unload_ok = result.get("unload", {}).get("return_code") == 0
        result["result"] = "passed" if (load_ok and runtime_ok and poc_ok) else "failed"
        return result

    def _save_verification(self, result: Dict):
        with open(os.path.join(self.workdir, self.cve_id, "verification.json"), "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

    @staticmethod
    def _hash_file(path: str) -> str:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _get_target_kernel(self) -> str:
        run_config = os.path.join(self.workdir, "run_config.json")
        if os.path.exists(run_config):
            with open(run_config) as f:
                return json.load(f).get("kernel_version", "6.6.102-5.2.an23.x86_64")
        return "6.6.102-5.2.an23.x86_64"
