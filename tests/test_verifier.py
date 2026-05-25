import subprocess

from agent.tools.verifier import Verifier


def _make_verifier(tmp_path):
    cve_id = "CVE-2026-0005"
    artifacts = tmp_path / cve_id / "artifacts"
    artifacts.mkdir(parents=True)
    ko_path = artifacts / "livepatch-test.ko"
    ko_path.write_bytes(b"ko")
    return Verifier(str(tmp_path), cve_id), str(ko_path)


def test_remote_verify_requires_insmod_sysfs_and_rmmod(tmp_path, monkeypatch):
    verifier, ko_path = _make_verifier(tmp_path)
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[:4] == ["ssh", "root@vm", "modinfo", "-F"]:
            return subprocess.CompletedProcess(command, 0, stdout=b"fixed_patch\n")
        if command == ["ssh", "root@vm", "uname", "-r"]:
            return subprocess.CompletedProcess(command, 0, stdout=b"6.6.102-5.2.an23.x86_64\n")
        return subprocess.CompletedProcess(command, 0, stdout=b"ok\n")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = verifier.verify(ko_path, vm_host="root@vm", poc_path="/tmp/dirty_frag_poc")

    assert result["result"] == "passed"
    assert result["runtime_check"]["sysfs_path"] == "/sys/kernel/livepatch/fixed_patch"
    assert ["ssh", "root@vm", "sudo", "insmod", "/tmp/livepatch.ko"] in commands
    assert ["ssh", "root@vm", "test", "-d", "/sys/kernel/livepatch/fixed_patch"] in commands
    assert ["ssh", "root@vm", "/tmp/dirty_frag_poc"] in commands
    assert ["ssh", "root@vm", "sudo", "rmmod", "fixed_patch"] in commands


def test_remote_load_failure_captures_dmesg(tmp_path, monkeypatch):
    verifier, ko_path = _make_verifier(tmp_path)

    def fake_run(command, **kwargs):
        if command[:4] == ["ssh", "root@vm", "modinfo", "-F"]:
            return subprocess.CompletedProcess(command, 0, stdout=b"failed_patch\n")
        if command == ["ssh", "root@vm", "uname", "-r"]:
            return subprocess.CompletedProcess(command, 0, stdout=b"6.6.102-5.2.an23.x86_64\n")
        if command[:4] == ["ssh", "root@vm", "sudo", "insmod"]:
            return subprocess.CompletedProcess(command, 1, stdout=b"Invalid module\n")
        if command == ["ssh", "root@vm", "sudo", "dmesg"]:
            return subprocess.CompletedProcess(command, 0, stdout=b"livepatch: Unknown symbol\n")
        return subprocess.CompletedProcess(command, 0, stdout=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = verifier.verify(ko_path, vm_host="root@vm")

    assert result["result"] == "failed"
    assert result["load"]["return_code"] == 1
    assert "Unknown symbol" in (tmp_path / "CVE-2026-0005" / "logs" / "dmesg_1.log").read_text()


def test_remote_verify_allows_hostname_without_user(tmp_path):
    verifier, _ = _make_verifier(tmp_path)

    assert verifier._validate_vm_host("anolis-vm") is True


def test_remote_verify_rejects_shell_like_poc_path(tmp_path):
    verifier, ko_path = _make_verifier(tmp_path)

    result = verifier.verify(ko_path, vm_host="root@vm", poc_path="/tmp/poc;reboot")

    assert result["result"] == "failed"
    assert "Invalid VM PoC path" in result["error"]


def test_remote_verify_does_not_load_on_kernel_mismatch(tmp_path, monkeypatch):
    verifier, ko_path = _make_verifier(tmp_path)
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command == ["ssh", "root@vm", "uname", "-r"]:
            return subprocess.CompletedProcess(command, 0, stdout=b"6.1.0-wrong\n")
        return subprocess.CompletedProcess(command, 0, stdout=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = verifier.verify(ko_path, vm_host="root@vm")

    assert result["result"] == "failed"
    assert result["kernel_match"] is False
    assert "Kernel mismatch" in result["load"]["error"]
    assert ["ssh", "root@vm", "sudo", "insmod", "/tmp/livepatch.ko"] not in commands
