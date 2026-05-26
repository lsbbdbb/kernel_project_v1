"""Tests for KpatchBuilder build result handling."""
import os
from types import SimpleNamespace

from agent.tools.kpatch_builder import KpatchBuilder


def test_build_collects_livepatch_from_command_cwd(tmp_path, monkeypatch):
    source_dir = tmp_path / "kernel-src"
    source_dir.mkdir()
    vmlinux = source_dir / "vmlinux"
    vmlinux.write_text("fake vmlinux")
    patch = tmp_path / "fix.patch"
    patch.write_text("diff --git a/a.c b/a.c\n")

    def fake_run(cmd, stdout, stderr, timeout, cwd, env=None):
        assert cwd.endswith(os.path.join("CVE-2026-0001", "artifacts"))
        assert "--skip-compiler-check" not in cmd
        ko_path = os.path.join(cwd, "livepatch-fix.ko")
        with open(ko_path, "wb") as f:
            f.write(b"fake ko")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("agent.tools.kpatch_builder.subprocess.run", fake_run)

    builder = KpatchBuilder(str(tmp_path), "CVE-2026-0001")
    result = builder.build(str(patch), str(source_dir), str(vmlinux))

    assert result["success"] is True
    assert result["artifact_path"].endswith("livepatch.ko")
    assert os.path.exists(result["artifact_path"])
    assert result["sha256"]


def test_build_stops_before_kpatch_when_kernel_release_mismatches(tmp_path):
    source_dir = tmp_path / "kernel-src"
    source_dir.mkdir()
    (source_dir / "Makefile").write_text("kernelrelease:\n\t@echo 6.6.102-wrong\n")
    vmlinux = source_dir / "vmlinux"
    vmlinux.write_text("fake vmlinux")
    patch = tmp_path / "fix.patch"
    patch.write_text("diff --git a/a.c b/a.c\n")

    result = KpatchBuilder(str(tmp_path), "CVE-2026-0002").build(
        str(patch), str(source_dir), str(vmlinux),
        expected_kernel_version="6.6.102-5.2.an23.x86_64",
    )

    assert result["success"] is False
    assert result["detected_kernel_version"] == "6.6.102-wrong"
    assert "kernel release mismatch" in open(result["log_path"]).read()


def test_build_records_and_uses_selected_kpatch_toolchain(tmp_path, monkeypatch):
    source_dir = tmp_path / "kernel-src"
    source_dir.mkdir()
    vmlinux = source_dir / "vmlinux"
    vmlinux.write_text("fake vmlinux")
    patch = tmp_path / "fix.patch"
    patch.write_text("diff --git a/a.c b/a.c\n")
    selected_bin = "/opt/kpatch-upstream/kpatch-build"

    def fake_run(cmd, stdout, stderr, timeout, cwd, env=None):
        assert cmd[0] == selected_bin
        (tmp_path / "CVE-2026-0003" / "artifacts" / "livepatch-fix.ko").write_bytes(b"fake ko")
        return SimpleNamespace(returncode=0)

    monkeypatch.setenv("KPATCH_BUILD_BIN", selected_bin)
    monkeypatch.setenv("KPATCH_BUILD_REF", "padding-aware-ref")
    monkeypatch.setattr("agent.tools.kpatch_builder.subprocess.run", fake_run)

    result = KpatchBuilder(str(tmp_path), "CVE-2026-0003").build(
        str(patch), str(source_dir), str(vmlinux)
    )

    assert result["success"] is True
    assert result["kpatch_build_binary"] == selected_bin
    assert result["kpatch_build_ref"] == "padding-aware-ref"
