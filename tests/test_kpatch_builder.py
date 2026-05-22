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

    def fake_run(cmd, stdout, stderr, timeout, cwd):
        assert cwd.endswith(os.path.join("CVE-2026-0001", "artifacts"))
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
