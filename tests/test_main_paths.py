"""Tests for CLI path resolution helpers."""
import os

from agent.__main__ import _target_source_dir


def test_target_source_dir_prefers_kernel_src_env(monkeypatch):
    monkeypatch.setenv("KERNEL_SRC", "/kernel-src/custom")

    assert _target_source_dir("/tmp/work", "6.6.102-5.2.an23.x86_64") == "/kernel-src/custom"


def test_target_source_dir_uses_exact_kernel_version_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("KERNEL_SRC", raising=False)
    kernel_dir = tmp_path / "kernel-src" / "linux-6.6.102-5.2.an23.x86_64"
    kernel_dir.mkdir(parents=True)
    workdir = tmp_path / "run"

    assert _target_source_dir(str(workdir), "6.6.102-5.2.an23.x86_64") == str(kernel_dir)
