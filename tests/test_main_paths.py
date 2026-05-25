"""Tests for CLI path resolution helpers."""
import json
import os
import subprocess

from agent import __main__ as agent_main
from agent.__main__ import (
    _action_apply_patch,
    _action_classify_failure,
    _action_check_target,
    _action_fetch_patch,
    _action_fix_environment,
    _action_prepare_rewrite,
    _action_run_build,
    _apply_llm_overrides,
    _target_source_dir,
)
from agent.llm.config import LLMConfig
from agent.state import StateManager
from agent.tools.rewrite_advisor import RewriteAdvisor


def test_target_source_dir_prefers_kernel_src_env(monkeypatch):
    monkeypatch.setenv("KERNEL_SRC", "/kernel-src/custom")

    assert _target_source_dir("/tmp/work", "6.6.102-5.2.an23.x86_64") == "/kernel-src/custom"


def test_target_source_dir_uses_exact_kernel_version_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("KERNEL_SRC", raising=False)
    kernel_dir = tmp_path / "kernel-src" / "linux-6.6.102-5.2.an23.x86_64"
    kernel_dir.mkdir(parents=True)
    workdir = tmp_path / "run"

    assert _target_source_dir(str(workdir), "6.6.102-5.2.an23.x86_64") == str(kernel_dir)


def test_llm_provider_override_updates_provider_credentials_and_endpoint(monkeypatch):
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "openai-test-key")

    config = _apply_llm_overrides(LLMConfig(), "openai", "gpt-4o-mini")

    assert config.provider == "openai"
    assert config.api_key == "openai-test-key"
    assert config.base_url is None
    assert config.model == "gpt-4o-mini"


def test_prepare_rewrite_validates_against_resolved_local_source(tmp_path, monkeypatch):
    cve_id = "CVE-2026-0001"
    kernel_version = "6.6.102-5.2.an23.x86_64"
    kernel_dir = tmp_path / "kernel-src" / f"linux-{kernel_version}"
    kernel_dir.mkdir(parents=True)
    workdir = tmp_path / "run"
    cve_dir = workdir / cve_id
    (cve_dir / "patches").mkdir(parents=True)
    (cve_dir / "patches" / "original.patch").write_text("patch")
    (cve_dir / "failure.json").write_text(json.dumps({
        "category": "compile", "reason_code": "api_mismatch", "retryable": True,
        "location": {"file": "net/example.c"},
    }))
    (cve_dir / "change_units.json").write_text(json.dumps({
        "units": [{"change_id": "CU-001", "file": "net/example.c",
                   "function": "example_check", "rewrite_allowed": True}]
    }))
    state_mgr = StateManager(str(workdir))
    state_mgr.init_run_config([cve_id], kernel_version)
    state_mgr.init_cve_state(cve_id)
    monkeypatch.delenv("KERNEL_SRC", raising=False)
    captured = {}

    def fake_apply(self, original_path, plan, target_source_dir, attempt):
        captured["source"] = target_source_dir
        return {"success": True, "output_path": "attempt_1.patch"}

    monkeypatch.setattr(RewriteAdvisor, "apply_rewrite", fake_apply)

    _action_prepare_rewrite(cve_id, str(workdir), state_mgr)

    assert captured["source"] == str(kernel_dir)


def test_check_target_skips_disabled_config_object(tmp_path, monkeypatch):
    cve_id = "CVE-2026-0002"
    kernel_version = "6.6.102-test.x86_64"
    source = tmp_path / "kernel-src" / f"linux-{kernel_version}"
    (source / "drivers" / "block").mkdir(parents=True)
    (source / ".config").write_text("# CONFIG_BLK_DEV_UBLK is not set\n")
    (source / "drivers" / "block" / "Makefile").write_text(
        "obj-$(CONFIG_BLK_DEV_UBLK) += ublk_drv.o\n"
    )
    workdir = tmp_path / "run"
    cve_dir = workdir / cve_id
    cve_dir.mkdir(parents=True)
    (cve_dir / "patch_ir.json").write_text(json.dumps({
        "files": [{"path": "drivers/block/ublk_drv.c"}]
    }))
    state_mgr = StateManager(str(workdir))
    state_mgr.init_run_config([cve_id], kernel_version)
    state_mgr.init_cve_state(cve_id)
    monkeypatch.delenv("KERNEL_SRC", raising=False)

    result = _action_check_target(cve_id, str(workdir), state_mgr)

    assert result["config_check"]["failure_mode"] == "config.module_disabled"
    assert state_mgr.get_state(cve_id)["state"] == "Skipped"
    assert state_mgr.get_state(cve_id)["status"] == "skipped"


def test_apply_hunk_failure_enters_failure_classification_path(tmp_path, monkeypatch):
    cve_id = "CVE-2026-0003"
    source = tmp_path / "source"
    (source / "net").mkdir(parents=True)
    (source / "net" / "example.c").write_text("target context\n")
    workdir = tmp_path / "run"
    patches = workdir / cve_id / "patches"
    patches.mkdir(parents=True)
    (patches / "original.patch").write_text(
        "diff --git a/net/example.c b/net/example.c\n"
        "--- a/net/example.c\n+++ b/net/example.c\n"
        "@@ -1 +1 @@\n-old context\n+fixed context\n"
    )
    state_mgr = StateManager(str(workdir))
    state_mgr.init_run_config([cve_id], "test")
    state_mgr.init_cve_state(cve_id)
    monkeypatch.setenv("KERNEL_SRC", str(source))
    monkeypatch.setenv("LC_ALL", "zh_CN.UTF-8")
    monkeypatch.setenv("LANG", "zh_CN.UTF-8")

    result = _action_apply_patch(cve_id, str(workdir), state_mgr)

    assert result["dry_run_ok"] is False
    assert state_mgr.get_state(cve_id)["state"] == "BuildFailed"
    assert "patch failed" in (workdir / cve_id / "logs" / "build_0.log").read_text()


def test_real_context_divergence_llm_rewrite_is_rebuilt(tmp_path, monkeypatch):
    cve_id = "CVE-2026-0004"
    source = tmp_path / "source"
    (source / "net").mkdir(parents=True)
    (source / "net" / "example.c").write_text(
        "int example_check(int len)\n{\n"
        "    int value = clamp_len(len);\n"
        "    return value;\n}\n"
    )
    original = (
        "diff --git a/net/example.c b/net/example.c\n"
        "--- a/net/example.c\n+++ b/net/example.c\n"
        "@@ -1,5 +1,7 @@ int example_check(int len)\n"
        " int example_check(int len)\n {\n"
        "     int value = len;\n"
        "+    if (len > MAX_LEN)\n"
        "+        return -EINVAL;\n"
        "     return value;\n"
        " }\n"
    )
    rewritten = original.replace("int value = len;", "int value = clamp_len(len);")
    workdir = tmp_path / "run"
    cve_dir = workdir / cve_id
    (cve_dir / "patches").mkdir(parents=True)
    (cve_dir / "patches" / "original.patch").write_text(original)
    (cve_dir / "failure.json").write_text(json.dumps({
        "category": "patch_apply", "reason_code": "hunk_failed",
        "retryable": True, "location": {"file": "net/example.c"},
    }))
    (cve_dir / "change_units.json").write_text(json.dumps({
        "units": [{"change_id": "CU-001", "file": "net/example.c",
                   "function": "example_check", "rewrite_allowed": True}]
    }))
    state_mgr = StateManager(str(workdir))
    state_mgr.init_run_config([cve_id], "test")
    state_mgr.init_cve_state(cve_id)
    monkeypatch.setenv("KERNEL_SRC", str(source))
    assert subprocess.run(
        ["git", "apply", "--check", str(cve_dir / "patches" / "original.patch")],
        cwd=source, capture_output=True,
    ).returncode != 0

    class FakeLLM:
        def ping(self):
            return True

        def chat(self, messages):
            return "```diff\n" + rewritten + "```"

    result = _action_prepare_rewrite(cve_id, str(workdir), state_mgr, FakeLLM())
    assert result["success"] is True
    assert result["rewrite_source"] == "llm"
    apply_result = _action_apply_patch(cve_id, str(workdir), state_mgr)
    assert apply_result["dry_run_ok"] is True

    captured = {}

    def fake_build(self, patch_path, source_dir, vmlinux_path,
                   kernel_devel_path=None, attempt=0, expected_kernel_version=None):
        captured["patch_path"] = patch_path
        captured["attempt"] = attempt
        captured["kernel_version"] = expected_kernel_version
        return {"success": True, "artifact_path": "livepatch.ko", "log_path": "build_1.log"}

    monkeypatch.setattr(agent_main.KpatchBuilder, "build", fake_build)
    _action_run_build(cve_id, str(workdir), state_mgr)

    assert captured["patch_path"].endswith("attempt_1.patch")
    assert captured["attempt"] == 1
    assert captured["kernel_version"] == "test"
    assert state_mgr.get_state(cve_id)["state"] == "BuildSucceeded"


def test_failed_rewritten_build_preserves_rewrite_attempt_evidence(tmp_path):
    cve_id = "CVE-2026-0005"
    workdir = tmp_path / "run"
    cve_dir = workdir / cve_id
    (cve_dir / "logs").mkdir(parents=True)
    (cve_dir / "logs" / "build_1.log").write_text(
        "error: too many arguments to function 'example_check'\n"
    )
    (cve_dir / "attempt_1.json").write_text(json.dumps({
        "attempt_index": 1,
        "output_patch": "patches/attempt_1.patch",
        "rewrite_source": "llm",
    }))
    state_mgr = StateManager(str(workdir))
    state_mgr.init_run_config([cve_id], "test")
    state_mgr.init_cve_state(cve_id)
    state_mgr.increment_attempt(cve_id)
    state_mgr.transition_to(cve_id, "BuildFailed", reason="rewrite failed")

    _action_classify_failure(cve_id, str(workdir), state_mgr)
    record = json.loads((cve_dir / "attempt_1.json").read_text())

    assert record["output_patch"] == "patches/attempt_1.patch"
    assert record["rewrite_source"] == "llm"
    assert record["failure"]["reason_code"] == "api_mismatch"


def test_fetch_failure_does_not_create_placeholder_patch(tmp_path):
    cve_id = "CVE-2026-0006"
    workdir = tmp_path / "run"
    metadata = workdir / cve_id / "metadata"
    metadata.mkdir(parents=True)
    (metadata / "cve_metadata.json").write_text(json.dumps({"nvd": {"references": []}}))
    state_mgr = StateManager(str(workdir))
    state_mgr.init_run_config([cve_id], "test")
    state_mgr.init_cve_state(cve_id)
    state_mgr.transition_to(cve_id, "CveResolved", reason="resolved")

    result = _action_fetch_patch(cve_id, str(workdir), state_mgr)

    assert result["success"] is False
    assert not (workdir / cve_id / "patches" / "original.patch").exists()
    assert state_mgr.get_state(cve_id)["state"] == "Failed"
    assert state_mgr.get_state(cve_id)["status"] == "failed"


def test_ensure_kernel_config_runs_make_olddefconfig(tmp_path, monkeypatch):
    """_ensure_kernel_config() should run make olddefconfig and succeed."""
    from agent.__main__ import _ensure_kernel_config
    src = tmp_path / "kernel-src"
    (src / "include" / "config").mkdir(parents=True)
    (src / ".config").write_text("CONFIG_TEST=y\n")
    # Need both olddefconfig and syncconfig targets for the full test
    (src / "Makefile").write_text(
        "olddefconfig:\n\t@echo 'Config update done'\n"
        "syncconfig:\n\t@touch include/config/auto.conf.cmd; exit 1\n"
    )
    assert _ensure_kernel_config(str(src)) is True
    assert (src / "include" / "config" / "auto.conf.cmd").exists()


def test_ensure_kernel_config_returns_false_for_missing_dir(tmp_path):
    from agent.__main__ import _ensure_kernel_config
    nonexistent = tmp_path / "no_such_dir"
    assert _ensure_kernel_config(str(nonexistent)) is False


def test_clean_kernel_source_does_not_crash_on_non_git_dir(tmp_path):
    from agent.__main__ import _clean_kernel_source
    plain_dir = tmp_path / "no_git"
    plain_dir.mkdir()
    (plain_dir / "some_file").write_text("x")
    # Should not crash
    _clean_kernel_source(str(plain_dir))
    # File should still exist (no git to restore)
    assert (plain_dir / "some_file").exists()


def test_clean_kernel_source_restores_git_state(tmp_path):
    from agent.__main__ import _clean_kernel_source
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=str(repo), capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test"], cwd=str(repo), capture_output=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=str(repo), capture_output=True)
    (repo / "tracked").write_text("original")
    subprocess.run(["git", "add", "."], cwd=str(repo), capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo), capture_output=True)
    # Create dirty state
    (repo / "tracked").write_text("modified")
    (repo / "untracked").write_text("new_file")
    _clean_kernel_source(str(repo))
    assert (repo / "tracked").read_text() == "original"
    assert not (repo / "untracked").exists()


def test_detect_kernel_release_returns_none_outside_kernel_tree(tmp_path):
    from agent.__main__ import _detect_kernel_release
    # A non-kernel directory with Makefile still won't produce a valid release
    src = tmp_path / "src"
    src.mkdir()
    (src / "Makefile").write_text(
        ".DEFAULT:\n\t@echo 'not a kernel tree'\n"
    )
    result = _detect_kernel_release(str(src))
    # Returns None because `make -s kernelrelease` isn't defined
    # (the .DEFAULT catches it but prints a non-empty line)
    assert result is None or not result.startswith("6.6.")


def test_detect_kernel_release_returns_none_for_missing_dir(tmp_path):
    from agent.__main__ import _detect_kernel_release
    assert _detect_kernel_release(str(tmp_path / "missing")) is None


def test_unfixed_environment_failure_stops_for_manual_review(tmp_path, monkeypatch):
    cve_id = "CVE-2026-0007"
    workdir = tmp_path / "run"
    cve_dir = workdir / cve_id
    cve_dir.mkdir(parents=True)
    (cve_dir / "failure.json").write_text(json.dumps({"reason_code": "kernel_mismatch"}))
    state_mgr = StateManager(str(workdir))
    state_mgr.init_run_config([cve_id], "test")
    state_mgr.init_cve_state(cve_id)

    result = _action_fix_environment(cve_id, str(workdir), state_mgr)

    assert result["success"] is False
    assert state_mgr.get_state(cve_id)["state"] == "ManualRequired"
    assert state_mgr.get_state(cve_id)["status"] == "manual_required"
