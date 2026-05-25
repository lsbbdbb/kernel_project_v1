"""Tests for YAML-backed knowledge loading."""
from agent.knowledge import loader as loader_module
from agent.knowledge.loader import KnowledgeLoader


def test_load_failure_patterns_without_pyyaml(monkeypatch):
    monkeypatch.setattr(loader_module, "yaml", None)
    KnowledgeLoader._failure_patterns = []

    patterns = KnowledgeLoader.load_failure_patterns()

    assert len(patterns) >= 9
    assert any(p["reason_code"] == "api_mismatch" for p in patterns)
    assert any(p["reason_code"] == "module_disabled"
               and p["next_action"] == "skip" for p in patterns)


def test_load_rewrite_strategies_without_pyyaml(monkeypatch):
    monkeypatch.setattr(loader_module, "yaml", None)
    KnowledgeLoader._rewrite_strategies = {}

    strategies = KnowledgeLoader.load_rewrite_strategies()

    assert strategies["api_mismatch"]["auto_allowed"] is True
    assert strategies["struct_abi"]["auto_allowed"] is True
    assert strategies["data_change"]["auto_allowed"] is True
