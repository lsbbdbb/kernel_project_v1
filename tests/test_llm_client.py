"""Tests for the LLM client foundation."""
from types import SimpleNamespace

from agent.llm.client import LLMClient
from agent.llm.config import LLMConfig


class FakeCompletions:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        message = SimpleNamespace(content="OK")
        choice = SimpleNamespace(message=message)
        return SimpleNamespace(choices=[choice])


class FakeClient:
    def __init__(self):
        self.chat = SimpleNamespace(completions=FakeCompletions())


def test_config_from_env_qwen(monkeypatch):
    monkeypatch.setenv("DASHSCOPE_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "qwen-plus")

    config = LLMConfig.from_env()

    assert config.provider == "qwen"
    assert config.model == "qwen-plus"
    assert config.api_key == "test-key"
    assert config.is_configured()


def test_config_from_env_deepseek(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")

    config = LLMConfig.from_env()

    assert config.provider == "deepseek"
    assert config.model == "deepseek-v4-pro"
    assert config.api_key == "test-key"
    assert config.base_url == "https://api.deepseek.com"
    assert config.is_configured()


def test_ping_false_without_key():
    config = LLMConfig(api_key=None)
    client = LLMClient(config)

    assert client.ping() is False


def test_chat_uses_injected_client():
    fake = FakeClient()
    config = LLMConfig(api_key="test-key", model="qwen-plus")
    client = LLMClient(config, client=fake)

    result = client.chat([{"role": "user", "content": "ping"}])

    assert result == "OK"
    assert fake.chat.completions.calls[0]["model"] == "qwen-plus"
    assert fake.chat.completions.calls[0]["messages"][0]["content"] == "ping"
    assert client.ping() is True
