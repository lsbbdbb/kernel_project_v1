"""LLM configuration helpers."""
import os
from dataclasses import dataclass
from typing import Optional


DEFAULT_BASE_URLS = {
    "qwen": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "deepseek": "https://api.deepseek.com",
    "openai": None,
    "ollama": "http://localhost:11434/v1",
}

MODEL_ALIASES = {
    "deepseekv4-pro": "deepseek-v4-pro",
}


@dataclass
class LLMConfig:
    """Runtime configuration for OpenAI-compatible LLM providers."""

    provider: str = "deepseek"
    model: str = "deepseek-v4-pro"
    api_key: Optional[str] = None
    base_url: Optional[str] = DEFAULT_BASE_URLS["deepseek"]
    temperature: float = 0.3
    max_tokens: int = 4096
    timeout: int = 120

    @classmethod
    def from_env(cls) -> "LLMConfig":
        provider = cls._provider_from_env()
        default_models = {
            "qwen": "qwen-max",
            "deepseek": "deepseek-v4-pro",
            "openai": "gpt-4o-mini",
            "ollama": "llama3.1",
        }
        default_model = default_models.get(provider, "gpt-4o-mini")
        model = cls.normalize_model(os.getenv("LLM_MODEL") or os.getenv("DASHSCOPE_MODEL") or default_model)
        api_key = cls._api_key_from_env(provider)
        base_url = os.getenv("LLM_BASE_URL") or DEFAULT_BASE_URLS.get(provider)

        return cls(
            provider=provider,
            model=model,
            api_key=api_key,
            base_url=base_url,
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.3")),
            max_tokens=int(os.getenv("LLM_MAX_TOKENS", "4096")),
            timeout=int(os.getenv("LLM_TIMEOUT", "120")),
        )

    @staticmethod
    def _provider_from_env() -> str:
        configured = os.getenv("LLM_PROVIDER")
        if configured:
            return configured.strip().lower()

        if os.getenv("DASHSCOPE_API_KEY"):
            return "qwen"
        if os.getenv("DEEPSEEK_API_KEY"):
            return "deepseek"
        if os.getenv("OPENAI_API_KEY"):
            return "openai"
        if os.getenv("OLLAMA_API_KEY"):
            return "ollama"

        return "deepseek"

    @staticmethod
    def _api_key_from_env(provider: str) -> Optional[str]:
        if provider == "qwen":
            return os.getenv("DASHSCOPE_API_KEY") or os.getenv("LLM_API_KEY")
        if provider == "deepseek":
            return os.getenv("DEEPSEEK_API_KEY") or os.getenv("LLM_API_KEY")
        if provider == "openai":
            return os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY")
        if provider == "ollama":
            return os.getenv("OLLAMA_API_KEY") or "ollama"
        return os.getenv("LLM_API_KEY")

    def is_configured(self) -> bool:
        """Return True when the provider has enough config to try a request."""
        if self.provider == "ollama":
            return bool(self.base_url)
        return bool(self.api_key)

    @staticmethod
    def normalize_model(model: str) -> str:
        """Accept common shorthand model names without changing provider APIs."""
        return MODEL_ALIASES.get(model, model)
