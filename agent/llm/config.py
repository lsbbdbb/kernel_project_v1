"""LLM configuration helpers."""
import os
from dataclasses import dataclass
from typing import Optional


DEFAULT_BASE_URLS = {
    "qwen": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "openai": None,
    "ollama": "http://localhost:11434/v1",
}


@dataclass
class LLMConfig:
    """Runtime configuration for OpenAI-compatible LLM providers."""

    provider: str = "qwen"
    model: str = "qwen-max"
    api_key: Optional[str] = None
    base_url: Optional[str] = DEFAULT_BASE_URLS["qwen"]
    temperature: float = 0.3
    max_tokens: int = 4096
    timeout: int = 120

    @classmethod
    def from_env(cls) -> "LLMConfig":
        provider = os.getenv("LLM_PROVIDER", "qwen").strip().lower()
        default_models = {
            "qwen": "qwen-max",
            "deepseek": "deepseek-chat",
            "openai": "gpt-4o-mini",
            "ollama": "llama3.1",
        }
        default_model = default_models.get(provider, "gpt-4o-mini")
        model = os.getenv("LLM_MODEL") or os.getenv("DASHSCOPE_MODEL") or default_model
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
