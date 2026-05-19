"""OpenAI-compatible LLM client wrapper."""
from typing import Dict, List, Optional

from agent.llm.config import LLMConfig


class LLMClient:
    """Small wrapper around OpenAI-compatible chat completions."""

    def __init__(self, config: Optional[LLMConfig] = None, client=None):
        self.config = config or LLMConfig.from_env()
        self.client = client
        self.init_error: Optional[str] = None

        if self.client is not None:
            return
        if not self.config.is_configured():
            self.init_error = "LLM provider is not configured"
            return

        try:
            from openai import OpenAI

            kwargs = {
                "api_key": self.config.api_key,
                "timeout": self.config.timeout,
            }
            if self.config.base_url:
                kwargs["base_url"] = self.config.base_url
            self.client = OpenAI(**kwargs)
        except Exception as exc:
            self.init_error = str(exc)
            self.client = None

    def chat(self, messages: List[Dict[str, str]]) -> str:
        """Send chat messages and return the first text response."""
        if self.client is None:
            raise RuntimeError(self.init_error or "LLM client is not initialized")

        response = self.client.chat.completions.create(
            model=self.config.model,
            messages=messages,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
        )
        return response.choices[0].message.content or ""

    def ping(self) -> bool:
        """Return False when no key, no SDK, or the provider is unreachable."""
        if self.client is None:
            return False
        try:
            self.chat([
                {"role": "system", "content": "Reply with OK only."},
                {"role": "user", "content": "ping"},
            ])
            return True
        except Exception:
            return False
