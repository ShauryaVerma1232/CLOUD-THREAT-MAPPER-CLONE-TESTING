"""
AI Provider Abstraction

Supports five backends — selected by the AI_PROVIDER env var:
  - gemini     → Google Gemini via google-genai SDK (free API key)
  - anthropic  → Claude via Anthropic API
  - openai     → GPT-4o via OpenAI API
  - ollama     → Local model via Ollama (no API key needed)
  - none       → Stub that returns placeholder text (default / offline)

All providers share the same interface:
  complete(system: str, user: str, max_tokens: int) -> str
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod

import structlog

log = structlog.get_logger()


# ── Base ───────────────────────────────────────────────────────────────────────

class AIProvider(ABC):
    """Abstract base for all LLM providers."""

    @abstractmethod
    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        """
        Send a system + user message pair and return the assistant response.
        Implementations must be synchronous (called from Celery workers).
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...


# ── Gemini ────────────────────────────────────────────────────────────────────

class GeminiProvider(AIProvider):
    """
    Google Gemini via the google-genai SDK.
    Free API keys available at https://aistudio.google.com/app/apikey
    """

    DEFAULT_MODEL = "gemini-1.5-flash"

    def __init__(self, api_key: str, model: str | None = None):
        from google import genai
        from google.genai import types
        self._client = genai.Client(api_key=api_key)
        self._types = types
        self._model_name = model or self.DEFAULT_MODEL

    @property
    def name(self) -> str:
        return f"gemini/{self._model_name}"

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        response = self._client.models.generate_content(
            model=self._model_name,
            contents=user,
            config=self._types.GenerateContentConfig(
                system_instruction=system,
                max_output_tokens=max_tokens,
                temperature=0.3,
            ),
        )
        return response.text


# ── Anthropic ─────────────────────────────────────────────────────────────────

class AnthropicProvider(AIProvider):
    """Claude via Anthropic Messages API."""

    MODEL = "claude-sonnet-4-20250514"

    def __init__(self, api_key: str):
        import anthropic
        self._client = anthropic.Anthropic(api_key=api_key)

    @property
    def name(self) -> str:
        return f"anthropic/{self.MODEL}"

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        message = self._client.messages.create(
            model=self.MODEL,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return message.content[0].text


# ── OpenAI ────────────────────────────────────────────────────────────────────

class OpenAIProvider(AIProvider):
    """GPT-4o via OpenAI Chat Completions API."""

    MODEL = "gpt-4o"

    def __init__(self, api_key: str):
        from openai import OpenAI
        self._client = OpenAI(api_key=api_key)

    @property
    def name(self) -> str:
        return f"openai/{self.MODEL}"

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        response = self._client.chat.completions.create(
            model=self.MODEL,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )
        return response.choices[0].message.content or ""


# ── Ollama ────────────────────────────────────────────────────────────────────

class OllamaProvider(AIProvider):
    """Local Ollama instance — no API key required."""

    def __init__(self, base_url: str, model: str = "llama3"):
        self._base_url = base_url.rstrip("/")
        self._model = model

    @property
    def name(self) -> str:
        return f"ollama/{self._model}"

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        import requests
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "stream": False,
            "options": {"num_predict": max_tokens},
        }
        resp = requests.post(
            f"{self._base_url}/api/chat",
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]


# ── Stub (no AI configured) ───────────────────────────────────────────────────

class StubProvider(AIProvider):
    """
    Placeholder used when AI_PROVIDER=none or no API key is set.
    Returns clearly-labelled stub text so the pipeline still runs.
    """

    @property
    def name(self) -> str:
        return "stub/none"

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        return (
            "[AI analysis not configured] "
            "Set AI_PROVIDER=gemini and GEMINI_API_KEY in your .env file "
            "to enable AI-powered security reasoning. "
            "Free keys available at https://aistudio.google.com/app/apikey"
        )


# ── Factory ───────────────────────────────────────────────────────────────────

def get_provider() -> AIProvider:
    """
    Read AI_PROVIDER from environment and return the appropriate provider.
    Falls back to StubProvider if anything is misconfigured.
    """
    provider_name = os.environ.get("AI_PROVIDER", "none").lower().strip()

    try:
        if provider_name == "gemini":
            api_key = os.environ.get("GEMINI_API_KEY", "")
            if not api_key:
                raise ValueError("GEMINI_API_KEY is not set")
            model = os.environ.get("GEMINI_MODEL", GeminiProvider.DEFAULT_MODEL)
            provider = GeminiProvider(api_key=api_key, model=model)

        elif provider_name == "anthropic":
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY is not set")
            provider = AnthropicProvider(api_key=api_key)

        elif provider_name == "openai":
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if not api_key:
                raise ValueError("OPENAI_API_KEY is not set")
            provider = OpenAIProvider(api_key=api_key)

        elif provider_name == "ollama":
            base_url = os.environ.get("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
            model    = os.environ.get("OLLAMA_MODEL", "llama3")
            provider = OllamaProvider(base_url=base_url, model=model)

        else:
            provider = StubProvider()

        log.info("ai.provider_loaded", provider=provider.name)
        return provider

    except Exception as e:
        log.warning("ai.provider_load_failed", error=str(e), fallback="stub")
        return StubProvider()
