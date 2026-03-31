"""
AI Provider Abstraction

Supports five backends — selected by the AI_PROVIDER env var:
  - groq       → Groq API (Llama3, free, generous limits) ← RECOMMENDED
  - gemini     → Google Gemini via google-genai SDK
  - anthropic  → Claude via Anthropic API
  - openai     → GPT-4o via OpenAI API
  - ollama     → Local model via Ollama (no API key needed)
  - none       → Stub that returns placeholder text (default / offline)
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod

import structlog

log = structlog.get_logger()


class AIProvider(ABC):
    @abstractmethod
    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str: ...

    @property
    @abstractmethod
    def name(self) -> str: ...


# ── Groq ──────────────────────────────────────────────────────────────────────

class GroqProvider(AIProvider):
    """
    Groq API — free tier, very generous limits, OpenAI-compatible.
    Get a free key at https://console.groq.com
    """

    DEFAULT_MODEL = "llama3-8b-8192"

    def __init__(self, api_key: str, model: str | None = None):
        from groq import Groq
        self._client = Groq(api_key=api_key)
        self._model = model or self.DEFAULT_MODEL

    @property
    def name(self) -> str:
        return f"groq/{self._model}"

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            temperature=0.3,
        )
        return response.choices[0].message.content or ""


# ── Gemini ────────────────────────────────────────────────────────────────────

class GeminiProvider(AIProvider):
    """Google Gemini via google-genai SDK."""

    DEFAULT_MODEL = "gemini-2.0-flash-lite"

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
    MODEL = "claude-sonnet-4-20250514"

    def __init__(self, api_key: str):
        import anthropic
        self._client = anthropic.Anthropic(api_key=api_key)

    @property
    def name(self) -> str:
        return f"anthropic/{self.MODEL}"

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        message = self._client.messages.create(
            model=self.MODEL, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": user}],
        )
        return message.content[0].text


# ── OpenAI ────────────────────────────────────────────────────────────────────

class OpenAIProvider(AIProvider):
    MODEL = "gpt-4o"

    def __init__(self, api_key: str):
        from openai import OpenAI
        self._client = OpenAI(api_key=api_key)

    @property
    def name(self) -> str:
        return f"openai/{self.MODEL}"

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        response = self._client.chat.completions.create(
            model=self.MODEL, max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )
        return response.choices[0].message.content or ""


# ── Ollama ────────────────────────────────────────────────────────────────────

class OllamaProvider(AIProvider):
    def __init__(self, base_url: str, model: str = "llama3"):
        self._base_url = base_url.rstrip("/")
        self._model = model

    @property
    def name(self) -> str:
        return f"ollama/{self._model}"

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        import requests
        resp = requests.post(
            f"{self._base_url}/api/chat",
            json={
                "model": self._model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user",   "content": user},
                ],
                "stream": False,
                "options": {"num_predict": max_tokens},
            },
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]


# ── Stub ──────────────────────────────────────────────────────────────────────

class StubProvider(AIProvider):
    @property
    def name(self) -> str:
        return "stub/none"

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        return (
            "[AI analysis not configured] "
            "Set AI_PROVIDER=groq and GROQ_API_KEY in your .env to enable. "
            "Free keys at https://console.groq.com"
        )


# ── Factory ───────────────────────────────────────────────────────────────────

def get_provider() -> AIProvider:
    provider_name = os.environ.get("AI_PROVIDER", "none").lower().strip()

    try:
        if provider_name == "groq":
            api_key = os.environ.get("GROQ_API_KEY", "")
            if not api_key:
                raise ValueError("GROQ_API_KEY is not set")
            model = os.environ.get("GROQ_MODEL", GroqProvider.DEFAULT_MODEL)
            provider = GroqProvider(api_key=api_key, model=model)

        elif provider_name == "gemini":
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
            model = os.environ.get("OLLAMA_MODEL", "llama3")
            provider = OllamaProvider(base_url=base_url, model=model)

        else:
            provider = StubProvider()

        log.info("ai.provider_loaded", provider=provider.name)
        return provider

    except Exception as e:
        log.warning("ai.provider_load_failed", error=str(e), fallback="stub")
        return StubProvider()
