"""
LLM API Connector Module for AI Guardian Toolkit.

Provides a unified interface for sending prompts to different LLM providers
(OpenAI, Anthropic, Ollama, custom REST endpoints) for security testing purposes.
"""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Optional

try:
    import requests as _requests_mod
except ImportError:
    _requests_mod = None

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional SDK imports (graceful fallback to raw requests)
# ---------------------------------------------------------------------------
try:
    import openai as _openai_mod
except ImportError:
    _openai_mod = None

try:
    import anthropic as _anthropic_mod
except ImportError:
    _anthropic_mod = None


# ---------------------------------------------------------------------------
# Response dataclass
# ---------------------------------------------------------------------------
@dataclass
class ConnectorResponse:
    """Standardised response returned by every connector."""
    text: str = ""
    tokens_used: int = 0
    latency_ms: float = 0.0
    model: str = ""
    raw_response: Optional[Dict] = field(default=None)
    error: Optional[str] = None
    success: bool = False


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------
class LLMConnector(ABC):
    """Abstract base class that every provider connector must implement."""

    @abstractmethod
    def send_prompt(self, prompt: str, system: str = "") -> ConnectorResponse:
        ...

    @abstractmethod
    def get_model_info(self) -> Dict:
        ...

    @abstractmethod
    def is_available(self) -> bool:
        ...

    def send_prompt_with_retry(
        self, prompt: str, system: str = "", max_retries: int = 3, delay: float = 1.0
    ) -> ConnectorResponse:
        """Send a prompt with automatic retry on failure."""
        last_response = ConnectorResponse(error="No attempts made")
        for attempt in range(1, max_retries + 1):
            response = self.send_prompt(prompt, system)
            if response.success:
                return response
            last_response = response
            logger.warning("Attempt %d/%d failed: %s", attempt, max_retries, response.error)
            if attempt < max_retries:
                time.sleep(delay)
        return last_response


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------
class OpenAIConnector(LLMConnector):
    def __init__(self, api_key: str, model: str = "gpt-4o-mini", base_url: str = None):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url or "https://api.openai.com/v1"
        self.request_delay: float = 1.0
        self.timeout: int = 30

    # -- internal helpers --------------------------------------------------
    def _send_via_sdk(self, prompt: str, system: str) -> ConnectorResponse:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        client = _openai_mod.OpenAI(api_key=self.api_key, base_url=self.base_url if self.base_url != "https://api.openai.com/v1" else None)
        start = time.perf_counter()
        resp = client.chat.completions.create(model=self.model, messages=messages, timeout=self.timeout)
        latency = (time.perf_counter() - start) * 1000

        tokens = resp.usage.total_tokens if resp.usage else 0
        text = resp.choices[0].message.content if resp.choices else ""
        return ConnectorResponse(
            text=text, tokens_used=tokens, latency_ms=latency,
            model=self.model, raw_response=resp.model_dump() if hasattr(resp, "model_dump") else None,
            error=None, success=True,
        )

    def _send_via_requests(self, prompt: str, system: str) -> ConnectorResponse:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {"model": self.model, "messages": messages}

        start = time.perf_counter()
        resp = _requests_mod.post(f"{self.base_url}/chat/completions", json=payload, headers=headers, timeout=self.timeout)
        latency = (time.perf_counter() - start) * 1000
        resp.raise_for_status()
        data = resp.json()

        text = data["choices"][0]["message"]["content"] if data.get("choices") else ""
        tokens = data.get("usage", {}).get("total_tokens", 0)
        return ConnectorResponse(
            text=text, tokens_used=tokens, latency_ms=latency,
            model=self.model, raw_response=data, error=None, success=True,
        )

    # -- public API --------------------------------------------------------
    def send_prompt(self, prompt: str, system: str = "") -> ConnectorResponse:
        time.sleep(self.request_delay)
        try:
            if _openai_mod is not None:
                return self._send_via_sdk(prompt, system)
            return self._send_via_requests(prompt, system)
        except Exception as exc:
            logger.error("OpenAI call failed: %s", exc)
            return ConnectorResponse(model=self.model, error=str(exc))

    def get_model_info(self) -> Dict:
        return {"provider": "openai", "model": self.model, "base_url": self.base_url, "sdk": _openai_mod is not None}

    def is_available(self) -> bool:
        return bool(self.api_key)


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------
class AnthropicConnector(LLMConnector):
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-5-20250929"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.anthropic.com/v1"
        self.request_delay: float = 1.0
        self.timeout: int = 30

    def _send_via_sdk(self, prompt: str, system: str) -> ConnectorResponse:
        client = _anthropic_mod.Anthropic(api_key=self.api_key)
        kwargs = {"model": self.model, "max_tokens": 1024, "messages": [{"role": "user", "content": prompt}]}
        if system:
            kwargs["system"] = system

        start = time.perf_counter()
        resp = client.messages.create(**kwargs)
        latency = (time.perf_counter() - start) * 1000

        text = resp.content[0].text if resp.content else ""
        tokens = (resp.usage.input_tokens + resp.usage.output_tokens) if resp.usage else 0
        return ConnectorResponse(
            text=text, tokens_used=tokens, latency_ms=latency,
            model=self.model, raw_response=resp.model_dump() if hasattr(resp, "model_dump") else None,
            error=None, success=True,
        )

    def _send_via_requests(self, prompt: str, system: str) -> ConnectorResponse:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {"model": self.model, "max_tokens": 1024, "messages": [{"role": "user", "content": prompt}]}
        if system:
            payload["system"] = system

        start = time.perf_counter()
        resp = _requests_mod.post(f"{self.base_url}/messages", json=payload, headers=headers, timeout=self.timeout)
        latency = (time.perf_counter() - start) * 1000
        resp.raise_for_status()
        data = resp.json()

        text = data["content"][0]["text"] if data.get("content") else ""
        usage = data.get("usage", {})
        tokens = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
        return ConnectorResponse(
            text=text, tokens_used=tokens, latency_ms=latency,
            model=self.model, raw_response=data, error=None, success=True,
        )

    def send_prompt(self, prompt: str, system: str = "") -> ConnectorResponse:
        time.sleep(self.request_delay)
        try:
            if _anthropic_mod is not None:
                return self._send_via_sdk(prompt, system)
            return self._send_via_requests(prompt, system)
        except Exception as exc:
            logger.error("Anthropic call failed: %s", exc)
            return ConnectorResponse(model=self.model, error=str(exc))

    def get_model_info(self) -> Dict:
        return {"provider": "anthropic", "model": self.model, "sdk": _anthropic_mod is not None}

    def is_available(self) -> bool:
        return bool(self.api_key)


# ---------------------------------------------------------------------------
# Ollama (local)
# ---------------------------------------------------------------------------
class OllamaConnector(LLMConnector):
    def __init__(self, model: str = "llama3.2", endpoint: str = "http://localhost:11434"):
        self.model = model
        self.endpoint = endpoint.rstrip("/")
        self.request_delay: float = 0.5
        self.timeout: int = 120

    def send_prompt(self, prompt: str, system: str = "") -> ConnectorResponse:
        time.sleep(self.request_delay)
        try:
            payload = {"model": self.model, "prompt": prompt, "stream": False}
            if system:
                payload["system"] = system

            start = time.perf_counter()
            resp = _requests_mod.post(f"{self.endpoint}/api/generate", json=payload, timeout=self.timeout)
            latency = (time.perf_counter() - start) * 1000
            resp.raise_for_status()
            data = resp.json()

            return ConnectorResponse(
                text=data.get("response", ""),
                tokens_used=data.get("eval_count", 0) + data.get("prompt_eval_count", 0),
                latency_ms=latency, model=self.model, raw_response=data,
                error=None, success=True,
            )
        except Exception as exc:
            logger.error("Ollama call failed: %s", exc)
            return ConnectorResponse(model=self.model, error=str(exc))

    def get_model_info(self) -> Dict:
        return {"provider": "ollama", "model": self.model, "endpoint": self.endpoint}

    def is_available(self) -> bool:
        try:
            resp = _requests_mod.get(f"{self.endpoint}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Custom REST endpoint
# ---------------------------------------------------------------------------
class CustomAPIConnector(LLMConnector):
    def __init__(
        self, endpoint: str, api_key: str = None,
        headers: Dict = None, prompt_field: str = "prompt",
        response_field: str = "response",
    ):
        self.endpoint = endpoint
        self.api_key = api_key
        self.headers = headers or {}
        self.prompt_field = prompt_field
        self.response_field = response_field
        self.request_delay: float = 1.0
        self.timeout: int = 30

        if self.api_key and "Authorization" not in self.headers:
            self.headers["Authorization"] = f"Bearer {self.api_key}"
        self.headers.setdefault("Content-Type", "application/json")

    def send_prompt(self, prompt: str, system: str = "") -> ConnectorResponse:
        time.sleep(self.request_delay)
        try:
            payload = {self.prompt_field: prompt}
            if system:
                payload["system"] = system

            start = time.perf_counter()
            resp = _requests_mod.post(self.endpoint, json=payload, headers=self.headers, timeout=self.timeout)
            latency = (time.perf_counter() - start) * 1000
            resp.raise_for_status()
            data = resp.json()

            text = data.get(self.response_field, str(data))
            return ConnectorResponse(
                text=text, tokens_used=data.get("tokens_used", 0),
                latency_ms=latency, model="custom", raw_response=data,
                error=None, success=True,
            )
        except Exception as exc:
            logger.error("Custom API call failed: %s", exc)
            return ConnectorResponse(model="custom", error=str(exc))

    def get_model_info(self) -> Dict:
        return {"provider": "custom", "endpoint": self.endpoint}

    def is_available(self) -> bool:
        return bool(self.endpoint)


# ---------------------------------------------------------------------------
# Factory & utilities
# ---------------------------------------------------------------------------
_PROVIDERS = {
    "openai": OpenAIConnector,
    "anthropic": AnthropicConnector,
    "ollama": OllamaConnector,
    "custom": CustomAPIConnector,
}


def create_connector(provider: str, **kwargs) -> LLMConnector:
    """Factory: create_connector("openai", api_key="sk-...", model="gpt-4o")"""
    provider = provider.lower()
    if provider not in _PROVIDERS:
        raise ValueError(f"Unknown provider '{provider}'. Choose from: {list(_PROVIDERS.keys())}")
    return _PROVIDERS[provider](**kwargs)


def check_available_providers() -> Dict[str, bool]:
    """Check which provider packages are installed."""
    return {
        "openai": _openai_mod is not None,
        "anthropic": _anthropic_mod is not None,
        "requests": _requests_mod is not None,
    }
