"""Provider contract and environment-driven provider construction."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import os


class ProviderError(RuntimeError):
    """A safe, user-displayable provider failure."""


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    model: str
    api_key: str
    base_url: str
    temperature: float
    max_tokens: int
    timeout: float = 45.0


class AIProvider(ABC):
    """Interface implemented by model providers."""

    @abstractmethod
    def generate_response(self, messages: list[dict[str, str]]) -> str:
        """Return one complete assistant response."""

    def stream_response(self, messages: list[dict[str, str]]):
        """Yield response fragments; providers may override for live streaming."""
        yield self.generate_response(messages)


def provider_config_from_environment() -> ProviderConfig | None:
    provider = os.environ.get("AI_PROVIDER", "").strip().lower()
    if not provider:
        return None
    if provider not in {"openai", "openai_compatible"}:
        raise ProviderError("Unsupported AI_PROVIDER. Use openai or openai_compatible.")
    model = os.environ.get("AI_MODEL", "").strip()
    if not model:
        raise ProviderError("Set AI_MODEL to enable VulnScan AI.")
    api_key = os.environ.get("AI_API_KEY", "").strip()
    if provider == "openai" and not api_key:
        raise ProviderError("Set AI_API_KEY to enable the configured AI provider.")
    base_url = os.environ.get("AI_BASE_URL", "").strip()
    if not base_url:
        if provider == "openai":
            base_url = "https://api.openai.com/v1"
        else:
            raise ProviderError("Set AI_BASE_URL for the openai_compatible provider.")
    try:
        temperature = float(os.environ.get("AI_TEMPERATURE", "0.2"))
        max_tokens = int(os.environ.get("AI_MAX_TOKENS", "700"))
    except ValueError as exc:
        raise ProviderError("AI_TEMPERATURE and AI_MAX_TOKENS must be numeric.") from exc
    if not 0 <= temperature <= 2 or not 64 <= max_tokens <= 4096:
        raise ProviderError("AI_TEMPERATURE must be 0–2 and AI_MAX_TOKENS must be 64–4096.")
    return ProviderConfig(
        name=provider,
        model=model,
        api_key=api_key,
        base_url=base_url,
        temperature=temperature,
        max_tokens=max_tokens,
    )


def create_provider() -> tuple[AIProvider | None, ProviderConfig | None]:
    config = provider_config_from_environment()
    if config is None:
        return None, None
    from .providers.openai_compatible import OpenAICompatibleProvider

    return OpenAICompatibleProvider(config), config