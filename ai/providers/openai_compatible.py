"""OpenAI Chat Completions-compatible HTTP provider using the standard library."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from ..provider import AIProvider, ProviderConfig, ProviderError


class OpenAICompatibleProvider(AIProvider):
    def __init__(self, config: ProviderConfig) -> None:
        self.config = config

    def _endpoint(self) -> str:
        base = self.config.base_url.rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        if base.endswith("/v1"):
            return f"{base}/chat/completions"
        return f"{base}/v1/chat/completions"

    def _request(self, messages, stream=False):
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": stream,
        }
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream" if stream else "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        request = urllib.request.Request(
            self._endpoint(),
            data=json.dumps(payload, ensure_ascii=True).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        return request

    @staticmethod
    def _error(exc: urllib.error.HTTPError) -> ProviderError:
        if exc.code == 401:
            return ProviderError("The AI provider rejected its API key.")
        if exc.code == 429:
            return ProviderError("The AI provider is rate limiting requests. Try again shortly.")
        if exc.code in {408, 504}:
            return ProviderError("The AI provider timed out. Try again shortly.")
        return ProviderError(f"The AI provider returned HTTP {exc.code}.")

    @staticmethod
    def _content(payload) -> str:
        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ProviderError("The AI provider returned a malformed response.") from None
        if isinstance(content, list):
            content = "".join(
                item.get("text", "") for item in content
                if isinstance(item, dict) and isinstance(item.get("text"), str)
            )
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("The AI provider returned an empty response.")
        return content.strip()

    def generate_response(self, messages: list[dict[str, str]]) -> str:
        try:
            with urllib.request.urlopen(self._request(messages), timeout=self.config.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise self._error(exc) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ProviderError("VulnScan AI is currently unavailable. Please check that Ollama is running.") from None
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
            raise ProviderError("The AI provider returned a malformed response.") from None
        return self._content(payload)

    def stream_response(self, messages: list[dict[str, str]]):
        try:
            response = urllib.request.urlopen(self._request(messages, stream=True), timeout=self.config.timeout)
        except urllib.error.HTTPError as exc:
            raise self._error(exc) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ProviderError("VulnScan AI is currently unavailable. Please check that Ollama is running.") from None
        try:
            if "text/event-stream" not in response.headers.get("Content-Type", "").lower():
                try:
                    payload = json.loads(response.read().decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError, OSError):
                    raise ProviderError("The AI provider returned a malformed response.") from None
                yield self._content(payload)
                return
            for raw_line in response:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    payload = json.loads(data)
                    fragment = payload["choices"][0].get("delta", {}).get("content", "")
                except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                    continue
                if isinstance(fragment, str) and fragment:
                    yield fragment
        except OSError:
            raise ProviderError("The AI response stream was interrupted.") from None
        finally:
            response.close()