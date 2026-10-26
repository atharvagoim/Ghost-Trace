"""Minimal async client for Groq's OpenAI-compatible Chat Completions API.

- Structured output: strict JSON Schema (`response_format.type = json_schema`), validated again on our side.
- Every request passes through `guard_payload` first, so secret-like content can never leave the server.
- Retries: 429 (honouring `retry-after`, capped), 5xx and timeouts; then the fallback model.
- Errors become `AIError` with a message that is safe to show users. Groq's raw error bodies are logged, not returned,
  and prompts are never logged.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass

import httpx

from ..config import get_settings
from .redact import guard_payload

log = logging.getLogger("ghosttrace.ai")

MAX_RETRY_WAIT = 8.0  # seconds; a serverless request can't afford to sleep long


class AIError(Exception):
    def __init__(self, status_code: int, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.retry_after = retry_after


class AINotConfigured(AIError):
    def __init__(self):
        super().__init__(503, "The AI analyst is not set up on this server. Add GROQ_API_KEY to the environment to turn it on.")


@dataclass
class AIResult:
    data: dict
    model: str
    redactions: int
    usage: dict
    latency_ms: int


class GroqClient:
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = get_settings()
        self.transport = transport  # injectable for tests

    def _models(self) -> list[str]:
        models = [self.settings.groq_model]
        if self.settings.groq_fallback_model and self.settings.groq_fallback_model != self.settings.groq_model:
            models.append(self.settings.groq_fallback_model)
        return models

    def _body(self, model: str, messages: list[dict], schema: dict, schema_name: str, max_tokens: int) -> dict:
        body = {
            "model": model,
            "messages": messages,
            "temperature": 0.2,
            "max_completion_tokens": max_tokens,
            "response_format": {"type": "json_schema", "json_schema": {"name": schema_name, "strict": True, "schema": schema}},
        }
        if self.settings.groq_reasoning_effort and model.startswith("openai/gpt-oss"):
            body["reasoning_effort"] = self.settings.groq_reasoning_effort
        return body

    async def chat_json(self, messages: list[dict], schema: dict, schema_name: str, max_tokens: int | None = None) -> AIResult:
        if not self.settings.ai_enabled:
            raise AINotConfigured()
        safe_messages, redactions = guard_payload(messages)
        max_tokens = max_tokens or self.settings.ai_max_output_tokens
        headers = {"Authorization": f"Bearer {self.settings.groq_api_key}", "Content-Type": "application/json"}
        url = f"{self.settings.groq_base_url.rstrip('/')}/chat/completions"
        last_error: AIError | None = None
        started = time.monotonic()

        async with httpx.AsyncClient(timeout=self.settings.groq_timeout_seconds, transport=self.transport) as client:
            for model in self._models():
                for attempt in range(2):
                    try:
                        resp = await client.post(url, headers=headers, json=self._body(model, safe_messages, schema, schema_name, max_tokens))
                    except httpx.TimeoutException:
                        last_error = AIError(504, "The AI service took too long to answer. Please try again.")
                        continue
                    except httpx.TransportError as exc:
                        log.warning("Groq transport error: %s", exc)
                        last_error = AIError(502, "Couldn't reach the AI service. Please try again in a moment.")
                        await asyncio.sleep(1.0)
                        continue

                    if resp.status_code == 200:
                        data = self._parse(resp)
                        if data is not None:
                            usage = resp.json().get("usage") or {}
                            log.info("Groq %s ok: %s prompt + %s completion tokens", model, usage.get("prompt_tokens"), usage.get("completion_tokens"))
                            return AIResult(data, model, redactions, usage, int((time.monotonic() - started) * 1000))
                        last_error = AIError(502, "The AI returned an unreadable answer. Please try again.")
                        continue

                    code = self._error_code(resp)
                    log.warning("Groq %s returned %s (%s)", model, resp.status_code, code)
                    if resp.status_code in (401, 403):
                        raise AIError(502, "The AI service rejected the server's API key. Check GROQ_API_KEY.")
                    if resp.status_code == 429:
                        retry_after = self._retry_after(resp)
                        last_error = AIError(429, "The AI service is busy right now. Please try again shortly.", retry_after)
                        if attempt == 0 and retry_after is not None and retry_after <= MAX_RETRY_WAIT:
                            await asyncio.sleep(retry_after)
                            continue
                        break  # try the fallback model instead of waiting longer
                    if resp.status_code == 400 and code == "json_validate_failed":
                        last_error = AIError(502, "The AI returned an answer in the wrong format. Please try again.")
                        continue
                    if resp.status_code == 413 or code == "context_length_exceeded":
                        raise AIError(413, "This is too large for the AI to review in one go. Try a smaller pull request.")
                    if resp.status_code in (404,) or code in ("model_not_found", "model_decommissioned"):
                        last_error = AIError(502, "The configured AI model isn't available. Check GROQ_MODEL.")
                        break  # next model
                    if resp.status_code >= 500:
                        last_error = AIError(502, "The AI service had a problem. Please try again.")
                        await asyncio.sleep(1.0 * (attempt + 1))
                        continue
                    raise AIError(502, "The AI request failed. Please try again.")
        raise last_error or AIError(502, "The AI request failed. Please try again.")

    @staticmethod
    def _parse(resp: httpx.Response) -> dict | None:
        try:
            content = resp.json()["choices"][0]["message"]["content"]
            data = json.loads(content)
            return data if isinstance(data, dict) else None
        except (KeyError, IndexError, TypeError, ValueError):
            return None

    @staticmethod
    def _error_code(resp: httpx.Response) -> str:
        try:
            err = resp.json().get("error") or {}
            return str(err.get("code") or err.get("type") or "")
        except ValueError:
            return ""

    @staticmethod
    def _retry_after(resp: httpx.Response) -> int | None:
        value = resp.headers.get("retry-after")
        try:
            return max(1, int(float(value))) if value else None
        except ValueError:
            return None
