from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from ida_pseudoforge.core.plan_schema import FunctionCapture
from ida_pseudoforge.logging import log_event
from ida_pseudoforge.models.prompting import SYSTEM_RENAME_PROMPT, build_rename_prompt


class OpenAICompatibleRenameProvider:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout_seconds: int = 60,
        extra_headers: dict[str, str] | None = None,
        api_key_env_vars: list[str] | None = None,
        base_url_env_vars: list[str] | None = None,
        model_env_vars: list[str] | None = None,
    ) -> None:
        self.api_key = api_key or _first_env(
            api_key_env_vars or ["PSEUDOFORGE_OPENAI_API_KEY", "OPENAI_API_KEY"]
        )
        self.base_url = (
            base_url
            or _first_env(base_url_env_vars or ["PSEUDOFORGE_OPENAI_BASE_URL"])
            or "https://api.openai.com/v1"
        ).rstrip("/")
        self.model = model or _first_env(model_env_vars or ["PSEUDOFORGE_OPENAI_MODEL"]) or "gpt-5-mini"
        self.timeout_seconds = timeout_seconds
        self.extra_headers = extra_headers or {}

    def suggest_renames(self, capture: FunctionCapture) -> str:
        if not self.api_key:
            raise RuntimeError("No API key configured for OpenAI-compatible rename provider")

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": SYSTEM_RENAME_PROMPT,
                },
                {
                    "role": "user",
                    "content": build_rename_prompt(capture),
                },
            ],
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        headers.update(self.extra_headers)

        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        log_event(
            "llm.http.start function=\"%s\" model=\"%s\" base_url=\"%s\""
            % (_ascii_for_log(capture.name), _ascii_for_log(self.model), _ascii_for_log(self.base_url))
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            log_event(
                "llm.http.failed function=\"%s\" model=\"%s\" http=%d"
                % (_ascii_for_log(capture.name), _ascii_for_log(self.model), exc.code)
            )
            raise RuntimeError(f"LLM request failed: HTTP {exc.code}: {detail}") from exc

        try:
            content = data["choices"][0]["message"]["content"] or "{}"
            log_event(
                "llm.http.done function=\"%s\" model=\"%s\" output_chars=%d"
                % (_ascii_for_log(capture.name), _ascii_for_log(self.model), len(content))
            )
            return content
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("LLM response did not contain message content") from exc


def _first_env(names: list[str]) -> str:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return ""


def _ascii_for_log(value: str) -> str:
    return value.encode("ascii", errors="replace").decode("ascii")
