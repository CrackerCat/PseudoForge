from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ida_pseudoforge.models.provider_registry import (
    PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
    PROVIDER_CLAUDE_CLI,
    PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    PROVIDER_CODEX_CLI,
    PROVIDER_DEEPSEEK,
    PROVIDER_OPENAI_COMPATIBLE,
    PROVIDER_OPENROUTER,
    normalize_provider,
    provider_defaults,
    provider_model_options,
)
from ida_pseudoforge.models.subprocess_utils import hidden_subprocess_kwargs


@dataclass(slots=True)
class ModelDiscoveryResult:
    models: list[str]
    source: str
    warning: str = ""


def discover_provider_models(
    provider: str,
    base_url: str = "",
    api_key: str = "",
    timeout_seconds: int = 15,
) -> ModelDiscoveryResult:
    normalized = normalize_provider(provider)

    if normalized in {PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI, PROVIDER_CODEX_CLI}:
        return _discover_codex_models(timeout_seconds)

    if normalized in {PROVIDER_OPENAI_COMPATIBLE, PROVIDER_OPENROUTER, PROVIDER_DEEPSEEK}:
        return _discover_openai_compatible_models(
            provider=normalized,
            base_url=base_url,
            api_key=api_key,
            timeout_seconds=timeout_seconds,
        )

    if normalized in {PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI, PROVIDER_CLAUDE_CLI}:
        return _static_models(normalized)

    return _fallback_models(normalized, "static fallback: unsupported provider")


def _discover_codex_models(timeout_seconds: int) -> ModelDiscoveryResult:
    try:
        result = subprocess.run(
            ["codex", "debug", "models"],
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=min(max(timeout_seconds, 5), 60),
            **hidden_subprocess_kwargs(),
        )
        if result.returncode == 0:
            models = _extract_model_ids(json.loads(result.stdout), key="slug")
            if models:
                return ModelDiscoveryResult(models=models, source="codex debug models")
    except Exception:
        pass

    cache_path = Path.home() / ".codex" / "models_cache.json"
    try:
        models = _extract_model_ids(json.loads(cache_path.read_text(encoding="utf-8")), key="slug")
        if models:
            return ModelDiscoveryResult(models=models, source=str(cache_path))
    except Exception:
        pass

    return _fallback_models(
        PROVIDER_CODEX_CLI,
        "static fallback: could not read Codex model catalog",
    )


def _discover_openai_compatible_models(
    provider: str,
    base_url: str,
    api_key: str,
    timeout_seconds: int,
) -> ModelDiscoveryResult:
    defaults = provider_defaults(provider)
    resolved_base_url = (base_url or defaults.base_url).rstrip("/")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = "Bearer %s" % api_key

    request = urllib.request.Request(
        "%s/models" % resolved_base_url,
        headers=headers,
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=min(max(timeout_seconds, 5), 60)) as response:
            models = _extract_model_ids(json.loads(response.read().decode("utf-8")), key="id")
            if models:
                return ModelDiscoveryResult(models=models, source="%s/models" % resolved_base_url)
    except urllib.error.HTTPError as exc:
        warning = "static fallback: model catalog request failed with HTTP %d" % exc.code
        return _fallback_models(provider, warning)
    except Exception as exc:
        return _fallback_models(provider, "static fallback: model catalog request failed: %s" % exc)

    return _fallback_models(provider, "static fallback: model catalog response was empty")


def _extract_model_ids(data: Any, key: str) -> list[str]:
    raw_models = data.get("models", []) if isinstance(data, dict) else []
    if not raw_models and isinstance(data, dict):
        raw_models = data.get("data", [])
    if not isinstance(raw_models, list):
        return []

    models = []
    seen = set()
    for item in raw_models:
        if not isinstance(item, dict):
            continue
        model = str(item.get(key, "") or item.get("id", "") or item.get("slug", "")).strip()
        if not model or model in seen:
            continue
        seen.add(model)
        models.append(model)
    return models


def _fallback_models(provider: str, warning: str) -> ModelDiscoveryResult:
    normalized = normalize_provider(provider)
    return ModelDiscoveryResult(
        models=list(provider_model_options(normalized)),
        source="static fallback",
        warning=warning,
    )


def _static_models(provider: str) -> ModelDiscoveryResult:
    normalized = normalize_provider(provider)
    return ModelDiscoveryResult(
        models=list(provider_model_options(normalized)),
        source="static provider list",
    )
