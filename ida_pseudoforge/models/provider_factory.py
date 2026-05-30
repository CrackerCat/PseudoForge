from __future__ import annotations

from ida_pseudoforge.config import LlmConfig
from ida_pseudoforge.models.base import RenameAssistProvider
from ida_pseudoforge.models.cli_provider import CliRenameProvider
from ida_pseudoforge.models.openai_compatible import OpenAICompatibleRenameProvider
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
)


def build_rename_provider(config: LlmConfig, api_key: str = "") -> RenameAssistProvider:
    provider = normalize_provider(config.provider)
    defaults = provider_defaults(provider)

    if provider == PROVIDER_OPENAI_COMPATIBLE:
        return OpenAICompatibleRenameProvider(
            api_key=api_key,
            base_url=_base_url_for_provider(config, provider, defaults.base_url),
            model=config.model or defaults.model,
            timeout_seconds=config.timeout_seconds,
            extra_headers=config.extra_headers,
        )

    if provider == PROVIDER_OPENROUTER:
        headers = {"X-Title": "PseudoForge"}
        headers.update(config.extra_headers)
        return OpenAICompatibleRenameProvider(
            api_key=api_key,
            base_url=_base_url_for_provider(config, provider, defaults.base_url),
            model=config.model or defaults.model,
            timeout_seconds=config.timeout_seconds,
            extra_headers=headers,
            api_key_env_vars=["PSEUDOFORGE_OPENROUTER_API_KEY", "OPENROUTER_API_KEY"],
            base_url_env_vars=["PSEUDOFORGE_OPENROUTER_BASE_URL"],
            model_env_vars=["PSEUDOFORGE_OPENROUTER_MODEL"],
        )

    if provider == PROVIDER_DEEPSEEK:
        return OpenAICompatibleRenameProvider(
            api_key=api_key,
            base_url=_base_url_for_provider(config, provider, defaults.base_url),
            model=config.model or defaults.model,
            timeout_seconds=config.timeout_seconds,
            extra_headers=config.extra_headers,
            api_key_env_vars=["PSEUDOFORGE_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY"],
            base_url_env_vars=["PSEUDOFORGE_DEEPSEEK_BASE_URL"],
            model_env_vars=["PSEUDOFORGE_DEEPSEEK_MODEL"],
        )

    if provider in {
        PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
        PROVIDER_CODEX_CLI,
        PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
        PROVIDER_CLAUDE_CLI,
    }:
        return CliRenameProvider(
            command_template=config.command_template or defaults.command_template,
            timeout_seconds=config.timeout_seconds,
            model=config.model or defaults.model,
        )

    raise RuntimeError(f"Unsupported LLM provider: {provider}")


def _base_url_for_provider(config: LlmConfig, provider: str, default_base_url: str) -> str:
    base_url = config.base_url
    openai_default = provider_defaults(PROVIDER_OPENAI_COMPATIBLE).base_url
    if not base_url:
        return default_base_url
    if provider != PROVIDER_OPENAI_COMPATIBLE and base_url.rstrip("/") == openai_default:
        return default_base_url
    return base_url
