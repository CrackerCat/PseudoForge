from __future__ import annotations

import re


_CYBER_POLICY_MARKERS = (
    "cyber-related safeguard",
    "cyber related safeguard",
    "violative cyber content",
    "cyber content",
    "cyber-use-case",
    "cyber verification program",
)

_POLICY_MARKERS = (
    "usage policy",
    "acceptable use policy",
    "aup",
    "policy block",
    "policy blocked",
)


def is_llm_provider_cyber_policy_block(error: object) -> bool:
    lowered = _normalized_error_text(error).lower()
    if not lowered:
        return False
    has_policy = any(marker in lowered for marker in _POLICY_MARKERS)
    has_cyber = any(marker in lowered for marker in _CYBER_POLICY_MARKERS)
    return has_policy and has_cyber


def summarize_llm_failure(error: object, max_length: int = 220) -> str:
    text = _normalized_error_text(error)
    if not text:
        return "unknown error"
    if is_llm_provider_cyber_policy_block(text):
        request_id = _extract_request_id(text)
        summary = "provider cyber policy block"
        if request_id:
            summary += " request_id=%s" % request_id
        return summary
    return _truncate(_sanitize_provider_text(text), max_length)


def format_llm_fallback_warning(error: object) -> str:
    summary = summarize_llm_failure(error)
    if is_llm_provider_cyber_policy_block(error):
        return "LLM rename assist blocked by provider cyber policy; deterministic fallback used: %s" % summary
    return "LLM rename assist failed; deterministic fallback used: %s" % summary


def _normalized_error_text(error: object) -> str:
    return " ".join(str(error or "").split())


def _sanitize_provider_text(text: str) -> str:
    sanitized = re.sub(r"https?://\S+", "[url]", text)
    return _ascii_text(sanitized)


def _extract_request_id(text: str) -> str:
    match = re.search(r"\bRequest ID:\s*([A-Za-z0-9_.:-]+)", text, flags=re.IGNORECASE)
    if not match:
        return ""
    return _ascii_text(match.group(1))


def _truncate(text: str, max_length: int) -> str:
    if len(text) <= max_length:
        return text
    return text[: max(0, max_length - 3)].rstrip() + "..."


def _ascii_text(text: str) -> str:
    return text.encode("ascii", errors="replace").decode("ascii")
