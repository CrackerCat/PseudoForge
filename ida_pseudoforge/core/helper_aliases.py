from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable

from ida_pseudoforge.core.normalize import (
    extract_calls,
    extract_function_name,
    extract_function_signature,
    extract_parameters_from_signature,
)


@dataclass(frozen=True)
class RuntimeHelperAlias:
    original_name: str
    alias_name: str
    role: str
    confidence: float
    reason: str


@dataclass(frozen=True)
class _RuntimeHelperCandidate:
    original_name: str
    base_alias: str
    role: str
    confidence: float
    reason: str


_DECOMPILER_HELPER_RE = re.compile(r"^(?:sub|j_sub)_[0-9A-Fa-f]+$")


def decompiler_helper_call_names(text: str, current_name: str) -> list[str]:
    result = []
    seen = set()
    for call_name in extract_calls(text):
        if call_name == current_name or not _DECOMPILER_HELPER_RE.match(call_name):
            continue
        if call_name in seen:
            continue
        seen.add(call_name)
        result.append(call_name)
    return result


def infer_direct_runtime_helper_aliases(
    text: str,
    current_name: str,
    helper_text_loader: Callable[[str], str | None],
    max_callees: int = 8,
) -> dict[str, RuntimeHelperAlias]:
    helper_texts = []
    for call_name in decompiler_helper_call_names(text, current_name):
        if len(helper_texts) >= max(0, int(max_callees)):
            break
        try:
            helper_text = helper_text_loader(call_name)
        except Exception:
            helper_text = None
        if helper_text:
            helper_texts.append(helper_text)
    return infer_runtime_helper_aliases_from_texts(helper_texts)


def infer_runtime_helper_aliases_from_texts(texts: Iterable[str]) -> dict[str, RuntimeHelperAlias]:
    candidates: list[_RuntimeHelperCandidate] = []
    seen: set[str] = set()
    for text in texts:
        candidate = infer_runtime_helper_alias(text)
        if candidate is None or candidate.original_name in seen:
            continue
        seen.add(candidate.original_name)
        candidates.append(candidate)
    return _assign_alias_names(candidates)


def infer_runtime_helper_alias(text: str) -> _RuntimeHelperCandidate | None:
    code_text = _strip_block_comments(text)
    signature = extract_function_signature(code_text)
    function_name = extract_function_name(signature)
    if not _DECOMPILER_HELPER_RE.match(function_name or ""):
        return None
    params = extract_parameters_from_signature(signature)
    if len(params) != 3:
        return None

    first_name = params[0][0]
    second_name = params[1][0]
    third_name = params[2][0]
    if (first_name, second_name, third_name) == ("destination", "fillByte", "byteCount"):
        if _looks_like_memory_fill_helper(code_text, first_name, second_name, third_name):
            return _RuntimeHelperCandidate(
                original_name=function_name,
                base_alias="memset",
                role="runtime-memory-fill",
                confidence=0.90,
                reason="three-argument helper returns destination and expands a fill byte across byteCount bytes",
            )
    if (first_name, second_name, third_name) == ("destination", "source", "byteCount"):
        if _looks_like_memory_move_helper(code_text, first_name, second_name, third_name):
            return _RuntimeHelperCandidate(
                original_name=function_name,
                base_alias="memmove",
                role="runtime-memory-move",
                confidence=0.88,
                reason="three-argument helper returns destination and copies between source/destination ranges",
            )
    return None


def _strip_block_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text or "", flags=re.DOTALL)


def apply_runtime_helper_aliases(text: str, aliases: dict[str, RuntimeHelperAlias]) -> str:
    if not text or not aliases:
        return text
    result = text
    for original_name, alias in sorted(aliases.items(), key=lambda item: len(item[0]), reverse=True):
        result = _replace_call_name(result, original_name, alias.alias_name)
    return _normalize_standard_memory_alias_calls(result)


def runtime_helper_alias_summary(aliases: dict[str, RuntimeHelperAlias]) -> list[dict[str, object]]:
    return [
        {
            "original_name": alias.original_name,
            "alias_name": alias.alias_name,
            "role": alias.role,
            "confidence": alias.confidence,
            "reason": alias.reason,
        }
        for alias in sorted(aliases.values(), key=lambda item: item.original_name)
    ]


def is_runtime_helper_alias_advisory(warning: object, aliases: dict[str, RuntimeHelperAlias]) -> bool:
    match = re.match(
        r"^(?P<name>(?:sub|j_sub)_[0-9A-Fa-f]+)\s+behaves like\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\b",
        str(warning or "").strip(),
    )
    if match is None:
        return False
    alias = aliases.get(match.group("name"))
    return alias is not None and alias.alias_name == match.group("alias")


def _assign_alias_names(candidates: list[_RuntimeHelperCandidate]) -> dict[str, RuntimeHelperAlias]:
    if not candidates:
        return {}
    role_counts: dict[str, int] = {}
    for candidate in candidates:
        role_counts[candidate.role] = role_counts.get(candidate.role, 0) + 1

    role_indexes: dict[str, int] = {}
    aliases: dict[str, RuntimeHelperAlias] = {}
    for candidate in sorted(candidates, key=lambda item: (item.role, item.original_name)):
        suffix = ""
        if candidate.base_alias not in {"memset", "memmove"} and role_counts.get(candidate.role, 0) > 1:
            role_indexes[candidate.role] = role_indexes.get(candidate.role, 0) + 1
            suffix = str(role_indexes[candidate.role])
        aliases[candidate.original_name] = RuntimeHelperAlias(
            original_name=candidate.original_name,
            alias_name=candidate.base_alias + suffix,
            role=candidate.role,
            confidence=candidate.confidence,
            reason=candidate.reason,
        )
    return aliases


def _looks_like_memory_fill_helper(text: str, destination: str, fill_byte: str, byte_count: str) -> bool:
    destination_re = re.escape(destination)
    fill_byte_re = re.escape(fill_byte)
    byte_count_re = re.escape(byte_count)
    if not _returns_first_parameter(text, destination_re):
        return False

    fill_pattern = bool(
        re.search(r"\b0x1(?:01){2,}[A-Za-z0-9]*\s*\*\s*%s\b" % fill_byte_re, text)
        or re.search(r"\b%s\s*\*\s*0x1(?:01){2,}[A-Za-z0-9]*\b" % fill_byte_re, text)
    )
    byte_count_control = bool(
        re.search(r"\b%s\s*(?:>=|>|<=|<|==|!=)\s*(?:0x[0-9A-Fa-f]+|\d+)\b" % byte_count_re, text)
        or re.search(r"--\s*%s\b|\b%s\s*--\b" % (byte_count_re, byte_count_re), text)
        or re.search(r"\b%s\s*[-+*/&|<>]" % byte_count_re, text)
    )
    destination_write = bool(
        re.search(r"\*\s*\([^;\n)]*\*\s*\)\s*%s\s*=" % destination_re, text)
        or re.search(r"\*\s*%s\s*=" % destination_re, text)
        or re.search(r"\b%s\s*\[\s*[^;\n\]]+\s*\]\s*=" % destination_re, text)
    )
    sized_destination = bool(
        re.search(r"\b%s\s*\[\s*%s\b" % (destination_re, byte_count_re), text)
        or re.search(r"&\s*%s\s*\[\s*%s\b" % (destination_re, byte_count_re), text)
    )
    return fill_pattern and byte_count_control and (destination_write or sized_destination)


def _replace_call_name(text: str, original_name: str, alias_name: str) -> str:
    pattern = re.compile(r"\b%s\b(?=\s*\()" % re.escape(original_name))

    def replace(match: re.Match[str]) -> str:
        if _looks_like_definition_name_context(text, match.start()):
            return match.group(0)
        return alias_name

    return pattern.sub(replace, text)


def _looks_like_definition_name_context(text: str, name_start: int) -> bool:
    line_start = text.rfind("\n", 0, name_start) + 1
    prefix = text[line_start:name_start].strip()
    if not prefix:
        return False
    if ";" in prefix or "=" in prefix:
        return False
    return bool(re.search(r"\b__(?:fastcall|stdcall|cdecl|thiscall|vectorcall)\b", prefix))


def _looks_like_memory_move_helper(text: str, destination: str, source: str, byte_count: str) -> bool:
    destination_re = re.escape(destination)
    source_re = re.escape(source)
    byte_count_re = re.escape(byte_count)
    if not _returns_first_parameter(text, destination_re):
        return False

    delta_names = _pointer_delta_variables(text, destination_re, source_re)
    pointer_delta = bool(
        re.search(r"\b%s\s*-\s*%s\b|\b%s\s*-\s*%s\b" % (source_re, destination_re, destination_re, source_re), text)
    )
    overlap_branch = bool(
        re.search(r"\b%s\s*(?:<|<=|>|>=)\s*%s\b" % (source_re, destination_re), text)
        or re.search(r"\b%s\s*(?:<|<=|>|>=)\s*%s\b" % (destination_re, source_re), text)
    )
    byte_count_control = bool(
        re.search(r"\b%s\s*(?:>=|>|<=|<|==|!=)\s*(?:0x[0-9A-Fa-f]+|\d+)\b" % byte_count_re, text)
        or re.search(r"--\s*%s\b|\b%s\s*--\b" % (byte_count_re, byte_count_re), text)
        or re.search(r"\b%s\s*[-+*/&|<>]" % byte_count_re, text)
    )
    source_read = bool(
        re.search(r"\b%s\s*\[\s*[^;\n\]]+\s*\]" % source_re, text)
        or re.search(r"\*\s*\([^;\n)]*\*\s*\)\s*%s\b" % source_re, text)
        or any(re.search(r"\[\s*%s\b|\b%s\s*[-+]" % (re.escape(delta), re.escape(delta)), text) for delta in delta_names)
    )
    destination_write = bool(
        re.search(r"\*\s*\([^;\n)]*\*\s*\)\s*%s\s*=" % destination_re, text)
        or re.search(r"\*\s*%s\s*=" % destination_re, text)
        or re.search(r"\b%s\s*\[\s*[^;\n\]]+\s*\]\s*=" % destination_re, text)
        or _has_destination_alias_write(text, destination_re, byte_count_re)
    )
    return pointer_delta and overlap_branch and byte_count_control and source_read and destination_write


def _pointer_delta_variables(text: str, destination: str, source: str) -> set[str]:
    result: set[str] = set()
    for match in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:%s\s*-\s*%s|%s\s*-\s*%s)\s*;"
        % (source, destination, destination, source),
        text,
    ):
        result.add(match.group(1))
    return result


def _has_destination_alias_write(text: str, destination: str, byte_count: str) -> bool:
    for match in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*&\s*%s\s*\[\s*%s\s*\]\s*;" % (destination, byte_count),
        text,
    ):
        alias = re.escape(match.group(1))
        if re.search(r"\*\s*%s\s*=" % alias, text[match.end() :]):
            return True
    return False


def _normalize_standard_memory_alias_calls(text: str) -> str:
    array_sizes = _local_array_byte_sizes(text)
    if not array_sizes:
        return text

    def replace_memset(match: re.Match[str]) -> str:
        target = match.group("target")
        expected_size = array_sizes.get(target)
        if expected_size is None:
            return match.group(0)
        actual_size = _parse_c_integer_literal(match.group("size"))
        if actual_size != expected_size:
            return match.group(0)
        return "memset(%s, 0, sizeof(%s))" % (target, target)

    return re.sub(
        r"\bmemset\(\s*(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*"
        r"(?P<value>0|0LL|0i64|0u|0UL|0ULL|NULL|nullptr|FALSE|false)\s*,\s*"
        r"(?P<size>0x[0-9A-Fa-f]+|\d+)(?:LL|i64|uLL|ULL|u|UL)?\s*\)",
        replace_memset,
        text or "",
    )


def _local_array_byte_sizes(text: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for match in re.finditer(
        r"(?m)^\s*(?P<type>[A-Za-z_][A-Za-z0-9_\s]*?)\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<count>0x[0-9A-Fa-f]+|\d+)\s*\]\s*;",
        text or "",
    ):
        element_size = _known_array_element_size(match.group("type"))
        count = _parse_c_integer_literal(match.group("count"))
        if element_size <= 0 or count is None:
            continue
        result[match.group("name")] = element_size * count
    return result


def _known_array_element_size(type_text: str) -> int:
    normalized = re.sub(r"\b(?:const|volatile|signed)\b", " ", type_text or "")
    normalized = re.sub(r"\s+", " ", normalized).strip().lower()
    sizes = {
        "_byte": 1,
        "byte": 1,
        "char": 1,
        "unsigned char": 1,
        "__int8": 1,
        "unsigned __int8": 1,
        "char8_t": 1,
        "uchar": 1,
        "_word": 2,
        "word": 2,
        "wchar_t": 2,
        "__int16": 2,
        "unsigned __int16": 2,
        "char16_t": 2,
        "short": 2,
        "unsigned short": 2,
        "ushort": 2,
        "_dword": 4,
        "dword": 4,
        "__int32": 4,
        "unsigned __int32": 4,
        "char32_t": 4,
        "long": 4,
        "unsigned long": 4,
        "int": 4,
        "unsigned int": 4,
        "ulong": 4,
        "_qword": 8,
        "qword": 8,
        "__int64": 8,
        "unsigned __int64": 8,
        "long long": 8,
        "unsigned long long": 8,
        "longlong": 8,
        "ulonglong": 8,
        "ulong64": 8,
        "_oword": 16,
        "__int128": 16,
        "xmmword": 16,
    }
    return sizes.get(normalized, 0)


def _parse_c_integer_literal(value: str) -> int | None:
    token = re.sub(r"(?i)(ui64|i64|ull|llu|ll|ul|lu|u|l)$", "", (value or "").strip())
    if not token:
        return None
    try:
        return int(token, 16 if token.lower().startswith("0x") else 10)
    except ValueError:
        return None


def _returns_first_parameter(text: str, escaped_parameter: str) -> bool:
    direct_return = re.search(r"\breturn\s+(?:\([^)]*\)\s*)?%s\s*;" % escaped_parameter, text)
    if direct_return:
        return True
    result_alias = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]*\)\s*)?%s\s*;" % escaped_parameter, text)
    if result_alias is None:
        return False
    alias_name = re.escape(result_alias.group(1))
    if re.search(r"\b%s\s*[-+*/]?=(?!=)" % alias_name, text[result_alias.end() :]):
        return False
    if re.search(r"\+\+%s\b|\b%s\+\+|--%s\b|\b%s--" % (alias_name, alias_name, alias_name, alias_name), text):
        return False
    return bool(re.search(r"\breturn\s+%s\s*;" % alias_name, text))
