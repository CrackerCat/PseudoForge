from __future__ import annotations

import re


class OfflinePseudocodeError(ValueError):
    pass


_CONTROL_PREFIX_RE = re.compile(r"^(?:if|for|while|switch|return|else|do)\b")
_FUNCTION_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_:~]*)\s*\(")
_PROSE_PREFIXES = (
    "copy ",
    "copied ",
    "cloud ",
    "decompiled ",
    "function output",
    "hex-rays output",
    "hexrays output",
    "here ",
    "ida free",
    "output ",
    "paste ",
    "pseudocode ",
)


def normalize_copied_pseudocode(text: str) -> str:
    normalized = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.splitlines()
    spans = _find_function_spans(lines)
    if not spans:
        raise OfflinePseudocodeError(
            "No function-like pseudocode was found. Copy a single complete Hex-Rays function body."
        )
    if len(spans) > 1:
        raise OfflinePseudocodeError(
            "Multiple function-like pseudocode blocks were found. Save one function per file for this CLI mode."
        )
    start, end = spans[0]
    return "\n".join(lines[start : end + 1]).strip() + "\n"


def _find_function_spans(lines: list[str]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(lines):
        candidate = _find_signature_open_brace(lines, index)
        if candidate is None:
            index += 1
            continue
        start, open_line = candidate
        close_line = _find_matching_close_brace(lines, open_line)
        if close_line < 0:
            raise OfflinePseudocodeError(
                "Function-like pseudocode has an opening brace but no matching closing brace."
            )
        spans.append((start, close_line))
        index = close_line + 1
    return spans


def _find_signature_open_brace(lines: list[str], start: int) -> tuple[int, int] | None:
    if not _could_start_signature(lines[start]):
        return None

    signature_lines = []
    paren_depth = 0
    saw_paren = False
    saw_close = False
    index = start
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or _is_ignorable_between_signature_and_brace(stripped):
            signature_lines.append(lines[index])
            index += 1
            continue
        if saw_close and "{" not in stripped:
            return None

        signature_lines.append(lines[index])
        paren_depth += stripped.count("(")
        paren_depth -= stripped.count(")")
        saw_paren = saw_paren or "(" in stripped
        saw_close = saw_close or (saw_paren and paren_depth <= 0 and ")" in stripped)

        if "{" in stripped:
            signature_text = "\n".join(signature_lines)
            if saw_close and paren_depth <= 0 and _looks_like_function_signature(signature_text):
                return start, index
            return None

        if saw_close and paren_depth <= 0:
            next_index = _next_significant_line(lines, index + 1)
            if next_index < 0:
                return None
            next_stripped = lines[next_index].strip()
            if next_stripped == "{":
                signature_text = "\n".join(signature_lines)
                if _looks_like_function_signature(signature_text):
                    return start, next_index
            return None

        index += 1
    return None


def _could_start_signature(line: str) -> bool:
    stripped = line.strip()
    if not stripped or _is_ignorable_between_signature_and_brace(stripped):
        return False
    lowered = stripped.lower()
    if lowered.startswith(_PROSE_PREFIXES):
        return False
    if stripped.startswith(("-", ">", "|")):
        return False
    if _CONTROL_PREFIX_RE.match(stripped):
        return False
    return "(" in stripped


def _looks_like_function_signature(signature_text: str) -> bool:
    signature = re.sub(r"\s+", " ", signature_text.replace("{", " ")).strip()
    if not signature or ";" in signature:
        return False
    lowered = signature.lower()
    if lowered.startswith(_PROSE_PREFIXES):
        return False
    match = _FUNCTION_NAME_RE.search(signature)
    if not match:
        return False
    function_name = match.group(1).split("::")[-1]
    if function_name in {"if", "for", "while", "switch", "return", "sizeof"}:
        return False
    prefix = signature[: match.start(1)].strip()
    if not prefix:
        return False
    if not re.search(r"[A-Za-z_][A-Za-z0-9_]*|[*&]", prefix):
        return False
    return True


def _next_significant_line(lines: list[str], start: int) -> int:
    for index in range(start, len(lines)):
        stripped = lines[index].strip()
        if not stripped or _is_ignorable_between_signature_and_brace(stripped):
            continue
        return index
    return -1


def _is_ignorable_between_signature_and_brace(stripped: str) -> bool:
    return stripped.startswith(("//", "/*", "*", "*/"))


def _find_matching_close_brace(lines: list[str], open_line: int) -> int:
    depth = 0
    seen_open = False
    for index in range(open_line, len(lines)):
        for char in lines[index]:
            if char == "{":
                depth += 1
                seen_open = True
            elif char == "}":
                depth -= 1
                if seen_open and depth == 0:
                    return index
    return -1
