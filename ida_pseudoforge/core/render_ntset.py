from __future__ import annotations

import re

from ida_pseudoforge.core.normalize import safe_identifier_replace


def normalize_ntset_system_information_body(text: str) -> str:
    result = text
    aliases = _m128_aliases_assigned_from_parameter(result, "systemInformation")
    if (
        "systemInfo128" in aliases
        and _m128_alias_reassigned(result, "systemInfo128", "systemInformation")
        and not re.search(r"\binfoBuffer128\b", result)
    ):
        result = safe_identifier_replace(result, {"systemInfo128": "infoBuffer128"})
        aliases = _m128_aliases_assigned_from_parameter(result, "systemInformation")
    stable_alias = _stable_m128_parameter_alias(result, aliases, "systemInformation")
    if not stable_alias and aliases:
        result, stable_alias = _split_mutable_m128_parameter_alias(result, aliases[0], "systemInformation")
        aliases = _m128_aliases_assigned_from_parameter(result, "systemInformation")
    for alias in aliases:
        result = re.sub(
            r"\b%s\s*=\s*systemInformation\s*;" % re.escape(alias),
            "%s = (__m128i *)systemInformation;" % alias,
            result,
            count=1,
        )
        result = re.sub(
            r"(?m)^(\s*__m128i\s*\*\s*%s\s*=\s*)systemInformation(\s*;)" % re.escape(alias),
            r"\1(__m128i *)systemInformation\2",
            result,
            count=1,
        )
    if stable_alias:
        result = re.sub(r"\bsystemInformation->(?=m128i_)", stable_alias + "->", result)
        result = re.sub(r"\bsystemInformation(?=\s*\[[^\]]+\]\s*\.m128i_)", stable_alias, result)
        result = re.sub(r"(?<![A-Za-z0-9_])\*systemInformation\b", "*" + stable_alias, result)
    else:
        result = re.sub(r"\bsystemInformation->(?=m128i_)", "((__m128i *)systemInformation)->", result)
        result = re.sub(
            r"\bsystemInformation(?=\s*\[[^\]]+\]\s*\.m128i_)",
            "((__m128i *)systemInformation)",
            result,
        )
        result = re.sub(r"(?<![A-Za-z0-9_])\*systemInformation\b", "*(__m128i *)systemInformation", result)

    probe_rewritten = False

    def rewrite_probe_end(match: re.Match[str]) -> str:
        nonlocal probe_rewritten
        probe_rewritten = True
        return "%suserProbeEnd = %s;" % (match.group("indent"), match.group("expr"))

    result = re.sub(
        r"(?m)^(?P<indent>\s*)systemInformationClass\s*=\s*(?P<expr>&[^\n;]*m128i_i8\[[^\n;]+\]);",
        rewrite_probe_end,
        result,
        count=1,
    )
    if probe_rewritten and not re.search(r"(?m)^\s*PVOID\s+userProbeEnd\s*;", result):
        result = re.sub(
            r"(?m)^(?P<indent>\s*)KPROCESSOR_MODE previousMode\s*;[^\n]*\n",
            lambda match: match.group(0) + match.group("indent") + "PVOID userProbeEnd;\n",
            result,
            count=1,
        )
    return result


def _m128_aliases_assigned_from_parameter(text: str, parameter_name: str) -> list[str]:
    declared = set()
    aliases = []
    for match in re.finditer(
        r"(?m)^\s*__m128i\s*\*\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:\s*=\s*(?P<expr>[^;\n]+))?\s*;",
        text,
    ):
        name = match.group("name")
        declared.add(name)
        expr = match.group("expr")
        if expr is not None and _rhs_is_parameter_alias(expr, parameter_name) and name not in aliases:
            aliases.append(name)
    for match in re.finditer(
        r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*;" % re.escape(parameter_name),
        text,
    ):
        name = match.group("name")
        if name in declared and name not in aliases:
            aliases.append(name)
    return aliases


def _stable_m128_parameter_alias(text: str, aliases: list[str], parameter_name: str) -> str:
    for alias in aliases:
        if not _m128_alias_reassigned(text, alias, parameter_name):
            return alias
    return ""


def _split_mutable_m128_parameter_alias(text: str, alias: str, parameter_name: str) -> tuple[str, str]:
    input_alias = _unique_identifier(text, parameter_name + "128")
    declaration_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)__m128i\s*\*\s*%s\s*=\s*(?:\(__m128i\s*\*\)\s*)?%s\s*;"
        % (re.escape(alias), re.escape(parameter_name))
    )
    match = declaration_pattern.search(text)
    if match:
        indent = match.group("indent")
        replacement = (
            "%s__m128i *%s = (__m128i *)%s;\n"
            "%s__m128i *%s = %s;"
            % (indent, input_alias, parameter_name, indent, alias, input_alias)
        )
        return declaration_pattern.sub(replacement, text, count=1), input_alias

    declaration_only_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)__m128i\s*\*\s*%s\s*;" % re.escape(alias)
    )
    assignment_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)%s\s*=\s*(?:\(__m128i\s*\*\)\s*)?%s\s*;"
        % (re.escape(alias), re.escape(parameter_name))
    )
    declaration_match = declaration_only_pattern.search(text)
    assignment_match = assignment_pattern.search(text)
    if not declaration_match or not assignment_match:
        return text, ""

    declaration_indent = declaration_match.group("indent")
    updated = declaration_only_pattern.sub(
        "%s__m128i *%s;\n%s__m128i *%s;" % (declaration_indent, alias, declaration_indent, input_alias),
        text,
        count=1,
    )

    assignment_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)%s\s*=\s*(?:\(__m128i\s*\*\)\s*)?%s\s*;"
        % (re.escape(alias), re.escape(parameter_name))
    )

    def rewrite_assignment(match: re.Match[str]) -> str:
        indent = match.group("indent")
        return (
            "%s%s = (__m128i *)%s;\n"
            "%s%s = %s;"
            % (indent, input_alias, parameter_name, indent, alias, input_alias)
        )

    updated = assignment_pattern.sub(rewrite_assignment, updated, count=1)
    return updated, input_alias


def _unique_identifier(text: str, preferred: str) -> str:
    if not re.search(r"\b%s\b" % re.escape(preferred), text):
        return preferred
    index = 1
    while True:
        candidate = "%s%d" % (preferred, index)
        if not re.search(r"\b%s\b" % re.escape(candidate), text):
            return candidate
        index += 1


def _m128_alias_reassigned(text: str, alias: str, parameter_name: str) -> bool:
    pattern = re.compile(r"\b%s\s*=\s*(?P<expr>[^;\n]+);" % re.escape(alias))
    for match in pattern.finditer(text):
        if _rhs_is_parameter_alias(match.group("expr"), parameter_name):
            continue
        return True
    return False


def _rhs_is_parameter_alias(expr: str, parameter_name: str) -> bool:
    value = re.sub(r"\s+", "", expr or "")
    if value == parameter_name:
        return True
    if value == "(__m128i*)%s" % parameter_name:
        return True
    return False
