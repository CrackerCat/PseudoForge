from __future__ import annotations

import re

from ida_pseudoforge.core.normalize import extract_parameters_from_signature


def rewrite_parameter_low_byte_call_arguments(text: str) -> str:
    parameter_names = _rendered_parameter_names(text)
    if not parameter_names:
        return text

    lines = text.splitlines()
    result = []
    index = 0
    while index < len(lines):
        match = re.match(
            r"^(?P<indent>\s*)LOBYTE\(\s*(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*=\s*(?P<expr>[^;\n]+);\s*$",
            lines[index],
        )
        if not match or match.group("target") not in parameter_names or index + 1 >= len(lines):
            result.append(lines[index])
            index += 1
            continue

        rewritten = _replace_call_argument_low_byte(lines[index + 1], match.group("target"), match.group("expr").strip())
        if rewritten == lines[index + 1]:
            result.append(lines[index])
            index += 1
            continue

        result.append(rewritten)
        index += 2

    return "\n".join(result)


def _rendered_parameter_names(text: str) -> set[str]:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if "(" not in line:
            continue
        end_index = _find_signature_end(lines, index)
        if end_index < index:
            continue
        signature = "\n".join(lines[index : end_index + 1])
        if "{" in signature or ";" in signature:
            continue
        params = extract_parameters_from_signature(signature)
        if params:
            return {name for name, _type_text in params}
    return set()


def _replace_call_argument_low_byte(line: str, target: str, expr: str) -> str:
    if "(" not in line or ")" not in line:
        return line
    replacement = "(unsigned __int8)%s" % expr
    pattern = re.compile(r"(?P<prefix>[(,]\s*)%s(?P<suffix>\s*[,)])" % re.escape(target))
    updated = pattern.sub(lambda match: match.group("prefix") + replacement + match.group("suffix"), line)
    return updated


def _find_signature_end(lines: list[str], start_index: int) -> int:
    depth = 0
    seen_open = False
    for index in range(start_index, len(lines)):
        for char in lines[index]:
            if char == "(":
                depth += 1
                seen_open = True
            elif char == ")":
                depth -= 1
                if seen_open and depth <= 0:
                    return index
    return -1
