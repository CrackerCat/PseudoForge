from __future__ import annotations

import re

from ida_pseudoforge.core.deterministic.context import RuleContext
from ida_pseudoforge.core.deterministic.schema import Rule, RuleMatch


def match_regex_rule(rule: Rule, context: RuleContext) -> list[RuleMatch]:
    if not _scope_matches(rule, context):
        return []
    match_data = rule.match or {}
    if not _match_text_gates(match_data, context.text):
        return []
    if "assignment_regex" in match_data:
        return _regex_matches(rule, context, str(match_data.get("assignment_regex", "")), assignment=True)
    if "regex" in match_data:
        return _regex_matches(rule, context, str(match_data.get("regex", "")), assignment=False)
    if _has_text_match_operator(match_data):
        return [
            RuleMatch(
                rule_id=rule.id,
                phase=rule.phase,
                confidence=rule.confidence,
                bindings={},
                span=None,
                evidence=str(rule.emit.get("evidence", "") or rule.id),
                emission_kind=str(rule.emit.get("kind", "")),
            )
        ]
    return []


def _regex_matches(rule: Rule, context: RuleContext, pattern: str, assignment: bool) -> list[RuleMatch]:
    if not pattern:
        return []
    flags = re.MULTILINE
    if assignment:
        flags |= re.DOTALL
    result = []
    for match in re.finditer(pattern, context.text, flags=flags):
        result.append(
            RuleMatch(
                rule_id=rule.id,
                phase=rule.phase,
                confidence=rule.confidence,
                bindings={key: str(value) for key, value in match.groupdict().items() if value is not None},
                span=match.span(),
                evidence=str(rule.emit.get("evidence", "") or rule.id),
                emission_kind=str(rule.emit.get("kind", "")),
            )
        )
    return result


def _scope_matches(rule: Rule, context: RuleContext) -> bool:
    scope = rule.scope or {}
    for key, value in scope.items():
        if key == "calls_any":
            if not _any_string_in_set(value, context.calls):
                return False
        elif key == "calls_all":
            if not _all_strings_in_set(value, context.calls):
                return False
        elif key == "lvars_any":
            if not _any_string_in_set(value, context.lvar_names):
                return False
        elif key == "function_name_regex":
            if re.search(str(value), context.capture.name or "") is None:
                return False
        elif key == "prototype_contains":
            if str(value) not in (context.capture.prototype or ""):
                return False
        elif key == "text_contains":
            if str(value) not in context.text:
                return False
        elif key == "text_contains_all":
            if not _all_strings_in_text(value, context.text):
                return False
        else:
            return False
    return True


def _match_text_gates(match_data: dict[str, object], text: str) -> bool:
    if "text_contains" in match_data and str(match_data.get("text_contains", "")) not in text:
        return False
    if "text_contains_all" in match_data and not _all_strings_in_text(match_data.get("text_contains_all"), text):
        return False
    return True


def _has_text_match_operator(match_data: dict[str, object]) -> bool:
    return "text_contains" in match_data or "text_contains_all" in match_data


def _any_string_in_set(value: object, candidates: set[str]) -> bool:
    values = _string_list(value)
    return any(item in candidates for item in values)


def _all_strings_in_set(value: object, candidates: set[str]) -> bool:
    values = _string_list(value)
    return bool(values) and all(item in candidates for item in values)


def _all_strings_in_text(value: object, text: str) -> bool:
    values = _string_list(value)
    return bool(values) and all(item in text for item in values)


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        return []
    return [str(value)]
