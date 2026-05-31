from __future__ import annotations

import json
from typing import Any


class JsonRenameProvider:
    def __init__(self, payload: Any) -> None:
        self._payload = payload

    def suggest_renames(self, capture: Any) -> str:
        if isinstance(self._payload, str):
            return self._payload
        return json.dumps(self._payload)


def _rule_pack(rules, schema_version: int = 1):
    return {
        "schema_version": schema_version,
        "id": "test.rules",
        "description": "test rules",
        "rules": rules,
    }


def _rename_rule(
    rule_id: str = "test.rename.v1",
    pattern: str = r"\b(?P<dst>v1)\s*=\s*a1\b",
    new_name: str = "inputValue",
    source: str = "rule",
    override_of: str = "",
    scope_text: str = "v1 = a1",
):
    rule = {
        "id": rule_id,
        "phase": "rename",
        "priority": 100,
        "confidence": 0.91,
        "override_of": override_of,
        "scope": {
            "text_contains": scope_text
        },
        "match": {
            "assignment_regex": pattern
        },
        "emit": {
            "kind": "rename",
            "rename_kind": "lvar",
            "target": "$dst",
            "new_name": new_name,
            "source": source,
            "evidence": "test binding"
        },
    }
    if not override_of:
        del rule["override_of"]
    return rule


def _call_arg_rewrite_rule() -> dict:
    return {
        "id": "test.call_arg_rewrite.v2",
        "phase": "call_arg_rewrite",
        "priority": 50,
        "confidence": 0.90,
        "scope": {
            "calls_any": ["ProbeForRead"]
        },
        "match": {
            "text_contains": "ProbeForRead"
        },
        "emit": {
            "kind": "call_arg_rewrite",
            "function_name": "ProbeForRead",
            "argument_index": 1,
            "replacement": "sizeof(*inputBuffer)",
            "preview_only": True,
            "evidence": "preview-only call argument rewrite"
        },
    }


def _semantic_comment_rule(comment_kind: str = "test_semantic_gate") -> dict:
    return {
        "id": "test.semantic_comment.v1",
        "phase": "semantic_comment",
        "priority": 80,
        "confidence": 0.90,
        "scope": {
            "text_contains": "ProbeForRead"
        },
        "match": {
            "text_contains": "ProbeForRead"
        },
        "emit": {
            "kind": "semantic_comment",
            "comment_kind": comment_kind,
            "text": "test semantic gate",
            "evidence": "test semantic gate"
        },
    }


def _text_rewrite_rule(
    rule_id: str = "test.text_rewrite.v2",
    before_regex: str = r"ProbeForRead\((?P<arg>inputBuffer), 8, 1\)",
    replacement: str = "ProbeForRead($arg, sizeof(*inputBuffer), 1)",
    comment_kind: str = "test_semantic_gate",
    priority: int = 50,
) -> dict:
    return {
        "id": rule_id,
        "phase": "text_rewrite",
        "priority": priority,
        "confidence": 0.90,
        "scope": {
            "requires_comment_kind": comment_kind,
            "text_contains": "ProbeForRead"
        },
        "match": {
            "before_regex": before_regex
        },
        "emit": {
            "kind": "text_rewrite",
            "replacement": replacement,
            "preview_only": True,
            "evidence": "preview-only text rewrite"
        },
    }


def _flow_rule(
    rule_id: str = "test.flow.v2",
    priority: int = 50,
    min_cases: int = 4,
    dispatcher_regex: str = "^code$",
    body_state_any: str | list[str] | None = None,
) -> dict:
    match = {
        "flow_case_count_min": min_cases,
        "flow_dispatcher_regex": dispatcher_regex,
    }
    if body_state_any is not None:
        match["flow_body_state_any"] = body_state_any
    return {
        "id": rule_id,
        "phase": "flow",
        "priority": priority,
        "confidence": 0.90,
        "scope": {
            "text_contains": "switch"
        },
        "match": match,
        "emit": {
            "kind": "flow",
            "flow_kind": "switch_recovery_review",
            "summary": "Recovered $case_count cases for $dispatcher",
            "preview_only": True,
            "evidence": "preview-only flow report"
        },
    }


def _call_arg_gate_match(
    function_name: str = "ProbeForRead",
    count: int = 3,
    argument_index: int = 2,
    value: str = "1",
) -> dict:
    return {
        "call_arg_count": {
            "function_name": function_name,
            "count": count,
        },
        "call_arg_literal": {
            "function_name": function_name,
            "argument_index": argument_index,
            "value": value,
        },
    }
