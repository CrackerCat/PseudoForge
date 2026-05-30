from __future__ import annotations

import re
from dataclasses import dataclass, field

from ida_pseudoforge.core.plan_schema import FunctionCapture


@dataclass(slots=True)
class AssignmentFact:
    target: str
    expression: str
    span: tuple[int, int]


@dataclass(slots=True)
class CallSiteFact:
    name: str
    span: tuple[int, int]


@dataclass(slots=True)
class LabelFact:
    name: str
    span: tuple[int, int]


@dataclass(slots=True)
class LiteralFact:
    value: str
    span: tuple[int, int]


@dataclass(slots=True)
class RuleContext:
    capture: FunctionCapture
    text: str
    lines: list[str]
    lvar_names: set[str]
    calls: set[str]
    assignments: list[AssignmentFact] = field(default_factory=list)
    call_sites: list[CallSiteFact] = field(default_factory=list)
    labels: list[LabelFact] = field(default_factory=list)
    literals: list[LiteralFact] = field(default_factory=list)


_ASSIGNMENT_RE = re.compile(
    r"\b(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>[^;\n]+);"
)
_CALL_RE = re.compile(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_LABEL_RE = re.compile(r"(?m)^(?P<name>[A-Za-z_][A-Za-z0-9_]*):")
_LITERAL_RE = re.compile(r"\b(?:0x[0-9A-Fa-f]+|\d+)\b")


def build_rule_context(capture: FunctionCapture, text: str | None = None) -> RuleContext:
    rule_text = capture.pseudocode if text is None else text
    return RuleContext(
        capture=capture,
        text=rule_text or "",
        lines=(rule_text or "").splitlines(),
        lvar_names={var.name for var in capture.lvars},
        calls={str(name) for name in capture.calls},
        assignments=_assignment_facts(rule_text or ""),
        call_sites=_call_site_facts(rule_text or ""),
        labels=_label_facts(rule_text or ""),
        literals=_literal_facts(rule_text or ""),
    )


def _assignment_facts(text: str) -> list[AssignmentFact]:
    return [
        AssignmentFact(
            target=match.group("target"),
            expression=match.group("expr").strip(),
            span=match.span(),
        )
        for match in _ASSIGNMENT_RE.finditer(text)
    ]


def _call_site_facts(text: str) -> list[CallSiteFact]:
    return [CallSiteFact(name=match.group("name"), span=match.span()) for match in _CALL_RE.finditer(text)]


def _label_facts(text: str) -> list[LabelFact]:
    return [LabelFact(name=match.group("name"), span=match.span()) for match in _LABEL_RE.finditer(text)]


def _literal_facts(text: str) -> list[LiteralFact]:
    return [LiteralFact(value=match.group(0), span=match.span()) for match in _LITERAL_RE.finditer(text)]
