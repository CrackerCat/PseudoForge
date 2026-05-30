from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class LocalVariable:
    name: str
    type: str = ""
    is_arg: bool = False
    index: int = -1


@dataclass(slots=True)
class FunctionCapture:
    ea: int = 0
    name: str = ""
    prototype: str = ""
    pseudocode: str = ""
    lvars: list[LocalVariable] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    source_path: str = ""

    def input_fingerprint(self) -> str:
        import hashlib

        payload = "\n".join(
            [
                self.name,
                self.prototype,
                self.pseudocode,
                ",".join(var.name for var in self.lvars),
            ]
        )
        return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


@dataclass(slots=True)
class RenameSuggestion:
    kind: str
    old: str
    new: str
    confidence: float
    source: str
    evidence: str
    apply: bool = True


@dataclass(slots=True)
class FlowRewrite:
    kind: str
    dispatcher: str
    recovered_cases: list[int] = field(default_factory=list)
    case_bodies: dict[int, list[str]] = field(default_factory=dict)
    case_names: dict[int, str] = field(default_factory=dict)
    confidence: float = 0.0
    export_only: bool = True
    evidence: str = ""


@dataclass(slots=True)
class CleanupLabel:
    label: str
    classification: str
    start_line: int
    end_line: int
    confidence: float
    evidence: str


@dataclass(slots=True)
class CleanPlan:
    function_ea: int
    function_name: str
    input_fingerprint: str
    renames: list[RenameSuggestion] = field(default_factory=list)
    flow_rewrites: list[FlowRewrite] = field(default_factory=list)
    cleanup_labels: list[CleanupLabel] = field(default_factory=list)
    comments: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    rule_report: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def active_renames(self) -> list[RenameSuggestion]:
        return [rename for rename in self.renames if rename.apply]
