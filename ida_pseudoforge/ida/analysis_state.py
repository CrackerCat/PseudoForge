from __future__ import annotations

import os
import ntpath
import threading
from dataclasses import dataclass
from pathlib import Path

from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture


def normalize_source_identity(value: str | Path | None) -> str:
    if not value:
        return ""
    try:
        text = str(Path(value))
    except Exception:
        text = str(value)
    if _looks_like_windows_path(text):
        return ntpath.normcase(ntpath.normpath(text))
    return os.path.normcase(os.path.normpath(text))


def _looks_like_windows_path(value: str) -> bool:
    return "\\" in value or (len(value) >= 2 and value[1] == ":")


@dataclass(frozen=True, slots=True)
class PluginAnalysisSession:
    target_path: str
    function_ea: int
    function_name: str
    fingerprint: str
    capture: FunctionCapture
    plan: CleanPlan
    forge_path: Path | None = None
    forge_text: str = ""

    @classmethod
    def from_capture_plan(
        cls,
        capture: FunctionCapture,
        plan: CleanPlan,
        target_path: str | Path | None,
        forge_path: str | Path | None = None,
        forge_text: str = "",
    ) -> "PluginAnalysisSession":
        return cls(
            target_path=normalize_source_identity(target_path or capture.source_path),
            function_ea=int(capture.ea),
            function_name=capture.name,
            fingerprint=plan.input_fingerprint or capture.input_fingerprint(),
            capture=capture,
            plan=plan,
            forge_path=Path(forge_path) if forge_path else None,
            forge_text=forge_text or "",
        )

    def matches_current(self, target_path: str | Path | None, function_ea: int) -> bool:
        if int(function_ea) != self.function_ea:
            return False
        current_target = normalize_source_identity(target_path)
        if self.target_path and current_target and self.target_path != current_target:
            return False
        return True


class PluginAnalysisState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._session: PluginAnalysisSession | None = None

    def get(self) -> PluginAnalysisSession | None:
        with self._lock:
            return self._session

    def set(self, session: PluginAnalysisSession) -> PluginAnalysisSession:
        with self._lock:
            self._session = session
        return session

    def clear(self) -> None:
        with self._lock:
            self._session = None
