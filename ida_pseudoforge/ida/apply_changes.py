from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ida_pseudoforge.core.plan_schema import CleanPlan, LocalVariable, RenameSuggestion
from ida_pseudoforge.core.validation import is_valid_c_identifier
from ida_pseudoforge.ida.thread_helpers import run_on_main_thread

try:
    import ida_hexrays  # type: ignore
except Exception:
    ida_hexrays = None


@dataclass(slots=True)
class RenameApplyResult:
    applied: list[dict[str, str]]
    rejected: list[str]


def apply_selected_renames(
    function_ea: int,
    plan: CleanPlan,
    selected_old_names: Iterable[str],
    known_lvar_names: Iterable[str] | None = None,
    captured_lvars: Iterable[LocalVariable] | None = None,
    current_lvars: Iterable[LocalVariable] | None = None,
) -> RenameApplyResult:
    if ida_hexrays is None:
        raise RuntimeError("IDA Hex-Rays APIs are not available")

    renames, rejected = preflight_selected_renames(
        plan,
        selected_old_names,
        known_lvar_names=known_lvar_names,
        captured_lvars=captured_lvars,
        current_lvars=current_lvars,
    )

    def do_apply() -> RenameApplyResult:
        applied = []
        for rename in renames:
            if ida_hexrays.rename_lvar(function_ea, rename.old, rename.new):
                applied.append({"old": rename.old, "new": rename.new})
            else:
                rejected.append("IDA rejected rename %s->%s" % (rename.old, rename.new))
        return RenameApplyResult(applied=applied, rejected=rejected)

    return run_on_main_thread(do_apply, write=True)


def preflight_selected_renames(
    plan: CleanPlan,
    selected_old_names: Iterable[str],
    known_lvar_names: Iterable[str] | None = None,
    captured_lvars: Iterable[LocalVariable] | None = None,
    current_lvars: Iterable[LocalVariable] | None = None,
) -> tuple[list[RenameSuggestion], list[str]]:
    selected = {str(name) for name in selected_old_names if str(name)}
    current_by_name = _lvar_map(current_lvars)
    captured_by_name = _lvar_map(captured_lvars)
    known_names = set(known_lvar_names or [])
    if current_lvars is not None:
        known_names = set(current_by_name)
    check_known_names = known_lvar_names is not None or current_lvars is not None
    by_old = {rename.old: rename for rename in plan.renames}
    accepted: list[RenameSuggestion] = []
    rejected: list[str] = []
    used_new_names = set()

    for old_name in sorted(selected):
        rename = by_old.get(old_name)
        if rename is None:
            rejected.append("Selected rename source is not in the plan: %s" % old_name)
            continue
        kind = (rename.kind or "").lower()
        if not rename.apply:
            rejected.append("Rename is not marked apply-safe: %s->%s" % (rename.old, rename.new))
            continue
        if kind not in {"arg", "lvar"}:
            rejected.append("Rename kind cannot modify IDB: %s" % rename.kind)
            continue
        if check_known_names and rename.old not in known_names:
            rejected.append("Current local variable is missing: %s" % rename.old)
            continue
        identity_error = _identity_mismatch(rename, captured_by_name, current_by_name)
        if identity_error:
            rejected.append(identity_error)
            continue
        if not is_valid_c_identifier(rename.new):
            rejected.append("Rename target is not a valid C identifier: %s" % rename.new)
            continue
        if check_known_names and rename.new in known_names and rename.new != rename.old:
            rejected.append("Rename target collides with current local variable: %s" % rename.new)
            continue
        if rename.new in used_new_names:
            rejected.append("Rename target is duplicated in the selected set: %s" % rename.new)
            continue
        used_new_names.add(rename.new)
        accepted.append(rename)

    return accepted, rejected


def _lvar_map(lvars: Iterable[LocalVariable] | None) -> dict[str, LocalVariable]:
    result: dict[str, LocalVariable] = {}
    for var in lvars or []:
        if var.name and var.name not in result:
            result[var.name] = var
    return result


def _identity_mismatch(
    rename: RenameSuggestion,
    captured_by_name: dict[str, LocalVariable],
    current_by_name: dict[str, LocalVariable],
) -> str:
    if not current_by_name:
        return ""
    expected = rename.identity
    captured = captured_by_name.get(rename.old)
    if not expected and captured is not None:
        expected = captured.identity
    current = current_by_name.get(rename.old)
    actual = current.identity if current is not None else ""
    if not expected or not actual:
        return ""
    if expected == actual:
        return ""
    return "Current local variable identity changed: %s" % rename.old
