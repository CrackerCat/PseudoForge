from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

from ida_pseudoforge.core.deterministic.schema import Rule, RulePack, RuleReport
from ida_pseudoforge.core.deterministic.validators import (
    parse_rule_pack_file,
    validate_rule_pack_data,
)

_RULE_PACK_CACHE: dict[tuple[tuple[str, ...], tuple[tuple[str, int, int], ...]], tuple[list[RulePack], list[dict[str, str]]]] = {}
_RULE_PACK_CACHE_LOCK = threading.Lock()


def builtin_rules_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "rules" / "builtin"


def project_rules_dir(project_root: str | Path | None = None) -> Path:
    root = Path(project_root) if project_root else Path.cwd()
    return root / "pseudoforge_rules"


def user_rules_dir() -> Path:
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        return Path(appdata) / "PseudoForge" / "rules"
    return Path.home() / "AppData" / "Roaming" / "PseudoForge" / "rules"


def default_rule_dirs(
    extra_dirs: list[str | Path] | None = None,
    project_root: str | Path | None = None,
) -> list[Path]:
    dirs: list[Path] = []
    seen: set[str] = set()
    for item in (builtin_rules_dir(), project_rules_dir(project_root), user_rules_dir()):
        _append_unique_rule_dir(dirs, seen, item)
    for item in extra_dirs or []:
        _append_unique_rule_dir(dirs, seen, item)
    return dirs


def load_default_rule_packs(
    extra_dirs: list[str | Path] | None = None,
    project_root: str | Path | None = None,
    report: RuleReport | None = None,
) -> list[RulePack]:
    return load_rule_packs_from_dirs(default_rule_dirs(extra_dirs, project_root), report=report)


def load_rule_packs_from_dirs(
    directories: list[str | Path],
    report: RuleReport | None = None,
) -> list[RulePack]:
    normalized_dirs = tuple(_normalize_path(directory) for directory in directories)
    signature = _rule_dirs_signature(normalized_dirs)
    cache_key = (normalized_dirs, signature)
    with _RULE_PACK_CACHE_LOCK:
        cached = _RULE_PACK_CACHE.get(cache_key)
    if cached is not None:
        packs, load_errors = cached
        _copy_load_errors(report, load_errors)
        return packs

    local_report = RuleReport()
    packs: list[RulePack] = []
    for directory_index, directory in enumerate(normalized_dirs):
        path = Path(directory)
        if not path.exists() or not path.is_dir():
            continue
        for file_path in sorted(path.glob("*.json")):
            pack = load_rule_pack_file(file_path, report=local_report, source_order=directory_index)
            if pack is not None:
                packs.append(pack)
    load_errors = list(local_report.load_errors)
    with _RULE_PACK_CACHE_LOCK:
        _RULE_PACK_CACHE[cache_key] = (packs, load_errors)
    _copy_load_errors(report, load_errors)
    return packs


def load_rule_pack_file(
    path: str | Path,
    report: RuleReport | None = None,
    source_order: int = 0,
) -> RulePack | None:
    file_path = Path(path)
    data, parse_errors = parse_rule_pack_file(file_path)
    if parse_errors:
        _record_load_errors(report, file_path, parse_errors)
        return None
    assert data is not None
    validation_errors = validate_rule_pack_data(data, str(file_path))
    if validation_errors:
        _record_load_errors(report, file_path, validation_errors)
        return None
    return _rule_pack_from_data(data, str(file_path), source_order)


def _rule_pack_from_data(data: dict[str, Any], source_path: str, source_order: int) -> RulePack:
    pack_id = str(data.get("id", "")).strip()
    source_label = rule_source_label(source_path)
    rules = []
    for item in data.get("rules", []):
        rule = Rule(
            id=str(item.get("id", "")).strip(),
            phase=str(item.get("phase", "")).strip(),
            priority=int(item.get("priority", 0)),
            confidence=float(item.get("confidence", 0.0)),
            scope=dict(item.get("scope", {}) or {}),
            match=dict(item.get("match", {}) or {}),
            emit=dict(item.get("emit", {}) or {}),
            enabled=bool(item.get("enabled", True)),
            override_of=str(item.get("override_of", "") or ""),
            source_path=source_path,
            source_label=source_label,
            source_order=source_order,
            pack_id=pack_id,
        )
        rules.append(rule)
    return RulePack(
        schema_version=int(data.get("schema_version", 1)),
        id=pack_id,
        description=str(data.get("description", "") or ""),
        rules=rules,
        source_path=source_path,
        source_label=source_label,
    )


def _record_load_errors(report: RuleReport | None, path: Path, errors: list[str]) -> None:
    if report is None:
        return
    for error in errors:
        report.load_errors.append(
            {
                "path": rule_source_label(path),
                "error": error,
            }
        )


def _copy_load_errors(report: RuleReport | None, errors: list[dict[str, str]]) -> None:
    if report is None:
        return
    report.load_errors.extend(dict(item) for item in errors)


def _append_unique_rule_dir(dirs: list[Path], seen: set[str], path: str | Path) -> None:
    key = _normalize_path(path).casefold()
    if key in seen:
        return
    seen.add(key)
    dirs.append(Path(path))


def _normalize_path(path: str | Path) -> str:
    try:
        return str(Path(path).resolve())
    except OSError:
        return str(Path(path))


def _rule_dirs_signature(directories: tuple[str, ...]) -> tuple[tuple[str, int, int], ...]:
    items: list[tuple[str, int, int]] = []
    for directory in directories:
        path = Path(directory)
        if not path.exists() or not path.is_dir():
            items.append((str(path), -1, -1))
            continue
        for file_path in sorted(path.glob("*.json")):
            try:
                stat = file_path.stat()
                items.append((str(file_path), int(stat.st_mtime_ns), int(stat.st_size)))
            except OSError:
                items.append((str(file_path), -1, -1))
    return tuple(items)


def rule_source_label(path: str | Path) -> str:
    file_path = Path(path)
    name = file_path.name or str(file_path)
    try:
        resolved = file_path.resolve()
    except OSError:
        resolved = file_path
    for prefix, directory in (
        ("builtin", builtin_rules_dir()),
        ("user", user_rules_dir()),
    ):
        try:
            resolved.relative_to(directory.resolve())
            return "%s/%s" % (prefix, name)
        except (OSError, ValueError):
            pass
    if any(part.lower() == "pseudoforge_rules" for part in resolved.parts):
        return "project/%s" % name
    return "external/%s" % name
