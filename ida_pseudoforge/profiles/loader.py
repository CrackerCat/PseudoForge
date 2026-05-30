from __future__ import annotations

import json
from functools import lru_cache
from typing import Any
from pathlib import Path


PROFILE_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=None)
def load_json_profile(name: str) -> Any:
    path = PROFILE_DIR / name
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}


@lru_cache(maxsize=None)
def load_profile(name: str) -> dict[str, str]:
    data = load_json_profile(name)
    if not isinstance(data, dict):
        return {}
    return {str(key): str(value) for key, value in data.items()}


def get_status_name(literal: str | int) -> str:
    return load_profile("status_codes.json").get(str(literal), "")


def get_system_information_class_name(value: int) -> str:
    return load_profile("system_information_class.json").get(str(value), "")


def get_process_information_class_name(value: int) -> str:
    return load_profile("process_information_class.json").get(str(value), "")


@lru_cache(maxsize=None)
def get_system_information_class_value(name: str) -> int | None:
    target = str(name or "").strip()
    if not target:
        return None
    for value, enum_name in load_profile("system_information_class.json").items():
        if enum_name == target:
            try:
                return int(value)
            except ValueError:
                return None
    return None


@lru_cache(maxsize=None)
def get_process_information_class_value(name: str) -> int | None:
    target = str(name or "").strip()
    if not target:
        return None
    for value, enum_name in load_profile("process_information_class.json").items():
        if enum_name == target:
            try:
                return int(value)
            except ValueError:
                return None
    return None
