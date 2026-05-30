from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable


DEFAULT_WDK_INCLUDE_ROOT = Path(r"C:\Program Files (x86)\Windows Kits\10\Include")
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "ida_pseudoforge" / "profiles" / "status_codes.json"
LOW_SUCCESS_ALLOWLIST = {"STATUS_SUCCESS", "STATUS_PENDING"}
PREFERRED_NAMES_BY_VALUE = {
    0x00000000: "STATUS_SUCCESS",
    0x00000103: "STATUS_PENDING",
}

_STATUS_DEFINE_RE = re.compile(
    r"^\s*#define\s+(STATUS_[A-Za-z0-9_]+)\s+\(\(NTSTATUS\)\s*(?P<value>0x[0-9A-Fa-f]+|\d+)[ULul]*\)",
    re.MULTILINE,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build PseudoForge NTSTATUS profile from local WDK ntstatus.h.")
    parser.add_argument("--wdk-include-root", default=str(DEFAULT_WDK_INCLUDE_ROOT))
    parser.add_argument("--version", default="")
    parser.add_argument("--header", default="")
    parser.add_argument("--out", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--list-versions", action="store_true")
    parser.add_argument("--include-low-success", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    include_root = Path(args.wdk_include_root)
    if args.list_versions:
        for version in _list_wdk_versions(include_root):
            print(version)
        return 0

    header_path = Path(args.header) if args.header else _find_ntstatus_header(include_root, args.version)
    definitions = parse_ntstatus_definitions(header_path.read_text(encoding="utf-8", errors="replace"))
    profile = build_status_code_profile(definitions, include_low_success=args.include_low_success)

    if args.summary:
        _print_summary(header_path, definitions, profile, include_low_success=args.include_low_success)

    text = json.dumps(profile, indent=2) + "\n"
    if args.dry_run:
        sys.stdout.write(text)
    else:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
    return 0


def parse_ntstatus_definitions(text: str) -> list[tuple[int, str]]:
    definitions: list[tuple[int, str]] = []
    for match in _STATUS_DEFINE_RE.finditer(text):
        value = int(match.group("value"), 0) & 0xFFFFFFFF
        name = match.group(1)
        definitions.append((value, name))
    return definitions


def build_status_code_profile(
    definitions: Iterable[tuple[int, str]], *, include_low_success: bool = False
) -> dict[str, str]:
    value_to_name: dict[int, str] = {}
    for value, name in definitions:
        if not _should_include_status(value, name, include_low_success=include_low_success):
            continue
        preferred = PREFERRED_NAMES_BY_VALUE.get(value)
        if preferred == name:
            value_to_name[value] = name
            continue
        if value in value_to_name:
            continue
        value_to_name[value] = name

    profile: dict[str, str] = {}
    for value in sorted(value_to_name):
        name = value_to_name[value]
        profile[str(value)] = name
        if value & 0x80000000:
            profile[str(value - 0x100000000)] = name
    return profile


def _should_include_status(value: int, name: str, *, include_low_success: bool) -> bool:
    if include_low_success:
        return True
    if name in LOW_SUCCESS_ALLOWLIST:
        return True
    return (value & 0xC0000000) != 0


def _find_ntstatus_header(include_root: Path, requested_version: str) -> Path:
    version_dir = _find_wdk_version_dir(include_root, requested_version)
    header = version_dir / "shared" / "ntstatus.h"
    if not header.exists():
        raise FileNotFoundError("ntstatus.h was not found under %s" % header)
    return header


def _find_wdk_version_dir(include_root: Path, requested_version: str) -> Path:
    if requested_version:
        path = include_root / requested_version
        if not path.is_dir():
            raise FileNotFoundError("WDK include version was not found: %s" % path)
        return path
    versions = _list_wdk_versions(include_root)
    if not versions:
        raise FileNotFoundError("No WDK include versions were found under %s" % include_root)
    return include_root / versions[-1]


def _list_wdk_versions(include_root: Path) -> list[str]:
    if not include_root.is_dir():
        return []
    return sorted(
        [path.name for path in include_root.iterdir() if path.is_dir() and re.match(r"^\d+(?:\.\d+)+$", path.name)],
        key=_version_key,
    )


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split(".") if part.isdigit())


def _print_summary(
    header_path: Path,
    definitions: list[tuple[int, str]],
    profile: dict[str, str],
    *,
    include_low_success: bool,
) -> None:
    unique_values = len({value for value, _name in definitions})
    unsigned_entries = sum(1 for key in profile if not key.startswith("-"))
    signed_entries = sum(1 for key in profile if key.startswith("-"))
    print("source: %s" % header_path, file=sys.stderr)
    print("raw_definitions: %d" % len(definitions), file=sys.stderr)
    print("raw_unique_values: %d" % unique_values, file=sys.stderr)
    print("profile_entries: %d" % len(profile), file=sys.stderr)
    print("profile_unsigned_entries: %d" % unsigned_entries, file=sys.stderr)
    print("profile_signed_entries: %d" % signed_entries, file=sys.stderr)
    print("include_low_success: %s" % include_low_success, file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
