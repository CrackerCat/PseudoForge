from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.deterministic.validators import validate_rule_pack_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate PseudoForge deterministic rule packs.")
    parser.add_argument("paths", nargs="+", help="Rule JSON file or directory path.")
    args = parser.parse_args(argv)

    files = _collect_rule_files(args.paths)
    if not files:
        print("No rule files found.")
        return 1

    failed = 0
    for path in files:
        errors = validate_rule_pack_file(path)
        if errors:
            failed += 1
            print("%s: FAIL" % path)
            for error in errors:
                print("  - %s" % error)
        else:
            print("%s: OK" % path)

    if failed:
        print("Validated %d rule file(s), %d failed." % (len(files), failed))
        return 1
    print("Validated %d rule file(s), all OK." % len(files))
    return 0


def _collect_rule_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for item in paths:
        path = Path(item)
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        elif path.exists():
            files.append(path)
        else:
            files.append(path)
    return files


if __name__ == "__main__":
    raise SystemExit(main())
