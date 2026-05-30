from __future__ import annotations

import json


def main() -> int:
    print(json.dumps({"renames": []}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
