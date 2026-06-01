from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.quality_score import (
    quality_summary_to_markdown,
    score_compare_directory,
    write_quality_summary,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score PseudoForge raw-vs-cleaned pseudocode quality artifacts.")
    parser.add_argument("--compare-dir", required=True, help="IDA batch compare directory containing raw/ and cleaned/.")
    parser.add_argument("--report", default="", help="Optional IDA batch JSONL report for EA/name metadata.")
    parser.add_argument("--json-output", default="", help="Write machine-readable quality summary JSON.")
    parser.add_argument("--markdown-output", default="", help="Write Markdown quality report.")
    parser.add_argument("--top", type=int, default=15, help="Number of worst functions to include.")
    parser.add_argument("--fail-under", type=int, default=0, help="Return non-zero if average score is below this value.")
    args = parser.parse_args(argv)

    report_path = Path(args.report) if args.report else None
    summary = score_compare_directory(Path(args.compare_dir), report_path=report_path, top=args.top)

    json_output = Path(args.json_output) if args.json_output else None
    markdown_output = Path(args.markdown_output) if args.markdown_output else None
    if json_output is not None:
        write_quality_summary(summary, json_output, markdown_output)
    elif markdown_output is not None:
        markdown_output.parent.mkdir(parents=True, exist_ok=True)
        markdown_output.write_text(quality_summary_to_markdown(summary, top=args.top), encoding="utf-8")
    else:
        print(json.dumps(summary, indent=2, sort_keys=True))

    if args.fail_under and float(summary.get("average_score", 0) or 0) < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
