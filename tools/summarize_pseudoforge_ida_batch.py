from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize a PseudoForge IDA batch JSONL report.")
    parser.add_argument("report", help="Path to pseudoforge_ida_batch JSONL report.")
    parser.add_argument("--top", type=int, default=10, help="Number of warnings/skips/slow functions to show.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON summary.")
    parser.add_argument("--fail-on-error", action="store_true", help="Return non-zero when PseudoForge errors are present.")
    args = parser.parse_args(argv)

    records = load_records(Path(args.report))
    summary = summarize_records(records, top=args.top)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print_text_summary(summary)
    return 1 if args.fail_on_error and summary["status_counts"].get("error", 0) else 0


def load_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
    return records


def summarize_records(records: list[dict[str, Any]], top: int = 10) -> dict[str, Any]:
    functions = [record for record in records if record.get("event") == "function"]
    status_counts = Counter(str(record.get("status", "")) for record in functions)
    warning_counts: Counter[str] = Counter()
    skip_reasons: Counter[str] = Counter()
    llm_status_counts: Counter[str] = Counter()
    errors: list[dict[str, Any]] = []
    slow_functions: list[dict[str, Any]] = []
    comparison_records = 0

    for record in functions:
        if record.get("llm_status"):
            llm_status_counts[str(record.get("llm_status", ""))] += 1
        if record.get("comparison"):
            comparison_records += 1
        if record.get("status") == "skipped":
            skip_reasons[str(record.get("reason", ""))] += 1
        if record.get("status") == "error":
            errors.append(_function_brief(record, "error"))
        for warning in record.get("warning_samples", []) or []:
            warning_counts[str(warning)] += 1
        slow_functions.append(
            {
                "ea": record.get("ea", ""),
                "name": record.get("name", ""),
                "elapsed_seconds": float(record.get("elapsed_seconds", 0) or 0),
                "status": record.get("status", ""),
            }
        )

    start = next((record for record in records if record.get("event") == "start"), {})
    final_summary = next((record for record in reversed(records) if record.get("event") == "summary"), {})
    slow_functions.sort(key=lambda item: item["elapsed_seconds"], reverse=True)

    return {
        "start": start,
        "summary": final_summary,
        "function_records": len(functions),
        "status_counts": dict(status_counts),
        "warning_groups": _counter_to_list(warning_counts, top),
        "skip_reasons": _counter_to_list(skip_reasons, top),
        "llm_status_counts": dict(llm_status_counts),
        "errors": errors[:top],
        "slow_functions": slow_functions[:top],
        "comparison_records": comparison_records,
    }


def print_text_summary(summary: dict[str, Any]) -> None:
    final = summary.get("summary") or {}
    start = summary.get("start") or {}
    status_counts = summary.get("status_counts") or {}

    print("PseudoForge IDA batch summary")
    if start.get("idb_path"):
        print("  IDB: %s" % start.get("idb_path"))
    if start.get("forge_path"):
        print("  Forge: %s" % start.get("forge_path"))
    if start.get("compare_dir"):
        print("  Compare: %s" % start.get("compare_dir"))
    print("  Processed: %s" % final.get("processed", summary.get("function_records", 0)))
    print("  Succeeded: %s" % final.get("succeeded", status_counts.get("ok", 0)))
    print("  Skipped: %s" % final.get("skipped", status_counts.get("skipped", 0)))
    print("  Failed: %s" % final.get("failed", status_counts.get("error", 0)))
    if final.get("elapsed_seconds") is not None:
        print("  Elapsed seconds: %s" % final.get("elapsed_seconds"))
    if summary.get("comparison_records"):
        print("  Comparison artifacts: %s" % summary.get("comparison_records"))
    if summary.get("llm_status_counts"):
        llm_status = ", ".join(
            "%s=%s" % (key, value)
            for key, value in sorted((summary.get("llm_status_counts") or {}).items())
        )
        print("  LLM statuses: %s" % llm_status)

    _print_group("Warning groups", summary.get("warning_groups") or [])
    _print_group("Skip reasons", summary.get("skip_reasons") or [])
    _print_functions("Errors", summary.get("errors") or [])
    _print_functions("Slow functions", summary.get("slow_functions") or [], include_elapsed=True)


def _print_group(title: str, items: list[dict[str, Any]]) -> None:
    print("")
    print(title + ":")
    if not items:
        print("  none")
        return
    for item in items:
        print("  %s  %s" % (item["count"], item["name"]))


def _print_functions(title: str, items: list[dict[str, Any]], include_elapsed: bool = False) -> None:
    print("")
    print(title + ":")
    if not items:
        print("  none")
        return
    for item in items:
        suffix = ""
        if include_elapsed:
            suffix = " %.3fs" % float(item.get("elapsed_seconds", 0) or 0)
        detail = item.get("error") or item.get("status") or ""
        print("  %s %s%s %s" % (item.get("ea", ""), item.get("name", ""), suffix, detail))


def _counter_to_list(counter: Counter[str], top: int) -> list[dict[str, Any]]:
    return [{"count": count, "name": name} for name, count in counter.most_common(top)]


def _function_brief(record: dict[str, Any], detail_key: str) -> dict[str, Any]:
    return {
        "ea": record.get("ea", ""),
        "name": record.get("name", ""),
        detail_key: record.get(detail_key, ""),
        "elapsed_seconds": record.get("elapsed_seconds", 0),
    }


if __name__ == "__main__":
    raise SystemExit(main())
