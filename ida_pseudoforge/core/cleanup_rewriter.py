from __future__ import annotations

import re

from ida_pseudoforge.core.plan_schema import CleanupLabel, FunctionCapture


LABEL_RE = re.compile(r"^\s*(?P<label>LABEL_\d+|[A-Za-z_][A-Za-z0-9_]*Cleanup[A-Za-z0-9_]*):\s*$")


def classify_cleanup_labels(capture: FunctionCapture) -> list[CleanupLabel]:
    lines = (capture.pseudocode or "").splitlines()
    labels = []
    label_indices = [
        (index, LABEL_RE.match(line).group("label"))
        for index, line in enumerate(lines)
        if LABEL_RE.match(line)
    ]

    for position, (start, label) in enumerate(label_indices):
        end = label_indices[position + 1][0] - 1 if position + 1 < len(label_indices) else len(lines) - 1
        body = lines[start + 1:end + 1]
        classification, confidence, evidence = _classify_body(body)
        labels.append(
            CleanupLabel(
                label=label,
                classification=classification,
                start_line=start,
                end_line=end,
                confidence=confidence,
                evidence=evidence,
            )
        )

    return labels


def _classify_body(body: list[str]) -> tuple[str, float, str]:
    text = "\n".join(body)
    entry_text = _entry_block_text(body)
    has_return = "return" in text

    if "__fastfail(3" in text:
        return (
            "failfast_corrupt_list_entry",
            0.96,
            "Calls __fastfail(3), commonly emitted for corrupt LIST_ENTRY integrity checks",
        )

    if "ExReleaseResourceLite" in text and "KeLeaveCriticalRegion" in text:
        return (
            "release_resource_and_leave_critical_region",
            0.94,
            "Releases an ERESOURCE and leaves the critical region before returning",
        )

    if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?:-107374\d+|322122\d+|0x[4C][0-9A-Fa-f]{7})\s*;", text) and "goto" in text:
        return (
            "set_error_status_and_cleanup",
            0.84,
            "Sets an NTSTATUS-style error and jumps to a common cleanup label",
        )

    if "VfFreeCapturedUnicodeString" in text:
        if has_return:
            return (
                "cleanup_captured_unicode_string_and_return",
                0.94,
                "Calls VfFreeCapturedUnicodeString and returns from the function",
            )
        return (
            "cleanup_captured_unicode_string",
            0.88,
            "Calls VfFreeCapturedUnicodeString",
        )

    if "ObfDereferenceObject" in text or "ObDereferenceObject" in text:
        if has_return:
            return (
                "dereference_object_and_return",
                0.93,
                "Dereferences an object reference and returns status",
            )
        return (
            "dereference_object",
            0.87,
            "Dereferences an object reference",
        )

    if has_return and _looks_like_irp_completion_return_tail(text):
        return (
            "irp_complete_request_tail",
            0.88,
            "Sets IRP IoStatus fields, completes the request, and returns status",
        )

    if has_return and _looks_like_success_accounting_return_tail(entry_text):
        return (
            "success_accounting_return_tail",
            0.80,
            "Updates accounting or state and returns the successful result",
        )

    if has_return and ("status" in text or "updated" in text):
        return (
            "status_return_tail",
            0.78,
            "Common tail returns a status accumulator",
        )

    if "goto" in text and ("Cleanup" in text or "LABEL_" in text):
        return (
            "cleanup_dispatch_tail",
            0.72,
            "Common tail dispatches to another label",
        )

    return (
        "unknown_label_block",
        0.35,
        "Label block did not match a known cleanup pattern",
    )


def _looks_like_irp_completion_return_tail(text: str) -> bool:
    if "IofCompleteRequest(" not in text and "IoCompleteRequest(" not in text:
        return False
    if not re.search(r"->IoStatus\.Status\s*=", text):
        return False
    if not re.search(r"\breturn\b", text):
        return False
    return True


def _looks_like_success_accounting_return_tail(text: str) -> bool:
    if "__fastfail" in text:
        return False
    if re.search(r"\b(?:status|updated)\b", text, re.IGNORECASE):
        return False
    if not re.search(r"\breturn\s+[A-Za-z_][A-Za-z0-9_]*\s*;", text):
        return False
    if re.search(r"\bgoto\b", text):
        return False
    return bool(
        re.search(r"(?:\+\+|--|\+=|-=)", text)
        or re.search(r"\b[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?\s*=\s*[^;\n]+;", text)
    )


def _entry_block_text(body: list[str]) -> str:
    lines = []
    for line in body:
        lines.append(line)
        stripped = line.strip()
        if (
            re.search(r"\breturn\b", stripped)
            or re.search(r"\bgoto\b", stripped)
            or "__fastfail" in stripped
        ):
            break
    return "\n".join(lines)
